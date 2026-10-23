#!/usr/bin/env node
// am-i-cooked scanner: lockfiles -> OSV match -> cve.now enrichment -> verdict.
// Usage: node scan.mjs [dir] [--json | --sarif | --markdown] [--fail-on=any|cooked|kev|none] [--ignore=ID,ID]
//                       [--offline] [--no-cache] [--baseline=earlier-report.json] [--strict]
// Exit code 0 = pass, 1 = failed the --fail-on threshold (default: any finding), 2 = nothing checked or error.
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, relative } from 'node:path';

// Endpoints can be overridden (tests point them at a local mock server).
const OSV = process.env.AM_I_COOKED_OSV_URL ?? 'https://api.osv.dev/v1';
const CVE_NOW = process.env.AM_I_COOKED_CVE_NOW_URL ?? 'https://cve.now/api/v1/entries';
const CACHE_DIR = process.env.AM_I_COOKED_CACHE ?? join(homedir(), '.cache', 'am-i-cooked');
const CACHE_TTL_MS = 6 * 60 * 60 * 1000;
const SKIP_DIRS = new Set(['node_modules', '.git', '.dart_tool', 'build', 'dist', '.venv', 'venv', 'target', 'vendor', '.build', '.gradle', 'Pods']);
const TEXT_LIMIT = 10;
const OSV_LABEL_TO_CVSS = { CRITICAL: 9.5, HIGH: 7.5, MODERATE: 5, MEDIUM: 5, LOW: 2 };

const args = process.argv.slice(2);
const asJson = args.includes('--json');
const asSarif = args.includes('--sarif');
const asMarkdown = args.includes('--markdown');
const offline = args.includes('--offline'); // answer from the local cache only, never touch the network
const useCache = !args.includes('--no-cache');
const strict = args.includes('--strict'); // fail (exit 2) when anything could not be checked
const failOn = args.find((a) => a.startsWith('--fail-on='))?.split('=')[1] ?? 'any';
const root = args.find((a) => !a.startsWith('--')) ?? '.';
if (!['any', 'cooked', 'kev', 'none'].includes(failOn)) {
  console.error('am-i-cooked: --fail-on must be any, cooked, kev or none');
  process.exit(2);
}

// ---- lockfile parsers: text -> [{ name, version }] ----

// Parsers return { name, version, direct? } (direct: true/false when the lockfile says, undefined when it does not)
// or { skip: reason } for dependencies that are not published packages (git, file, url): those are reported, not guessed.
function parseNpmLock(text) {
  const lock = JSON.parse(text);
  const root = lock.packages?.[''] ?? {};
  const directNames = new Set(['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'].flatMap((k) => Object.keys(root[k] ?? {})));
  return Object.entries(lock.packages ?? {})
    .filter(([path, pkg]) => path && !pkg.link) // workspace links are local code
    .map(([path, pkg]) => {
      const name = pkg.name ?? path.split('node_modules/').pop();
      if (pkg.resolved && !/^https?:\/\//.test(pkg.resolved)) return { skip: pkg.resolved.startsWith('file:') ? 'file' : 'git', name, version: pkg.version };
      return pkg.version ? { name, version: pkg.version, direct: path === `node_modules/${name}` && directNames.has(name) } : null;
    })
    .filter(Boolean);
}

function parsePnpm(text) {
  const out = [];
  let inPackages = false;
  for (const line of text.split('\n')) {
    if (/^\S/.test(line)) inPackages = line.trim() === 'packages:';
    if (!inPackages) continue;
    const m = line.match(/^ {2}'?\/?((?:@[^/@\s']+\/)?[^@\s'/(]+)@(\d[^:'(\s]*)/);
    if (m) out.push({ name: m[1], version: m[2] });
  }
  return out;
}

function parseYarn(text) {
  const out = [];
  let name = null;
  for (const line of text.split('\n')) {
    const head = line.match(/^"?((?:@[^/@]+\/)?[^@"\s]+)@/);
    if (head && !line.startsWith(' ')) name = head[1];
    const ver = line.match(/^ {2}version:? "?([^"\s]+)"?/);
    if (ver && name) out.push({ name, version: ver[1] });
  }
  return out;
}

function parseRequirements(text) {
  return text
    .split('\n')
    .map((line) => line.match(/^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?==([^\s;#\\]+)/))
    .filter(Boolean)
    .map((m) => ({ name: m[1], version: m[2] }));
}

function parsePoetry(text) {
  return text
    .split('[[package]]')
    .slice(1)
    .filter((block) => !/^source = \{ (editable|virtual) /m.test(block)) // uv: the project itself
    .map((block) => ({
      name: block.match(/^name = "([^"]+)"/m)?.[1],
      version: block.match(/^version = "([^"]+)"/m)?.[1],
    }))
    .filter((p) => p.name && p.version);
}

function parsePubspec(text) {
  const out = [];
  let cur = null;
  for (const line of text.split('\n')) {
    const head = line.match(/^ {2}([A-Za-z0-9_]+):\s*$/);
    if (head) out.push((cur = { name: head[1] }));
    const dep = line.match(/^ {4}dependency:\s*"?([^"\n]+?)"?\s*$/);
    if (dep && cur) cur.direct = dep[1].startsWith('direct');
    const source = line.match(/^ {4}source:\s*(\S+)/);
    if (source && cur) cur.source = source[1];
    const ver = line.match(/^ {4}version:\s*"?([^"\s]+)"?/);
    if (ver && cur) cur.version = ver[1];
  }
  return out
    .filter((p) => p.version && p.source !== 'sdk' && p.source !== 'path') // SDK and local packages are not advisories material
    .map(({ source, ...p }) => (source && source !== 'hosted' ? { skip: 'git', name: p.name, version: p.version } : p));
}

function parseCargo(text) {
  return text
    .split('[[package]]')
    .slice(1)
    .map((block) => ({
      name: block.match(/^name = "([^"]+)"/m)?.[1],
      version: block.match(/^version = "([^"]+)"/m)?.[1],
      source: block.match(/^source = "([^"]+)"/m)?.[1],
    }))
    .filter((p) => p.name && p.version && p.source) // no source = local workspace crate
    .map(({ source, ...p }) => (source.startsWith('git+') ? { skip: 'git', ...p } : p));
}

function parseGoSum(text) {
  return text
    .split('\n')
    .map((line) => line.match(/^(\S+) (v\S+?) h1:/))
    .filter((m) => m && !m[2].endsWith('/go.mod'))
    .map((m) => ({ name: m[1], version: m[2] }));
}

function parseGemfile(text) {
  const out = [];
  const direct = new Set();
  let section = '';
  for (const line of text.split('\n')) {
    if (/^[A-Z]+$/.test(line)) section = line;
    if (section === 'DEPENDENCIES') {
      const dep = line.match(/^ {2}([A-Za-z0-9_.-]+)/);
      if (dep) direct.add(dep[1]);
    }
    const spec = line.match(/^ {4}([A-Za-z0-9_.-]+) \((\d[\w.]*)(?:-[^)]*)?\)$/);
    if (!spec) continue;
    if (section === 'GEM') out.push({ name: spec[1], version: spec[2] });
    else if (section === 'GIT') out.push({ skip: 'git', name: spec[1], version: spec[2] }); // PATH gems are local code
  }
  return out.map((p) => (p.skip ? p : { ...p, direct: direct.has(p.name) }));
}

function parseComposer(text) {
  const lock = JSON.parse(text);
  return [...(lock.packages ?? []), ...(lock['packages-dev'] ?? [])]
    .filter((p) => p.name && p.version)
    .map((p) => ({ name: p.name, version: p.version.replace(/^v/, '') }));
}

function parseBun(text) {
  const lock = JSON.parse(text.replace(/,(\s*[}\]])/g, '$1')); // bun.lock is JSON with trailing commas
  return Object.values(lock.packages ?? {})
    .map((entry) => (Array.isArray(entry) ? entry[0] : null))
    .filter((spec) => typeof spec === 'string' && !spec.includes('workspace:'))
    .map((spec) => ({ name: spec.slice(0, spec.lastIndexOf('@')), version: spec.slice(spec.lastIndexOf('@') + 1) }))
    .filter((p) => p.name && p.version);
}

function parseGradle(text) {
  return text
    .split('\n')
    .map((line) => line.match(/^([^#=\s:]+:[^#=\s:]+):([^=\s:]+)=/))
    .filter(Boolean)
    .map((m) => ({ name: m[1], version: m[2] }));
}

function parseNuget(text) {
  const lock = JSON.parse(text);
  return Object.values(lock.dependencies ?? {}).flatMap((framework) =>
    Object.entries(framework)
      .filter(([, dep]) => dep.resolved && dep.type !== 'Project')
      .map(([name, dep]) => ({ name, version: dep.resolved, direct: dep.type === 'Direct' })));
}

function parseMix(text) {
  return text
    .split('\n')
    .map((line) => line.match(/^\s*"[^"]+": \{:hex, :([^,]+), "([^"]+)"/))
    .filter(Boolean)
    .map((m) => ({ name: m[1], version: m[2] }));
}

// Swift Package Manager: v1 files nest pins under "object", v2/v3 do not. Pins on a branch or revision have no version.
function parseSwiftResolved(text) {
  const lock = JSON.parse(text);
  const pins = lock.pins ?? lock.object?.pins ?? [];
  return pins
    .map((pin) => ({ url: pin.location ?? pin.repositoryURL, version: pin.state?.version }))
    .filter((pin) => pin.url && pin.version)
    .map((pin) => ({ name: pin.url.replace(/^[a-z+]+:\/\//, '').replace(/^git@([^:]+):/, '$1/').replace(/\.git$/, ''), version: pin.version }));
}

function parseCabalFreeze(text) {
  return [...text.matchAll(/any\.([A-Za-z0-9-]+)\s*==\s*(\d[\d.]*)/g)].map((m) => ({ name: m[1], version: m[2] }));
}

function parseStackLock(text) {
  return [...text.matchAll(/hackage:\s*([A-Za-z0-9-]+?)-(\d[\d.]*)@/g)].map((m) => ({ name: m[1], version: m[2] }));
}

const LOCKFILES = {
  'package-lock.json': { ecosystem: 'npm', parse: parseNpmLock },
  'pnpm-lock.yaml': { ecosystem: 'npm', parse: parsePnpm },
  'yarn.lock': { ecosystem: 'npm', parse: parseYarn },
  'requirements.txt': { ecosystem: 'PyPI', parse: parseRequirements },
  'poetry.lock': { ecosystem: 'PyPI', parse: parsePoetry },
  'uv.lock': { ecosystem: 'PyPI', parse: parsePoetry },
  'pubspec.lock': { ecosystem: 'Pub', parse: parsePubspec },
  'Cargo.lock': { ecosystem: 'crates.io', parse: parseCargo },
  'go.sum': { ecosystem: 'Go', parse: parseGoSum },
  'Gemfile.lock': { ecosystem: 'RubyGems', parse: parseGemfile },
  'composer.lock': { ecosystem: 'Packagist', parse: parseComposer },
  'bun.lock': { ecosystem: 'npm', parse: parseBun },
  'gradle.lockfile': { ecosystem: 'Maven', parse: parseGradle },
  'packages.lock.json': { ecosystem: 'NuGet', parse: parseNuget },
  'mix.lock': { ecosystem: 'Hex', parse: parseMix },
  'Package.resolved': { ecosystem: 'SwiftURL', parse: parseSwiftResolved },
  'cabal.project.freeze': { ecosystem: 'Hackage', parse: parseCabalFreeze },
  'stack.yaml.lock': { ecosystem: 'Hackage', parse: parseStackLock },
};

const lockfileFor = (name) =>
  LOCKFILES[name]
  ?? (/^requirements.*\.txt$/.test(name) ? LOCKFILES['requirements.txt'] : null)
  ?? (/gradle\.lockfile$/.test(name) ? LOCKFILES['gradle.lockfile'] : null); // also buildscript-gradle.lockfile

function findLockfiles(dir, depth = 0) {
  if (depth > 4) return [];
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    if (entry.isDirectory()) return SKIP_DIRS.has(entry.name) ? [] : findLockfiles(join(dir, entry.name), depth + 1);
    return lockfileFor(entry.name) ? [join(dir, entry.name)] : [];
  });
}

// ---- network ----

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function cachePath(url, init) {
  const key = createHash('sha256').update(`${init?.method ?? 'GET'} ${url} ${init?.body ?? ''}`).digest('hex').slice(0, 32);
  return join(CACHE_DIR, `${key}.json`);
}

function readCache(file) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

function writeCache(file, data) {
  try {
    mkdirSync(CACHE_DIR, { recursive: true });
    writeFileSync(file, JSON.stringify({ at: Date.now(), data }));
  } catch {
    // a read-only cache dir must never break a scan
  }
}

// GET/POST JSON with a disk cache (6h), retries on 429/5xx/network errors, and stale-cache fallback.
// Returns null on 404. Throws an Error whose message says what to do.
async function getJson(url, init) {
  const file = cachePath(url, init);
  const cached = useCache || offline ? readCache(file) : null;
  const host = new URL(url).host;
  if (cached && (offline || Date.now() - cached.at < CACHE_TTL_MS)) return cached.data;
  if (offline) throw new Error(`--offline: no cached answer from ${host} for this scan. Run once online first.`);

  let failure = '';
  for (let attempt = 0; attempt < 3; attempt++) {
    if (attempt) await sleep(500 * 2 ** attempt);
    try {
      const res = await fetch(url, { ...init, signal: AbortSignal.timeout(20000) });
      if (res.status === 404) {
        writeCache(file, null);
        return null;
      }
      if (res.ok) {
        const data = await res.json();
        writeCache(file, data);
        return data;
      }
      failure = `${host} answered HTTP ${res.status}`;
      if (res.status !== 429 && res.status < 500) break; // other 4xx will not get better
    } catch (err) {
      failure = `cannot reach ${host} (${err.cause?.code ?? err.name})`;
    }
  }
  if (cached) {
    console.error(`am-i-cooked: ${failure}; using cached data from ${new Date(cached.at).toISOString()}`);
    return cached.data;
  }
  throw new Error(`${failure}. Check your connection, or scan from cache with --offline.`);
}

async function osvMatch(packages) {
  const matches = new Map(); // "ecosystem:name@version" -> [osv ids]
  for (let i = 0; i < packages.length; i += 500) {
    const chunk = packages.slice(i, i + 500);
    const body = JSON.stringify({
      queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })),
    });
    const data = await getJson(`${OSV}/querybatch`, { method: 'POST', body });
    if (!data) throw new Error('OSV.dev returned no data for this request');
    chunk.forEach((p, j) => {
      const ids = (data.results[j]?.vulns ?? []).map((v) => v.id);
      if (ids.length) matches.set(p.key, ids);
    });
  }
  return matches;
}

// Details for one vulnerability id: cve.now first (KEV, CVSS, fixed versions), OSV.dev as fallback.
async function vulnDetails(id) {
  const now = await getJson(`${CVE_NOW}/${id}`).catch(() => null);
  if (now?.id) {
    return {
      id: now.id,
      title: now.title,
      cvss: now.severity?.cvss ?? null,
      kev: Boolean(now.exploitation?.kev),
      likelyExploited: Boolean(now.exploitation?.epssReached || now.exploitation?.exploitDb),
      affected: (now.affected ?? [])
        .filter((a) => a.package)
        .map((a) => ({ ecosystem: a.ecosystem, name: a.package, fixed: (a.ranges ?? []).map((r) => r.fixed).filter(Boolean) })),
      source: 'cve.now',
    };
  }
  const osv = await getJson(`${OSV}/vulns/${id}`).catch(() => null);
  if (!osv) return { id, title: id, cvss: null, kev: false, likelyExploited: false, affected: [], source: 'none' };
  return {
    id: osv.aliases?.find((a) => a.startsWith('CVE-')) ?? osv.id,
    title: osv.summary ?? osv.id,
    cvss: OSV_LABEL_TO_CVSS[osv.database_specific?.severity] ?? null,
    kev: false,
    likelyExploited: false,
    affected: (osv.affected ?? []).map((a) => ({
      ecosystem: a.package?.ecosystem,
      name: a.package?.name,
      fixed: (a.ranges ?? []).flatMap((r) => r.events ?? []).map((e) => e.fixed).filter(Boolean),
    })),
    source: 'osv.dev',
  };
}

// ---- helpers ----

const stripV = (v) => v.replace(/^v/, ''); // Go versions carry a "v" prefix, advisories do not

function compareVersions(a, b) {
  const pa = stripV(a).split(/[.\-+]/);
  const pb = stripV(b).split(/[.\-+]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = Number(pa[i] ?? 0);
    const y = Number(pb[i] ?? 0);
    if (Number.isNaN(x) || Number.isNaN(y)) {
      const c = String(pa[i] ?? '').localeCompare(String(pb[i] ?? ''));
      if (c) return c;
    } else if (x !== y) return x - y;
  }
  return 0;
}

function smallestFix(details, pkg) {
  const fixes = details.affected
    .filter((a) => a.name?.toLowerCase() === pkg.name.toLowerCase() && a.ecosystem?.toLowerCase() === pkg.ecosystem.toLowerCase())
    .flatMap((a) => a.fixed)
    .filter((v) => compareVersions(v, pkg.version) > 0)
    .sort(compareVersions);
  return fixes[0] ?? null;
}

function verdictFor(findings, lockfileCount, packageCount) {
  if (!lockfileCount || !packageCount) return 'unknown'; // nothing was actually checked, never say safe
  if (!findings.length) return 'safe';
  const cooked = findings.some((f) => f.kev || (f.cvss ?? 0) >= 9 || (f.likelyExploited && (f.cvss ?? 0) >= 7));
  return cooked ? 'cooked' : 'a bit cooked';
}

// 0-100. The worst finding sets the base: CVSS/10 x exploit multiplier (KEV 1, exploit seen 0.9, theoretical 0.75;
// missing CVSS counts as 5). Each extra finding adds 2, capped at +15. "Theoretical" means no known exploitation,
// not "unreachable": this is not a reachability analysis.
function riskScore(findings) {
  if (!findings.length) return 0;
  const weight = (f) => ((f.cvss ?? 5) / 10) * (f.kev ? 1 : f.likelyExploited ? 0.9 : 0.75);
  const worst = Math.max(...findings.map(weight));
  return Math.min(100, Math.round(worst * 100 + Math.min(15, (findings.length - 1) * 2)));
}

// One target per package: the highest fix needed to clear every finding. When that is a major jump,
// also report the highest fix inside the current major (safeTarget) and what it leaves open.
function upgradePlan(findings) {
  const majorOf = (v) => stripV(v).split('.')[0];
  const plan = new Map();
  for (const f of findings) {
    const key = `${f.ecosystem}:${f.package}@${f.installed}`;
    const row = plan.get(key) ?? { ecosystem: f.ecosystem, package: f.package, installed: f.installed, target: null, safeTarget: null, fixes: 0, unfixed: 0, residualAfterSafe: 0, worstCvss: 0, direct: f.direct };
    const higher = (a, b) => (!a || compareVersions(b, a) > 0 ? b : a);
    if (f.fixedIn) {
      row.fixes++;
      row.target = higher(row.target, f.fixedIn);
      if (majorOf(f.fixedIn) === majorOf(f.installed)) row.safeTarget = higher(row.safeTarget, f.fixedIn);
      else row.residualAfterSafe++;
    } else {
      row.unfixed++;
      row.residualAfterSafe++;
    }
    row.worstCvss = Math.max(row.worstCvss, f.cvss ?? 0);
    plan.set(key, row);
  }
  for (const row of plan.values()) row.majorJump = Boolean(row.target) && majorOf(row.target) !== majorOf(row.installed);
  return [...plan.values()].sort((a, b) => b.worstCvss - a.worstCvss);
}

// Accepted risks: --ignore=ID,ID and/or a .cookedignore file in the scanned root (one id per line, # comments).
function loadIgnored() {
  const fromFlag = (args.find((a) => a.startsWith('--ignore='))?.split('=')[1] ?? '').split(',');
  const file = join(root, '.cookedignore');
  const fromFile = existsSync(file) ? readFileSync(file, 'utf8').split('\n').map((l) => l.replace(/#.*/, '')) : [];
  return new Set([...fromFlag, ...fromFile].map((id) => id.trim().toUpperCase()).filter(Boolean));
}

// Post-fix verification: compare against an earlier --json report. A finding is the same if id and package match
// (the installed version changes when you upgrade).
function compareToBaseline(report) {
  const file = args.find((a) => a.startsWith('--baseline='))?.split('=')[1];
  if (!file) return null;
  let before;
  try {
    before = JSON.parse(readFileSync(file, 'utf8'));
    if (!Array.isArray(before.findings)) throw new Error('no findings array');
  } catch (err) {
    throw new Error(`--baseline: cannot read ${file} as an am-i-cooked --json report (${err.message})`);
  }
  const key = (f) => `${f.id}|${f.package}`;
  const now = new Set(report.findings.map(key));
  const was = new Set(before.findings.map(key));
  return {
    baseline: file,
    verdictBefore: before.verdict,
    verdictAfter: report.verdict,
    fixed: before.findings.filter((f) => !now.has(key(f))).map((f) => ({ id: f.id, package: f.package })),
    remaining: report.findings.filter((f) => was.has(key(f))).length,
    introduced: report.findings.filter((f) => !was.has(key(f))).map((f) => ({ id: f.id, package: f.package })),
  };
}

const comparisonLine = (c) =>
  `Since baseline: ${c.verdictBefore} -> ${c.verdictAfter}. ${c.fixed.length} fixed, ${c.remaining} remaining, ${c.introduced.length} new.`;

// ---- main ----

async function main() {
  const lockfiles = findLockfiles(root);
  const packages = new Map();
  const errors = []; // lockfiles that could not be read: reported, never silently skipped
  const skipped = new Map(); // git/file dependencies: not checked, reported
  for (const file of lockfiles) {
    const { ecosystem, parse } = lockfileFor(file.split('/').pop());
    try {
      for (const p of parse(readFileSync(file, 'utf8'))) {
        const key = `${ecosystem}:${p.name}@${p.version}`;
        if (p.skip) {
          skipped.set(key, { name: p.name, version: p.version, ecosystem, lockfile: relative(root, file), reason: p.skip });
          continue;
        }
        const known = packages.get(key);
        if (known) known.direct = known.direct || p.direct;
        else packages.set(key, { ...p, ecosystem, key, lockfile: relative(root, file) });
      }
    } catch (err) {
      errors.push({ lockfile: relative(root, file), message: `could not parse: ${err.message}` });
    }
  }

  const matches = await osvMatch([...packages.values()]);
  const ids = [...new Set([...matches.values()].flat())];
  const details = new Map();
  for (let i = 0; i < ids.length; i += 10) {
    await Promise.all(ids.slice(i, i + 10).map(async (id) => details.set(id, await vulnDetails(id))));
  }

  const seen = new Set();
  const findings = [];
  for (const [key, vulnIds] of matches) {
    const pkg = packages.get(key);
    for (const osvId of vulnIds) {
      const d = details.get(osvId);
      const dedupe = `${key}|${d.id}`;
      if (seen.has(dedupe)) continue;
      seen.add(dedupe);
      findings.push({
        id: d.id, title: d.title, ecosystem: pkg.ecosystem, package: pkg.name, installed: pkg.version,
        fixedIn: smallestFix(d, pkg), cvss: d.cvss, kev: d.kev, likelyExploited: d.likelyExploited,
        lockfile: pkg.lockfile, source: d.source,
        direct: pkg.direct ?? null,
        knownExploited: d.kev || d.likelyExploited,
        advisory: `https://cve.now/${d.id}`, osvId, osv: `https://osv.dev/vulnerability/${osvId}`,
      });
    }
  }
  const ignoredIds = loadIgnored();
  const kept = findings.filter((f) => !ignoredIds.has(f.id.toUpperCase()));
  const ignored = findings.length - kept.length;
  findings.length = 0;
  findings.push(...kept);
  findings.sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0));

  const report = {
    verdict: verdictFor(findings, lockfiles.length, packages.size),
    scannedAt: new Date().toISOString(),
    lockfiles: lockfiles.map((f) => relative(root, f)),
    packagesScanned: packages.size,
    errors,
    skipped: [...skipped.values()],
    ignored,
    summary: {
      riskScore: riskScore(findings),
      total: findings.length,
      knownExploited: findings.filter((f) => f.knownExploited).length,
      theoretical: findings.filter((f) => !f.knownExploited).length,
    },
    upgrades: upgradePlan(findings),
    findings,
  };

  report.comparison = compareToBaseline(report);

  if (asJson) console.log(JSON.stringify(report, null, 2));
  else if (asSarif) console.log(JSON.stringify(toSarif(report), null, 2));
  else if (asMarkdown) console.log(toMarkdown(report));
  else printReport(report);
  process.exitCode = exitCode(report); // not process.exit(): it truncates piped stdout at 64 KB
}

function exitCode(r) {
  if (r.verdict === 'unknown') return 2;
  const failed = {
    any: r.findings.length > 0,
    cooked: r.verdict === 'cooked',
    kev: r.findings.some((f) => f.kev),
    none: false,
  }[failOn];
  if (failed) return 1;
  return strict && (r.errors.length || r.skipped.length) ? 2 : 0; // strict: an incomplete check is not a pass
}

// Markdown for PR comments and the GitHub job summary.
function toMarkdown(r) {
  const icon = { cooked: '🔥', 'a bit cooked': '⚠️', safe: '✅', unknown: '❔' }[r.verdict];
  const lines = [`## ${icon} am-i-cooked: ${r.verdict}`, '', `${r.packagesScanned} packages, ${r.lockfiles.length} lockfile(s)${r.ignored ? `, ${r.ignored} ignored` : ''}.`];
  if (r.comparison) lines.push('', `**${comparisonLine(r.comparison)}**`);
  if (r.findings.length) lines.push('', `**Risk score ${r.summary.riskScore}/100**: ${r.summary.knownExploited} known exploited, ${r.summary.theoretical} theoretical.`);
  if (r.upgrades.length) {
    lines.push('', '| Package | Installed | Upgrade to | Worst CVSS | Note |', '| --- | --- | --- | --- | --- |');
    for (const u of r.upgrades) {
      const note = [u.majorJump && 'major jump', u.majorJump && u.safeTarget && `safer: ${u.safeTarget}`, u.unfixed && `${u.unfixed} without fix`].filter(Boolean).join(', ');
      lines.push(`| \`${u.package}\` | ${u.installed} | ${u.target ?? 'no fix known'} | ${u.worstCvss || '?'} | ${note} |`);
    }
    const urgent = r.findings.filter((f) => f.knownExploited);
    if (urgent.length) lines.push('', `**Known exploited:** ${urgent.map((f) => `[${f.id}](${f.advisory})`).join(', ')}`);
  }
  if (r.verdict === 'safe') lines.push('', 'No known vulnerability matches. This is not proof of safety.');
  for (const e of r.errors) lines.push('', `⚠️ \`${e.lockfile}\`: ${e.message}`);
  if (r.skipped.length) lines.push('', `⚠️ ${r.skipped.length} git/file dependenc${r.skipped.length === 1 ? 'y was' : 'ies were'} not checked: ${r.skipped.slice(0, 5).map((d) => `\`${d.name}\``).join(', ')}.`);
  if (r.verdict === 'unknown') lines.push('', 'Nothing was checked: no supported lockfile, or no exact pinned versions (ranges like `>=1.0` cannot be matched).');
  return lines.join('\n');
}

// SARIF 2.1.0, for GitHub code scanning (github/codeql-action/upload-sarif).
function toSarif(r) {
  const level = (f) => (f.kev || (f.cvss ?? 0) >= 9 ? 'error' : (f.cvss ?? 0) >= 7 ? 'warning' : 'note');
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'am-i-cooked', informationUri: 'https://github.com/noushiFlex/am-i-cooked',
        rules: [...new Map(r.findings.map((f) => [f.id, { id: f.id, shortDescription: { text: String(f.title).slice(0, 200) }, helpUri: `https://cve.now/${f.id}` }])).values()] } },
      results: r.findings.map((f) => ({
        ruleId: f.id,
        level: level(f),
        message: { text: `${f.package}@${f.installed} is vulnerable (CVSS ${f.cvss ?? '?'}${f.kev ? ', actively exploited' : ''}). ${f.fixedIn ? `Fixed in ${f.fixedIn}.` : 'No fix known.'}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: f.lockfile }, region: { startLine: 1 } } }],
        properties: { knownExploited: f.knownExploited, cvss: f.cvss },
      })),
    }],
  };
}

function printReport(r) {
  console.log(`Verdict: ${r.verdict.toUpperCase()}  (${r.packagesScanned} packages, ${r.lockfiles.length} lockfile(s))`);
  if (r.findings.length) console.log(`Risk score: ${r.summary.riskScore}/100  (${r.summary.knownExploited} known exploited, ${r.summary.theoretical} theoretical)`);
  if (r.comparison) console.log(comparisonLine(r.comparison));
  for (const e of r.errors) console.log(`WARNING ${e.lockfile}: ${e.message}`);
  if (r.skipped.length) console.log(`WARNING ${r.skipped.length} dependenc${r.skipped.length === 1 ? 'y' : 'ies'} not checked (git/file, not a published version): ${r.skipped.slice(0, 5).map((d) => d.name).join(', ')}${r.skipped.length > 5 ? ', ...' : ''}${strict ? '' : '. Use --strict to fail on this.'}`);
  if (!r.lockfiles.length) console.log('No supported lockfile found. Nothing was checked.');
  else if (!r.packagesScanned) console.log('Dependency files found, but none pins an exact version (ranges like ">=1.0" cannot be matched). Nothing was checked.\nPin versions first (uv lock, pip freeze > requirements.txt, poetry lock) and re-run.');
  if (r.upgrades.length) {
    console.log('\nUpgrade plan (one version clears every finding for that package):');
    for (const u of r.upgrades) {
      const safer = u.majorJump && u.safeTarget ? `safer: ${u.safeTarget} clears ${u.fixes + u.unfixed - u.residualAfterSafe}, ${u.residualAfterSafe} still need the major` : null;
      const notes = [u.direct === false && 'transitive: upgrade the parent first', u.majorJump && 'MAJOR jump, check changelog', safer, u.unfixed && `${u.unfixed} finding(s) have no known fix`].filter(Boolean);
      console.log(`  ${u.package}  ${u.installed} -> ${u.target ?? 'no fix known'}${notes.length ? `  (${notes.join('; ')})` : ''}`);
    }
  }
  const shown = r.findings.slice(0, TEXT_LIMIT);
  for (const f of shown) {
    const flags = [f.kev && 'KEV', f.likelyExploited && 'exploit seen'].filter(Boolean).join(', ');
    console.log(`\n${f.id}  CVSS ${f.cvss ?? '?'}${flags ? `  [${flags}]` : ''}`);
    console.log(`  ${f.package}@${f.installed} -> ${f.fixedIn ?? 'no fix known'}  (${f.lockfile})${f.direct === true ? ' [direct]' : f.direct === false ? ' [transitive]' : ''}`);
    console.log(`  ${String(f.title).slice(0, 110)}`);
    console.log(`  ${f.advisory}`);
  }
  if (r.findings.length > shown.length) console.log(`\n... ${r.findings.length - shown.length} more finding(s). Use --json for the full list.`);
  if (r.verdict === 'safe') console.log('\nNo known vulnerability matches. This is not proof of safety.');
}

main().catch((err) => {
  console.error(`am-i-cooked: ${err.message}`);
  process.exitCode = 2;
});
