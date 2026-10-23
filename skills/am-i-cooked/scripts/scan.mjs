#!/usr/bin/env node
// am-i-cooked scanner: lockfiles -> OSV match -> cve.now enrichment -> verdict.
// Usage: node scan.mjs [dir] [--json]. Exit code 0 = safe, 1 = vulnerable, 2 = nothing checked or error.
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';

const OSV = 'https://api.osv.dev/v1';
const CVE_NOW = 'https://cve.now/api/v1/entries';
const SKIP_DIRS = new Set(['node_modules', '.git', '.dart_tool', 'build', 'dist', '.venv', 'venv']);
const TEXT_LIMIT = 10;
const OSV_LABEL_TO_CVSS = { CRITICAL: 9.5, HIGH: 7.5, MODERATE: 5, MEDIUM: 5, LOW: 2 };

const args = process.argv.slice(2);
const asJson = args.includes('--json');
const root = args.find((a) => !a.startsWith('--')) ?? '.';

// ---- lockfile parsers: text -> [{ name, version }] ----

function parseNpmLock(text) {
  const lock = JSON.parse(text);
  return Object.entries(lock.packages ?? {})
    .filter(([path, pkg]) => path && pkg.version && !pkg.link)
    .map(([path, pkg]) => ({ name: pkg.name ?? path.split('node_modules/').pop(), version: pkg.version }));
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
    .map((block) => ({
      name: block.match(/^name = "([^"]+)"/m)?.[1],
      version: block.match(/^version = "([^"]+)"/m)?.[1],
    }))
    .filter((p) => p.name && p.version);
}

function parsePubspec(text) {
  const out = [];
  let name = null;
  for (const line of text.split('\n')) {
    const head = line.match(/^ {2}([A-Za-z0-9_]+):\s*$/);
    if (head) name = head[1];
    const ver = line.match(/^ {4}version:\s*"?([^"\s]+)"?/);
    if (ver && name) out.push({ name, version: ver[1] });
  }
  return out;
}

const LOCKFILES = {
  'package-lock.json': { ecosystem: 'npm', parse: parseNpmLock },
  'pnpm-lock.yaml': { ecosystem: 'npm', parse: parsePnpm },
  'yarn.lock': { ecosystem: 'npm', parse: parseYarn },
  'requirements.txt': { ecosystem: 'PyPI', parse: parseRequirements },
  'poetry.lock': { ecosystem: 'PyPI', parse: parsePoetry },
  'pubspec.lock': { ecosystem: 'Pub', parse: parsePubspec },
};

function findLockfiles(dir, depth = 0) {
  if (depth > 4) return [];
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    if (entry.isDirectory()) return SKIP_DIRS.has(entry.name) ? [] : findLockfiles(join(dir, entry.name), depth + 1);
    return LOCKFILES[entry.name] ? [join(dir, entry.name)] : [];
  });
}

// ---- network ----

async function getJson(url, init) {
  const res = await fetch(url, { ...init, signal: AbortSignal.timeout(20000) });
  if (!res.ok) return null;
  return res.json();
}

async function osvMatch(packages) {
  const matches = new Map(); // "ecosystem:name@version" -> [osv ids]
  for (let i = 0; i < packages.length; i += 500) {
    const chunk = packages.slice(i, i + 500);
    const body = JSON.stringify({
      queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })),
    });
    const data = await getJson(`${OSV}/querybatch`, { method: 'POST', body });
    if (!data) throw new Error('OSV.dev request failed');
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

function compareVersions(a, b) {
  const pa = a.split(/[.\-+]/);
  const pb = b.split(/[.\-+]/);
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

function verdictFor(findings, lockfileCount) {
  if (!lockfileCount) return 'unknown';
  if (!findings.length) return 'safe';
  const cooked = findings.some((f) => f.kev || (f.cvss ?? 0) >= 9 || (f.likelyExploited && (f.cvss ?? 0) >= 7));
  return cooked ? 'cooked' : 'a bit cooked';
}

// One target version per package: the highest fix needed to clear every finding.
function upgradePlan(findings) {
  const plan = new Map();
  for (const f of findings) {
    const key = `${f.ecosystem}:${f.package}@${f.installed}`;
    const row = plan.get(key) ?? { ecosystem: f.ecosystem, package: f.package, installed: f.installed, target: null, fixes: 0, unfixed: 0, worstCvss: 0 };
    if (f.fixedIn) {
      row.fixes++;
      if (!row.target || compareVersions(f.fixedIn, row.target) > 0) row.target = f.fixedIn;
    } else row.unfixed++;
    row.worstCvss = Math.max(row.worstCvss, f.cvss ?? 0);
    plan.set(key, row);
  }
  const majorOf = (v) => v.split('.')[0];
  for (const row of plan.values()) row.majorJump = Boolean(row.target) && majorOf(row.target) !== majorOf(row.installed);
  return [...plan.values()].sort((a, b) => b.worstCvss - a.worstCvss);
}

// ---- main ----

async function main() {
  const lockfiles = findLockfiles(root);
  const packages = new Map();
  for (const file of lockfiles) {
    const { ecosystem, parse } = LOCKFILES[file.split('/').pop()];
    for (const p of parse(readFileSync(file, 'utf8'))) {
      const key = `${ecosystem}:${p.name}@${p.version}`;
      if (!packages.has(key)) packages.set(key, { ...p, ecosystem, key, lockfile: relative(root, file) });
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
      });
    }
  }
  findings.sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0));

  const report = {
    verdict: verdictFor(findings, lockfiles.length),
    scannedAt: new Date().toISOString(),
    lockfiles: lockfiles.map((f) => relative(root, f)),
    packagesScanned: packages.size,
    upgrades: upgradePlan(findings),
    findings,
  };

  if (asJson) console.log(JSON.stringify(report, null, 2));
  else printReport(report);
  process.exit(report.verdict === 'unknown' ? 2 : findings.length ? 1 : 0);
}

function printReport(r) {
  console.log(`Verdict: ${r.verdict.toUpperCase()}  (${r.packagesScanned} packages, ${r.lockfiles.length} lockfile(s))`);
  if (!r.lockfiles.length) console.log('No supported lockfile found. Nothing was checked.');
  if (r.upgrades.length) {
    console.log('\nUpgrade plan (one version clears every finding for that package):');
    for (const u of r.upgrades) {
      const notes = [u.majorJump && 'MAJOR jump, check changelog', u.unfixed && `${u.unfixed} finding(s) have no known fix`].filter(Boolean);
      console.log(`  ${u.package}  ${u.installed} -> ${u.target ?? 'no fix known'}${notes.length ? `  (${notes.join('; ')})` : ''}`);
    }
  }
  const shown = r.findings.slice(0, TEXT_LIMIT);
  for (const f of shown) {
    const flags = [f.kev && 'KEV', f.likelyExploited && 'exploit seen'].filter(Boolean).join(', ');
    console.log(`\n${f.id}  CVSS ${f.cvss ?? '?'}${flags ? `  [${flags}]` : ''}`);
    console.log(`  ${f.package}@${f.installed} -> ${f.fixedIn ?? 'no fix known'}  (${f.lockfile})`);
    console.log(`  ${String(f.title).slice(0, 110)}`);
  }
  if (r.findings.length > shown.length) console.log(`\n... ${r.findings.length - shown.length} more finding(s). Use --json for the full list.`);
  if (r.verdict === 'safe') console.log('\nNo known vulnerability matches. This is not proof of safety.');
}

main().catch((err) => {
  console.error(`am-i-cooked: ${err.message}`);
  process.exit(2);
});
