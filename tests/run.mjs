// Integration test: scans the vulnerable lockfiles in tests/fixtures (needs network).
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert/strict';

const scan = new URL('../skills/am-i-cooked/scripts/scan.mjs', import.meta.url).pathname;
const fixtures = new URL('./fixtures', import.meta.url).pathname;
const run = (...args) => spawnSync('node', [scan, ...args], { encoding: 'utf8' });

const vulnerable = run(fixtures, '--json');
assert.equal(vulnerable.status, 1, 'vulnerable fixtures must exit 1');
const report = JSON.parse(vulnerable.stdout);
assert.equal(report.verdict, 'cooked');
assert.equal(report.lockfiles.length, 12, 'all twelve lockfile formats are found');
for (const name of ['lodash', 'axios', 'requests', 'urllib3', 'minimist', 'http', 'serde_yaml', 'golang.org/x/crypto', 'nokogiri', 'symfony/http-kernel', 'pyyaml']) {
  assert.ok(report.findings.some((f) => f.package === name), `finding expected for ${name}`);
}
assert.ok(report.upgrades.every((u) => u.target === null || u.target !== u.installed), 'targets differ from installed');
assert.ok(report.upgrades.find((u) => u.package === 'urllib3').majorJump, 'urllib3 1.x -> 2.x flagged as major');

assert.ok(report.packagesScanned >= 17, 'bun.lock workspace entries are skipped, real packages counted');

assert.equal(run(fixtures, '--fail-on=none').status, 0, '--fail-on=none never fails on findings');
assert.equal(run(fixtures, '--fail-on=bogus').status, 2, 'invalid --fail-on is rejected');
const sarif = JSON.parse(run(fixtures, '--sarif').stdout);
assert.equal(sarif.version, '2.1.0');
assert.ok(sarif.runs[0].results.length > 0 && sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'SARIF results carry a lockfile location');

const goUpgrade = report.upgrades.find((u) => u.package === 'golang.org/x/crypto');
assert.ok(goUpgrade.target, 'Go "v"-prefixed versions still resolve to a fix');
assert.ok(goUpgrade.majorJump === false || goUpgrade.target.startsWith('0.'), 'Go v0 pseudo-version is not a false major jump');

assert.ok(report.summary.riskScore > 0 && report.summary.riskScore <= 100, 'risk score in 1..100');
assert.equal(report.summary.knownExploited + report.summary.theoretical, report.summary.total);
assert.ok(report.findings.every((f) => f.advisory.startsWith('https://cve.now/') && f.osv.startsWith('https://osv.dev/')), 'every finding links to its advisory');
const urllib = report.upgrades.find((u) => u.package === 'urllib3');
assert.ok(urllib.majorJump && urllib.residualAfterSafe >= 0 && 'safeTarget' in urllib, 'major jumps expose a safer in-major alternative');

const target = report.findings[0].id;
const ignoredRun = JSON.parse(run(fixtures, '--json', `--ignore=${target.toLowerCase()}`).stdout);
assert.equal(ignoredRun.ignored, 1, '--ignore removes the finding (case-insensitive)');
assert.ok(!ignoredRun.findings.some((f) => f.id === target));

const baselineFile = join(mkdtempSync(join(tmpdir(), 'aic-')), 'before.json');
writeFileSync(baselineFile, JSON.stringify(report));
const afterFix = JSON.parse(run(fixtures, '--json', `--ignore=${target}`, `--baseline=${baselineFile}`).stdout).comparison;
assert.equal(afterFix.fixed.length, 1, 'baseline: the removed finding is reported as fixed');
assert.equal(afterFix.fixed[0].id, target);
assert.equal(afterFix.remaining, report.findings.length - 1);
assert.equal(afterFix.introduced.length, 0);
assert.equal(run(fixtures, `--baseline=/nonexistent.json`).status, 2, 'unreadable baseline exits 2');

const md = run(fixtures, '--markdown').stdout;
assert.match(md, /^## .* am-i-cooked: cooked/);
assert.match(md, /\| `lodash` \|/);

const unpinnedDir = mkdtempSync(join(tmpdir(), 'aic-'));
writeFileSync(join(unpinnedDir, 'requirements.txt'), 'django>=5.1,<5.2\nrequests>=2\n');
const unpinned = run(unpinnedDir);
assert.equal(unpinned.status, 2, 'unpinned ranges must exit 2, never report safe');
assert.match(unpinned.stdout, /UNKNOWN/);
assert.match(unpinned.stdout, /none pins an exact version/);

// Cache + offline: a second scan from an isolated cache dir must give the same answer without network.
const cacheDir = mkdtempSync(join(tmpdir(), 'aic-cache-'));
const withCache = (...args) => spawnSync('node', [scan, ...args], { encoding: 'utf8', env: { ...process.env, AM_I_COOKED_CACHE: cacheDir } });
const online = JSON.parse(withCache(fixtures, '--json').stdout);
const cached = withCache(fixtures, '--json', '--offline');
assert.equal(cached.status, 1, 'offline scan from a warm cache still finds vulnerabilities');
assert.equal(JSON.parse(cached.stdout).findings.length, online.findings.length, 'offline findings match online findings');
const cold = spawnSync('node', [scan, fixtures, '--offline'], { encoding: 'utf8', env: { ...process.env, AM_I_COOKED_CACHE: mkdtempSync(join(tmpdir(), 'aic-cold-')) } });
assert.equal(cold.status, 2, 'offline with an empty cache must fail loudly, never say safe');
assert.match(cold.stderr, /--offline: no cached answer/);
const dead = spawnSync('node', [scan, fixtures], { encoding: 'utf8', env: { ...process.env, AM_I_COOKED_CACHE: mkdtempSync(join(tmpdir(), 'aic-dead-')), AM_I_COOKED_OSV_URL: 'http://127.0.0.1:9/v1' } });
assert.equal(dead.status, 2, 'unreachable API must exit 2');
assert.match(dead.stderr, /cannot reach 127\.0\.0\.1:9.*--offline/);

const empty = run(mkdtempSync(join(tmpdir(), 'aic-')));
assert.equal(empty.status, 2, 'no lockfile must exit 2, never report safe');
assert.match(empty.stdout, /UNKNOWN/);

console.log('ok');
