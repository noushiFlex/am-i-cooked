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

const target = report.findings[0].id;
const ignoredRun = JSON.parse(run(fixtures, '--json', `--ignore=${target.toLowerCase()}`).stdout);
assert.equal(ignoredRun.ignored, 1, '--ignore removes the finding (case-insensitive)');
assert.ok(!ignoredRun.findings.some((f) => f.id === target));

const md = run(fixtures, '--markdown').stdout;
assert.match(md, /^## .* am-i-cooked: cooked/);
assert.match(md, /\| `lodash` \|/);

const unpinnedDir = mkdtempSync(join(tmpdir(), 'aic-'));
writeFileSync(join(unpinnedDir, 'requirements.txt'), 'django>=5.1,<5.2\nrequests>=2\n');
const unpinned = run(unpinnedDir);
assert.equal(unpinned.status, 2, 'unpinned ranges must exit 2, never report safe');
assert.match(unpinned.stdout, /UNKNOWN/);
assert.match(unpinned.stdout, /none pins an exact version/);

const empty = run(mkdtempSync(join(tmpdir(), 'aic-')));
assert.equal(empty.status, 2, 'no lockfile must exit 2, never report safe');
assert.match(empty.stdout, /UNKNOWN/);

console.log('ok');
