// Deterministic tests: the scanner talks to a local mock of OSV.dev and cve.now, no network needed.
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert/strict';

const scan = new URL('../skills/am-i-cooked/scripts/scan.mjs', import.meta.url).pathname;

// ---- mock data ----
const OSV_MATCHES = {
  'npm:a@1.0.0': ['GHSA-aaaa'], // in CISA KEV
  'npm:b@1.0.0': ['GHSA-bbbb'], // medium, behind one 429
  'npm:d@1.0.0': ['GHSA-dddd'], // unknown to cve.now, OSV fallback
};
const CVE_NOW = {
  'GHSA-aaaa': {
    id: 'CVE-2026-0001', title: 'Bug A', severity: { cvss: 7 }, exploitation: { kev: true },
    affected: [{ ecosystem: 'npm', package: 'a', ranges: [{ introduced: '0', fixed: '1.2.0' }, { introduced: '0', fixed: '1.1.0' }, { introduced: '0', fixed: '0.9.0' }] }],
  },
  'GHSA-bbbb': {
    id: 'CVE-2026-0002', title: 'Bug B', severity: { cvss: 5 }, exploitation: {},
    affected: [{ ecosystem: 'npm', package: 'b', ranges: [{ introduced: '0', fixed: '1.0.1' }] }],
  },
};
const OSV_VULNS = {
  'GHSA-dddd': {
    id: 'GHSA-dddd', aliases: ['CVE-2026-0004'], summary: 'OSV only', database_specific: { severity: 'HIGH' },
    affected: [{ package: { name: 'd', ecosystem: 'npm' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '2.0.0' }] }] }],
  },
};

const hits = { b: 0 };
const server = createServer((req, res) => {
  const send = (code, body) => {
    res.writeHead(code, { 'content-type': 'application/json' });
    res.end(JSON.stringify(body));
  };
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    const url = new URL(req.url, 'http://x');
    if (url.pathname === '/v1/querybatch') {
      const { queries } = JSON.parse(body);
      return send(200, { results: queries.map((q) => ({ vulns: (OSV_MATCHES[`${q.package.ecosystem}:${q.package.name}@${q.version}`] ?? []).map((id) => ({ id })) })) });
    }
    if (url.pathname.startsWith('/v1/vulns/')) {
      const v = OSV_VULNS[url.pathname.split('/').pop()];
      return v ? send(200, v) : send(404, {});
    }
    if (url.pathname.startsWith('/entries/')) {
      const id = url.pathname.split('/').pop();
      if (id === 'GHSA-bbbb' && hits.b++ === 0) return send(429, {}); // first call rate-limited
      return CVE_NOW[id] ? send(200, CVE_NOW[id]) : send(404, {});
    }
    send(404, {});
  });
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const port = server.address().port;

const project = mkdtempSync(join(tmpdir(), 'aic-unit-'));
const lock = (pkgs) => JSON.stringify({ lockfileVersion: 3, packages: { '': {}, ...Object.fromEntries(pkgs.map(([n, v]) => [`node_modules/${n}`, { version: v }])) } });
writeFileSync(join(project, 'package-lock.json'), lock([['a', '1.0.0'], ['b', '1.0.0'], ['c', '1.0.0'], ['d', '1.0.0']]));

const run = (dir, ...args) =>
  new Promise((resolve) => {
    const child = spawn('node', [scan, dir, ...args], {
      env: {
        ...process.env,
        AM_I_COOKED_OSV_URL: `http://127.0.0.1:${port}/v1`,
        AM_I_COOKED_CVE_NOW_URL: `http://127.0.0.1:${port}/entries`,
        AM_I_COOKED_CACHE: mkdtempSync(join(tmpdir(), 'aic-unit-cache-')),
      },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => (stdout += c));
    child.stderr.on('data', (c) => (stderr += c));
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });

try {
  // matching, enrichment, retry on 429, OSV fallback
  const first = await run(project, '--json');
  assert.equal(first.status, 1, first.stderr);
  const report = JSON.parse(first.stdout);
  assert.equal(report.packagesScanned, 4);
  assert.equal(report.findings.length, 3, 'a, b and d match; clean package c does not');
  assert.equal(report.verdict, 'cooked', 'a KEV hit makes the verdict cooked');
  assert.ok(hits.b >= 2, 'the 429 on cve.now was retried');

  const byPkg = Object.fromEntries(report.findings.map((f) => [f.package, f]));
  assert.equal(byPkg.a.id, 'CVE-2026-0001');
  assert.equal(byPkg.a.kev, true);
  assert.equal(byPkg.a.fixedIn, '1.1.0', 'smallest fix above the installed version, ignoring 0.9.0');
  assert.equal(byPkg.b.cvss, 5);
  assert.equal(byPkg.b.knownExploited, false);
  assert.equal(byPkg.d.id, 'CVE-2026-0004', 'OSV fallback prefers the CVE alias');
  assert.equal(byPkg.d.cvss, 7.5, 'OSV severity label maps to a CVSS estimate');
  assert.equal(byPkg.d.source, 'osv.dev');
  assert.equal(byPkg.d.fixedIn, '2.0.0');

  // risk score: worst = a (7/10 x 1 for KEV = 70), + 2 per extra finding (2 extras) = 74
  assert.equal(report.summary.riskScore, 74);
  assert.equal(report.summary.knownExploited, 1);
  assert.equal(report.summary.theoretical, 2);

  // ignoring the KEV finding downgrades the verdict, and counts what was hidden
  const ignored = JSON.parse((await run(project, '--json', '--ignore=cve-2026-0001')).stdout);
  assert.equal(ignored.ignored, 1);
  assert.equal(ignored.verdict, 'a bit cooked');

  // --fail-on thresholds
  assert.equal((await run(project, '--fail-on=none')).status, 0);
  assert.equal((await run(project, '--fail-on=kev')).status, 1);
  assert.equal((await run(project, '--fail-on=kev', '--ignore=CVE-2026-0001')).status, 0, 'no KEV left after ignoring it');
  assert.equal((await run(project, '--fail-on=cooked', '--ignore=CVE-2026-0001')).status, 0);
  assert.equal((await run(project, '--fail-on=any', '--ignore=CVE-2026-0001')).status, 1);

  // a clean project is safe, and says it is not proof
  const cleanDir = mkdtempSync(join(tmpdir(), 'aic-unit-clean-'));
  writeFileSync(join(cleanDir, 'package-lock.json'), lock([['c', '1.0.0']]));
  const clean = await run(cleanDir);
  assert.equal(clean.status, 0);
  assert.match(clean.stdout, /Verdict: SAFE/);
  assert.match(clean.stdout, /not proof of safety/);

  // corrupt lockfile: the scan reports it instead of crashing, and never claims safe
  const brokenDir = mkdtempSync(join(tmpdir(), 'aic-unit-broken-'));
  writeFileSync(join(brokenDir, 'package-lock.json'), '{ not json');
  const broken = await run(brokenDir, '--json');
  assert.equal(broken.status, 2);
  assert.equal(JSON.parse(broken.stdout).verdict, 'unknown');
  assert.equal(JSON.parse(broken.stdout).errors.length, 1);

  console.log('unit ok');
} finally {
  server.close();
}
