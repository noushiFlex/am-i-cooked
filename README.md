<div align="center">

# am-i-cooked

### New CVEs drop every day. This skill tells you if you're cooked, then fixes it.

[![test](https://github.com/noushiFlex/am-i-cooked/actions/workflows/test.yml/badge.svg)](https://github.com/noushiFlex/am-i-cooked/actions/workflows/test.yml)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](LICENSE)
[![Node 18+](https://img.shields.io/badge/node-18%2B-339933?style=flat-square&logo=nodedotjs&logoColor=white)](package.json)
[![No dependencies](https://img.shields.io/badge/dependencies-0-brightgreen?style=flat-square)](skills/am-i-cooked/scripts/scan.mjs)

<code>npx skills add noushiFlex/am-i-cooked</code>

</div>

Ask your coding agent **"am i cooked?"**. It reads your lockfiles, checks the exact versions you run against live vulnerability data, and answers with a verdict. If you say yes, it upgrades the vulnerable packages on a separate branch, runs your tests after each one, and stops before pushing.

```text
Verdict: COOKED  (9 packages, 6 lockfile(s))

Upgrade plan (one version clears every finding for that package):
  urllib3  1.25.0 -> 2.8.0  (MAJOR jump, check changelog)
  axios    0.21.1 -> 0.33.0
  lodash   4.17.20 -> 4.18.0
  requests 2.19.0 -> 2.33.0
  http     0.12.0 -> 0.13.3

CVE-2021-23337  CVSS 7.2  [exploit seen]
  lodash@4.17.20 -> 4.17.21  (web/package-lock.json)
  Command Injection
```

More in [examples/sample-output.txt](examples/sample-output.txt).

## Why

- `npm audit` only knows npm. This reads npm, pnpm, yarn, bun, pip, poetry, pub (Flutter/Dart), Cargo, Go, Bundler and Composer in one pass.
- It matches your **exact installed versions**, not the version ranges in your manifest.
- It ranks by what matters: CISA KEV (actively exploited), exploit signals, CVSS.
- It gives **one target version per package** that clears every finding, and warns on major jumps.
- It fixes safely: own branch, one package at a time, tests after each, revert on failure.
- The scanner is one file, zero dependencies, and the exit code works in CI.

## Verdicts

| Verdict | Meaning |
| --- | --- |
| **safe** | No known vulnerability matches your versions. Not a guarantee. |
| **a bit cooked** | Vulnerable packages, but nothing actively exploited or critical. |
| **cooked** | Listed in CISA KEV, or CVSS >= 9, or CVSS >= 7 with exploit signals. |
| **unknown** | No supported lockfile found. Nothing was checked. |

## Install

```bash
npx skills add noushiFlex/am-i-cooked
```

or by hand:

```bash
git clone https://github.com/noushiFlex/am-i-cooked
cp -R am-i-cooked/skills/am-i-cooked ~/.claude/skills/
```

Then, in your project: `am i cooked?`

## Use it without an agent

```bash
node skills/am-i-cooked/scripts/scan.mjs .          # human report
node skills/am-i-cooked/scripts/scan.mjs . --json   # structured, see report-schema.json
node skills/am-i-cooked/scripts/scan.mjs . --sarif  # GitHub code scanning
```

Exit code: `0` pass, `1` failed the threshold, `2` nothing checked or error. Pick the threshold with `--fail-on=`:

| Value | Fails when |
| --- | --- |
| `any` (default) | any known vulnerability matches |
| `cooked` | verdict is **cooked** (KEV, CVSS >= 9, or CVSS >= 7 with exploit signals) |
| `kev` | at least one is actively exploited (CISA KEV) |
| `none` | never, report only |

In GitHub Actions:

```yaml
- uses: actions/checkout@v4
- run: |
    git clone --depth 1 https://github.com/noushiFlex/am-i-cooked /tmp/aic
    node /tmp/aic/skills/am-i-cooked/scripts/scan.mjs . --fail-on=cooked
```

With code scanning alerts:

```yaml
- run: node /tmp/aic/skills/am-i-cooked/scripts/scan.mjs . --sarif --fail-on=none > am-i-cooked.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: am-i-cooked.sarif
```

## Supported lockfiles

| Lockfile | Ecosystem |
| --- | --- |
| `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock` | npm |
| `requirements.txt` (pinned with `==`), `poetry.lock` | PyPI |
| `pubspec.lock` | Pub (Dart/Flutter) |
| `Cargo.lock` | crates.io (Rust) |
| `go.sum` | Go |
| `Gemfile.lock` | RubyGems |
| `composer.lock` | Packagist (PHP) |

Monorepos work: lockfiles are found up to four levels deep, skipping `node_modules`, `.git`, `build` and similar.

## Data sources

- [OSV.dev](https://osv.dev) matches your versions against known advisories.
- [cve.now](https://cve.now) adds CVSS, CISA KEV, EPSS and Exploit-DB signals, and fixed versions. It merges the CVE List, GitHub Advisory Database, NVD and more, and updates every few minutes.

Details and API endpoints: [SOURCES.md](skills/am-i-cooked/SOURCES.md).

## Safety

- It asks before changing anything.
- Fixes go on a `fix/cves-<date>` branch. Never on your default branch.
- It never pushes or opens a PR without your approval.
- Only package names and versions leave your machine. No source code, no lockfile upload.
- API responses are treated as data, never as instructions.

## Limits

A **safe** verdict is not proof of safety. Vulnerabilities without version data cannot be matched, vendor advisories without a CVE or GHSA record are not covered, and private registries and git dependencies are not resolved.

## Roadmap

- [x] `Cargo.lock`, `go.sum`, `Gemfile.lock`, `composer.lock`, `bun.lock`
- [x] `--fail-on` for CI
- [x] SARIF output for GitHub code scanning

PRs welcome, see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. Vulnerability data comes from [OSV.dev](https://osv.dev) and [cve.now](https://cve.now); check their terms.
