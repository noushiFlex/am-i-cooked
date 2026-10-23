<div align="center">

# am-i-cooked

### New CVEs drop every day. This skill tells you if you're cooked, then fixes it.

[![test](https://github.com/noushiFlex/am-i-cooked/actions/workflows/test.yml/badge.svg)](https://github.com/noushiFlex/am-i-cooked/actions/workflows/test.yml)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](LICENSE)
[![Node 18+](https://img.shields.io/badge/node-18%2B-339933?style=flat-square&logo=nodedotjs&logoColor=white)](package.json)
[![No dependencies](https://img.shields.io/badge/dependencies-0-brightgreen?style=flat-square)](skills/am-i-cooked/scripts/scan.mjs)

<code>npx skills add noushiFlex/am-i-cooked</code>

</div>

<p align="center"><img src="docs/demo.svg" alt="am-i-cooked printing a COOKED verdict and an upgrade plan" width="820" /></p>

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

- `npm audit` only knows npm. This reads npm, pnpm, yarn, bun, pip, poetry, uv, pub (Flutter/Dart), Cargo, Go, Bundler, Composer, Gradle, NuGet, Hex, Swift and Haskell lockfiles in one pass.
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

## Risk score

Every scan with findings gets a **risk score from 0 to 100** and a split between **known exploited** (CISA KEV, EPSS threshold reached, or a public exploit exists) and **theoretical** (no known exploitation). The worst finding sets the base (CVSS x exploit multiplier), and each extra finding adds 2 points, capped at +15. "Theoretical" does not mean unreachable: this is not a reachability analysis.

When a package needs a major version jump, the upgrade plan also shows the **safer** in-major version and how many findings it leaves open, so you can choose between a quick patch bump and a risky major.

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
node skills/am-i-cooked/scripts/scan.mjs . --markdown  # PR comment / job summary
```

### Strict mode

By default, dependencies that are not published versions (git, file URLs) are listed as a warning and the scan goes on. `--strict` turns an incomplete check into a failure: exit code `2` when any lockfile could not be parsed or any dependency was not checked. Findings that fail `--fail-on` still exit `1`.

Each finding is tagged `[direct]` or `[transitive]` when the lockfile says so (`package-lock.json`, `pubspec.lock`, `Gemfile.lock`, `packages.lock.json`). Transitive rows in the upgrade plan tell you to upgrade the parent first.

### Cache and offline

Answers from OSV.dev and cve.now are cached for 6 hours in `~/.cache/am-i-cooked` (override with `AM_I_COOKED_CACHE`). Requests retry with backoff on rate limits and server errors, and fall back to stale cache if the network is down.

- `--offline` answers from the cache only and never touches the network. It needs one earlier online scan of the same lockfiles, and it fails loudly (exit 2) on a cache miss instead of guessing.
- `--no-cache` forces fresh answers.

### Verify a fix

Save a report before fixing, then compare after:

```bash
node skills/am-i-cooked/scripts/scan.mjs . --json > before.json
# ... upgrade ...
node skills/am-i-cooked/scripts/scan.mjs . --baseline=before.json
# Since baseline: cooked -> safe. 12 fixed, 0 remaining, 0 new.
```

### Accept a risk

Hide a finding you reviewed and accept, with `--ignore=CVE-2020-28500,CVE-2021-23337` or a `.cookedignore` file at the root of the scanned directory:

```text
# lodash ReDoS, our input is never user-controlled
CVE-2020-28500
```

Use the id the report prints. Ignored findings are counted (`ignored` in the JSON) and never counted in the verdict, so write the reason in the comment.

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
- uses: noushiFlex/am-i-cooked@main
  with:
    fail-on: cooked   # any | cooked | kev | none
```

It writes the Markdown report to the job summary and fails the job at the threshold you pick. Or run the script yourself:

```yaml
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
| `requirements*.txt` (pinned with `==`), `poetry.lock`, `uv.lock` | PyPI |
| `pubspec.lock` | Pub (Dart/Flutter) |
| `Cargo.lock` | crates.io (Rust) |
| `go.sum` | Go |
| `Gemfile.lock` | RubyGems |
| `composer.lock` | Packagist (PHP) |
| `gradle.lockfile` (also `*-gradle.lockfile`) | Maven (Java/Kotlin) |
| `packages.lock.json` | NuGet (.NET) |
| `mix.lock` | Hex (Elixir) |
| `Package.resolved` | SwiftURL (Swift Package Manager) |
| `cabal.project.freeze`, `stack.yaml.lock` | Hackage (Haskell) |

Not supported: `pom.xml` (version ranges, no lockfile: use `mvn dependency:tree` or Gradle locking), CocoaPods (OSV.dev has no CocoaPods ecosystem, so nothing could be matched), and manifests without a lockfile.

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

A **safe** verdict is not proof of safety. If nothing was checked (no lockfile, or only unpinned ranges like `django>=5.1`), the verdict is **unknown**, never safe. Vulnerabilities without version data cannot be matched, vendor advisories without a CVE or GHSA record are not covered, and private registries and git dependencies are not resolved.

## Roadmap

- [x] `Cargo.lock`, `go.sum`, `Gemfile.lock`, `composer.lock`, `bun.lock`
- [x] `--fail-on` for CI
- [x] SARIF output for GitHub code scanning
- [x] `.cookedignore` and Markdown report

PRs welcome, see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. Vulnerability data comes from [OSV.dev](https://osv.dev) and [cve.now](https://cve.now); check their terms.
