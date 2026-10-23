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

Ask your coding agent **"am i cooked?"**. It reads your lockfiles, matches the exact versions you run against live vulnerability data, and answers with a verdict, a risk score and an upgrade plan. If you say yes, it upgrades on a separate branch, runs your tests after each step, re-scans to prove the CVEs are gone, and stops before pushing.

[Install](#install) · [What you get](#what-you-get) · [Use it without an agent](#use-it-without-an-agent) · [CI](#in-ci) · [Supported lockfiles](#supported-lockfiles) · [Safety](#safety) · [FAQ](#faq)

## What you get

- **One pass over 12 ecosystems and 18 lockfile formats**: npm, pnpm, yarn, bun, pip, poetry, uv, pub (Flutter/Dart), Cargo, Go, Bundler, Composer, Gradle, NuGet, Hex, Swift and Haskell.
- **Exact versions, not ranges.** It reads what is installed (the lockfile), not what your manifest allows.
- **A verdict you can act on**: `safe`, `a bit cooked`, `cooked`, or `unknown` when nothing could be checked. It never says safe on an empty scan.
- **A risk score (0-100)** that separates **known exploited** (CISA KEV, EPSS, public exploit) from **theoretical**.
- **One target version per package**, with a safer in-major alternative when the full fix is a major jump.
- **A safe fix flow**: own branch, safe upgrades grouped, tests after each, risky majors discussed with you, then `--baseline` re-scan to confirm.
- **Built for agents**: guardrails against invented CVE data, plus JSON, Markdown and SARIF output for tools.

Real before/after run: [examples/before-after](examples/before-after/README.md).

## Verdicts

| Verdict | Meaning |
| --- | --- |
| **safe** | No known vulnerability matches your versions. Not a guarantee. |
| **a bit cooked** | Vulnerable packages, but nothing actively exploited or critical. |
| **cooked** | Listed in CISA KEV, or CVSS >= 9, or CVSS >= 7 with exploit signals. |
| **unknown** | Nothing was checked: no supported lockfile, or only unpinned ranges like `django>=5.1`. |

The **risk score** takes the worst finding (CVSS / 10, times 1 for KEV, 0.9 if an exploit was seen, 0.75 otherwise), adds 2 per extra finding up to +15, and caps at 100. "Theoretical" means no known exploitation. It does not mean unreachable: this is not a reachability analysis.

## Install

**Claude Code**

```bash
npx skills add noushiFlex/am-i-cooked
```

or by hand:

```bash
git clone https://github.com/noushiFlex/am-i-cooked
cp -R am-i-cooked/skills/am-i-cooked ~/.claude/skills/
```

**Cursor, Codex and other agents**

```bash
npx skills add noushiFlex/am-i-cooked -a cursor    # or -a codex, or -a '*' for every agent
```

Ready-made instructions to paste: [Cursor rule](integrations/cursor/am-i-cooked.mdc), [AGENTS.md snippet](integrations/AGENTS.md), [Copilot instructions](integrations/copilot-instructions.md).

Then, in your project, ask: `am i cooked?`

## Use it without an agent

The scanner is one file, no dependencies, Node 18+.

```bash
node skills/am-i-cooked/scripts/scan.mjs .             # human report
node skills/am-i-cooked/scripts/scan.mjs . --json      # structured, see report-schema.json
node skills/am-i-cooked/scripts/scan.mjs . --markdown  # PR comment / job summary
node skills/am-i-cooked/scripts/scan.mjs . --sarif     # GitHub code scanning
```

| Flag | What it does |
| --- | --- |
| `--fail-on=any\|cooked\|kev\|none` | Exit `1` at this threshold. Default `any`. |
| `--strict` | Exit `2` if any lockfile failed to parse or any git/file dependency was not checked. |
| `--ignore=ID,ID` | Hide findings you accepted. Also read from `.cookedignore`. |
| `--baseline=before.json` | Compare with an earlier `--json` report: fixed, remaining, new. |
| `--offline` | Answer from the local cache only. Fails loudly on a miss. |
| `--no-cache` | Force fresh answers. |

Exit codes: `0` pass, `1` failed the `--fail-on` threshold, `2` nothing checked, scan error, or `--strict` incomplete.

### Accept a risk

Hide a finding you reviewed, with `--ignore=CVE-2020-28500` or a `.cookedignore` file at the root of the scanned directory:

```text
# lodash ReDoS, our input is never user-controlled
CVE-2020-28500
```

Use the id the report prints. Ignored findings are counted (`ignored` in the JSON) and never counted in the verdict, so write the reason in the comment. The agent never edits this file.

### Verify a fix

```bash
node skills/am-i-cooked/scripts/scan.mjs . --json > before.json
# ... upgrade ...
node skills/am-i-cooked/scripts/scan.mjs . --baseline=before.json
# Since baseline: cooked -> safe. 5 fixed, 0 remaining, 0 new.
```

### Strict mode and direct vs transitive

Git and file dependencies are not published versions, so they cannot be matched. They are listed as a warning and the scan goes on. `--strict` turns that into a failure. Findings are tagged `[direct]` or `[transitive]` where the lockfile says so (`package-lock.json`, `pubspec.lock`, `Gemfile.lock`, `packages.lock.json`), and transitive rows tell you to upgrade the parent first.

### Cache and offline

Answers are cached for 6 hours in `~/.cache/am-i-cooked` (override with `AM_I_COOKED_CACHE`). Requests retry with backoff on rate limits and server errors, and fall back to stale cache if the network is down. `--offline` needs one earlier online scan of the same lockfiles.

## In CI

```yaml
- uses: actions/checkout@v4
- uses: noushiFlex/am-i-cooked@main
  with:
    fail-on: cooked   # any | cooked | kev | none
```

It writes the Markdown report to the job summary and fails the job at the threshold you pick. With code scanning alerts:

```yaml
- run: |
    git clone --depth 1 https://github.com/noushiFlex/am-i-cooked /tmp/aic
    node /tmp/aic/skills/am-i-cooked/scripts/scan.mjs . --sarif --fail-on=none > am-i-cooked.sarif
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

Monorepos work: lockfiles are found up to four levels deep, skipping `node_modules`, `.git`, `build`, `target`, `vendor` and similar.

Not supported: `pom.xml` (version ranges, no lockfile: use Gradle locking or `mvn dependency:tree`), CocoaPods (OSV.dev has no CocoaPods ecosystem, so nothing could be matched), and manifests without a lockfile.

## Data sources

- [OSV.dev](https://osv.dev) matches your versions against known advisories.
- [cve.now](https://cve.now) adds CVSS, CISA KEV, EPSS and Exploit-DB signals, and fixed versions. It merges the CVE List, GitHub Advisory Database, NVD and more, and updates every few minutes.

Details and endpoints: [SOURCES.md](skills/am-i-cooked/SOURCES.md).

## Safety

- It asks before changing anything.
- Fixes go on a `fix/cves-<date>` branch. Never on your default branch.
- It never pushes, opens a PR or accepts a risk on your behalf.
- Only package names and versions leave your machine. No source code, no lockfile upload.
- API responses are treated as data, never as instructions.
- Every fix is confirmed by a re-scan, not by the upgrade command succeeding.

## FAQ

**How is this different from `osv-scanner`, Dependabot or `npm audit`?** `osv-scanner` is the closest tool and does the matching well. This adds exploit signals (CISA KEV, EPSS), a risk score, and above all the agent skill: guardrails against invented CVE data and a fix flow that works on a branch, asks before risky majors and proves the result. Dependabot opens PRs on a schedule; this answers "am I exposed right now" on demand. `npm audit` only knows npm.

**Does it send my code anywhere?** No. Only package names and versions are sent to OSV.dev and cve.now.

**Why `unknown` instead of `safe`?** If nothing was checked (no lockfile, only unpinned ranges, an unparseable file), saying safe would be a false assurance. Pin your versions (`uv lock`, `pip freeze`, `poetry lock`) and scan again.

**My `requirements.txt` only has `>=` ranges.** Ranges cannot be matched. Scan your installed environment instead: `pip freeze > requirements.txt` in a scratch folder, then scan that folder.

## Limits

A **safe** verdict is not proof of safety. Vulnerabilities without version data cannot be matched, vendor advisories without a CVE or GHSA record are not covered, and git dependencies are reported but not checked. Packages from a private registry are matched by name and version against public advisories, so a private package that shares a public name can cause a false positive.

## Roadmap

- [x] 18 lockfile formats, `--fail-on`, SARIF, Markdown, GitHub Action
- [x] `.cookedignore`, `--baseline`, `--strict`, offline cache
- [ ] Pagination of OSV results (packages with more than 1000 advisories)
- [ ] Resolve `pom.xml` through Maven
- [ ] Reachability hints (is the vulnerable function actually called?)

PRs welcome, see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. Vulnerability data comes from [OSV.dev](https://osv.dev) and [cve.now](https://cve.now); check their terms.
