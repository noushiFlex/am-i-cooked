# Before and after

A real run of the fix flow on a one-dependency project. Both lockfiles are in this folder: `before/` pins `lodash@4.17.20`, `after/` pins `lodash@4.18.0`, the version the upgrade plan recommended.

## 1. Scan and save the report

```bash
node skills/am-i-cooked/scripts/scan.mjs examples/before-after/before --json > before.json
node skills/am-i-cooked/scripts/scan.mjs examples/before-after/before
```

```text
Verdict: COOKED  (1 packages, 1 lockfile(s))
Risk score: 73/100  (1 known exploited, 4 theoretical)

Upgrade plan (one version clears every finding for that package):
  lodash  4.17.20 -> 4.18.0

CVE-2026-4800  CVSS 8.1
  lodash@4.17.20 -> 4.18.0  (package-lock.json) [direct]
  lodash vulnerable to Code Injection via `_.template` imports key names
  https://cve.now/CVE-2026-4800

CVE-2021-23337  CVSS 7.2  [exploit seen]
...
```

## 2. Upgrade on a branch, run the tests, then re-scan against the saved report

```bash
node skills/am-i-cooked/scripts/scan.mjs examples/before-after/after --baseline=before.json
```

```text
Verdict: SAFE  (1 packages, 1 lockfile(s))
Since baseline: cooked -> safe. 5 fixed, 0 remaining, 0 new.

No known vulnerability matches. This is not proof of safety.
```

`fixed` counts findings that were in `before.json` and are gone now. A fix is only confirmed by this comparison, never by the upgrade command succeeding.

These lockfiles are deliberately vulnerable examples. Do not "fix" `before/`.
