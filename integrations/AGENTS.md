## Dependency security (am-i-cooked)

Install once: `npx skills add noushiFlex/am-i-cooked -a codex` (installs to `.agents/skills/am-i-cooked`).

When asked whether the project is exposed to known vulnerabilities, or to update vulnerable packages:

1. Run `node .agents/skills/am-i-cooked/scripts/scan.mjs .` and report the verdict, risk score and upgrade plan. Facts come from this output only: never invent CVE ids, scores or versions.
2. Stop and ask before changing anything.
3. If the user agrees, follow `.agents/skills/am-i-cooked/FIXING.md`: new branch, safe upgrades first, tests after each, then confirm with `scan.mjs . --baseline=before.json`.
4. Never say "safe" for an `unknown` verdict, a failed scan, or before re-scanning. Never push, open a PR or accept a risk on the user's behalf.
