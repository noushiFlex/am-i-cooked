## Dependency security (am-i-cooked)

Install once: `npx skills add noushiFlex/am-i-cooked -a '*'`. The scanner is `.agents/skills/am-i-cooked/scripts/scan.mjs` (Node 18+, no dependencies).

For questions about vulnerable dependencies or CVEs, run `node .agents/skills/am-i-cooked/scripts/scan.mjs .` and answer from its output only. Never invent CVE ids, scores or fixed versions. Never report "safe" when the verdict is `unknown`. Ask before changing dependencies, work on a separate branch, re-scan with `--baseline` to confirm each fix, and never push or open a PR without approval.
