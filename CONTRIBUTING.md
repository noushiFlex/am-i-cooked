# Contributing

Small, focused pull requests are welcome.

## Setup

Node 18+ is the only requirement. There are no dependencies to install.

```bash
npm test                      # scans tests/fixtures, needs network
node skills/am-i-cooked/scripts/scan.mjs <dir>
```

## Good first contributions

- A new lockfile parser (`Cargo.lock`, `go.sum`, `Gemfile.lock`, `composer.lock`, `bun.lock`). Add the parser and its entry in `LOCKFILES` in `scan.mjs`, a fixture in `tests/fixtures/`, and an assertion in `tests/run.mjs`.
- Pagination of OSV `querybatch` results.
- Better transitive-dependency fix advice in `FIXING.md`.

## Rules

- No runtime dependencies. The scanner must stay a single file that runs with `node`.
- Never send source code or file contents to a remote service. Package names and versions only.
- The skill asks before changing anything, and never pushes on its own. Keep it that way.
- `tests/fixtures` contains deliberately vulnerable versions. Do not "fix" them.
