# Fixing vulnerable dependencies

Only after the user agreed to fix. The scanner's `upgrades` list gives, per package, a `target` (clears every finding) and a `safeTarget` (highest fix inside the installed major version, with `residualAfterSafe` findings left open).

## Before touching anything

1. Confirm the working tree is clean (`git status`). If not, stop and ask.
2. Save the pre-fix report: `node <this-skill-dir>/scripts/scan.mjs . --json > /tmp/before.json`.
3. Create a branch: `git checkout -b fix/cves-<YYYY-MM-DD>`. Never work on the default branch.
4. Run the project's tests and build once to get a baseline. A failing baseline must be reported, not hidden.

## Choose the upgrade, least risky first

Work through the plan in this order:

1. **Patch or minor inside the current major** (`safeTarget` when `majorJump` is false, or `target`): do these first. They rarely break anything.
2. **Group them.** Upgrade all patch/minor bumps together, run the tests once. Green: commit the group as one commit. Red: bisect by halving the group until the culprit is isolated, revert only that package.
3. **Major jump** (`majorJump: true`): never do it silently. Show the user the options and let them choose:

   | Option | When |
   | --- | --- |
   | Take `safeTarget` | An in-major fix exists. Say how many findings it leaves open (`residualAfterSafe`). |
   | Take the major `target` | Read the changelog first, list the breaking changes that touch this project, upgrade alone on its own commit. |
   | Replace the package | The package is abandoned or has no fix (`unfixed > 0`). Name a maintained alternative only if you are sure it exists, and say what code must change. |
   | Pin and mitigate | No fix and no replacement. Pin the version, describe the mitigation (input validation, disabling the vulnerable feature), and record the decision. |
   | Accept the risk | Only the user can decide. They add the id to `.cookedignore` with a written reason. Never add it yourself. |

4. **Constraint conflicts.** If the manifest forbids the target (for example `django>=5.1,<5.2` and the fix is 5.2.x), say so. Changing a constraint is a decision for the user, and other dependencies may not support the new range.

## Ask before risky choices

Ask short, targeted questions, one decision at a time, with a recommendation:

> `urllib3` 1.25.0: the full fix is 2.8.0 (major jump). 1.26.19 clears 4 of 10 findings with no breaking changes. I recommend 1.26.19 now and 2.x in a separate PR. OK?

Never ask a question the scan output already answers.

## Per package

1. Upgrade with the project's own package manager so the lockfile stays consistent:

   | Lockfile | Command |
   | --- | --- |
   | `package-lock.json` | `npm install <pkg>@<target>` |
   | `pnpm-lock.yaml` | `pnpm add <pkg>@<target>` |
   | `yarn.lock` | `yarn add <pkg>@<target>` |
   | `requirements.txt` | edit the pin, then `pip install -r requirements.txt` |
   | `poetry.lock` | `poetry add <pkg>@<target>` |
   | `uv.lock` | `uv lock --upgrade-package <pkg>==<target>` |
   | `bun.lock` | `bun add <pkg>@<target>` |
   | `pubspec.lock` | `flutter pub upgrade <pkg>` (check the SDK constraint first) |
   | `Cargo.lock` | `cargo update -p <pkg> --precise <target>` |
   | `go.sum` | `go get <module>@v<target>` then `go mod tidy` |
   | `Gemfile.lock` | `bundle update <gem> --conservative` |
   | `composer.lock` | `composer update <vendor/pkg>` |
   | `gradle.lockfile` | bump the version in the build file, then `./gradlew dependencies --write-locks` |
   | `packages.lock.json` | `dotnet add package <pkg> --version <target>` |
   | `mix.lock` | `mix deps.update <pkg>` (check the requirement in `mix.exs` first) |
   | `Package.resolved` | `swift package update <pkg>` (check the requirement in `Package.swift` first) |
   | `cabal.project.freeze` | relax the bound in the `.cabal` file, then `cabal freeze` |
   | `stack.yaml.lock` | bump the version in `extra-deps` or the snapshot, then `stack build` |

2. Transitive dependency (not in the manifest)? Prefer upgrading the parent. Use overrides (`overrides`, `resolutions`, `dependency_overrides`) only as a last resort, and say so.
3. Run tests and build. If they fail: revert that package (`git checkout -- .`), mark it "needs manual work", continue with the next one.
4. Commit each successful upgrade or group on its own: `fix(deps): bump <pkg> to <target> (CVE-XXXX-YYYY)`.

## After: prove it

1. Re-scan against the saved report and show the verdict change:

   ```bash
   node <this-skill-dir>/scripts/scan.mjs . --baseline=/tmp/before.json
   ```

   The output says how many findings were fixed, how many remain and whether any are new. Never claim a fix without this re-scan. A new finding means an upgrade pulled in a vulnerable transitive dependency: report it.
2. Summarise: fixed, left (with the reason and the chosen option from the table), needs a human.

## Pull request (only if the user asks)

Opening a PR is outward-facing. Ask first, then:

```bash
gh pr create --draft --title "fix(deps): close N CVEs (risk X -> Y)" --body-file /tmp/pr.md
```

The body must contain: the verdict before and after, a table of closed CVEs (id, package, old to new version, CVSS), the residual risks with the reason each was left, the commands used to verify, and a note that tests passed on the branch. Open it as a draft. Never merge it.

## Never

- `npm audit fix --force` or any command that bumps majors in bulk.
- Deleting a lockfile to "start clean".
- Silencing a finding to make the verdict green.
- Pushing, opening a PR or merging without explicit approval.
