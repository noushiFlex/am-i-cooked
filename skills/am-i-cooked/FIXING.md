# Fixing vulnerable dependencies

Only after the user agreed to fix. The scanner's `upgrades` list gives one target version per package.

## Before touching anything

1. Confirm the working tree is clean (`git status`). If not, stop and ask.
2. Create a branch: `git checkout -b fix/cves-<YYYY-MM-DD>`. Never work on the default branch.
3. Run the project's tests and build once to get a baseline. A failing baseline must be reported, not hidden.

## Per package, worst CVSS first

1. Pick the target from the upgrade plan.
2. If the row says `MAJOR jump`: read the package changelog first and tell the user what breaks. Prefer a patched release on the current major when the advisory lists one.
3. Upgrade with the project's own package manager so the lockfile stays consistent:

   | Lockfile | Command |
   | --- | --- |
   | `package-lock.json` | `npm install <pkg>@<target>` |
   | `pnpm-lock.yaml` | `pnpm add <pkg>@<target>` |
   | `yarn.lock` | `yarn add <pkg>@<target>` |
   | `requirements.txt` | edit the pin, then `pip install -r requirements.txt` |
   | `poetry.lock` | `poetry add <pkg>@<target>` |
   | `bun.lock` | `bun add <pkg>@<target>` |
   | `pubspec.lock` | `flutter pub upgrade <pkg>` (check the SDK constraint first) |
   | `Cargo.lock` | `cargo update -p <pkg> --precise <target>` |
   | `go.sum` | `go get <module>@v<target>` then `go mod tidy` |
   | `Gemfile.lock` | `bundle update <gem> --conservative` |
   | `composer.lock` | `composer update <vendor/pkg>` |

4. Transitive dependency (not in the manifest)? Prefer upgrading the parent. Use overrides (`overrides`, `resolutions`, `dependency_overrides`) only as a last resort, and say so.
5. Run tests and build. If they fail: revert that package (`git checkout -- .`), mark it "needs manual work", continue with the next one.
6. Commit each successful upgrade on its own: `fix(deps): bump <pkg> to <target> (CVE-XXXX-YYYY)`.

## After

1. Re-run the scanner and show the new verdict next to the old one.
2. List: fixed, left (with the reason), needs a human.
3. Do not push, open a PR or publish. Ask first.

## Never

- `npm audit fix --force` or any command that bumps majors in bulk.
- Deleting a lockfile to "start clean".
- Silencing a finding to make the verdict green.
