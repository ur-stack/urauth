---
name: deploy-pkg
description: Deploy a package by bumping its version, generating a CHANGELOG.md entry from git history since the last tag, and creating a release tag. Use when the user wants to release/deploy/publish a package.
---

Deploy the currently active package. Follow these steps precisely:

## 1. Identify the package

Determine which package to deploy based on the user's current working directory or the file they have open. Look for:
- `package.json` (npm — name field gives the package name)
- `pyproject.toml` (Python — `[project]` name field)
- `Cargo.toml` (Rust — `[package]` name field)

Read the manifest file to get the current version and package name.

## 2. Determine the tag prefix

Each package uses a tag prefix for scoped releases:
- npm packages: `{package-name}-v` (e.g., `@urauth/ts-v0.2.0`)
- Python packages: `{package-name}-py-v` (e.g., `urauth-py-v0.2.0`)
- Rust packages: `{package-name}-rs-v` (e.g., `urauth-rs-v0.2.0`)

## 3. Find the last release tag

Run: `git tag -l "{tag-prefix}*" --sort=-v:refname | head -1`

If no tag exists, this is the first release — use the full git history for the package directory.

## 4. Ask the user for the version bump type

Ask: "What type of release? (patch / minor / major) Current version: X.Y.Z"

Calculate the new version based on their answer using semver rules.

## 5. Collect changes since last release

If a previous tag exists:
```bash
git log {last-tag}..HEAD --oneline -- {package-directory}
```

If no previous tag:
```bash
git log --oneline -- {package-directory}
```

## 6. Generate the CHANGELOG entry

Read the existing `CHANGELOG.md` in the package directory. Categorize the commits into keepachangelog sections:

- **Added** — new features (`feat:` commits)
- **Changed** — changes to existing functionality (`refactor:`, `update:` commits)
- **Deprecated** — soon-to-be removed features
- **Removed** — removed features
- **Fixed** — bug fixes (`fix:` commits)
- **Security** — vulnerability fixes (`security:` commits)

Only include sections that have entries. Write clear, user-facing descriptions (not raw commit messages). Group related commits into single entries where appropriate.

Update the CHANGELOG.md:
1. Under `## [Unreleased]`, add any unreleased items (usually empty after release)
2. Add a new `## [X.Y.Z] - YYYY-MM-DD` section with the categorized changes
3. Update the comparison links at the bottom:
   - `[Unreleased]` link should compare from the new tag to HEAD
   - New version link should compare from the previous tag to the new tag (or link to the tag if first release)

## 7. Bump the version in the manifest

- **package.json**: Update the `"version"` field
- **pyproject.toml**: Update `version = "..."` under `[project]`
- **Cargo.toml**: Update `version = "..."` under `[package]`

## 8. Commit and tag

```bash
git add {package-directory}/CHANGELOG.md {manifest-file}
git commit -m "release: {package-name} v{new-version}"
git tag {tag-prefix}{new-version}
```

## 9. Show summary and ask to push

Display:
- Package name and new version
- CHANGELOG entry preview
- The git tag created

Then ask: "Ready to push the commit and tag to origin? (yes/no)"

If yes:
```bash
git push origin {current-branch}
git push origin {tag-prefix}{new-version}
```

## Important notes

- Never skip the CHANGELOG update — it is the source of truth for releases
- Always use the keepachangelog format: https://keepachangelog.com/en/1.1.0/
- Dates must be ISO 8601 format: YYYY-MM-DD
- If the package has no changes since the last tag, warn the user and abort
- If the working directory has uncommitted changes in the package, warn and ask the user to commit first
