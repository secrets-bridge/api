# Changelog

All notable changes to `secrets-bridge/api` are tracked here. Format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project uses [SemVer](https://semver.org/).

Until `v0.1.0` ships, every change lands under `[Unreleased]`. The
rolling `:dev` container tag (published by
`.github/workflows/docker-publish.yml`) reflects whatever is currently
on `main`.

## [Unreleased]

### Added
- `SB_ENV` deployment-mode env var. `production` (default) refuses the
  LocalKMS backend at boot; `dev` allows it and triggers the dev
  seeder.
- Dev seeder creates three users (admin / approver / requester) bound
  to the matching system roles when `SB_ENV=dev` and `local_users` is
  empty. Password is shared via `SB_DEV_SEED_PASSWORD` or generated
  per user at random and logged once at WARN level.
- Docker image publishing workflow (`docker-publish.yml`) — multi-arch
  (amd64 + arm64), pushed to `ghcr.io/secrets-bridge/api`. Tags:
  rolling `dev` on every push to `main`; semver tags + `latest`
  activate post-`v0.1.0`.

### Changed
- `pkg/keymgmt.FromEnv(ctx)` now takes a second `env` argument so the
  resolver can reject `BackendLocal` outside dev. Sole caller
  (`cmd/api/main.go`) updated.

---

## How to cut a release (post-v0.1.0)

1. Land all release-bound work on `main`.
2. Update this file: move `[Unreleased]` entries under a new
   `[vX.Y.Z] — YYYY-MM-DD` heading. Add a fresh empty `[Unreleased]`
   on top.
3. `git tag vX.Y.Z && git push origin vX.Y.Z`.
4. The `docker-publish` workflow picks up the tag and publishes:
   - `ghcr.io/secrets-bridge/api:vX.Y.Z`
   - `ghcr.io/secrets-bridge/api:vX.Y`
   - `ghcr.io/secrets-bridge/api:latest` (only for non-prerelease)
5. Create the GitHub Release pointing at the tag, pasting this file's
   section for that version as the release notes.
