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
- Object storage for media (`pkg/objectstore`, #253): an S3 backend on
  AWS SDK v2 for AWS S3 and S3-compatible servers such as MinIO,
  configured with `SB_OBJECTSTORE_*`. Project and team logos are now
  stored in the bucket at `<prefix>/logos/<kind>/<entity-id>/<sha256>.png`
  and streamed by the api with the same routes, headers, ETag and
  `logo_version` as before. Migration 0040 adds `object_key` and
  `byte_length` and makes `png` nullable; a backfill at start (under a
  Redis lock, `SB_OBJECTSTORE_LOGO_BACKFILL`) moves existing logos out
  of Postgres. Without object storage configured, logo uploads and
  deletes answer 503. docker-compose gains MinIO and a bucket bootstrap.
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
- Security batch, October 2026. Behaviour callers and operators see:
  - OIDC login needs an `email` claim with `email_verified: true`, or
    it answers 401. Disabled users are refused on every path (#197).
  - Cross-team submit needs the source `project_id` and environment,
    and a `requester_id` in a submit body is ignored. Verify votes go
    source first, then security (409 `cross_team_vote_out_of_turn`), and
    fill rejects undeclared keys (#198).
  - Adding or removing an MFA factor needs a fresh step-up once a factor
    exists. MFA endpoints answer 429 when locked or rate limited and 503
    when Redis is down (#199).
  - Internal errors return fixed messages (`POST /jobs` and TOTP enroll
    failures are 500, not 400), `/readyz` no longer echoes driver
    errors, every `/api/v1` response is `Cache-Control: no-store`, and
    `http://` ArgoCD endpoints are refused outside `SB_ENV=dev` unless
    `SB_ALLOW_INSECURE_ARGOCD_ADDR=true` (#203).
  - Admin PUTs are partial updates: a missing key keeps the stored
    value, send `""` or `null` to clear. A grant with a malformed scope
    grants nothing. Project-scoped reads answer 404 without coverage
    (#206).
  - A request's `target_provider_config` body field is ignored. The job
    gets its provider config from the bound catalog row. Direct reveal,
    read and patch need a binding that governs the environment, and
    approve fails a request whose binding no longer governs it, with no
    job (#201).
  - Agent wraps and discovery are scoped to the agent that claimed the
    job and to its bound connection. Discovery on a disabled connection
    is refused (#202).
  - Request status changes are conditional, so the loser of a race
    gets 409. Wraps are never extended, and a request past its
    `request_ttl` answers 410 `request_expired` on approve, verify or
    fill (#205).
  - `docker-compose.yml` binds every port to 127.0.0.1 and the api reads
    `SB_WRAP_MASTER_KEY` and `SB_JWT_SECRET` from the shell (#204).

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
