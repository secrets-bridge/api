# CLAUDE.md: secrets-bridge/api

Instructions for Claude Code and contributors working in this repo. For the whole platform, see https://secrets-bridge.io.

## What this repo is

The Secrets Bridge control plane API (Go, Fiber v3, Postgres, Redis). The UI and every agent talk to it. It owns authentication, RBAC, the policy engine, approval workflows, wraps, jobs, the secrets catalog and the audit log. It never holds secret values in plaintext at rest.

## Layout

| Path | Purpose |
|---|---|
| `cmd/api` | Wiring: config, storage, Redis runtime, KMS, services and every route in `main.go` with the permission that guards it |
| `internal/handlers` | Thin HTTP handlers: parse, call a service, map errors to status codes |
| `internal/services` | Business logic: request lifecycle (`requests*.go`), PolicyEngine (`policy*.go`), reveal sessions, agent enrollment, MFA, OIDC, provider connections, wraps, jobs |
| `internal/auth` | JWT (stdlib HS256), `auth.Require(perm)` guards, permission constants |
| `internal/middleware` | Request ID, logging, recover, session auth behind a default-deny route group, agent auth |
| `pkg/storage` | pgx repositories and ordered SQL migrations in `pkg/storage/migrations` (applied on start) |
| `pkg/runtime` | Redis: idempotency, locks, rate limits, pub/sub |
| `pkg/workflow` | Access request state machine |
| `pkg/keymgmt` | KMS backends selected by `SB_KMS_BACKEND`: `local` (dev only), `vault-transit`, `aws-kms` |
| `pkg/objectstore` | Media in S3-compatible object storage (`Store` interface, S3 backend, `objectstoretest` fakes and live-test helper) |
| `pkg/sealing` | X25519 + HKDF + AES-GCM envelope sealing between api and agent |
| `pkg/argocd` | Read-only ArgoCD client, opt-in with `SB_GITOPS_ENABLED` |
| `pkg/sanitize` | Scrubbing helpers for user or provider text that might be echoed |

`pkg/*` is imported by `worker`. Changing an exported package must keep `worker` building, so merge here first.

## Build and test

```bash
go build ./... && go vet ./...
golangci-lint run
go mod tidy   # CI fails on a diff

# integration tests need Postgres 17, Redis and an S3 API (MinIO); they skip when these are unset
export TEST_DATABASE_URL=postgres://secrets_bridge:devpass@localhost:5432/secrets_bridge_test?sslmode=disable
export TEST_REDIS_URL=redis://localhost:6379/1
export TEST_OBJECTSTORE_ENDPOINT=http://localhost:9000
export TEST_OBJECTSTORE_ACCESS_KEY=secrets-bridge TEST_OBJECTSTORE_SECRET_KEY=devpass-minio
go test -race -count=1 -p 1 ./...
```

`docker compose up -d postgres redis minio minio-init` in this repo starts Postgres, Redis and MinIO on 127.0.0.1 for local runs. The compose file holds no keys: the api container reads `SB_WRAP_MASTER_KEY` and `SB_JWT_SECRET` from your shell and refuses to boot without them.

## Key configuration

`DATABASE_URL`, `REDIS_URL`, `API_ADDR`, `SB_ENV` (`dev` or `production`), `SB_JWT_SECRET` (32+ bytes), `SB_KMS_BACKEND` and its `SB_KMS_*` settings, `SB_BOOTSTRAP_ADMIN_EMAIL` / `_PASSWORD`, `SB_OIDC_*`, `SB_MFA_*`, `SB_OBJECTSTORE_*` (media storage; see README). Switches such as `SB_ALLOW_INSECURE_HEADER_AUTH` and `SB_ALLOW_DIRECT_AGENT_MINT` default to off and must stay off outside local development.

## Rules for this repo

- **No secret values** in Postgres (outside KMS-wrapped `secret_wraps`), Redis, logs, API responses, error messages or audit metadata. Tests that touch values should assert the plaintext does not appear in the database or audit rows.
- **Media goes to object storage**, never Postgres: images and other uploads go through `pkg/objectstore`, and Postgres keeps only metadata and the object key. No secret values in object storage.
- **Identity comes from the authenticated session only.** Never trust a user or agent ID from a request body, query string or header.
- Every route is behind authentication by default. A public route must be an explicit, reviewed exception.
- Every workflow-changing action emits an audit event with a correlation ID.
- Handlers stay thin; logic goes in services, SQL in `pkg/storage`, state transitions in `pkg/workflow`.
- Migrations are append-only: add a new numbered pair (`.up.sql` and `.down.sql`), never edit a merged one. The `audit_events` table is append-only by trigger.
- Prod environments never allow direct reveal. Do not weaken that check or the policy invariant that strips such rules.
- Return generic messages on auth failures; put the detail in the audit log.
- Changes to auth, the policy engine or the schema of existing tables need maintainer agreement in an issue first.

## Contributing

Feature branch off `main`, conventional commits, small PRs, CI green, then open a PR for maintainer review. Never push to `main`.

This repo is public. Keep account IDs, hostnames, cluster names, real secret paths and company names out of code, tests, commits, PRs and issues. Use placeholders such as `123456789012`, `vault.example.com` and `tenant-a-uat`.
