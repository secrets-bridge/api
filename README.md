# secrets-bridge / api

**Control Plane API for [Secrets Bridge](https://github.com/secrets-bridge)** — Go + Fiber. Owns the workflow / RBAC / audit / metadata domain backed by PostgreSQL and Redis. Agents and the dashboard SPA talk to this service over HTTPS.

## Status

| Issue | Step | Status |
|---|---|---|
| [#1](https://github.com/secrets-bridge/api/issues/1) | Scaffold Fiber API + probes + middleware | **this PR** |
| [#2](https://github.com/secrets-bridge/api/issues/2) | Postgres schema + repositories | open |
| [#3](https://github.com/secrets-bridge/api/issues/3) | Redis runtime (locks, idempotency) | open |
| [#4](https://github.com/secrets-bridge/api/issues/4) | Agent registration + heartbeat | open |
| [#5](https://github.com/secrets-bridge/api/issues/5) | Agent job claim/complete loop | open |
| [#6](https://github.com/secrets-bridge/api/issues/6) | Request/approval workflow + audit | open |

## Layout

```
cmd/api/          main + config (the binary)
internal/
  handlers/       HTTP layer — thin parse/serialize, calls services
  middleware/     requestID, logger, recover, auth/RBAC/audit (stubs today)
  observability/  structured logger; metrics + traces land later
  services/       business logic — testable in isolation
pkg/
  storage/        Postgres repositories + migrations (issue #2)
  runtime/        Redis primitives — locks, idempotency, rate limit (issue #3)
  workflow/       approval state machine + audit (issue #6)
```

`pkg/*` is the import surface that the `worker` repo will reuse per [REFACTOR_PLAN.md §4](https://github.com/secrets-bridge/.github/blob/main/profile/README.md). `internal/*` is closed.

## Runtime

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /healthz` | none | Process liveness (kubelet) |
| `GET /readyz`  | none | Dependency readiness (kubelet) |
| `GET /metrics` | none | Prometheus exposition (scrape) |
| `/api/v1/*`    | OIDC bearer (stub today) | Versioned API surface |

## Configuration

| Env var | Default | Notes |
|---|---|---|
| `API_ADDR` | `:8080` | Listen address |
| `API_SHUTDOWN_GRACE` | `15s` | Graceful-shutdown deadline |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

Real dependencies (`DATABASE_URL`, `REDIS_URL`, OIDC issuer, etc.) are deliberately absent from this scaffold — they land with the issues that introduce their package.

## Hard rules

These are enforced in code review and (where possible) by CI. Violations block merge.

- **No secret values** anywhere in this service: not in PostgreSQL, not in Redis, not in logs, not in API responses, not in errors, not in audit events. Provider values stay inside their provider and are only touched by the agent.
- **Stateless.** No in-process state that wouldn't survive a pod restart.
- **Every privileged action emits an audit event with a correlation ID.** The audit stub already logs a TODO so missing coverage is visible during development.

## Local development

```bash
go build ./...
go vet ./...
go test -race -count=1 ./...
go run ./cmd/api &
curl -s localhost:8080/healthz
curl -s localhost:8080/readyz
curl -s localhost:8080/metrics | head
```

## Container

```bash
docker build -t secrets-bridge-api:dev .
docker run --rm -p 8080:8080 secrets-bridge-api:dev
```

The image is multi-stage built on `golang:1.24-alpine` and runs on `distroless/static` as the `nonroot` user. No shell, no package manager.
