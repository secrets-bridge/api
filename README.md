<p align="center">
  <a href="https://github.com/secrets-bridge"><img src="https://raw.githubusercontent.com/secrets-bridge/.github/main/profile/logo.svg" alt="Secrets Bridge" width="520" /></a>
</p>

<p align="center">
  <b>The brain behind your secrets.</b><br/>
  Unified secrets control plane for cloud-native teams.<br/>
  <a href="https://secrets-bridge.io">secrets-bridge.io</a> · <a href="https://github.com/secrets-bridge">all repos</a>
</p>

---
# secrets-bridge / api

**Control Plane API for [Secrets Bridge](https://github.com/secrets-bridge)** — Go + Fiber v3. Owns the workflow / RBAC / audit / metadata domain backed by PostgreSQL and Redis. Agents and the dashboard SPA talk to this service over HTTPS.

## Capabilities

| Concern | Status | Where |
|---|---|---|
| Postgres schema + migrations | Live | `pkg/storage/migrations/0001`-`0026_*.sql` |
| Redis runtime (idempotency, locks, rate-limit, pub-sub) | Live | `pkg/runtime/` |
| Agent registration + heartbeat (single-credential model) | Live | `internal/services/agents.go` |
| Agent job claim → complete loop | Live | `internal/services/jobs.go` |
| Patch + read-flow request lifecycle | Live | `internal/services/requests.go` |
| KMS-envelope-encrypted secret wraps | Live | `pkg/keymgmt/` — backends: local / vault-transit / aws-kms |
| Wire-envelope encryption (X25519 sealing CP→Agent, KMS DEK Agent→CP) | Live | `pkg/sealing/` + `pkg/keymgmt/` |
| Dynamic policy + workflow engine — `PolicyDecision` with PROD invariant | Live | `internal/services/policy.go` (Slice L2) |
| First-class environment model (`kind=non_prod/prod` classification, `risk_level`) | Live | `pkg/storage/environments.go` + migrations 0022/0024 (Slice L1+L3) |
| Dev-facing per-env endpoints + `secret.reveal.direct` permission | Live | `internal/handlers/dev_secrets.go` + `internal/services/requests.go::SubmitDirectReveal` (Slice L4) |
| RBAC + permission catalog | Live | `internal/auth/` |
| Team hierarchy + section-head pattern | Live | `internal/auth/scope_projects.go` + migration 0018 |
| GitOps observation panel (ArgoCD, read-only) | Live (opt-in) | `pkg/argocd/` — `SB_GITOPS_ENABLED=true` |
| Cookie auth + server-side sessions | Live | `pkg/storage/sessions.go` + `internal/services/sessions.go` |
| Account lockout + login rate limit | Live | `internal/services/auth.go` (5 wrong → 15min lock; per-IP rate limit) |
| OIDC client (PKCE + back-channel logout) | Live (opt-in via `SB_OIDC_ISSUER`) | `internal/services/oidc.go` |
| App-MFA enrollment (TOTP + WebAuthn) + step-up on Tier 2 ops | Live | `internal/services/mfa_*.go` + `internal/middleware/stepup.go` (Slices H–I) |
| Login-time MFA gate (opt-in) | Live | `internal/middleware/requirestamped.go` — `SB_REQUIRE_MFA_AT_LOGIN=true` (Slice K) |
| Group-claim → role mapping at JIT | Open ([#57](https://github.com/secrets-bridge/api/pull/57)) | `RoleReconciler` in oidc.go |

## Layout

```
cmd/api/                main + config (the binary)
internal/
  auth/                 permission catalog (constants + Catalog + RBAC resolver)
  handlers/             HTTP layer — thin parse/serialize, calls services
  middleware/           RequestID / Logger / Recover / AuthWith / AgentAuth /
                        RateLimit / RequireFreshMFA / RBAC / Audit
  observability/        structured logger (slog JSON)
  services/             business logic — testable in isolation
pkg/
  argocd/               read-only ArgoCD client (BRD §26 GitOps integration)
  keymgmt/              KeyManager interface + local / vault-transit / aws-kms
  runtime/              Redis primitives — locks, idempotency, rate limit, pub/sub
  sealing/              X25519 + HKDF-SHA256 + AES-256-GCM wire-envelope crypto
  storage/              Postgres repositories + migrations (golang-migrate)
  workflow/             (reserved for workflow state-machine helpers)
```

`pkg/*` is the import surface reused by the `worker` repo per [REFACTOR_PLAN.md §4](https://github.com/secrets-bridge/.github/blob/main/profile/README.md). `internal/*` is closed.

## Runtime

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /healthz` | none | Process liveness (kubelet) |
| `GET /readyz`  | none | Dependency readiness (Postgres + Redis pings) |
| `GET /metrics` | none | Prometheus exposition (scrape) |
| `POST /api/v1/auth/login` | none (public) | Local-admin sign-in; sets `sb_session` cookie + returns legacy JWT (back-compat) |
| `POST /api/v1/auth/logout` | cookie | Idempotent session revoke + clear cookie |
| `GET /api/v1/auth/oidc/start` | none | PKCE + state + nonce → 302 to IdP authorize. `?step_up=mfa` forces MFA re-prompt |
| `GET /api/v1/auth/oidc/callback` | IdP | Code exchange + JIT-provision + cookie set + redirect to `return_to` |
| `POST /api/v1/auth/oidc/logout` | cookie | RP-initiated logout + IdP `end_session_endpoint` |
| `POST /api/v1/auth/oidc/backchannel` | IdP signature | RFC 8417 — revoke every session for the user's `sub` |
| `/api/v1/*` (everything else) | cookie / Bearer JWT / X-User-Id stub | Versioned API surface |

Tier 2 ops (approve / reject / reveal wrap) additionally require `last_mfa_at` within the step-up TTL (15 min). Stale sessions get `401 step_up_required` + `WWW-Authenticate: step-up max_age=900 acr_values=mfa`.

## Configuration

### Core runtime

| Env var | Default | Notes |
|---|---|---|
| `API_ADDR` | `:8080` | Listen address |
| `API_SHUTDOWN_GRACE` | `15s` | Graceful-shutdown deadline |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `DATABASE_URL` | required | Postgres DSN |
| `REDIS_URL` | required | Redis URL (db index in path) |
| `SB_ENV` | `production` | `dev` or `production`. In `production`, `local` KMS backend is REJECTED at boot. |

### Auth / sessions / OIDC (Slices A1–E)

| Env var | Default | Notes |
|---|---|---|
| `SB_JWT_SECRET` | required | HMAC-SHA256 key, ≥32 bytes (base64 preferred). Used for legacy Bearer JWT path. |
| `SB_JWT_TOKEN_TTL` | `8h` | Lifetime of the legacy JWT issued by `/auth/login`. Cookie session has its own policy. |
| `SB_BOOTSTRAP_ADMIN_EMAIL` + `SB_BOOTSTRAP_ADMIN_PASSWORD` | (unset) | First-boot seed of the local-admin user. Idempotent. |
| `SB_BOOTSTRAP_ADMIN_USER_ID` | (unset) | First-boot grant of `admin` role to this user_id. Idempotent. |
| `SB_DEV_SEED_PASSWORD` | (unset) | Shared password for the three dev seed users when `SB_ENV=dev`. Without it, a random password per user is logged ONCE at WARN. |
| `SB_OIDC_ISSUER` | (unset) | OIDC provider URL. **OIDC routes only mount when set.** Discovery URL like `https://authentik.example.com/application/o/secrets-bridge/`. |
| `SB_OIDC_CLIENT_ID` | (unset) | Public client identifier registered with the IdP. |
| `SB_OIDC_CLIENT_SECRET` | (unset) | Client secret. Confidential clients only; PKCE-only public clients leave unset. |
| `SB_OIDC_REDIRECT_URL` | (unset) | Public callback URL; must match the IdP's registered redirect. |
| `SB_OIDC_SCOPES` | `openid profile email` | Space-separated. Add `groups` if your IdP needs it explicitly for the claim. |
| `SB_OIDC_POST_LOGOUT_REDIRECT` | (unset) | Where the IdP sends users after `end_session_endpoint`. |
| `SB_OIDC_GROUP_CLAIM` (open in #57) | `groups` | ID-token claim that carries the user's groups. Authentik / Keycloak / Okta default. |
| `SB_OIDC_GROUP_MAP` (open in #57) | (unset) | JSON object `{"<idp-group>":"<sb-role>"}`. Empty → reconciler short-circuits; JIT users get no grants. Validated at boot — malformed JSON fails LOUD. |
| `SB_MFA_DEV_ALLOW_PWD` | `false` | **Interim flag (Slice H).** When `true` AND `SB_ENV=dev`, every live session is treated as MFA-fresh — Tier 2 step-up is bypassed. **Refused at boot under `SB_ENV=production`.** Exists to unblock dev/UAT pilots while app-level MFA (`/auth/mfa/{challenge,verify}` + WebAuthn / TOTP enrolment) is being built. Drop once Slice H4 ships. |

### KMS / wrap envelope

| Env var | Default | Notes |
|---|---|---|
| `SB_KMS_BACKEND` | `local` | `local`, `vault-transit`, or `aws-kms`. **`local` REFUSED when `SB_ENV != "dev"`.** |
| `SB_WRAP_MASTER_KEY` | (required for `local`) | base64(32 bytes). Local-only KMS for dev. |
| `SB_KMS_VAULT_ADDR` / `_TOKEN` / `_KEY` / `_MOUNT` | (required for `vault-transit`) | Vault Transit-backed KeyManager. |
| `SB_KMS_AWS_REGION` / `_KEY_ID` / `_ENDPOINT` | (required for `aws-kms`) | AWS KMS-backed KeyManager. Credentials via standard AWS SDK chain (IRSA / instance role / env). |

### GitOps integration (BRD §26, opt-in)

| Env var | Default | Notes |
|---|---|---|
| `SB_GITOPS_ENABLED` | `false` | When off, ArgoCD admin + observation endpoints aren't mounted; request lifecycle has no GitOps fan-out. |

## Hard rules

Enforced in code review + (where possible) by CI. Violations block merge.

- **No secret values** anywhere in this service — not in Postgres, not in Redis, not in logs, not in API responses, not in errors, not in audit events. Provider values stay inside their provider; only the agent touches them.
- **No plaintext password** in any audit event metadata. Anti-leak canary tests grep for known-distinctive strings.
- **Stateless.** No in-process state that wouldn't survive a pod restart. Sessions, lockout state, rate-limit windows, OIDC state — all in Postgres or Redis.
- **Every privileged action emits an audit event with a correlation_id.** `audit_events` is append-only at the schema level (BEFORE UPDATE/DELETE triggers).
- **Cookie attributes:** HttpOnly always, SameSite=Strict, Secure prod-only (`SB_ENV=dev` drops it for `http://localhost` Vite dev). MaxAge = AbsoluteTTL (default 8h).
- **The role reconciler ONLY touches `granted_by = 'system:oidc'` rows.** Admin-assigned grants are invisible to it. This protects bootstrap-admin + manually-curated team-scoped grants from getting blown away on every OIDC sign-in.

## Local development

```bash
docker compose up -d postgres redis
export TEST_DATABASE_URL="postgres://secrets_bridge:devpass@localhost:5432/secrets_bridge_test?sslmode=disable"
export TEST_REDIS_URL="redis://localhost:6379/1"

go build ./...
go vet ./...
go test -race -count=1 -p 1 ./...
go run ./cmd/api
```

For the LocalKMS backend in dev:

```bash
export SB_ENV=dev
export SB_WRAP_MASTER_KEY=$(openssl rand -base64 32)
export SB_JWT_SECRET=$(openssl rand -base64 32)
```

For OIDC against Authentik:

```bash
export SB_OIDC_ISSUER="https://authentik.example.com/application/o/secrets-bridge/"
export SB_OIDC_CLIENT_ID="secrets-bridge"
export SB_OIDC_CLIENT_SECRET="<from-authentik>"
export SB_OIDC_REDIRECT_URL="https://sb.example.com/api/v1/auth/oidc/callback"
export SB_OIDC_GROUP_MAP='{"sb-admins":"admin","sb-approvers":"approver","sb-devs":"developer"}'
```

## Container

```bash
docker build -t secrets-bridge-api:dev .
docker run --rm -p 8080:8080 \
  -e DATABASE_URL=postgres://... \
  -e REDIS_URL=redis://... \
  -e SB_JWT_SECRET=... \
  -e SB_KMS_BACKEND=vault-transit \
  -e SB_KMS_VAULT_ADDR=... \
  -e SB_KMS_VAULT_TOKEN=... \
  -e SB_KMS_VAULT_KEY=sb-wrap \
  secrets-bridge-api:dev
```

Multi-stage build on `golang:1.25-alpine`, runs on `distroless/static` as the `nonroot` user. No shell, no package manager.

## See also

- [`secrets-bridge/skills/api/SKILL.md`](https://github.com/secrets-bridge/skills/blob/main/api/SKILL.md) — internal working-instructions skill for this repo (env vars, conventions, gotchas).
- [`secrets-bridge/skills/PROGRESS.md`](https://github.com/secrets-bridge/skills/blob/main/PROGRESS.md) — slice-by-slice activity log; each PR has an entry with the load-bearing invariants called out.
- [`BRD.md`](https://github.com/secrets-bridge/secrets-bridge/blob/main/BRD.md) — full business + functional requirements.
