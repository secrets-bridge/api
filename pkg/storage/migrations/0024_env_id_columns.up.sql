-- 0024_env_id_columns
--
-- Slice L3 — first-class environment binding across the
-- access-request lifecycle.
--
-- Before this migration, the environment travelled as a free string
-- inside `access_requests.target_scope` and was joined to the
-- `secrets.labels.Env` label downstream. Those two surfaces were
-- the de-facto join keys, but neither pinned a foreign key into
-- `environments`. The result: an operator could rename an env in
-- `environments` and the existing access-request rows would silently
-- lose their binding; cross-checking auth at decision time required
-- two string compares with no DB constraint catching drift.
--
-- This migration adds `environment_id UUID REFERENCES environments(id)`
-- to the three places that need the authoritative binding:
--
--   * `access_requests.environment_id` — submitted by Slice L4 dev
--     endpoints; backfilled from `target_scope->>'environment'` +
--     `project_id` lookup by 0025. NULL allowed for legacy
--     submissions where the operator hasn't yet created the
--     matching `environments` row.
--
--   * `secret_wraps.environment_id` — copied verbatim from the parent
--     `access_requests.environment_id` at wrap creation. For
--     direct-reveal wraps (Slice L4), set inline at issue time.
--
--   * `project_secrets.environment_id` — the AUTHORITATIVE per-env
--     allowlist. Slice L4's GET /projects/:id/environments/:env_id/secrets
--     joins through THIS column, not through the secret's labels.
--     Labels stay supported for DISPLAY only.
--
-- All three columns are added as NULL-able to keep the migration
-- additive. A later migration (post-backfill stable) flips them to
-- NOT NULL.
--
-- This migration ALSO adds `secret_wraps.issued_via`:
--
--   * `'request'`       — wrap was issued as part of the existing
--     access-request flow (write/patch/read).
--   * `'direct_reveal'` — Slice L4 dev endpoint issued the wrap
--     directly without an `access_requests` row. NULL `request_id`
--     is allowed for this kind.
--
-- The name is deliberately env-NEUTRAL (`direct_reveal`, not the
-- earlier `uat_direct` proposal) because the gate is
-- `environment.kind = non_prod` AND a policy decision — not the
-- literal UAT name. PRD §15's defaults set non_prod TTL to 120s and
-- prod to 60s; the kind label drives the routing, not the env's
-- name.

BEGIN;

ALTER TABLE access_requests
    ADD COLUMN environment_id UUID REFERENCES environments(id);

CREATE INDEX access_requests_environment_id_idx
    ON access_requests (environment_id)
    WHERE environment_id IS NOT NULL;

ALTER TABLE secret_wraps
    ADD COLUMN environment_id UUID REFERENCES environments(id),
    ADD COLUMN issued_via TEXT NOT NULL DEFAULT 'request'
        CHECK (issued_via IN ('request', 'direct_reveal'));

CREATE INDEX secret_wraps_environment_id_idx
    ON secret_wraps (environment_id)
    WHERE environment_id IS NOT NULL;

CREATE INDEX secret_wraps_issued_via_idx
    ON secret_wraps (issued_via);

ALTER TABLE project_secrets
    ADD COLUMN environment_id UUID REFERENCES environments(id);

CREATE INDEX project_secrets_environment_id_idx
    ON project_secrets (environment_id)
    WHERE environment_id IS NOT NULL;

COMMIT;
