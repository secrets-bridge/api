-- 0014_project_secrets
--
-- Multi-tenancy data model. Binds discovered catalog rows
-- (secrets) to projects so non-admin callers see only their
-- project's secrets in /api/v1/secrets, and so submit
-- (POST /requests/{read,patch}) can validate that the requested
-- secret_ref + key set is in scope for the caller's projects.
--
-- See secrets-bridge/api#43 for the full spec.
--
-- N:M because the same secret_ref on the same cluster can
-- legitimately serve multiple projects (e.g. /eks/uat/shared/db
-- bound to both billing and reporting).

BEGIN;

CREATE TABLE project_secrets (
    project_id   UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    secret_id    UUID NOT NULL REFERENCES secrets(id)  ON DELETE CASCADE,

    -- Per-binding key allowlist. NULL = every key the secret carries
    -- is allowed for this project. Non-NULL = only these keys can be
    -- requested by members of this project; submit returns 403 with
    -- error_kind=out_of_scope_key for anything outside the list.
    --
    -- Stored as text[] (not jsonb) because every element is the same
    -- shape (single key name) and we want native array operators
    -- (= ANY, &&) for the validation hot path.
    allowed_keys TEXT[],

    -- Which operations members can submit for this binding. Subset of
    -- ('read','patch','discover'). Defaults to {'read'} so a new
    -- binding is least-privilege by default; admin opts into patch
    -- explicitly.
    allowed_ops  TEXT[] NOT NULL DEFAULT ARRAY['read']
        CHECK (allowed_ops <@ ARRAY['read','patch','discover']),

    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Who created the binding. Free text today (no users FK yet);
    -- becomes a FK when local_users / OIDC swap lands.
    created_by   TEXT,

    PRIMARY KEY (project_id, secret_id)
);

-- Lookup by secret_id (for catalog filtering, where we go
-- secret -> projects -> caller's project_ids).
CREATE INDEX project_secrets_secret_id_idx ON project_secrets (secret_id);

-- updated_at trigger; uses the touch_updated_at() function shipped
-- with the initial migration.
CREATE TRIGGER project_secrets_touch_updated_at
    BEFORE UPDATE ON project_secrets
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

COMMIT;
