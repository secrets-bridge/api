-- 0030_provider_connections_admin
--
-- EPIC P (Provider Connections) — P1.
--
-- provider_connections becomes a real operator/admin feature. Two
-- moves in one migration:
--
--   A. Extend provider_connections with discovery scheduling columns
--      + description + cluster_name. Discovery is OFF by default so
--      adding the columns doesn't change behaviour for existing rows.
--
--   B. Create project_provider_connections — the N:M binding table
--      between projects (+ optional environments) and provider
--      connections. v1 ships only purpose='destination'; the column
--      is pre-claimed so future purposes (source, discover_target)
--      extend via the CHECK without a schema migration.
--
-- Hard rules baked in:
--
--   * discover_enabled=true requires cluster_name IS NOT NULL — the
--     worker needs cluster_name to route discovery work to the right
--     agent (matched against agent.scope.cluster). The service layer
--     refuses at write; the CHECK constraint is the safety net.
--
--   * Two partial UNIQUE indexes on the join table cover the
--     PostgreSQL NULL-semantic gap: env-specific bindings vs
--     project-wide bindings (env_id IS NULL). A single
--     UNIQUE (project_id, environment_id, provider_connection_id,
--     purpose) would let two project-wide bindings co-exist because
--     PG treats NULL ≠ NULL.
--
--   * Provider connection deletion is RESTRICT on the binding FK —
--     an in-use connection cannot vanish from under live requests or
--     bindings. The service layer's DELETE handler surfaces the in-
--     use counts (bindings + open requests) in the 409 body.
--
--   * Project / environment deletion is CASCADE on the binding FKs —
--     dropping a project drops its bindings. The provider connection
--     itself survives.
--
--   * scope JSONB has had a NEVER-stores-credentials hard rule since
--     0001; this migration adds no new fields that could break that
--     invariant. The canary test in storage_test.go scans every
--     scope row for credential-shaped substrings.

BEGIN;

-- =====================================================================
-- A. provider_connections — new columns
-- =====================================================================

ALTER TABLE provider_connections
    ADD COLUMN cluster_name              TEXT,
    ADD COLUMN description               TEXT,
    ADD COLUMN discover_enabled          BOOLEAN     NOT NULL DEFAULT false,
    ADD COLUMN discover_interval_seconds INTEGER     NOT NULL DEFAULT 300
        CHECK (discover_interval_seconds >= 60 AND discover_interval_seconds <= 86400),
    ADD COLUMN last_discover_at          TIMESTAMPTZ,
    ADD COLUMN last_discover_status      TEXT
        CHECK (last_discover_status IN ('success', 'failure', 'running')),
    ADD COLUMN last_discover_error       TEXT,
    ADD COLUMN last_discover_started_at  TIMESTAMPTZ,
    ADD COLUMN last_discover_finished_at TIMESTAMPTZ;

-- Schema-level safety net: discover_enabled=true requires cluster_name.
ALTER TABLE provider_connections
    ADD CONSTRAINT provider_connections_discover_requires_cluster
    CHECK (discover_enabled = false OR cluster_name IS NOT NULL);

-- Worker hot-path: SELECT … WHERE discover_enabled=true ORDER BY
-- last_discover_at NULLS FIRST. Partial index keeps the scan tiny
-- even in deployments where 95% of connections are passive metadata
-- for cross-team destinations.
CREATE INDEX provider_connections_discover_enabled_idx
    ON provider_connections (last_discover_at NULLS FIRST)
    WHERE discover_enabled = true;

-- =====================================================================
-- B. project_provider_connections — N:M binding table
-- =====================================================================

CREATE TABLE project_provider_connections (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    project_id              UUID        NOT NULL
                                REFERENCES projects(id)            ON DELETE CASCADE,

    -- Nullable for project-wide bindings (any environment). The
    -- service layer's dropdown query returns BOTH env-specific
    -- bindings (when env_id is supplied) AND project-wide bindings
    -- (env_id IS NULL).
    environment_id          UUID        NULL
                                REFERENCES environments(id)        ON DELETE CASCADE,

    -- RESTRICT: an in-use connection cannot be deleted. Service-
    -- layer DELETE handler queries the count first and returns 409
    -- connection_in_use with bindings_count + open_requests_count.
    provider_connection_id  UUID        NOT NULL
                                REFERENCES provider_connections(id) ON DELETE RESTRICT,

    -- v1 supports only 'destination'. Future purposes ('source',
    -- 'discover_target', …) extend via ALTER CONSTRAINT, NOT a
    -- schema migration on the column itself.
    purpose                 TEXT        NOT NULL DEFAULT 'destination'
        CHECK (purpose IN ('destination')),

    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by              TEXT
);

-- Partial UNIQUE for env-specific bindings (env_id IS NOT NULL).
-- A given (project, env, connection, purpose) appears at most once.
CREATE UNIQUE INDEX project_provider_connections_env_specific_uniq
    ON project_provider_connections
        (project_id, environment_id, provider_connection_id, purpose)
    WHERE environment_id IS NOT NULL;

-- Partial UNIQUE for project-wide bindings (env_id IS NULL).
-- Without this, two NULL env_ids would slip past the env-specific
-- UNIQUE because PG treats NULL ≠ NULL.
CREATE UNIQUE INDEX project_provider_connections_project_wide_uniq
    ON project_provider_connections
        (project_id, provider_connection_id, purpose)
    WHERE environment_id IS NULL;

-- Dropdown query path: GET /provider-connections?project_id=&environment_id=.
-- The service-layer query OR's env-specific + project-wide bindings;
-- both branches lead with project_id.
CREATE INDEX project_provider_connections_project_idx
    ON project_provider_connections (project_id);

CREATE INDEX project_provider_connections_project_env_idx
    ON project_provider_connections (project_id, environment_id)
    WHERE environment_id IS NOT NULL;

-- Reverse lookup for the DELETE RESTRICT path — the admin DELETE
-- handler queries this to surface "in use by N bindings" before the
-- FK error ever fires.
CREATE INDEX project_provider_connections_connection_idx
    ON project_provider_connections (provider_connection_id);

-- updated_at trigger (matches the rest of pkg/storage).
CREATE TRIGGER project_provider_connections_touch_updated_at
    BEFORE UPDATE ON project_provider_connections
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

COMMIT;
