-- 0050_gateway_discovery
--
-- Argo CD discovery storage (ADR 0002 S4, api#308; wire contract in
-- gateway docs/design/discovery-contract.md). Decision D6 (dedicated
-- tables) was approved on skills#111.
--
--   gateways.discovery_max_entries
--                               per-connector cap on discovered targets
--                               (default 2000, hard maximum 10000)
--   gateway_connectors          the approved scope digest (C6), why the
--                               connector is paused (status_reason), the
--                               discovery lease and generations (C9), the
--                               allowed AppProjects of the latest upload
--                               and the digest of the last accepted upload
--                               (retry answers duplicate)
--   gateway_discovered_targets  one row per (connector, derived target id):
--                               AppProject, namespace and name for display,
--                               first and last seen, present or missing
--   gateway_connector_project_teams
--                               AppProject to team mapping (C4)
--   gateway_discovery_snapshots the latest sealed snapshot per connector.
--                               Opaque: the control plane cannot open it
--                               and stores the strings exactly as uploaded
--   gateway_connector_bindings  target_source (static or discovered) and
--                               suspended_reason
--   observation_tasks           two more verdict reasons for cancelled
--                               tasks: target_missing, binding_suspended
--
-- Nothing here is a URL, a raw Application uid, a credential or a value.
-- The per-replica scope digest rides in gateway_replicas.connector_health.

BEGIN;

ALTER TABLE gateways
    ADD COLUMN discovery_max_entries INTEGER NOT NULL DEFAULT 2000
        CHECK (discovery_max_entries BETWEEN 1 AND 10000);

ALTER TABLE gateway_connectors
    ADD COLUMN approved_scope_digest TEXT
        CHECK (approved_scope_digest IS NULL OR approved_scope_digest ~ '^sha256:[0-9a-f]{64}$'),
    ADD COLUMN status_reason TEXT
        CHECK (status_reason IN ('scope_changed','scope_mismatch_between_replicas','snapshot_stale')),
    -- Last accepted upload generation, and the highest generation ever
    -- granted (an expired lease burns its generation).
    ADD COLUMN discovery_generation BIGINT NOT NULL DEFAULT 0 CHECK (discovery_generation >= 0),
    ADD COLUMN discovery_generation_granted BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN discovery_lease_id UUID,
    ADD COLUMN discovery_lease_replica_id UUID,
    ADD COLUMN discovery_lease_generation BIGINT,
    ADD COLUMN discovery_lease_expires_at TIMESTAMPTZ,
    ADD COLUMN last_lease_granted_at TIMESTAMPTZ,
    ADD COLUMN last_discovery_at TIMESTAMPTZ,
    ADD COLUMN discovery_allowed_projects JSONB
        CHECK (discovery_allowed_projects IS NULL OR jsonb_typeof(discovery_allowed_projects) = 'array'),
    ADD COLUMN last_upload_lease_id UUID,
    ADD COLUMN last_upload_sha256 BYTEA CHECK (last_upload_sha256 IS NULL OR length(last_upload_sha256) = 32),
    ADD COLUMN last_upload_response JSONB,
    ADD CONSTRAINT gateway_connectors_generation_order CHECK (discovery_generation_granted >= discovery_generation),
    ADD CONSTRAINT gateway_connectors_lease_consistent CHECK (
        (discovery_lease_id IS NULL) = (discovery_lease_replica_id IS NULL) AND
        (discovery_lease_id IS NULL) = (discovery_lease_generation IS NULL) AND
        (discovery_lease_id IS NULL) = (discovery_lease_expires_at IS NULL)
    ),
    ADD CONSTRAINT gateway_connectors_upload_consistent CHECK (
        (last_upload_lease_id IS NULL) = (last_upload_sha256 IS NULL) AND
        (last_upload_lease_id IS NULL) = (last_upload_response IS NULL)
    );

CREATE TABLE gateway_discovered_targets (
    connector_id          UUID NOT NULL REFERENCES gateway_connectors(id) ON DELETE CASCADE,
    -- contract.TargetIdentityDigest(connector_id, uid): d- and 26
    -- base32 characters. Never the uid.
    target_id             TEXT NOT NULL CHECK (target_id ~ '^d-[a-z2-7]{26}$'),
    gateway_id            UUID NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
    -- Names mode (the MVP). Opaque mode will relax these in a later
    -- migration.
    app_project           TEXT NOT NULL CHECK (length(app_project) <= 253 AND app_project ~ '^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$'),
    namespace             TEXT NOT NULL CHECK (namespace ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    name                  TEXT NOT NULL CHECK (length(name) <= 253 AND name ~ '^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$' AND name !~ '\.\.'),
    status                TEXT NOT NULL DEFAULT 'present' CHECK (status IN ('present','missing')),
    generation_first_seen BIGINT NOT NULL CHECK (generation_first_seen >= 1),
    last_seen_generation  BIGINT NOT NULL CHECK (last_seen_generation >= generation_first_seen),
    first_seen_at         TIMESTAMPTZ NOT NULL,
    last_seen_at          TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (connector_id, target_id)
);
-- The catalog read sorts and pages on this tuple.
CREATE INDEX gateway_discovered_targets_catalog_idx
    ON gateway_discovered_targets (gateway_id, connector_id, app_project, namespace, name, target_id);
CREATE INDEX gateway_discovered_targets_project_idx
    ON gateway_discovered_targets (connector_id, app_project);

CREATE TABLE gateway_connector_project_teams (
    connector_id  UUID NOT NULL REFERENCES gateway_connectors(id) ON DELETE CASCADE,
    app_project   TEXT NOT NULL CHECK (length(app_project) <= 253 AND app_project ~ '^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$'),
    -- A mapped team cannot be deleted: unmap it first, which suspends
    -- the bindings it covered.
    team_id       UUID NOT NULL REFERENCES teams(id) ON DELETE RESTRICT,
    approved_by   TEXT NOT NULL,
    approved_at   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (connector_id, app_project, team_id)
);
CREATE INDEX gateway_connector_project_teams_team_idx ON gateway_connector_project_teams (team_id);

CREATE TABLE gateway_discovery_snapshots (
    connector_id   UUID PRIMARY KEY REFERENCES gateway_connectors(id) ON DELETE CASCADE,
    generation     BIGINT NOT NULL CHECK (generation >= 1),
    -- Whole seconds, so it round-trips byte for byte as RFC 3339.
    discovered_at  TIMESTAMPTZ NOT NULL CHECK (discovered_at = date_trunc('second', discovered_at)),
    alg            TEXT NOT NULL CHECK (alg = 'A256GCM+HKDF-SHA256/v1'),
    nonce          TEXT NOT NULL CHECK (nonce ~ '^[A-Za-z0-9+/]{16}$'),
    ciphertext     TEXT NOT NULL CHECK (length(ciphertext) BETWEEN 24 AND 2000000 AND ciphertext ~ '^[A-Za-z0-9+/]+={0,2}$'),
    stored_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE gateway_connector_bindings
    ADD COLUMN target_source TEXT NOT NULL DEFAULT 'static' CHECK (target_source IN ('static','discovered')),
    ADD COLUMN suspended_reason TEXT
        CHECK (suspended_reason IN ('target_missing','identity_changed','mapping_removed','scope_changed')),
    ADD COLUMN suspended_at TIMESTAMPTZ,
    ADD CONSTRAINT gateway_connector_bindings_suspended_stamped CHECK ((suspended_reason IS NULL) = (suspended_at IS NULL));
CREATE INDEX gateway_connector_bindings_argocd_target_idx
    ON gateway_connector_bindings (argocd_connector_id, argocd_target_id) WHERE deleted_at IS NULL;

ALTER TABLE observation_tasks DROP CONSTRAINT IF EXISTS observation_tasks_verdict_reason_check;
ALTER TABLE observation_tasks ADD CONSTRAINT observation_tasks_verdict_reason_check CHECK (verdict_reason IN (
    'no_provider_version','volume_refresh_not_observable','subpath_mount_not_refreshed',
    'reload_mechanism_unknown','refresh_interval_exceeds_deadline','failure_observed',
    'no_stage_observed','superseded_by_later_write','source_changed','connector_missing',
    'gateway_errors','gateway_over_privileged','gateway_unavailable','deadline_reached',
    'context_only','binding_removed','target_missing','binding_suspended'));

-- team_covers reports whether team is root or a descendant of root,
-- walking up from team (bounded depth). The dispatch re-check and the
-- bind rule use it for "the binding project's team is in the subtree of
-- a team the AppProject maps to" (ADR 0002 C4).
CREATE FUNCTION team_covers(root UUID, team UUID) RETURNS BOOLEAN
LANGUAGE sql STABLE AS $$
    WITH RECURSIVE up(id, depth) AS (
        SELECT team, 0 WHERE team IS NOT NULL
        UNION ALL
        SELECT t.parent_team_id, up.depth + 1
        FROM teams t JOIN up ON t.id = up.id
        WHERE t.parent_team_id IS NOT NULL AND up.depth < 64
    )
    SELECT EXISTS (SELECT 1 FROM up WHERE up.id = root)
$$;

COMMIT;
