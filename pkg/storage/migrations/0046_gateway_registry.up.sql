-- 0046_gateway_registry
--
-- Gateway registry (api#293, gateway control-plane design sections 3.1
-- to 3.5). A Gateway is an outbound-only observation process inside a
-- customer boundary. It authenticates with X-Gateway-Secret, a credential
-- of its own: these tables share nothing with agents or
-- agent_enrollment_tokens.
--
--   gateways                    one row per logical Gateway, created by an
--                               admin; secret_hash is NULL until enrolled
--   gateway_enrollment_tokens   one-time tokens (SHA-256 at rest)
--   gateway_replicas            one row per Gateway process, upserted on
--                               heartbeat
--   gateway_connectors          connectors the Gateway advertises through
--                               its catalog, with their targets; ids only
--   gateway_connector_bindings  admin-made link from a secret scope in an
--                               environment to an advertised target
--
-- Nothing here stores a URL, a credential path, a token or a value.
-- Release 1 binds Argo CD connectors only; the tables stay generic.

BEGIN;

CREATE TABLE gateways (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                 TEXT NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    -- The boundary this Gateway speaks for: a display label chosen by the
    -- admin, not a hostname.
    boundary             TEXT NOT NULL CHECK (length(boundary) BETWEEN 1 AND 128),
    -- When set, every binding for this Gateway must be in this environment.
    environment_id       UUID REFERENCES environments(id) ON DELETE RESTRICT,
    secret_hash          BYTEA,
    status               TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','active','stale','disabled','revoked')),
    gateway_version      TEXT,
    contract_versions    JSONB NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(contract_versions) = 'array'),
    max_inflight_tasks   INTEGER NOT NULL DEFAULT 20 CHECK (max_inflight_tasks BETWEEN 1 AND 1000),
    max_replicas         INTEGER NOT NULL DEFAULT 200 CHECK (max_replicas BETWEEN 1 AND 1000),
    -- Digest of the last accepted catalog, echoed on heartbeat.
    catalog_version      TEXT,
    catalog_updated_at   TIMESTAMPTZ,
    last_seen_at         TIMESTAMPTZ,
    last_status          TEXT CHECK (last_status IN ('ok','degraded','not_ready','over_privileged','shutting_down')),
    -- Written by the control plane only.
    last_error           TEXT,
    enrolled_at          TIMESTAMPTZ,
    disabled_at          TIMESTAMPTZ,
    revoked_at           TIMESTAMPTZ,
    revoked_by           TEXT,
    created_by           TEXT NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- An active or stale Gateway always has a credential; a pending one
    -- never does.
    CONSTRAINT gateways_secret_matches_status CHECK (
        (status = 'pending' AND secret_hash IS NULL) OR
        (status IN ('active','stale') AND secret_hash IS NOT NULL) OR
        status IN ('disabled','revoked')
    ),
    CONSTRAINT gateways_revoked_stamped CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);
CREATE INDEX gateways_status_idx    ON gateways (status);
CREATE INDEX gateways_last_seen_idx ON gateways (last_seen_at);
CREATE TRIGGER gateways_touch_updated_at BEFORE UPDATE ON gateways
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

CREATE TABLE gateway_enrollment_tokens (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gateway_id             UUID NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
    token_hash             BYTEA NOT NULL UNIQUE,
    expected_cluster_name  TEXT,
    expires_at             TIMESTAMPTZ NOT NULL,
    consumed_at            TIMESTAMPTZ,
    revoked_at             TIMESTAMPTZ,
    revoked_by             TEXT,
    created_by             TEXT NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT gateway_enrollment_tokens_expiry_after_creation CHECK (expires_at > created_at)
);
CREATE INDEX gateway_enrollment_tokens_gateway_idx ON gateway_enrollment_tokens (gateway_id);

CREATE TABLE gateway_replicas (
    gateway_id       UUID NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
    replica_id       UUID NOT NULL,
    gateway_version  TEXT,
    -- Heartbeat facts, enums and counts only.
    status           TEXT NOT NULL DEFAULT 'ok'
        CHECK (status IN ('ok','degraded','not_ready','over_privileged','shutting_down')),
    in_flight        INTEGER NOT NULL DEFAULT 0 CHECK (in_flight >= 0),
    catalog_version  TEXT,
    -- [{connector_id, kind, status}], enum values only.
    connector_health JSONB NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(connector_health) = 'array'),
    first_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (gateway_id, replica_id)
);
CREATE INDEX gateway_replicas_seen_idx ON gateway_replicas (gateway_id, last_seen_at);

CREATE TABLE gateway_connectors (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gateway_id          UUID NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
    -- connector_id on the wire.
    name                TEXT NOT NULL CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    kind                TEXT NOT NULL CHECK (kind IN ('eso','rollout','argocd')),
    -- [{target_id, namespace?, name?, refresh_interval_seconds?,
    --   progress_deadline_seconds?, stale}]. namespace and name are for
    -- admin display only; nothing matches on them.
    advertised_targets  JSONB NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(advertised_targets) = 'array'),
    status              TEXT NOT NULL DEFAULT 'advertised'
        CHECK (status IN ('advertised','approved','disabled','missing')),
    approved_by         TEXT,
    approved_at         TIMESTAMPTZ,
    last_advertised_at  TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (gateway_id, name)
);
CREATE TRIGGER gateway_connectors_touch_updated_at BEFORE UPDATE ON gateway_connectors
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

CREATE TABLE gateway_connector_bindings (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gateway_id             UUID NOT NULL REFERENCES gateways(id) ON DELETE RESTRICT,
    environment_id         UUID NOT NULL REFERENCES environments(id) ON DELETE RESTRICT,
    -- Secret scope, exactly one form: a catalog secret, or a provider
    -- connection plus secret reference.
    secret_id              UUID REFERENCES secrets(id) ON DELETE CASCADE,
    provider_connection_id UUID REFERENCES provider_connections(id) ON DELETE CASCADE,
    secret_ref             TEXT CHECK (secret_ref IS NULL OR length(secret_ref) BETWEEN 1 AND 512),
    -- Derived from the pairs set below, by the service.
    expected_stages        JSONB NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(expected_stages) = 'array'),
    eso_connector_id       UUID REFERENCES gateway_connectors(id) ON DELETE RESTRICT,
    eso_target_id          TEXT,
    rollout_connector_id   UUID REFERENCES gateway_connectors(id) ON DELETE RESTRICT,
    rollout_target_id      TEXT,
    argocd_connector_id    UUID REFERENCES gateway_connectors(id) ON DELETE RESTRICT,
    argocd_target_id       TEXT,
    observation_timeout_s  INTEGER NOT NULL DEFAULT 1800 CHECK (observation_timeout_s BETWEEN 60 AND 86400),
    enabled                BOOLEAN NOT NULL DEFAULT TRUE,
    created_by             TEXT NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at             TIMESTAMPTZ,
    CONSTRAINT gateway_connector_bindings_one_scope CHECK (
        (secret_id IS NOT NULL AND provider_connection_id IS NULL AND secret_ref IS NULL) OR
        (secret_id IS NULL AND provider_connection_id IS NOT NULL AND secret_ref IS NOT NULL)
    ),
    CONSTRAINT gateway_connector_bindings_eso_pair     CHECK ((eso_connector_id IS NULL) = (eso_target_id IS NULL)),
    CONSTRAINT gateway_connector_bindings_rollout_pair CHECK ((rollout_connector_id IS NULL) = (rollout_target_id IS NULL)),
    CONSTRAINT gateway_connector_bindings_argocd_pair  CHECK ((argocd_connector_id IS NULL) = (argocd_target_id IS NULL)),
    CONSTRAINT gateway_connector_bindings_one_target CHECK (
        eso_connector_id IS NOT NULL OR rollout_connector_id IS NOT NULL OR argocd_connector_id IS NOT NULL
    ),
    CONSTRAINT gateway_connector_bindings_target_ids CHECK (
        (eso_target_id     IS NULL OR eso_target_id     ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$') AND
        (rollout_target_id IS NULL OR rollout_target_id ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$') AND
        (argocd_target_id  IS NULL OR argocd_target_id  ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$')
    )
);
CREATE INDEX gateway_connector_bindings_gateway_idx ON gateway_connector_bindings (gateway_id) WHERE deleted_at IS NULL;
CREATE INDEX gateway_connector_bindings_secret_idx  ON gateway_connector_bindings (secret_id, environment_id) WHERE deleted_at IS NULL;
CREATE INDEX gateway_connector_bindings_conn_idx    ON gateway_connector_bindings (provider_connection_id, secret_ref, environment_id) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX gateway_connector_bindings_one_per_target
    ON gateway_connector_bindings (
        gateway_id, environment_id,
        COALESCE(secret_id::text, provider_connection_id::text || ':' || secret_ref),
        COALESCE(eso_connector_id::text, ''),     COALESCE(eso_target_id, ''),
        COALESCE(rollout_connector_id::text, ''), COALESCE(rollout_target_id, ''),
        COALESCE(argocd_connector_id::text, ''),  COALESCE(argocd_target_id, '')
    )
    WHERE deleted_at IS NULL;
CREATE TRIGGER gateway_connector_bindings_touch_updated_at BEFORE UPDATE ON gateway_connector_bindings
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

COMMIT;
