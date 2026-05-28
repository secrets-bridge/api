-- 0010 — secrets discovery (Phase 2 Piece 6).
--
-- The CP-side cache of secrets the agent has discovered via
-- core/providers.ListMetadata. Powers the dashboard's "list all
-- secrets" / "search by tag" / "filter by cluster" views.
--
-- Identity model:
--   - cluster_name is a first-class column (not just a label), set by
--     the agent from SB_CLUSTER_NAME. It's part of the uniqueness
--     tuple so the same secret_ref in two different clusters appears
--     as two distinct rows.
--   - labels is a jsonb bag for everything else: provider-native tags
--     (Vault labels, AWS tags), admin-edited labels, and any
--     additional dimensions an operator wants to slice by. GIN index
--     makes containment queries cheap.
--
-- Upsert semantics:
--   - Agent posts the rows it currently sees in one batch.
--   - CP does ON CONFLICT (cluster_name, provider_type, secret_ref)
--     DO UPDATE — refreshes labels, version, checksum, last_seen_at.
--   - Rows the agent stops seeing aren't deleted here. A background
--     worker (or admin sweep) can mark stale rows status='missing'
--     based on last_seen_at staleness. v1 just exposes last_seen_at
--     for the UI to decide.

BEGIN;

CREATE TABLE secrets (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Identity. The tuple (cluster_name, provider_type, secret_ref)
    -- is what uniquely names a discovered secret.
    cluster_name         TEXT NOT NULL,
    provider_type        TEXT NOT NULL,
    secret_ref           TEXT NOT NULL,

    -- The provider config the agent used when discovering. Stored as
    -- the same opaque shape access_requests.target_provider_config
    -- uses so the same value can be replayed back to the agent for
    -- subsequent read/patch requests.
    provider_config      JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Tagging surface. Provider-native labels merged with anything
    -- the agent or admin attaches. Searched via GIN.
    labels               JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Provider-reported metadata. version/checksum are opaque
    -- strings; timestamps come from the provider itself.
    version              TEXT,
    checksum             TEXT,
    created_at_source    TIMESTAMPTZ,
    updated_at_source    TIMESTAMPTZ,

    -- secrets-bridge bookkeeping.
    status               TEXT NOT NULL DEFAULT 'present'
                            CHECK (status IN ('present', 'missing')),
    first_seen_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Identity index — the upsert target.
CREATE UNIQUE INDEX secrets_identity_idx
    ON secrets (cluster_name, provider_type, secret_ref);

-- The dominant query shape: filter by cluster + zero or more labels.
CREATE INDEX secrets_cluster_idx
    ON secrets (cluster_name);

-- GIN over labels for fast `WHERE labels @> '{"team":"billing"}'`.
CREATE INDEX secrets_labels_gin_idx
    ON secrets USING gin (labels);

-- Surface stale rows quickly for the missing-detection worker.
CREATE INDEX secrets_last_seen_idx
    ON secrets (last_seen_at);

CREATE TRIGGER secrets_touch_updated_at
    BEFORE UPDATE ON secrets
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

COMMIT;
