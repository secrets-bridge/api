-- 0038 — Agent Onboarding MVP (api#178, epic api#177).
--
-- Additive + nullable extension of the certified `agents` table — NO
-- parallel registry and NO second credential. The persistent agent
-- credential stays `agents.secret_hash` (the enroll API calls it
-- `agent_token` externally). Plus a new `agent_enrollment_tokens` table for
-- the one-time, short-TTL, hash-only enrollment flow.
--
-- Safety: every new `agents` column is nullable (or NOT NULL WITH a
-- default), so the live agent row keeps working untouched. There is NO
-- one-shot NOT NULL on the populated table — `provider_connection_id` is
-- enforced for NEW enrollments at the service layer; a later migration may
-- tighten it once every row is backfilled. The status CHECK is only widened
-- (never narrowed), mirroring 0003.

BEGIN;

-- One-time agent enrollment tokens. Only the hash is stored; the plaintext
-- is returned once to the admin and never persisted or logged.
CREATE TABLE agent_enrollment_tokens (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_connection_id UUID NOT NULL REFERENCES provider_connections(id) ON DELETE CASCADE,
    name                   TEXT,
    token_hash             BYTEA NOT NULL UNIQUE,
    expected_cluster_name  TEXT,
    expected_provider_type TEXT,
    expires_at             TIMESTAMPTZ NOT NULL,
    consumed_at            TIMESTAMPTZ,
    consumed_by_agent_id   UUID REFERENCES agents(id) ON DELETE SET NULL,
    revoked_at             TIMESTAMPTZ,
    -- revoked_by / created_by are actor IDENTITIES (local-user UUID or an
    -- OIDC subject), stored as TEXT to match access_requests.requester_id /
    -- reveal_sessions.user_id — never a UUID FK.
    revoked_by             TEXT,
    created_by             TEXT NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT agent_enrollment_tokens_expiry_after_creation CHECK (expires_at > created_at)
);

CREATE INDEX agent_enrollment_tokens_connection_idx ON agent_enrollment_tokens (provider_connection_id);
CREATE INDEX agent_enrollment_tokens_expires_idx    ON agent_enrollment_tokens (expires_at);
CREATE INDEX agent_enrollment_tokens_consumed_idx   ON agent_enrollment_tokens (consumed_at);
CREATE INDEX agent_enrollment_tokens_revoked_idx    ON agent_enrollment_tokens (revoked_at);

-- Additive, nullable columns on the certified agents table.
ALTER TABLE agents
    ADD COLUMN provider_connection_id  UUID REFERENCES provider_connections(id) ON DELETE SET NULL,
    ADD COLUMN cluster_name            TEXT,
    ADD COLUMN provider_type           TEXT,
    ADD COLUMN region                  TEXT,
    ADD COLUMN agent_version           TEXT,
    ADD COLUMN public_key_fingerprint  TEXT,
    ADD COLUMN capabilities            JSONB NOT NULL DEFAULT '[]',
    ADD COLUMN last_status             TEXT,
    ADD COLUMN last_error              TEXT,
    ADD COLUMN disabled_at             TIMESTAMPTZ,
    ADD COLUMN revoked_at              TIMESTAMPTZ,
    -- revoked_by is an actor identity (TEXT), not a UUID FK — matches the
    -- rest of the schema's actor columns.
    ADD COLUMN revoked_by              TEXT;

CREATE INDEX agents_provider_connection_idx ON agents (provider_connection_id);
CREATE INDEX agents_cluster_name_idx        ON agents (cluster_name);
CREATE INDEX agents_status_idx              ON agents (status);
CREATE INDEX agents_last_seen_idx           ON agents (last_seen_at);
CREATE INDEX agents_revoked_idx             ON agents (revoked_at);

-- Widen the status CHECK: add enrolled/error/disabled (never remove the
-- existing active/stale/revoked).
ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_status_check;
ALTER TABLE agents ADD CONSTRAINT agents_status_check
    CHECK (status IN ('enrolled', 'active', 'stale', 'error', 'disabled', 'revoked'));

COMMIT;
