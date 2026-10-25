-- 0051: Agent enrollment v2 (skills#116, api#327).
--
-- The Agent's X25519 key is generated on the customer side and bound to
-- the agent at enrollment, after a proof of possession. There is no
-- route that overwrites it: the only change is the audited rotation
-- flow, which bumps public_key_version.
--
--   * agent_enrollment_challenges: a nonce sealed to the submitted key,
--     stored as its SHA-256, bound to one enrollment token, 120s, single
--     use.
--   * agent_key_rotation_tokens: the admin's one-time rotation token
--     (hash only), bound to one agent and the key version it was issued
--     against.
--   * agent_key_rotation_challenges: the same proof of possession for
--     the new key.
--   * agents.public_key_version, and a CHECK that every agent that is
--     not revoked has a valid 32-byte x25519 key whose fingerprint
--     column matches it.
--
-- Existing rows (pre-release, no production data to keep): an agent
-- without a usable key is marked revoked, so it can never authenticate
-- again and its row stays for the audit trail. An agent that does have
-- a 32-byte x25519 key keeps it as version 1, and its fingerprint is
-- recomputed from the key (the old column was whatever the agent
-- reported). Such an agent still has to send the new
-- X-Agent-Key-Fingerprint header, which needs the matching private key.

BEGIN;

UPDATE agents
SET    status     = 'revoked',
       revoked_at = COALESCE(revoked_at, now()),
       revoked_by = COALESCE(revoked_by, 'migration:0051_agent_enrollment_v2')
WHERE  status <> 'revoked'
  AND  (public_key IS NULL
        OR octet_length(public_key) <> 32
        OR public_key_algorithm IS DISTINCT FROM 'x25519');

UPDATE agents
SET    public_key_fingerprint = CASE
           WHEN public_key IS NOT NULL THEN 'sha256:' || encode(sha256(public_key), 'hex')
       END;

ALTER TABLE agents
    ADD COLUMN public_key_version INTEGER NOT NULL DEFAULT 1,
    ADD CONSTRAINT agents_public_key_version_positive CHECK (public_key_version >= 1),
    ADD CONSTRAINT agents_public_key_required CHECK (
        status = 'revoked'
        OR (public_key IS NOT NULL
            AND octet_length(public_key) = 32
            AND public_key_algorithm = 'x25519')),
    ADD CONSTRAINT agents_public_key_fingerprint_matches CHECK (
        public_key IS NULL
        OR public_key_fingerprint IS NOT DISTINCT FROM 'sha256:' || encode(sha256(public_key), 'hex'));

-- Defence in depth for "no key substitution": the key changes only
-- together with a version bump of exactly one, which only the rotation
-- confirm does.
CREATE FUNCTION agents_public_key_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.public_key IS DISTINCT FROM OLD.public_key THEN
        IF NEW.public_key_version <> OLD.public_key_version + 1 THEN
            RAISE EXCEPTION 'agents.public_key changes only through key rotation'
                USING ERRCODE = 'check_violation';
        END IF;
    ELSIF NEW.public_key_version <> OLD.public_key_version THEN
        RAISE EXCEPTION 'agents.public_key_version changes only with the key'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER agents_public_key_guard
    BEFORE UPDATE OF public_key, public_key_version ON agents
    FOR EACH ROW EXECUTE FUNCTION agents_public_key_guard();

CREATE TABLE agent_enrollment_challenges (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    enrollment_token_id  UUID NOT NULL REFERENCES agent_enrollment_tokens(id) ON DELETE CASCADE,
    public_key           BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
    public_key_algorithm TEXT NOT NULL CHECK (public_key_algorithm = 'x25519'),
    nonce_hash           BYTEA NOT NULL CHECK (octet_length(nonce_hash) = 32),
    expires_at           TIMESTAMPTZ NOT NULL,
    used_at              TIMESTAMPTZ,
    used_by_agent_id     UUID REFERENCES agents(id) ON DELETE SET NULL,
    invalidated_at       TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT agent_enrollment_challenges_expiry CHECK (expires_at > created_at)
);

CREATE INDEX agent_enrollment_challenges_token_idx ON agent_enrollment_challenges (enrollment_token_id);
CREATE INDEX agent_enrollment_challenges_expires_idx ON agent_enrollment_challenges (expires_at);

CREATE TABLE agent_key_rotation_tokens (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id                    UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    token_hash                  BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    expected_public_key_version INTEGER NOT NULL CHECK (expected_public_key_version >= 1),
    expires_at                  TIMESTAMPTZ NOT NULL,
    consumed_at                 TIMESTAMPTZ,
    revoked_at                  TIMESTAMPTZ,
    revoke_reason               TEXT,
    -- an actor identity (TEXT), like the rest of the schema's actor columns
    created_by                  TEXT NOT NULL,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT agent_key_rotation_tokens_expiry CHECK (expires_at > created_at)
);

-- At most one open rotation per agent: issuing a new token revokes the
-- previous one in the same transaction.
CREATE UNIQUE INDEX agent_key_rotation_tokens_one_open
    ON agent_key_rotation_tokens (agent_id)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;

CREATE TABLE agent_key_rotation_challenges (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rotation_token_id    UUID NOT NULL REFERENCES agent_key_rotation_tokens(id) ON DELETE CASCADE,
    agent_id             UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    public_key           BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
    public_key_algorithm TEXT NOT NULL CHECK (public_key_algorithm = 'x25519'),
    nonce_hash           BYTEA NOT NULL CHECK (octet_length(nonce_hash) = 32),
    expires_at           TIMESTAMPTZ NOT NULL,
    used_at              TIMESTAMPTZ,
    invalidated_at       TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT agent_key_rotation_challenges_expiry CHECK (expires_at > created_at)
);

CREATE INDEX agent_key_rotation_challenges_token_idx ON agent_key_rotation_challenges (rotation_token_id);
CREATE INDEX agent_key_rotation_challenges_agent_idx ON agent_key_rotation_challenges (agent_id);

COMMIT;
