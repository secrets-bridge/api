-- 0002 — separate the agent's long-lived secret from the one-time
-- registration token.
--
-- The flow:
--   1. Admin calls MintRegistrationToken → row inserted with
--      registration_token_hash set, secret_hash NULL, status pending.
--   2. Agent calls POST /api/v1/agents/register with the token →
--      registration_token_hash is verified, cleared; a fresh
--      agent_secret is minted, its hash stored in secret_hash;
--      status → active.
--   3. Agent calls POST /api/v1/agents/heartbeat → secret_hash is
--      verified, last_seen_at bumped.
--
-- Splitting the columns keeps the audit trail clean: an admin can tell
-- at a glance whether an agent has redeemed its registration token by
-- checking whether registration_token_hash is NULL.

BEGIN;

ALTER TABLE agents
    ADD COLUMN secret_hash BYTEA;

COMMIT;
