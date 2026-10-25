-- Reverts 0051. Agents revoked by the up migration stay revoked: an
-- agent without a usable key has no way back in either schema.

BEGIN;

DROP TABLE IF EXISTS agent_key_rotation_challenges;
DROP TABLE IF EXISTS agent_key_rotation_tokens;
DROP TABLE IF EXISTS agent_enrollment_challenges;

DROP TRIGGER IF EXISTS agents_public_key_guard ON agents;
DROP FUNCTION IF EXISTS agents_public_key_guard();

ALTER TABLE agents
    DROP CONSTRAINT IF EXISTS agents_public_key_fingerprint_matches,
    DROP CONSTRAINT IF EXISTS agents_public_key_required,
    DROP CONSTRAINT IF EXISTS agents_public_key_version_positive,
    DROP COLUMN IF EXISTS public_key_version;

COMMIT;
