-- Down for 0038 — Agent Onboarding MVP.

BEGIN;

-- Restore the narrower status CHECK. Heal any rows using the new statuses
-- back to a legacy value first so the constraint can be re-added.
ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_status_check;
UPDATE agents SET status = 'active' WHERE status IN ('enrolled', 'error', 'disabled');
ALTER TABLE agents ADD CONSTRAINT agents_status_check
    CHECK (status IN ('active', 'stale', 'revoked'));

DROP INDEX IF EXISTS agents_provider_connection_idx;
DROP INDEX IF EXISTS agents_cluster_name_idx;
DROP INDEX IF EXISTS agents_status_idx;
DROP INDEX IF EXISTS agents_last_seen_idx;
DROP INDEX IF EXISTS agents_revoked_idx;

ALTER TABLE agents
    DROP COLUMN IF EXISTS provider_connection_id,
    DROP COLUMN IF EXISTS cluster_name,
    DROP COLUMN IF EXISTS provider_type,
    DROP COLUMN IF EXISTS region,
    DROP COLUMN IF EXISTS agent_version,
    DROP COLUMN IF EXISTS public_key_fingerprint,
    DROP COLUMN IF EXISTS capabilities,
    DROP COLUMN IF EXISTS last_status,
    DROP COLUMN IF EXISTS last_error,
    DROP COLUMN IF EXISTS disabled_at,
    DROP COLUMN IF EXISTS revoked_at,
    DROP COLUMN IF EXISTS revoked_by;

DROP TABLE IF EXISTS agent_enrollment_tokens;

COMMIT;
