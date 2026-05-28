-- 0003 — collapse the two-credential agent model into one.
--
-- The two-step (registration_token → register → agent_secret) flow
-- looked good on paper but pushed real operational complexity onto
-- operators: it requires either a PVC to persist identity.json across
-- Pod restarts, or a pre-install Job to re-mint every time. For the
-- MVP we collapse to a single long-lived credential issued at mint
-- time. Rotation flow stays the same shape (mint a new agent or call a
-- future POST /agents/:id/rotate-secret).
--
-- The change:
--   - drop registration_token_hash entirely (column is unused after this)
--   - require secret_hash NOT NULL (every active agent must have one)
--   - drop the 'pending' status — agents are 'active' at mint time
--   - back-fill any leftover 'pending' rows just in case

BEGIN;

-- Heal any leftover state before the constraints tighten.
UPDATE agents SET status = 'active' WHERE status = 'pending';

ALTER TABLE agents DROP COLUMN IF EXISTS registration_token_hash;
ALTER TABLE agents ALTER COLUMN secret_hash SET NOT NULL;
ALTER TABLE agents ALTER COLUMN status SET DEFAULT 'active';

-- Rebuild the status CHECK without 'pending'.
ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_status_check;
ALTER TABLE agents ADD CONSTRAINT agents_status_check
    CHECK (status IN ('active', 'stale', 'revoked'));

COMMIT;
