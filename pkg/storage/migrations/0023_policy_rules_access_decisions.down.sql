-- Reverses 0023_policy_rules_access_decisions.

BEGIN;

ALTER TABLE policy_rules
    DROP COLUMN IF EXISTS reveal_ttl_seconds,
    DROP COLUMN IF EXISTS requires_mfa,
    DROP COLUMN IF EXISTS direct_reveal_allowed;

COMMIT;
