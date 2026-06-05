-- 0028_cross_team_request_flow (down)
--
-- Reverts the Slice N1 schema additions. Drop indexes first, then
-- constraints, then columns, then restore the original CHECK
-- constraints. The DEFAULT on workflow_definitions ensures existing
-- rows are populated when the column was added; on revert the
-- column is dropped entirely.

DROP INDEX IF EXISTS access_requests_fill_expiry_idx;
DROP INDEX IF EXISTS access_requests_pending_verify_idx;
DROP INDEX IF EXISTS access_requests_inbox_idx;

ALTER TABLE workflow_definitions
    DROP COLUMN IF EXISTS requires_security_approval,
    DROP COLUMN IF EXISTS fill_ttl_seconds;

ALTER TABLE access_requests
    DROP CONSTRAINT IF EXISTS access_requests_cross_team_snapshot_required,
    DROP CONSTRAINT IF EXISTS access_requests_cross_team_targets_required,
    DROP CONSTRAINT IF EXISTS access_requests_cross_team_status_only;

ALTER TABLE access_requests
    DROP COLUMN IF EXISTS snap_min_approvers,
    DROP COLUMN IF EXISTS snap_requires_security_approval,
    DROP COLUMN IF EXISTS matched_policy_rule_id,
    DROP COLUMN IF EXISTS fill_expires_at,
    DROP COLUMN IF EXISTS filled_by_user_id,
    DROP COLUMN IF EXISTS filled_at,
    DROP COLUMN IF EXISTS fill_comment,
    DROP COLUMN IF EXISTS refuse_reason,
    DROP COLUMN IF EXISTS destination_keys,
    DROP COLUMN IF EXISTS destination_secret_ref,
    DROP COLUMN IF EXISTS destination_provider_connection_id,
    DROP COLUMN IF EXISTS target_environment_id,
    DROP COLUMN IF EXISTS target_project_id,
    DROP COLUMN IF EXISTS target_team_id;

-- Restore the original CHECK constraints (status + type pre-N1).
ALTER TABLE access_requests
    DROP CONSTRAINT IF EXISTS access_requests_status_check;
ALTER TABLE access_requests
    ADD CONSTRAINT access_requests_status_check
        CHECK (status IN (
            'pending', 'approved', 'rejected', 'cancelled',
            'executed', 'failed', 'expired'
        ));

ALTER TABLE access_requests
    DROP CONSTRAINT IF EXISTS access_requests_type_check;
ALTER TABLE access_requests
    ADD CONSTRAINT access_requests_type_check
        CHECK (type IN ('read', 'update', 'rotate', 'patch'));
