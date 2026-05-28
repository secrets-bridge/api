BEGIN;

DROP INDEX IF EXISTS approvals_one_decision_per_approver;
DROP INDEX IF EXISTS access_requests_workflow_idx;
DROP INDEX IF EXISTS access_requests_requester_status_idx;
DROP INDEX IF EXISTS access_requests_status_idx;

ALTER TABLE access_requests DROP CONSTRAINT IF EXISTS access_requests_patch_fields_present;
ALTER TABLE access_requests DROP CONSTRAINT IF EXISTS access_requests_status_check;
ALTER TABLE access_requests DROP CONSTRAINT IF EXISTS access_requests_type_check;

ALTER TABLE access_requests ADD CONSTRAINT access_requests_type_check
    CHECK (type IN ('read', 'update', 'rotate'));
ALTER TABLE access_requests ADD CONSTRAINT access_requests_status_check
    CHECK (status IN ('pending', 'approved', 'rejected', 'executed', 'failed', 'expired'));

ALTER TABLE access_requests
    DROP COLUMN IF EXISTS reject_reason,
    DROP COLUMN IF EXISTS job_id,
    DROP COLUMN IF EXISTS target_scope,
    DROP COLUMN IF EXISTS target_keys,
    DROP COLUMN IF EXISTS target_secret_ref,
    DROP COLUMN IF EXISTS target_provider_config,
    DROP COLUMN IF EXISTS target_provider_type,
    DROP COLUMN IF EXISTS workflow_id;

ALTER TABLE access_requests ALTER COLUMN secret_mapping_id SET NOT NULL;

COMMIT;
