BEGIN;

ALTER TABLE secret_wraps DROP CONSTRAINT secret_wraps_one_shot;
ALTER TABLE secret_wraps ADD CONSTRAINT secret_wraps_one_shot
    CHECK (
        (consumed_at IS NULL AND consumed_by_agent IS NULL) OR
        (consumed_at IS NOT NULL AND consumed_by_agent IS NOT NULL)
    );
ALTER TABLE secret_wraps DROP COLUMN consumed_by_user;

ALTER TABLE access_requests DROP CONSTRAINT access_requests_target_fields_present;
ALTER TABLE access_requests ADD CONSTRAINT access_requests_patch_fields_present
    CHECK (
        type != 'patch'
        OR (workflow_id IS NOT NULL
            AND target_provider_type IS NOT NULL
            AND target_secret_ref IS NOT NULL)
    );

ALTER TABLE sync_jobs DROP CONSTRAINT sync_jobs_job_type_check;
ALTER TABLE sync_jobs ADD CONSTRAINT sync_jobs_job_type_check
    CHECK (job_type IN ('sync', 'discover', 'verify', 'delete', 'patch'));

COMMIT;
