BEGIN;

ALTER TABLE sync_jobs DROP CONSTRAINT sync_jobs_job_type_check;
ALTER TABLE sync_jobs ADD CONSTRAINT sync_jobs_job_type_check
    CHECK (job_type IN ('sync', 'discover', 'verify', 'delete'));

COMMIT;
