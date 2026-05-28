-- 0008 — add 'patch' to sync_jobs.job_type.
--
-- Piece 3 left the request lifecycle ending at status='approved'. The
-- next stop on the state machine is `executed` — reached when an agent
-- successfully applies the requested change to the provider.
--
-- A 'patch' job carries the request_id + target metadata + a list of
-- {wrap_id, key_name} pairs in its payload. The agent claims, retrieves
-- each wrap via Piece 3c, merges them into the provider secret bundle,
-- and reports outcome via the existing /jobs/:id/complete endpoint.

BEGIN;

ALTER TABLE sync_jobs DROP CONSTRAINT sync_jobs_job_type_check;
ALTER TABLE sync_jobs ADD CONSTRAINT sync_jobs_job_type_check
    CHECK (job_type IN ('sync', 'discover', 'verify', 'delete', 'patch'));

COMMIT;
