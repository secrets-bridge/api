-- Reverses 0025_backfill_env_ids. The backfill is idempotent — the
-- down migration NULLs out only the rows the up migration could
-- plausibly have set, leaving any rows that were already non-NULL
-- (set by application writes after 0024) untouched is impossible
-- without an audit table. So the safest down: NULL every
-- environment_id; the next up re-runs the backfill cleanly.

BEGIN;

UPDATE access_requests SET environment_id = NULL;
UPDATE secret_wraps    SET environment_id = NULL;
UPDATE project_secrets SET environment_id = NULL;

COMMIT;
