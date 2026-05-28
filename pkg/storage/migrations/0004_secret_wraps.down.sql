BEGIN;

DROP INDEX IF EXISTS secret_wraps_active_idx;
DROP INDEX IF EXISTS secret_wraps_request_idx;
DROP TABLE IF EXISTS secret_wraps;

COMMIT;
