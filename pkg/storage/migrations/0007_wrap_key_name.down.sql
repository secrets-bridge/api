BEGIN;

DROP INDEX IF EXISTS secret_wraps_request_key_idx;
ALTER TABLE secret_wraps DROP COLUMN IF EXISTS key_name;

COMMIT;
