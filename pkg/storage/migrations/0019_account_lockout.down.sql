BEGIN;

DROP INDEX IF EXISTS local_users_locked_until_idx;
ALTER TABLE local_users
    DROP COLUMN IF EXISTS locked_until,
    DROP COLUMN IF EXISTS failed_login_count;

COMMIT;
