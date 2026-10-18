BEGIN;

DROP INDEX IF EXISTS local_users_pending_approval_idx;
ALTER TABLE local_users
    DROP COLUMN IF EXISTS pending_approval;

COMMIT;
