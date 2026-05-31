BEGIN;

DROP INDEX IF EXISTS sessions_expires_at_idx;
DROP INDEX IF EXISTS sessions_user_id_active_idx;
DROP INDEX IF EXISTS sessions_token_hash_uniq;
DROP TABLE IF EXISTS sessions;

COMMIT;
