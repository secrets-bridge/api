-- Reverses 0027_reveal_sessions.

BEGIN;

DROP INDEX IF EXISTS reveal_sessions_active_idx;
DROP INDEX IF EXISTS reveal_sessions_user_id_idx;
DROP TABLE IF EXISTS reveal_sessions;

COMMIT;
