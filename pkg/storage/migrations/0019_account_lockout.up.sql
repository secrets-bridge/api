-- 0019_account_lockout
--
-- Adds durable account-lockout state to local_users for the local-admin
-- login slice. Rate-limit windows live in Redis (evictable); lockout
-- state lives in Postgres because losing it would silently re-enable
-- a previously-locked account. Architect's locked-in decision (Q7).
--
-- failed_login_count — running counter, reset to 0 on each successful
--                      login; incremented on every wrong-password
--                      failure.
-- locked_until        — NULL means not locked. Future timestamp means
--                       locked until that point. Past timestamp is
--                       semantically "not locked" but is allowed to
--                       persist as evidence — the application clears
--                       it on the next successful login.

BEGIN;

ALTER TABLE local_users
    ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN locked_until       TIMESTAMPTZ;

-- Admins eyeballing "who is currently locked" need this; tiny table,
-- partial index keeps the cost negligible.
CREATE INDEX local_users_locked_until_idx
    ON local_users (locked_until)
    WHERE locked_until IS NOT NULL;

COMMIT;
