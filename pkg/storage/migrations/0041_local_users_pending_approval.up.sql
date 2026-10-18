-- 0041_local_users_pending_approval
--
-- An account can wait for an admin's approval before it may act
-- (api#265, api#266). Accounts created by a Google sign-in start
-- waiting; an admin approves them with a role, or declines them.
--
-- pending_approval — FALSE for every existing and admin-created
--                    account. While TRUE, a session may only read
--                    /users/me and sign out, and bearer tokens are
--                    refused. Approval clears it in the same
--                    transaction that grants the role.
--
-- It sits next to `disabled` and the lockout columns (0019) because
-- the session lookup and the bearer-token check already read the
-- account's state from this row on every request.

BEGIN;

ALTER TABLE local_users
    ADD COLUMN pending_approval BOOLEAN NOT NULL DEFAULT FALSE;

-- The admin list and its badge read the waiting accounts, oldest
-- first. Waiting rows are few; the partial index keeps it small.
CREATE INDEX local_users_pending_approval_idx
    ON local_users (created_at)
    WHERE pending_approval;

COMMIT;
