-- 0020_sessions
--
-- Server-side session table (architect Q2 + Q8). Replaces the
-- stateless-JWT-in-sessionStorage posture with a durable session
-- record so revocation is immediate and back-channel logout (RFC 8414)
-- has somewhere to mark a session dead.
--
-- The opaque session id (`token_hash`) is what the UI presents in the
-- HttpOnly Secure SameSite cookie. The hash stays in Postgres — the
-- plaintext value is generated, returned ONCE in the Set-Cookie
-- response, and never persisted. Same pattern as
-- `agents.secret_hash`.
--
-- Two TTLs:
--   - `expires_at`        absolute lifetime (architect Q3 default 8h)
--   - `idle_expires_at`   slides forward on each authenticated request
--                         (architect Q3 default 30 min)
--
-- Both must be in the future for the session to be live. Sliding the
-- idle TTL is the application's responsibility (SessionService.Touch).
--
-- `revoked_at` marks a session dead without a DELETE. We keep the row
-- around so audit queries can still resolve `session_id` to its
-- owning user, IP, and User-Agent after the user signs out.
--
-- `last_mfa_at` is reserved for Slice D (step-up auth). Slice A2 sets
-- it on creation; Slice D extends the contract.

BEGIN;

CREATE TABLE sessions (
    id               UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID        NOT NULL REFERENCES local_users (id) ON DELETE CASCADE,
    token_hash       BYTEA       NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at       TIMESTAMPTZ NOT NULL,
    idle_expires_at  TIMESTAMPTZ NOT NULL,
    last_mfa_at      TIMESTAMPTZ,
    revoked_at       TIMESTAMPTZ,
    ip               TEXT,
    user_agent       TEXT
);
-- expires_at > created_at is enforced by the application; a CHECK
-- constraint here would block sweepers from rewriting the row for
-- post-mortem analysis. The application's Issue path always sets a
-- future expiry; the only way the constraint would have caught
-- anything is operator-side direct UPDATEs, which are out of scope.

-- Lookup by the cookie's hashed value MUST be fast — every
-- authenticated request hits this index.
CREATE UNIQUE INDEX sessions_token_hash_uniq ON sessions (token_hash);

-- Admin "show me X's active sessions" path.
CREATE INDEX sessions_user_id_active_idx
    ON sessions (user_id, expires_at)
    WHERE revoked_at IS NULL;

-- Sweeper / garbage collection of expired rows (future worker slice).
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

COMMIT;
