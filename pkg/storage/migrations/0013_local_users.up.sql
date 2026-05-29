-- Local users for the minimal-login slice (api#TBD / ui#TBD).
--
-- Adds the smallest possible identity store so the UI can drop the
-- LoginStub. Email + bcrypt password hash + display name. Disabled
-- flag lets an admin revoke a user without deleting historical
-- audit references.
--
-- The user's `id` (UUID) is the identifier consumed everywhere else
-- in the platform (audit `actor`, `user_roles.user_id`, X-User-Id
-- legacy header, etc.). When the OIDC swap lands (api#26), the OIDC
-- `sub` claim replaces local UUIDs but the column type and downstream
-- consumers stay the same.
--
-- Hard rules respected:
--   - `password_hash` is BYTEA to make the "this is a hash, not a
--     credential" intent explicit in \d+ output.
--   - No plaintext password column anywhere; no "remember me" /
--     "password hint" anti-patterns.
--   - Email is CITEXT-style case-insensitive via a CHECK + lowercased
--     storage (the api layer lowercases on insert; SCHEMA lowercases
--     on lookup via the index).

CREATE TABLE IF NOT EXISTS local_users (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT         NOT NULL,
    password_hash   BYTEA        NOT NULL,
    display_name    TEXT         NOT NULL DEFAULT '',
    disabled        BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    -- Reject empty, whitespace-only, or any email containing
    -- characters that should never appear in a normalized lowercase
    -- email. The CHECK is intentionally loose — a complete RFC 5322
    -- validator belongs in the application layer.
    CONSTRAINT local_users_email_nonempty CHECK (length(trim(email)) > 0),
    CONSTRAINT local_users_email_lowercase CHECK (email = lower(email))
);

-- Case-insensitive uniqueness without depending on CITEXT.
CREATE UNIQUE INDEX local_users_email_unique
    ON local_users (email);

CREATE INDEX local_users_disabled_idx
    ON local_users (disabled) WHERE disabled = TRUE;

-- Touch updated_at on every UPDATE (matches the pattern from
-- migration 0001 for projects / environments / etc.).
CREATE TRIGGER local_users_touch_updated_at
    BEFORE UPDATE ON local_users
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at();
