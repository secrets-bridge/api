-- 0044_user_identities
--
-- Accounts bound to an external identity by (issuer, subject), never by
-- email (api#265 review point 1, api#267). A Google sign-in finds its
-- account through this table only; an existing account gets a row when
-- its owner connects Google from the account page, with their own
-- session and a fresh second factor.
--
-- One identity per (issuer, subject), and one identity per issuer per
-- account. Deleting the account removes its identities. The env-var
-- OIDC provider still matches by verified email; moving it here is
-- api#268.

BEGIN;

CREATE TABLE user_identities (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES local_users(id) ON DELETE CASCADE,
    provider_type TEXT NOT NULL,
    issuer        TEXT NOT NULL,
    subject       TEXT NOT NULL,
    email_at_link TEXT NOT NULL,
    linked_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (issuer, subject),
    UNIQUE (user_id, issuer)
);

COMMIT;
