-- 0042_sso_providers
--
-- Sign-in providers configured from the console (api#265, api#267),
-- next to the env-var OIDC provider, which is unchanged.
--
-- sso_providers — one row per provider. Only `google` for now, at most
--   one of each type. The client secret is envelope-encrypted with the
--   configured KMS, like argocd_endpoints.token_* and the TOTP factor
--   secrets: the plaintext is never stored, logged or returned.
--   allowed_domains are the Google Workspace domains (`hd`) that may
--   sign in. A provider starts disabled; enabling it needs a public
--   address, a secret and at least one domain.
--
-- sso_settings — one row. public_url is the install's public address,
--   used to build redirect URIs instead of request headers (SB_PUBLIC_URL
--   overrides it). pending_cap bounds how many accounts may wait for
--   approval at once.

BEGIN;

CREATE TABLE sso_providers (
    id                                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type                              TEXT NOT NULL UNIQUE CHECK (type IN ('google')),
    display_name                      TEXT NOT NULL,
    client_id                         TEXT NOT NULL,
    client_secret_ciphertext          BYTEA,
    client_secret_nonce               BYTEA,
    client_secret_data_key_ciphertext BYTEA,
    client_secret_kms_key_id          TEXT,
    allowed_domains                   TEXT[] NOT NULL CHECK (cardinality(allowed_domains) > 0),
    require_approval                  BOOLEAN NOT NULL DEFAULT TRUE,
    default_role_id                   UUID REFERENCES roles(id) ON DELETE RESTRICT,
    enabled                           BOOLEAN NOT NULL DEFAULT FALSE,
    created_by                        TEXT,
    updated_by                        TEXT,
    created_at                        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                        TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- The secret's four columns are set together or not at all.
    CHECK ((client_secret_ciphertext IS NULL) = (client_secret_nonce IS NULL)
       AND (client_secret_ciphertext IS NULL) = (client_secret_data_key_ciphertext IS NULL)
       AND (client_secret_ciphertext IS NULL) = (client_secret_kms_key_id IS NULL)),
    -- A default role only applies when approval is off.
    CHECK (default_role_id IS NULL OR NOT require_approval)
);

CREATE TABLE sso_settings (
    id          BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    public_url  TEXT,
    pending_cap INTEGER NOT NULL DEFAULT 50 CHECK (pending_cap BETWEEN 1 AND 10000),
    updated_by  TEXT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO sso_settings (id) VALUES (TRUE);

COMMIT;
