-- 0021_user_mfa_factors
--
-- App-level MFA factor storage (Slice H1). The architectural pivot
-- away from IdP-`amr`-based MFA (Slice D) means the Control Plane
-- now owns enrollment + step-up directly. Slice H1 only ships the
-- schema + repository; the TOTP / WebAuthn services land in H2 + H3
-- and the `/auth/mfa/{challenge,verify}` endpoints in H4.
--
-- Two factor kinds for v1:
--
--   * `totp`     — RFC 6238. `secret_*` columns hold the 20-byte
--                  shared HMAC-SHA1 secret in envelope-encrypted
--                  form. WebAuthn-specific columns are NULL.
--   * `webauthn` — FIDO2 / WebAuthn. `secret_*` columns hold the
--                  authenticator's public key COSE blob (envelope-
--                  encrypted at rest for defence in depth, even
--                  though public keys are not strictly secret).
--                  `webauthn_credential_id` is the rawId surfaced
--                  during `navigator.credentials.get()` and is
--                  used to look the row up at assertion time.
--                  `webauthn_sign_count` tracks the authenticator's
--                  monotonic counter for clone detection.
--
-- The CHECK constraint pins the allowed kinds at the schema layer
-- so an unknown discriminator can't sneak in via direct INSERT.
-- Future kinds (WebAuthn-platform-only, passkeys, recovery codes)
-- get their own migration.
--
-- Envelope encryption follows the same pattern as `secret_wraps`:
--
--   * `data_key_ciphertext` — KMS-wrapped per-row data key
--   * `kms_key_id`           — resolved master-key identifier
--   * `secret_ciphertext`    — AES-256-GCM ciphertext of the factor
--                              secret (TOTP shared secret or
--                              WebAuthn COSE public key)
--   * `secret_nonce`         — AES-GCM 96-bit nonce
--
-- The services layer (`pkg/services`) is what calls into
-- `pkg/keymgmt` to mint + unwrap data keys; the storage layer is
-- just dumb byte storage.
--
-- WebAuthn integrity:
--
--   * `webauthn_credential_id` is UNIQUE across all rows (partial
--      index — TOTP rows are excluded from the constraint). Reuse
--      would let a stolen authenticator be re-registered under a
--      second account, dodging revocation.
--   * `webauthn_sign_count` is BIGINT, NOT NULL, defaults 0, and
--      the application enforces monotonic increase. Non-increasing
--      assertions are how clone detection surfaces.
--   * `webauthn_aaguid` records which authenticator model produced
--      the credential. Audit-only; no enforcement.
--
-- Per-user label uniqueness keeps the enrollment UI sane — users
-- name their keys ("Yubikey 5", "iPhone 15", "Backup TOTP") and
-- expect distinct labels within their own account, not globally.

BEGIN;

CREATE TABLE user_mfa_factors (
    id                       UUID        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                  UUID        NOT NULL REFERENCES local_users (id) ON DELETE CASCADE,
    kind                     TEXT        NOT NULL,
    label                    TEXT        NOT NULL,

    -- Envelope-encrypted factor secret. NOT NULL even for WebAuthn —
    -- the COSE public key always lives here.
    secret_ciphertext        BYTEA       NOT NULL,
    secret_nonce             BYTEA       NOT NULL,
    data_key_ciphertext      BYTEA       NOT NULL,
    kms_key_id               TEXT        NOT NULL,

    -- WebAuthn-specific (NULL for kind='totp').
    webauthn_credential_id   BYTEA,
    webauthn_sign_count      BIGINT      NOT NULL DEFAULT 0,
    webauthn_aaguid          UUID,

    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at             TIMESTAMPTZ,

    CONSTRAINT user_mfa_factors_kind_chk
        CHECK (kind IN ('totp', 'webauthn')),

    -- TOTP rows MUST NOT carry WebAuthn metadata; WebAuthn rows MUST
    -- carry a credential_id. Belt + braces vs the application layer.
    CONSTRAINT user_mfa_factors_totp_shape_chk
        CHECK (
            kind <> 'totp'
            OR (webauthn_credential_id IS NULL AND webauthn_aaguid IS NULL)
        ),
    CONSTRAINT user_mfa_factors_webauthn_shape_chk
        CHECK (
            kind <> 'webauthn'
            OR webauthn_credential_id IS NOT NULL
        ),

    -- Per-user label uniqueness so the user can tell their factors apart.
    CONSTRAINT user_mfa_factors_user_label_uniq
        UNIQUE (user_id, label)
);

-- "Show me this user's enrolled factors" — the /users/me/mfa list path.
CREATE INDEX user_mfa_factors_user_id_idx
    ON user_mfa_factors (user_id, kind, created_at DESC);

-- WebAuthn assertion lookup: the browser sends rawId, we fetch the row.
-- Partial UNIQUE — only WebAuthn rows participate, so TOTP can keep
-- the column NULL without violating uniqueness.
CREATE UNIQUE INDEX user_mfa_factors_webauthn_credential_id_uniq
    ON user_mfa_factors (webauthn_credential_id)
    WHERE webauthn_credential_id IS NOT NULL;

COMMIT;
