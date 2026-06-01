BEGIN;

DROP INDEX IF EXISTS user_mfa_factors_webauthn_credential_id_uniq;
DROP INDEX IF EXISTS user_mfa_factors_user_id_idx;
DROP TABLE IF EXISTS user_mfa_factors;

COMMIT;
