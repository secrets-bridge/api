-- Reverses 0024_env_id_columns.

BEGIN;

DROP INDEX IF EXISTS project_secrets_environment_id_idx;
DROP INDEX IF EXISTS secret_wraps_issued_via_idx;
DROP INDEX IF EXISTS secret_wraps_environment_id_idx;
DROP INDEX IF EXISTS access_requests_environment_id_idx;

ALTER TABLE project_secrets DROP COLUMN IF EXISTS environment_id;

ALTER TABLE secret_wraps
    DROP COLUMN IF EXISTS issued_via,
    DROP COLUMN IF EXISTS environment_id;

ALTER TABLE access_requests DROP COLUMN IF EXISTS environment_id;

COMMIT;
