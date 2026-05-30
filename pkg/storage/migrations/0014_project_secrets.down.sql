BEGIN;

DROP TRIGGER IF EXISTS project_secrets_touch_updated_at ON project_secrets;
DROP TABLE IF EXISTS project_secrets;

COMMIT;
