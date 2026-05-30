BEGIN;

DROP INDEX IF EXISTS projects_team_id_idx;
ALTER TABLE projects DROP COLUMN IF EXISTS team_id;

COMMIT;
