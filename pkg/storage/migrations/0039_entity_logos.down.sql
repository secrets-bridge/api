-- Down for 0039: drop the logo tables.

BEGIN;

DROP TABLE IF EXISTS team_logos;
DROP TABLE IF EXISTS project_logos;

COMMIT;
