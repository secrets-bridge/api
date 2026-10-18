-- Down for 0040: back to images in Postgres.
--
-- Rows whose image lives only in object storage (png IS NULL) can't be
-- restored from here, so they are removed: the logo disappears and can
-- be uploaded again. Copy the objects back first if that matters.

BEGIN;

DELETE FROM project_logos WHERE png IS NULL;
DELETE FROM team_logos WHERE png IS NULL;

ALTER TABLE project_logos
    DROP CONSTRAINT IF EXISTS project_logos_image_present,
    DROP COLUMN IF EXISTS byte_length,
    DROP COLUMN IF EXISTS object_key,
    ALTER COLUMN png SET NOT NULL;

ALTER TABLE team_logos
    DROP CONSTRAINT IF EXISTS team_logos_image_present,
    DROP COLUMN IF EXISTS byte_length,
    DROP COLUMN IF EXISTS object_key,
    ALTER COLUMN png SET NOT NULL;

COMMIT;
