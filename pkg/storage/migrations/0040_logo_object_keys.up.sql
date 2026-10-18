-- 0040: move logo images to object storage (secrets-bridge/api#253).
--
-- Postgres keeps logo metadata only; the image itself lives in
-- S3-compatible object storage under object_key
-- (<prefix>/logos/<kind>/<entity-id>/<sha256>.png).
--
-- Step one of a two-step change, so a rolling deploy keeps working:
--   * object_key: new, nullable. Set by every new upload and by the
--     one-time backfill the api runs at start.
--   * byte_length: new, nullable. The stored PNG's size, so the audit
--     on delete can report it without reading the object.
--   * png: kept for now but made nullable. New uploads write NULL; the
--     backfill copies existing bytes to the object store, sets
--     object_key and byte_length, then sets png to NULL.
-- A later migration drops png once every deployment has run the
-- backfill (no row with png IS NOT NULL left).
--
-- The CHECK makes sure a row always has an image somewhere. While png
-- is set it wins: a replica still on the old version may have written
-- it after the row was moved.

BEGIN;

ALTER TABLE project_logos
    ADD COLUMN object_key  TEXT,
    ADD COLUMN byte_length INT CHECK (byte_length IS NULL OR byte_length BETWEEN 1 AND 65536),
    ALTER COLUMN png DROP NOT NULL,
    ADD CONSTRAINT project_logos_image_present CHECK (png IS NOT NULL OR object_key IS NOT NULL);

ALTER TABLE team_logos
    ADD COLUMN object_key  TEXT,
    ADD COLUMN byte_length INT CHECK (byte_length IS NULL OR byte_length BETWEEN 1 AND 65536),
    ALTER COLUMN png DROP NOT NULL,
    ADD CONSTRAINT team_logos_image_present CHECK (png IS NOT NULL OR object_key IS NOT NULL);

COMMIT;
