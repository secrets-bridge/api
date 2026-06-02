-- Reverses 0022_environments_kind_classification.

BEGIN;

ALTER TABLE environments
    DROP COLUMN IF EXISTS description,
    DROP COLUMN IF EXISTS risk_level,
    DROP COLUMN IF EXISTS kind;

DROP TYPE IF EXISTS environment_kind;

COMMIT;
