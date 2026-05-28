BEGIN;

ALTER TABLE agents
    DROP COLUMN IF EXISTS public_key_algorithm,
    DROP COLUMN IF EXISTS public_key;

COMMIT;
