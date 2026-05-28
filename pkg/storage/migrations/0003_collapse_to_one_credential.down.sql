BEGIN;

ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_status_check;
ALTER TABLE agents ADD CONSTRAINT agents_status_check
    CHECK (status IN ('pending', 'active', 'stale', 'revoked'));

ALTER TABLE agents ALTER COLUMN status SET DEFAULT 'pending';
ALTER TABLE agents ALTER COLUMN secret_hash DROP NOT NULL;
ALTER TABLE agents ADD COLUMN registration_token_hash BYTEA;

COMMIT;
