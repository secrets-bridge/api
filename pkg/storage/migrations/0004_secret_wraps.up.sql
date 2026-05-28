-- 0004 — KMS-encrypted secret value wraps.
--
-- This is the table that lets a developer submit a new secret value
-- (during an "update key" or "add key" request) without the plaintext
-- ever landing in the Postgres user tables. The plaintext is encrypted
-- in CP API process memory using a per-row AES-256 data key; the data
-- key is itself encrypted (wrapped) by the operator's KMS master key.
-- Only the encrypted forms land on disk.
--
-- A wrap is single-shot: when an agent retrieves it, consumed_at and
-- consumed_by_agent are set and no future retrieval is allowed. The
-- row is kept (not deleted) for audit retention — the encrypted blob
-- is no security risk once its data key has been used and the
-- consuming agent has the plaintext.
--
-- request_id is NULLABLE in this migration so wraps can be tested in
-- isolation. The follow-up workflow PR adds the NOT NULL constraint
-- and enforces "wrap MUST belong to a request" at the service layer.

BEGIN;

CREATE TABLE secret_wraps (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id          UUID REFERENCES access_requests(id) ON DELETE CASCADE,

    -- The encrypted plaintext value (AES-256-GCM).
    encrypted_value     BYTEA NOT NULL,
    -- The 12-byte GCM nonce used to encrypt encrypted_value.
    nonce               BYTEA NOT NULL,
    -- The per-row AES key, encrypted under the KMS master key.
    data_key_ciphertext BYTEA NOT NULL,
    -- Master key identifier — lets the KMS pick the right key during
    -- rotation transitions (when multiple master keys overlap).
    kms_key_id          TEXT NOT NULL,
    -- Algorithm pin. Only AES-256-GCM is currently supported; the
    -- column exists so a future migration can introduce additional
    -- algorithms without code churn.
    algorithm           TEXT NOT NULL DEFAULT 'AES-256-GCM'
                            CHECK (algorithm IN ('AES-256-GCM')),

    -- Non-reversible fingerprint of the PLAINTEXT for diff/dedup and
    -- audit trail. NEVER usable to recover the value.
    content_hash        BYTEA NOT NULL,
    -- Plaintext byte length, for audit telemetry ("a 64-byte secret
    -- was created" without revealing what it is).
    byte_length         INTEGER NOT NULL CHECK (byte_length >= 0),

    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Set by the workflow engine when the wrap is created; reset by
    -- state transitions (request approved → shorter TTL; agent claimed
    -- → even shorter). Background job deletes rows past this point.
    expires_at          TIMESTAMPTZ NOT NULL,

    -- Single-shot retrieval enforcement: both columns set together or
    -- both NULL.
    consumed_at         TIMESTAMPTZ,
    consumed_by_agent   UUID REFERENCES agents(id) ON DELETE SET NULL,

    CONSTRAINT secret_wraps_one_shot CHECK (
        (consumed_at IS NULL AND consumed_by_agent IS NULL) OR
        (consumed_at IS NOT NULL AND consumed_by_agent IS NOT NULL)
    )
);

CREATE INDEX secret_wraps_request_idx
    ON secret_wraps (request_id)
    WHERE request_id IS NOT NULL;

CREATE INDEX secret_wraps_active_idx
    ON secret_wraps (expires_at)
    WHERE consumed_at IS NULL;

COMMIT;
