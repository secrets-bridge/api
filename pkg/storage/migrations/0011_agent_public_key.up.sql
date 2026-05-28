-- 0011 — wire-envelope encryption (Piece 8b-1).
--
-- Adds an agent public key column so the CP can SEAL responses to a
-- specific agent rather than send plaintext (base64) over the wire.
-- The agent generates an X25519 keypair locally at first start,
-- registers the public key at mint time, keeps the private key
-- in-memory (or on disk under the same envelope as identity.json).
--
-- For CP→Agent responses (patch flow's GET /agents/:id/wraps/:id):
--   - CP generates an ephemeral X25519 keypair per call
--   - shared = X25519(ephem_priv, agent_pub) → HKDF → AES-256-GCM key
--   - body: { ciphertext, nonce, ephemeral_public_key, algorithm }
--   - agent computes shared = X25519(agent_priv, ephem_pub) and decrypts
--
-- For Agent→CP requests (read flow's POST /agents/:id/wraps):
--   - agent first GETs a DEK from POST /agents/:id/dek (the CP's KMS
--     generates a data key + returns both plaintext and ciphertext_blob)
--   - agent AES-GCM encrypts with the plaintext_dek, throws it away,
--     POSTs ciphertext + nonce + ciphertext_blob to /wraps
--   - CP feeds blob back to KMS to recover the DEK, decrypts, then
--     envelope-encrypts for storage as usual
--
-- This migration only touches the agent-side schema: the public key
-- the CP needs to seal outbound. The DEK path is stateless on the
-- schema (KMS handles it).
--
-- public_key is nullable so existing agents keep working unsealed
-- (backwards compat). New mints with --public-key get sealed
-- responses; old agents fall back to plaintext-over-TLS.

BEGIN;

ALTER TABLE agents
    ADD COLUMN public_key             BYTEA,
    ADD COLUMN public_key_algorithm   TEXT CHECK (public_key_algorithm IN ('x25519'));

COMMIT;
