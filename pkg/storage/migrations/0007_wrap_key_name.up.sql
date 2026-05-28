-- 0007 — add key_name to secret_wraps.
--
-- A patch request carries N keys (e.g. DB_PASSWORD + DB_USER). Piece 3b
-- wrote one wrap per key but stored only the value; the agent retrieving
-- the wraps had no way to know which key each wrap corresponds to.
--
-- Adding key_name closes that gap so the agent can ListByRequest →
-- iterate {wrap_id, key_name} pairs → fetch each value → PutValue
-- under the matching key in the provider's secret bundle.
--
-- Nullable to preserve compatibility with non-patch flows that may wrap
-- a single un-keyed payload in the future.

BEGIN;

ALTER TABLE secret_wraps ADD COLUMN key_name TEXT;

-- Lookup index for "what wraps does this request own, by key name?"
-- which is the dominant access pattern from RequestService + the agent
-- retrieval endpoint.
CREATE INDEX secret_wraps_request_key_idx
    ON secret_wraps (request_id, key_name)
    WHERE request_id IS NOT NULL;

COMMIT;
