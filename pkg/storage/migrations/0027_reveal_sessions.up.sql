-- 0027_reveal_sessions
--
-- Slice M1 — schema for the time-limited bulk reveal session UX.
--
-- One row represents one open reveal session: the user clicked "Reveal"
-- on a project + env, the server bundled N single-shot wraps into one
-- response, and the SPA is now showing them with a countdown timer.
--
-- Two halves of the lifecycle live here:
--
--   * `opened_at` + `expires_at` + `ttl_seconds` — set at Open time
--     from the matched `policy_rules.reveal_ttl_seconds` (Slice L2).
--     The schema CHECK pins the range to 10..300 (matching the
--     policy_rules CHECK) so a misbehaving service layer cannot
--     write a session that lives longer than the operator allowed.
--
--   * `expired_at` + `expired_reason` — set when the session is torn
--     down. Three reasons:
--       'ttl'        — server-side worker sweeper saw expires_at past;
--                       the canonical timer fired (Slice M3).
--       'user_hide'  — the user clicked Hide Now (SPA → POST expire).
--       'unmount'    — the SPA navigated away mid-session (fire-and-
--                       forget POST).
--     A NULL `expired_at` means the session is still active in the
--     server's view. The partial index `reveal_sessions_active_idx`
--     makes the sweeper's range query a single seek.
--
-- `wrap_ids` is the array of `secret_wraps.id` rows the session
-- issued. Stored as `UUID[]` because we need ARRAY membership (the
-- sweeper iterates the array to advance the wraps' expires_at) and
-- not GIN-style containment search. No FK array is possible in
-- Postgres; the sweeper is responsible for the soft join.
--
-- `access_request_id` is nullable so direct-reveal sessions (Slice L4
-- path) can exist without a parent access_request. Today only request-
-- flow sessions are wired by the service (Slice M2); direct-reveal
-- + reveal-session integration lands once the M4 SPA replaces the
-- single-shot RevealModal.
--
-- HARD RULE: this table never holds secret values. The plaintext lives
-- in the SPA's React refs during the active window, and the wraps'
-- ciphertext lives in `secret_wraps.encrypted_value`. The reveal_sessions
-- row is metadata-only — operator-facing breadcrumb to "this user opened
-- a reveal on this env at this time, holding N keys until expires_at".

BEGIN;

CREATE TABLE reveal_sessions (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           TEXT NOT NULL,
    project_id        UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    environment_id    UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    access_request_id UUID REFERENCES access_requests(id) ON DELETE SET NULL,
    ttl_seconds       SMALLINT NOT NULL CHECK (ttl_seconds BETWEEN 10 AND 300),
    opened_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at        TIMESTAMPTZ NOT NULL,
    expired_at        TIMESTAMPTZ,
    expired_reason    TEXT CHECK (expired_reason IS NULL OR expired_reason IN ('ttl', 'user_hide', 'unmount')),
    wrap_ids          UUID[] NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX reveal_sessions_user_id_idx ON reveal_sessions (user_id);

-- Partial index drives the sweeper's hot path:
--   SELECT id FROM reveal_sessions
--     WHERE expires_at <= now() AND expired_at IS NULL;
-- Active rows only (typically a small slice of total) so the sweeper's
-- 5s tick stays cheap as historical sessions accumulate.
CREATE INDEX reveal_sessions_active_idx
    ON reveal_sessions (expires_at)
    WHERE expired_at IS NULL;

COMMIT;
