-- R-follow-up #2 (api#121) — admin-configurable platform settings.
-- Lifts the EPIC R Slice R1 hardcode of PlatformReservedPriority=9000
-- into a row in this table so platform admin can edit via the SPA
-- without a redeploy.
--
-- §1 lock — v1 supports ONLY the `platform_reserved_priority` key. The
-- service layer enforces a key whitelist; this table is generic so
-- future admin-configurable knobs slot in as new rows without per-knob
-- migrations.
--
-- HARD RULE — platform_settings must NEVER store secrets, credentials,
-- tokens, or provider auth material. This is a platform-configuration
-- table only. Service-layer + reviewers enforce.

CREATE TABLE platform_settings (
    key         TEXT PRIMARY KEY,
    value       JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- actor id string (matches the existing audit Actor convention).
    -- Nullable so the seed row inserted at migration time can leave it
    -- empty; every subsequent update populates it.
    updated_by  TEXT
);

-- §3 correction 3 — every UPDATE bumps updated_at via trigger so a
-- contributor who forgets to set it explicitly can't leave the row
-- stuck at seed time.
CREATE TRIGGER platform_settings_touch_updated_at
    BEFORE UPDATE ON platform_settings
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at();

-- DB-level guard for the known key per §1 optional safety check. JSONB
-- cast must succeed AND value must be within bounds for the planner to
-- accept the row. Future keys add their own clauses to this CHECK or
-- migrate it to per-key constraints.
ALTER TABLE platform_settings
    ADD CONSTRAINT platform_settings_known_key_bounds
    CHECK (
        key <> 'platform_reserved_priority'
        OR (
            value ? 'value'
            AND jsonb_typeof(value->'value') = 'number'
            AND (value->>'value') ~ '^[0-9]+$'
            AND ((value->>'value')::int BETWEEN 100 AND 1000000)
        )
    );

-- Seed: preserve byte-for-byte EPIC R behaviour on upgrade.
INSERT INTO platform_settings (key, value)
VALUES ('platform_reserved_priority', '{"value": 9000}'::jsonb)
ON CONFLICT (key) DO NOTHING;
