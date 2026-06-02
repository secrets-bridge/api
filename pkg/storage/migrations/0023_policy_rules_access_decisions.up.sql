-- 0023_policy_rules_access_decisions
--
-- Slice L2 — moves access decisions onto policy_rules.
--
-- Before this migration, workflow_definitions described BOTH the
-- approval ceremony (min_approvers, wrap TTLs, request TTL, etc.)
-- AND was the only place to attach access-control behaviour. The
-- problem: two projects in the same environment may want the same
-- approval ceremony but different access semantics — one allows
-- non-prod direct reveal, the other requires a request even in
-- non-prod. Forcing those into separate workflows duplicated ceremony
-- config and made the policy table redundant.
--
-- This migration splits the concerns:
--
--   * workflow_definitions = approval CEREMONY (unchanged)
--   * policy_rules         = access DECISION (gains the three columns)
--
-- The three new columns:
--
--   * direct_reveal_allowed — when true AND the matched
--     environment is non_prod, the API may bypass access_requests
--     entirely and issue a single-shot wrap. The PolicyEngine
--     (Slice L2) zeroes this whenever the scope's environment.kind
--     resolves to 'prod', regardless of what the operator wrote —
--     PROD direct-reveal becomes impossible by construction.
--
--   * requires_mfa — when true the API attaches RequireFreshMFA
--     middleware to the matched route. PROD seed defaults true,
--     non_prod defaults false.
--
--   * reveal_ttl_seconds — how long a reveal session (Slice M) or
--     a single-shot wrap stays valid. Capped to 10..300 by CHECK so
--     the API enforces a server-side floor on the strict end and
--     a server-side ceiling matching PRD §15 (120s max for direct
--     reveal in non-prod; PROD reveal capped at the same 120s
--     ceiling because the API also enforces it route-level).
--
-- All three default SAFE — existing rules keep their strictest
-- stance after the migration runs (direct_reveal=false, requires
-- _mfa=false but the reveal flow defaults the env to PROD-style
-- handling, and 60s TTL).

BEGIN;

ALTER TABLE policy_rules
    ADD COLUMN direct_reveal_allowed BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN requires_mfa          BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN reveal_ttl_seconds    SMALLINT NOT NULL DEFAULT 60
        CHECK (reveal_ttl_seconds BETWEEN 10 AND 300);

COMMIT;
