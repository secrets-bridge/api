-- 0026_seed_secret_reveal_direct
--
-- Slice L4 — seeds the new env-agnostic `secret.reveal.direct`
-- permission into the bootstrap `developer` role. The permission is
-- the eligibility flag for the direct-reveal path; the gate ALSO
-- requires:
--
--   * the matched policy_rule has `direct_reveal_allowed=true`
--     (Slice L2), AND
--   * the matched environment has `kind != 'prod'` (Slice L1's
--     hard safety boundary, enforced by the PolicyEngine in L2).
--
-- Without all three, the user is routed through the request flow
-- regardless of the permission. Operators who want to tighten the
-- baseline can strip this perm from the developer role; operators
-- who want to widen can grant it to additional roles via the
-- existing Roles admin endpoint. Neither knob can re-enable PROD
-- direct-reveal — that is impossible by construction.
--
-- The admin role is NOT given this perm by default — operators are
-- expected to use the existing request flow for admin-tier ops.
--
-- Idempotent. The jsonb-set form preserves any operator-added
-- entries on the array.

BEGIN;

UPDATE roles
SET permissions = (
    SELECT to_jsonb(array_agg(DISTINCT v))
    FROM jsonb_array_elements_text(permissions || '["secret.reveal.direct"]'::jsonb) AS v
)
WHERE name = 'developer' AND is_system = true;

COMMIT;
