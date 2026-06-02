-- 0025_backfill_env_ids
--
-- Slice L3 — idempotent backfill of `environment_id` columns
-- introduced by 0024. Runs against existing data:
--
--   * access_requests.environment_id  ← target_scope->>'environment'
--     + project_id lookup in environments
--   * secret_wraps.environment_id     ← parent access_request's env_id
--   * project_secrets.environment_id  ← project_id + secrets.labels.Env
--     (the label-bridge migration helper)
--
-- The matching is CASE-INSENSITIVE on the environment name so a
-- legacy "UAT" label maps to a new "uat" row cleanly. Operators
-- can correct any mis-bindings via the L1 admin endpoints + a
-- future Slice L UI tool.
--
-- Idempotent: every UPDATE filters on `environment_id IS NULL`, so
-- re-running the migration produces identical state.
--
-- Rows that can't resolve a binding (env doesn't exist for the
-- project, target_scope has no environment, secret has no Env
-- label) stay NULL. The operator sees them in the admin UI and
-- fixes via the dev page in Slice L4.
--
-- Authorisation in the Slice L4 hot path uses `environment_id`
-- directly — labels are NOT consulted for security decisions
-- post-backfill. The label bridge here is a migration-time helper
-- only.

BEGIN;

-- ---- access_requests ----------------------------------------------

UPDATE access_requests ar
SET environment_id = e.id
FROM environments e
WHERE ar.environment_id IS NULL
  AND ar.target_scope ? 'environment'
  AND ar.target_scope ? 'project_id'
  AND e.project_id::text = ar.target_scope->>'project_id'
  AND lower(e.name) = lower(ar.target_scope->>'environment');

-- ---- secret_wraps -------------------------------------------------

UPDATE secret_wraps sw
SET environment_id = ar.environment_id
FROM access_requests ar
WHERE sw.environment_id IS NULL
  AND sw.request_id = ar.id
  AND ar.environment_id IS NOT NULL;

-- ---- project_secrets ---------------------------------------------
-- The label-bridge: secrets.labels.Env (operator-controlled tag from
-- discovery) matches environments.name within the same project.
-- Where a single (project, secret) row could plausibly bind to N
-- envs, we leave it NULL — ambiguous bindings should be resolved by
-- operator intent, not a guess from the migration.

UPDATE project_secrets ps
SET environment_id = matched.env_id
FROM (
    SELECT ps.project_id, ps.secret_id, e.id AS env_id
    FROM project_secrets ps
    JOIN secrets s ON s.id = ps.secret_id
    JOIN environments e ON e.project_id = ps.project_id
    WHERE ps.environment_id IS NULL
      AND s.labels ? 'Env'
      AND lower(s.labels->>'Env') = lower(e.name)
    GROUP BY ps.project_id, ps.secret_id, e.id
    HAVING count(*) = 1
) matched
WHERE ps.project_id = matched.project_id
  AND ps.secret_id  = matched.secret_id
  AND ps.environment_id IS NULL;

COMMIT;
