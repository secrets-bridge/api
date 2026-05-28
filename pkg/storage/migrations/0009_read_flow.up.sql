-- 0009 — read-flow lifecycle.
--
-- The patch flow (Pieces 3a-4d) handles the write side: user supplies
-- VALUES, request gets approved, agent writes them to the provider.
-- The read flow is symmetric on the other side: user requests to VIEW
-- existing values, request gets approved, agent fetches them via
-- core/providers.GetValue and creates wraps via a new agent-side
-- endpoint. The requester then retrieves the wraps through a
-- user-bound endpoint.
--
-- Schema-level changes needed:
--
--   1. Add 'read' to the sync_jobs.job_type CHECK so the agent-side
--      router can dispatch to a ReadExecutor.
--
--   2. Generalize the access_requests_patch_fields_present CHECK so
--      it applies to BOTH 'patch' and 'read' requests. Both flow
--      types need workflow_id + target_provider_type +
--      target_secret_ref; only the value flow direction differs.
--
--   3. Wraps in the read flow are created BY the agent (not the
--      user), so the existing secret_wraps schema is fine — they
--      already carry request_id + key_name and are single-shot
--      consumable. The new agent-side POST /agents/:id/wraps endpoint
--      reuses WrapService.Wrap under the hood.

BEGIN;

ALTER TABLE sync_jobs DROP CONSTRAINT sync_jobs_job_type_check;
ALTER TABLE sync_jobs ADD CONSTRAINT sync_jobs_job_type_check
    CHECK (job_type IN ('sync', 'discover', 'verify', 'delete', 'patch', 'read'));

-- Rename the constraint to reflect that it now governs both patch
-- and read flows. Drop + re-add with the broader name.
ALTER TABLE access_requests DROP CONSTRAINT access_requests_patch_fields_present;
ALTER TABLE access_requests ADD CONSTRAINT access_requests_target_fields_present
    CHECK (
        type NOT IN ('patch', 'read')
        OR (workflow_id IS NOT NULL
            AND target_provider_type IS NOT NULL
            AND target_secret_ref IS NOT NULL)
    );

-- Extend secret_wraps so a USER can consume a wrap (read flow's
-- user-bound retrieval endpoint). Previously only agents could mark
-- a wrap consumed — the CHECK required consumed_by_agent NOT NULL
-- whenever consumed_at was set. Now the wrap's consumer can be
-- either an agent (patch flow) or a user (read flow).
ALTER TABLE secret_wraps ADD COLUMN consumed_by_user TEXT;

ALTER TABLE secret_wraps DROP CONSTRAINT secret_wraps_one_shot;
ALTER TABLE secret_wraps ADD CONSTRAINT secret_wraps_one_shot
    CHECK (
        (consumed_at IS NULL AND consumed_by_agent IS NULL AND consumed_by_user IS NULL)
        OR (consumed_at IS NOT NULL
            AND ((consumed_by_agent IS NOT NULL) OR (consumed_by_user IS NOT NULL))
            AND NOT (consumed_by_agent IS NOT NULL AND consumed_by_user IS NOT NULL))
    );

COMMIT;
