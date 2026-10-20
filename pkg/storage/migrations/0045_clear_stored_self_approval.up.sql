-- 0045_clear_stored_self_approval
--
-- skills#103 / api#288: a requester can never approve their own
-- request, so allow_self_approval is not honoured any more. This clears
-- the stored flag so every row matches the behaviour (backups, exports,
-- the column drop that follows), with one audit row per workflow it
-- changes. Data only: the column stays until a later migration drops
-- it, after a release in which the api no longer reads or writes it.
-- Idempotent: a second run finds no row to change.

BEGIN;

INSERT INTO audit_events (actor, action, resource, status, correlation_id, metadata)
SELECT 'system:migration', 'workflow.update', 'workflow:' || id::text, 'success', gen_random_uuid(),
       jsonb_build_object('workflow_id', id::text, 'changed_keys', jsonb_build_array('allow_self_approval'))
FROM workflow_definitions
WHERE allow_self_approval;

UPDATE workflow_definitions SET allow_self_approval = false WHERE allow_self_approval;

COMMIT;
