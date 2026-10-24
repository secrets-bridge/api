-- 0050 down: drops the discovery storage. Discovered targets, the team
-- mapping and the sealed snapshots are deleted, and bindings to
-- discovered targets go with their columns' meaning, so a binding row
-- that pointed at a d- target is deleted (soft) first: after the
-- rollback nothing could dispatch it safely. Tasks closed with the two
-- new verdict reasons are rewritten to binding_removed so the old
-- constraint holds.

BEGIN;

UPDATE gateway_connector_bindings SET deleted_at = COALESCE(deleted_at, now()), enabled = false
WHERE target_source = 'discovered';

UPDATE observation_tasks SET verdict_reason = 'binding_removed'
WHERE verdict_reason IN ('target_missing', 'binding_suspended');

ALTER TABLE observation_tasks DROP CONSTRAINT IF EXISTS observation_tasks_verdict_reason_check;
ALTER TABLE observation_tasks ADD CONSTRAINT observation_tasks_verdict_reason_check CHECK (verdict_reason IN (
    'no_provider_version','volume_refresh_not_observable','subpath_mount_not_refreshed',
    'reload_mechanism_unknown','refresh_interval_exceeds_deadline','failure_observed',
    'no_stage_observed','superseded_by_later_write','source_changed','connector_missing',
    'gateway_errors','gateway_over_privileged','gateway_unavailable','deadline_reached',
    'context_only','binding_removed'));

DROP FUNCTION IF EXISTS team_covers(UUID, UUID);

DROP INDEX IF EXISTS gateway_connector_bindings_argocd_target_idx;
ALTER TABLE gateway_connector_bindings
    DROP CONSTRAINT IF EXISTS gateway_connector_bindings_suspended_stamped,
    DROP COLUMN IF EXISTS suspended_at,
    DROP COLUMN IF EXISTS suspended_reason,
    DROP COLUMN IF EXISTS target_source;

DROP TABLE IF EXISTS gateway_discovery_snapshots;
DROP TABLE IF EXISTS gateway_connector_project_teams;
DROP TABLE IF EXISTS gateway_discovered_targets;

ALTER TABLE gateway_connectors
    DROP CONSTRAINT IF EXISTS gateway_connectors_upload_consistent,
    DROP CONSTRAINT IF EXISTS gateway_connectors_lease_consistent,
    DROP CONSTRAINT IF EXISTS gateway_connectors_generation_order,
    DROP COLUMN IF EXISTS last_upload_response,
    DROP COLUMN IF EXISTS last_upload_sha256,
    DROP COLUMN IF EXISTS last_upload_lease_id,
    DROP COLUMN IF EXISTS discovery_allowed_projects,
    DROP COLUMN IF EXISTS last_discovery_at,
    DROP COLUMN IF EXISTS last_lease_granted_at,
    DROP COLUMN IF EXISTS discovery_lease_expires_at,
    DROP COLUMN IF EXISTS discovery_lease_generation,
    DROP COLUMN IF EXISTS discovery_lease_replica_id,
    DROP COLUMN IF EXISTS discovery_lease_id,
    DROP COLUMN IF EXISTS discovery_generation_granted,
    DROP COLUMN IF EXISTS discovery_generation,
    DROP COLUMN IF EXISTS status_reason,
    DROP COLUMN IF EXISTS approved_scope_digest;

ALTER TABLE gateways DROP COLUMN IF EXISTS discovery_max_entries;

COMMIT;
