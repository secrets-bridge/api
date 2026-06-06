-- Rollback of 0030_provider_connections_admin.
-- Reverse order: drop join-table objects first, then the new
-- provider_connections columns + constraints.

BEGIN;

DROP TRIGGER IF EXISTS project_provider_connections_touch_updated_at
    ON project_provider_connections;

DROP INDEX IF EXISTS project_provider_connections_connection_idx;
DROP INDEX IF EXISTS project_provider_connections_project_env_idx;
DROP INDEX IF EXISTS project_provider_connections_project_idx;
DROP INDEX IF EXISTS project_provider_connections_project_wide_uniq;
DROP INDEX IF EXISTS project_provider_connections_env_specific_uniq;

DROP TABLE IF EXISTS project_provider_connections;

DROP INDEX IF EXISTS provider_connections_discover_enabled_idx;

ALTER TABLE provider_connections
    DROP CONSTRAINT IF EXISTS provider_connections_discover_requires_cluster;

ALTER TABLE provider_connections
    DROP COLUMN IF EXISTS last_discover_finished_at,
    DROP COLUMN IF EXISTS last_discover_started_at,
    DROP COLUMN IF EXISTS last_discover_error,
    DROP COLUMN IF EXISTS last_discover_status,
    DROP COLUMN IF EXISTS last_discover_at,
    DROP COLUMN IF EXISTS discover_interval_seconds,
    DROP COLUMN IF EXISTS discover_enabled,
    DROP COLUMN IF EXISTS description,
    DROP COLUMN IF EXISTS cluster_name;

COMMIT;
