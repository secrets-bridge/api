BEGIN;

DROP TRIGGER IF EXISTS sync_jobs_touch_updated_at             ON sync_jobs;
DROP TRIGGER IF EXISTS access_requests_touch_updated_at       ON access_requests;
DROP TRIGGER IF EXISTS secret_mappings_touch_updated_at       ON secret_mappings;
DROP TRIGGER IF EXISTS agents_touch_updated_at                ON agents;
DROP TRIGGER IF EXISTS provider_connections_touch_updated_at  ON provider_connections;
DROP TRIGGER IF EXISTS environments_touch_updated_at          ON environments;
DROP TRIGGER IF EXISTS projects_touch_updated_at              ON projects;
DROP FUNCTION IF EXISTS touch_updated_at();

DROP TRIGGER IF EXISTS audit_events_no_delete ON audit_events;
DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events;
DROP FUNCTION IF EXISTS audit_events_reject_mutations();

DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS sync_runs;
DROP TABLE IF EXISTS sync_jobs;
DROP TABLE IF EXISTS approvals;
DROP TABLE IF EXISTS access_requests;
DROP TABLE IF EXISTS secret_mappings;
DROP TABLE IF EXISTS agents;
DROP TABLE IF EXISTS provider_connections;
DROP TABLE IF EXISTS environments;
DROP TABLE IF EXISTS projects;

COMMIT;
