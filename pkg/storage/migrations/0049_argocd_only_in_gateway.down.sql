-- 0049 down: the schema only. The purged Argo CD tokens are gone and
-- environments moved to none stay on none: a rollback never turns the
-- control-plane Argo CD path back on (secrets-bridge/gateway#13). The
-- tables come back empty so the 0012 down still applies.

BEGIN;

ALTER TABLE environments DROP CONSTRAINT IF EXISTS environments_observation_source_check;
ALTER TABLE environments ADD CONSTRAINT environments_observation_source_check
    CHECK (observation_source IN ('control_plane', 'gateway', 'none'));
ALTER TABLE environments ALTER COLUMN observation_source SET DEFAULT 'control_plane';

COMMENT ON TABLE gitops_observations IS NULL;

CREATE TABLE IF NOT EXISTS argocd_endpoints (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                     TEXT NOT NULL,
    environment_id           UUID REFERENCES environments(id) ON DELETE SET NULL,
    base_url                 TEXT NOT NULL,
    token_ciphertext         BYTEA NOT NULL,
    token_data_key_ciphertext BYTEA NOT NULL,
    token_nonce              BYTEA NOT NULL,
    token_kms_key_id         TEXT NOT NULL,
    tls_ca_pem               TEXT,
    tls_server_name          TEXT,
    enabled                  BOOLEAN NOT NULL DEFAULT TRUE,
    last_health_at           TIMESTAMPTZ,
    last_health_error        TEXT,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at               TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS argocd_endpoints_name_unique
    ON argocd_endpoints (name) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS argocd_endpoints_environment_idx
    ON argocd_endpoints (environment_id) WHERE deleted_at IS NULL;
DROP TRIGGER IF EXISTS argocd_endpoints_touch_updated_at ON argocd_endpoints;
CREATE TRIGGER argocd_endpoints_touch_updated_at
    BEFORE UPDATE ON argocd_endpoints
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

CREATE TABLE IF NOT EXISTS gitops_app_mappings (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_mapping_id        UUID REFERENCES secret_mappings(id) ON DELETE CASCADE,
    provider_connection_id   UUID REFERENCES provider_connections(id) ON DELETE CASCADE,
    argocd_endpoint_id       UUID NOT NULL REFERENCES argocd_endpoints(id) ON DELETE RESTRICT,
    application_name         TEXT NOT NULL,
    application_namespace    TEXT,
    project_name             TEXT,
    cluster_name             TEXT,
    enabled                  BOOLEAN NOT NULL DEFAULT TRUE,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at               TIMESTAMPTZ,
    CONSTRAINT gitops_app_mappings_one_scope CHECK (
        (secret_mapping_id IS NOT NULL AND provider_connection_id IS NULL) OR
        (secret_mapping_id IS NULL AND provider_connection_id IS NOT NULL)
    )
);
CREATE INDEX IF NOT EXISTS gitops_app_mappings_secret_mapping_idx
    ON gitops_app_mappings (secret_mapping_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS gitops_app_mappings_provider_connection_idx
    ON gitops_app_mappings (provider_connection_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS gitops_app_mappings_endpoint_idx
    ON gitops_app_mappings (argocd_endpoint_id) WHERE deleted_at IS NULL;
DROP TRIGGER IF EXISTS gitops_app_mappings_touch_updated_at ON gitops_app_mappings;
CREATE TRIGGER gitops_app_mappings_touch_updated_at
    BEFORE UPDATE ON gitops_app_mappings
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- History rows point at endpoints that no longer exist, so the key is
-- restored NOT VALID: new rows are checked, old ones are not.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'gitops_observations_argocd_endpoint_id_fkey') THEN
        ALTER TABLE gitops_observations ADD CONSTRAINT gitops_observations_argocd_endpoint_id_fkey
            FOREIGN KEY (argocd_endpoint_id) REFERENCES argocd_endpoints(id) ON DELETE RESTRICT NOT VALID;
    END IF;
END
$$;

COMMIT;
