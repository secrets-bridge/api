-- 0012 — GitOps visibility integration (BRD §26).
--
-- Three new tables that close the audit loop AFTER a secret change
-- reaches the provider:
--
--   argocd_endpoints
--     Per-environment ArgoCD endpoint configuration. Stores the URL,
--     a KMS-wrapped token (NEVER plaintext), TLS pinning material,
--     and an enabled flag. Soft-deleted via `deleted_at` so audit
--     history outlasts rotations.
--
--   gitops_app_mappings
--     Binds a Secrets Bridge scope (secret_mapping_id OR
--     provider_connection_id — exactly one set) to one or more
--     ArgoCD applications. The observation worker resolves
--     access_requests → mappings → applications and polls per-app.
--
--   gitops_observations
--     Per-request, per-application row capturing the polling
--     lifecycle and the observed state. polling_state machine:
--       queued       — created right after request.transition(executed)
--       active       — poller is running ticks against this row
--       applied      — workload reached healthy + sync completed
--       applied_unverified — timeout fired before applied
--       failed       — ArgoCD reported a permanent failure
--
--   observed_state jsonb holds the latest snapshot: health, sync
--   status, last sync revision, rollout progress, pod readiness.
--   Never carries raw manifests; only filtered status fields per §26.4.
--
-- All three carry an audit-friendly created_by + updated_at; the
-- existing touch_updated_at() trigger is reused.

BEGIN;

CREATE TABLE argocd_endpoints (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                     TEXT NOT NULL,
    environment_id           UUID REFERENCES environments(id) ON DELETE SET NULL,
    base_url                 TEXT NOT NULL,
    -- Token is stored as a KMS-wrapped envelope (same pattern as
    -- secret_wraps): never PostgreSQL plaintext.
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

CREATE UNIQUE INDEX argocd_endpoints_name_unique
    ON argocd_endpoints (name) WHERE deleted_at IS NULL;

CREATE INDEX argocd_endpoints_environment_idx
    ON argocd_endpoints (environment_id) WHERE deleted_at IS NULL;

CREATE TRIGGER argocd_endpoints_touch_updated_at
    BEFORE UPDATE ON argocd_endpoints
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();


CREATE TABLE gitops_app_mappings (
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

    -- Exactly one of secret_mapping_id or provider_connection_id must
    -- be set. The mapping is to a Secrets Bridge concept; both columns
    -- nullable so either lookup path resolves.
    CONSTRAINT gitops_app_mappings_one_scope CHECK (
        (secret_mapping_id IS NOT NULL AND provider_connection_id IS NULL) OR
        (secret_mapping_id IS NULL AND provider_connection_id IS NOT NULL)
    )
);

CREATE INDEX gitops_app_mappings_secret_mapping_idx
    ON gitops_app_mappings (secret_mapping_id) WHERE deleted_at IS NULL;
CREATE INDEX gitops_app_mappings_provider_connection_idx
    ON gitops_app_mappings (provider_connection_id) WHERE deleted_at IS NULL;
CREATE INDEX gitops_app_mappings_endpoint_idx
    ON gitops_app_mappings (argocd_endpoint_id) WHERE deleted_at IS NULL;

CREATE TRIGGER gitops_app_mappings_touch_updated_at
    BEFORE UPDATE ON gitops_app_mappings
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();


CREATE TABLE gitops_observations (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id               UUID NOT NULL REFERENCES access_requests(id) ON DELETE CASCADE,
    argocd_endpoint_id       UUID NOT NULL REFERENCES argocd_endpoints(id) ON DELETE RESTRICT,
    application_name         TEXT NOT NULL,
    application_namespace    TEXT,
    polling_state            TEXT NOT NULL
        CHECK (polling_state IN ('queued', 'active', 'applied', 'applied_unverified', 'failed')),
    observed_state           JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_polled_at           TIMESTAMPTZ,
    polls_count              INTEGER NOT NULL DEFAULT 0,
    last_error               TEXT,
    timeout_at               TIMESTAMPTZ,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    terminal_at              TIMESTAMPTZ
);

CREATE INDEX gitops_observations_request_idx
    ON gitops_observations (request_id);
CREATE INDEX gitops_observations_active_idx
    ON gitops_observations (polling_state, last_polled_at)
    WHERE polling_state IN ('queued', 'active');
CREATE INDEX gitops_observations_timeout_idx
    ON gitops_observations (timeout_at)
    WHERE polling_state IN ('queued', 'active');

CREATE TRIGGER gitops_observations_touch_updated_at
    BEFORE UPDATE ON gitops_observations
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

COMMIT;
