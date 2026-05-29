BEGIN;

DROP TRIGGER IF EXISTS gitops_observations_touch_updated_at  ON gitops_observations;
DROP TRIGGER IF EXISTS gitops_app_mappings_touch_updated_at  ON gitops_app_mappings;
DROP TRIGGER IF EXISTS argocd_endpoints_touch_updated_at     ON argocd_endpoints;

DROP TABLE IF EXISTS gitops_observations;
DROP TABLE IF EXISTS gitops_app_mappings;
DROP TABLE IF EXISTS argocd_endpoints;

COMMIT;
