-- 0049_argocd_only_in_gateway
--
-- Gateway R1 cutover (secrets-bridge/gateway#13): the Gateway is the
-- only component that talks to Argo CD. The control-plane poller, the
-- Argo CD endpoint and app-mapping routes and pkg/argocd are gone, so:
--
--   argocd_endpoints, gitops_app_mappings
--     dropped. argocd_endpoints held each Argo CD account token as a
--     KMS envelope (token_ciphertext, token_data_key_ciphertext,
--     token_nonce, token_kms_key_id). Nothing reads either table any
--     more. One audit row per endpoint (soft-deleted ones too, their
--     envelope was still stored) records the purge, ids only. Backups
--     taken before this migration still hold the ciphertext until they
--     age out: rotate the Argo CD account token on the Argo CD side.
--
--   gitops_observations
--     kept as read-only history (ADR 0001 section 9 step 5). The foreign
--     key to argocd_endpoints goes with that table; argocd_endpoint_id
--     stays as a bare id. No row is rewritten.
--
--   environments.observation_source
--     control_plane selected the removed poller. Every environment on it
--     moves to none, with one audit row each; the default becomes none
--     and the column refuses control_plane from now on. Observation
--     shows unavailable until an admin moves the environment to gateway.
--
-- Idempotent: a second run finds no table to drop and no environment to
-- move, and writes no audit row.

BEGIN;

DO $$
BEGIN
    IF to_regclass('argocd_endpoints') IS NOT NULL THEN
        INSERT INTO audit_events (actor, action, resource, status, correlation_id, metadata)
        SELECT 'system:migration', 'argocd_endpoint.token_purged', 'argocd_endpoint:' || id::text, 'success',
               gen_random_uuid(),
               jsonb_strip_nulls(jsonb_build_object(
                   'environment_id', environment_id::text,
                   'changed_keys', jsonb_build_array(
                       'token_ciphertext', 'token_data_key_ciphertext', 'token_nonce', 'token_kms_key_id'),
                   'reason', 'gateway_cutover'))
        FROM argocd_endpoints;
    END IF;
END
$$;

ALTER TABLE gitops_observations DROP CONSTRAINT IF EXISTS gitops_observations_argocd_endpoint_id_fkey;
DROP TABLE IF EXISTS gitops_app_mappings;
DROP TABLE IF EXISTS argocd_endpoints;

COMMENT ON TABLE gitops_observations IS
    'History of the removed control-plane Argo CD poller (secrets-bridge/gateway#13). Read-only, context only, never written.';

INSERT INTO audit_events (actor, action, resource, status, correlation_id, metadata)
SELECT 'system:migration', 'environment.observation_source.update', 'environment:' || id::text, 'success',
       gen_random_uuid(),
       jsonb_build_object(
           'environment_id', id::text, 'project_id', project_id::text,
           'observation_source_before', 'control_plane', 'observation_source_after', 'none',
           'reason', 'gateway_cutover')
FROM environments
WHERE observation_source = 'control_plane';

UPDATE environments SET observation_source = 'none' WHERE observation_source = 'control_plane';

ALTER TABLE environments ALTER COLUMN observation_source SET DEFAULT 'none';
ALTER TABLE environments DROP CONSTRAINT IF EXISTS environments_observation_source_check;
ALTER TABLE environments ADD CONSTRAINT environments_observation_source_check
    CHECK (observation_source IN ('gateway', 'none'));

COMMIT;
