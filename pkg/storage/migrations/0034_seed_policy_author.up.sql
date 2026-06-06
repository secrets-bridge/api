-- EPIC R (api#108) Slice R1 — seeds the system role that carries the
-- new policy.author permission. Operators grant scoped to a project_id
-- or team_id via user_roles.scope.
--
-- is_system=true means editable but not deletable. Mirrors the
-- provider_connection_binder pattern from EPIC Q (migration 0032).

BEGIN;

INSERT INTO roles (name, description, permissions, is_system)
VALUES (
    'policy_author',
    'Author project-scoped policy rules for non-prod environments. Assign scoped to a project_id or team_id via user_roles.scope. Cannot edit platform global rules; cannot author rules that match production environments; cannot use priority >= 9000 (platform reserved band).',
    '["policy.author"]'::jsonb,
    true
)
ON CONFLICT (name) DO NOTHING;

COMMIT;
