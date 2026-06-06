-- EPIC Q (api#99), Slice Q1 — seeds the system role that carries the
-- new integration.bind permission. Operators grant this role scoped to
-- a project_id or team_id (via existing user_roles.scope) so a section
-- head can self-serve binds on their own projects without holding the
-- global integration.edit.
--
-- is_system=true means the row is editable (operators can rename or
-- adjust description) but not deletable. Mirrors the value_provider +
-- security_approver pattern shipped in EPIC N (migration 0029).

BEGIN;

INSERT INTO roles (name, description, permissions, is_system)
VALUES (
    'provider_connection_binder',
    'Bind or unbind self-service-bindable provider connections on projects and environments you cover. Assign scoped to a project_id or team_id via user_roles.scope. The connection must have self_service_bindable=true on the platform admin side; otherwise the bind is refused at the api layer regardless of role grant. Production environments are reserved for global integration.edit users in v1.',
    '["integration.bind"]'::jsonb,
    true
)
ON CONFLICT (name) DO NOTHING;

COMMIT;
