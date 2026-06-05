-- 0029_cross_team_roles
--
-- Slice N2 — seeds two system roles for the cross-team integration
-- workflow (Slice N) into the roles table:
--
--   value_provider     — secret.value.provide
--   security_approver  — secret.security.approve
--
-- Both are is_system=true so operators can edit `permissions[]` (e.g.
-- add a role for combined provider + security duty, though SoD at the
-- service layer still applies) but cannot delete them.
--
-- Hard rules baked into the seed (see the EPIC tracker api#72 +
-- internal/auth/permissions.go):
--   - NOT added to admin / approver / developer by default. Operators
--     explicitly grant per least-privilege.
--   - secret.value.provide is scope-bearing — typical grant carries
--     scope={"team_id": "<uuid>"}; the UI's team-picker enforces a
--     team selection (or an explicit type-to-confirm for global).
--   - secret.security.approve is NOT scope-bearing in v1; the
--     workflow's requires_security_approval boolean is the gate.
--   - Strict separation: security_approver does NOT auto-include
--     secret.approve. A user holding both must be granted both roles
--     explicitly. Even then, SoD at the Verify layer refuses a single
--     actor satisfying BOTH the source and security votes on the same
--     request.
--
-- Idempotent. ON CONFLICT (name) DO NOTHING keeps re-runs safe.

BEGIN;

INSERT INTO roles (name, description, permissions, is_system)
VALUES
    ('value_provider',
     'Allowed to fill or refuse cross-team integration requests scoped to a team. Assign per team via the user_roles.scope team_id field. A grant at global scope (scope IS NULL) covers every team''s inbox.',
     '["secret.value.provide"]'::jsonb,
     true),
    ('security_approver',
     'Required for PROD cross-team requests when the matched workflow has requires_security_approval=true. Strict scope: only carries the security-approve permission; does NOT include normal approve. Operators who want a combined approver must assign BOTH roles explicitly; even then, the same actor cannot satisfy source AND security votes on the same request (separation of duties).',
     '["secret.security.approve"]'::jsonb,
     true)
ON CONFLICT (name) DO NOTHING;

COMMIT;
