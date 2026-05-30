-- 0015_seed_role_permissions_for_catalog
--
-- Slice B of api#43 added a catalog filter on GET /secrets that
-- gates the response on the caller's `secret.list` permission.
-- Slice C added a submit-time gate on POST /requests + /requests/read
-- that gates on `secret.request`. Both already-correct in the
-- original seed for `secret.request`, but the seed never had
-- `secret.list` (the dedicated catalog perm landed later in
-- internal/auth/permissions.go without a matching role update).
--
-- Symptoms on existing UAT installs:
--   - the seeded admin had role.edit / secret.request / etc but no
--     secret.list, so GET /secrets returned 0 rows (the filter
--     restricted to an empty access set)
--   - the seeded approver + developer were missing both secret.list
--     AND agent.list, so they couldn't see what they were asked to
--     approve / request against
--
-- This migration brings every system role up to a sane default for
-- a single-tenant install: admin gets everything, approver gets
-- catalog read + audit read + approve, developer gets catalog read
-- + audit read + submit. Scoped multi-tenant grants (project_id
-- in user_roles.scope) still narrow what each user actually sees.
--
-- Idempotent: the UPDATE rewrites the permissions array in place.

BEGIN;

UPDATE roles SET permissions = '[
    "role.edit",
    "user_role.edit",
    "workflow.edit",
    "policy.edit",
    "integration.edit",
    "agent.mint",
    "agent.revoke",
    "agent.list",
    "secret.list",
    "secret.request",
    "secret.approve",
    "audit.read"
]'::jsonb
WHERE name = 'admin' AND is_system = true;

UPDATE roles SET permissions = '[
    "secret.list",
    "secret.approve",
    "audit.read"
]'::jsonb
WHERE name = 'approver' AND is_system = true;

UPDATE roles SET permissions = '[
    "secret.list",
    "secret.request",
    "audit.read"
]'::jsonb
WHERE name = 'developer' AND is_system = true;

COMMIT;
