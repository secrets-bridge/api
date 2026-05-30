-- 0017_seed_admin_team_edit
--
-- Slice 1 of the team-hierarchy work added a `team.edit` permission
-- gating /teams + /teams/:id/members admin endpoints. The seeded
-- `admin` role from 0005 + 0015 doesn't carry it, so on an existing
-- install the admin would hit 403 trying to create the first team.
--
-- Idempotent: rewrites the permissions array in place. Approver +
-- developer don't gain anything — they have no business mutating the
-- team graph.

BEGIN;

UPDATE roles SET permissions = '[
    "role.edit",
    "user_role.edit",
    "team.edit",
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

COMMIT;
