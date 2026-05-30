-- Reverts the system role permissions to the original 0005 seed.
BEGIN;

UPDATE roles SET permissions = '[
    "role.edit",
    "user_role.edit",
    "workflow.edit",
    "policy.edit",
    "agent.mint",
    "agent.revoke",
    "secret.request",
    "secret.approve",
    "audit.read"
]'::jsonb
WHERE name = 'admin' AND is_system = true;

UPDATE roles SET permissions = '["secret.approve","audit.read"]'::jsonb
WHERE name = 'approver' AND is_system = true;

UPDATE roles SET permissions = '["secret.request","audit.read"]'::jsonb
WHERE name = 'developer' AND is_system = true;

COMMIT;
