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

COMMIT;
