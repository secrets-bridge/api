-- 0005 — Dynamic workflow + policy engine.
--
-- Everything an operator might want to tune (roles, who approves what,
-- TTLs, separation-of-duties) is now ROWS, not constants. Admin UI
-- (Piece 5) edits these tables; PolicyEngine (this PR) resolves the
-- right workflow for a given request scope at runtime.
--
-- Tables:
--   roles                  — admin-defined permission bundles
--   user_roles             — RBAC assignments with optional scope narrowing
--   workflow_definitions   — approval templates (TTLs, # of approvers, …)
--   policy_rules           — selector → workflow mapping with priority
--
-- A small set of system rows is seeded at the bottom so the platform
-- starts in a usable state: one admin role, one default "standard"
-- workflow, one match-all policy pointing at the default workflow.
-- is_system rows can be edited but not deleted (enforced at the
-- service layer, not the schema, so super-admins still have an out).

BEGIN;

-- ---------------------------------------------------------------
-- roles — permission bundles
-- ---------------------------------------------------------------
CREATE TABLE roles (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT NOT NULL UNIQUE,
    description  TEXT NOT NULL DEFAULT '',
    -- Array of action strings, e.g. ["secret.request","secret.approve"].
    -- Wildcards may be supported later; today exact-match only.
    permissions  JSONB NOT NULL DEFAULT '[]',
    is_system    BOOLEAN NOT NULL DEFAULT false,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TRIGGER roles_touch_updated_at
    BEFORE UPDATE ON roles
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- ---------------------------------------------------------------
-- user_roles — assignments with optional scope narrowing
-- ---------------------------------------------------------------
CREATE TABLE user_roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     TEXT NOT NULL,
    role_id     UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    -- Empty {} = global grant. Narrow with project_id, environment, etc.
    scope       JSONB NOT NULL DEFAULT '{}',
    granted_by  TEXT,
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX user_roles_user_idx ON user_roles (user_id);
CREATE INDEX user_roles_role_idx ON user_roles (role_id);

-- ---------------------------------------------------------------
-- workflow_definitions — admin-defined approval templates
-- ---------------------------------------------------------------
CREATE TABLE workflow_definitions (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                     TEXT NOT NULL UNIQUE,
    description              TEXT NOT NULL DEFAULT '',
    -- 0 = auto-approve. 1 = single approver. ≥2 = multi-stage.
    min_approvers            INTEGER NOT NULL DEFAULT 1
                                 CHECK (min_approvers >= 0),
    -- Which role's members can approve this workflow's requests.
    -- NULL means "any user with the secret.approve permission".
    approver_role_id         UUID REFERENCES roles(id) ON DELETE SET NULL,
    -- TTLs for the secret_wraps lifecycle. WrapService.Refresh() is
    -- called with the relevant value on each state transition.
    wrap_ttl_created         INTERVAL NOT NULL DEFAULT '7 days',
    wrap_ttl_approved        INTERVAL NOT NULL DEFAULT '1 hour',
    wrap_ttl_claimed         INTERVAL NOT NULL DEFAULT '5 minutes',
    -- How long the whole request lives in the queue before it
    -- auto-expires (no approval action).
    request_ttl              INTERVAL NOT NULL DEFAULT '14 days',
    require_justification    BOOLEAN  NOT NULL DEFAULT true,
    -- Separation of duties: requester ≠ approver. Off only for
    -- low-risk workflows (dev environments, etc.).
    allow_self_approval      BOOLEAN  NOT NULL DEFAULT false,
    -- e.g. ["slack:#sec-approvals","email:approvers@..."]
    notification_channels    JSONB    NOT NULL DEFAULT '[]',
    -- Exactly one workflow can carry is_default = true. Used when
    -- no policy_rule matches a request's scope.
    is_default               BOOLEAN  NOT NULL DEFAULT false,
    enabled                  BOOLEAN  NOT NULL DEFAULT true,
    is_system                BOOLEAN  NOT NULL DEFAULT false,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Partial unique index: only one row can be the default.
CREATE UNIQUE INDEX workflow_definitions_one_default
    ON workflow_definitions ((is_default))
    WHERE is_default = true;

CREATE TRIGGER workflow_definitions_touch_updated_at
    BEFORE UPDATE ON workflow_definitions
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- ---------------------------------------------------------------
-- policy_rules — selector → workflow mapping with priority
-- ---------------------------------------------------------------
CREATE TABLE policy_rules (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name          TEXT NOT NULL,
    -- JSON object whose keys are scope dimensions:
    --   {"project_id": "...", "environment": "prod",
    --    "provider_type": "vault", "secret_ref_prefix": "myapp/"}
    -- Every present key must match the incoming request for the rule
    -- to apply. Absent keys are wildcards.
    selector      JSONB NOT NULL DEFAULT '{}',
    workflow_id   UUID NOT NULL REFERENCES workflow_definitions(id) ON DELETE CASCADE,
    -- Higher priority wins. The system seed rule uses priority 0 so
    -- any operator-added rule (priority 100+) takes precedence.
    priority      INTEGER NOT NULL DEFAULT 100,
    enabled       BOOLEAN NOT NULL DEFAULT true,
    is_system     BOOLEAN NOT NULL DEFAULT false,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX policy_rules_resolution_idx
    ON policy_rules (priority DESC, created_at ASC)
    WHERE enabled = true;

CREATE TRIGGER policy_rules_touch_updated_at
    BEFORE UPDATE ON policy_rules
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- ---------------------------------------------------------------
-- System seed rows
-- ---------------------------------------------------------------
INSERT INTO roles (name, description, permissions, is_system) VALUES
    ('admin', 'Platform administrators',
     '["role.edit","user_role.edit","workflow.edit","policy.edit","agent.mint","agent.revoke","secret.request","secret.approve","audit.read"]'::jsonb,
     true),
    ('approver', 'Can approve or reject secret update requests',
     '["secret.approve","audit.read"]'::jsonb,
     true),
    ('developer', 'Can submit secret update requests',
     '["secret.request","audit.read"]'::jsonb,
     true);

INSERT INTO workflow_definitions
    (name, description, min_approvers, approver_role_id,
     wrap_ttl_created, wrap_ttl_approved, wrap_ttl_claimed,
     request_ttl, require_justification, allow_self_approval,
     notification_channels, is_default, is_system)
SELECT
    'standard',
    'Default workflow — single approver, 7-day wrap, 1h post-approval.',
    1,
    (SELECT id FROM roles WHERE name = 'approver'),
    '7 days'::interval, '1 hour'::interval, '5 minutes'::interval,
    '14 days'::interval, true, false,
    '[]'::jsonb, true, true;

INSERT INTO policy_rules
    (name, selector, workflow_id, priority, is_system)
SELECT
    'match-all (system default)',
    '{}'::jsonb,
    (SELECT id FROM workflow_definitions WHERE name = 'standard'),
    0,  -- lowest priority; operator rules at 100+ take precedence
    true;

COMMIT;
