-- EPIC R (api#108) Slice R1 — scopes policy_rules to a project so
-- section heads can author non-prod policy for their own projects
-- without holding the global policy.edit permission.
--
-- Default-NULL on existing rows = platform-owned. Zero behavior change
-- for the existing PolicyEngine walk; the resolver gets a per-request
-- applicability filter in this same PR.

ALTER TABLE policy_rules
    ADD COLUMN project_id UUID NULL REFERENCES projects(id) ON DELETE CASCADE;

CREATE INDEX policy_rules_project_id_idx
    ON policy_rules (project_id)
    WHERE project_id IS NOT NULL;

-- Selector consistency: if the selector pins a project_id, it MUST
-- equal the row's project_id. Prevents a scoped author from authoring
-- a rule with selector.project_id=X while the row column is Y.
ALTER TABLE policy_rules
    ADD CONSTRAINT policy_rules_selector_project_matches_column
    CHECK (
        project_id IS NULL
        OR NOT (selector ? 'project_id')
        OR selector->>'project_id' = project_id::text
    );

-- Scoped rules MUST carry an environment constraint that resolves to
-- non_prod. The DB catches the cheap cases (env_kind=non_prod direct,
-- OR env_id present); the service layer catches the env_id -> env.kind
-- JOIN cases that a CHECK can't express.
ALTER TABLE policy_rules
    ADD CONSTRAINT policy_rules_scoped_requires_env
    CHECK (
        project_id IS NULL
        OR (
            (selector ? 'environment_kind' AND selector->>'environment_kind' = 'non_prod')
            OR (selector ? 'environment_id')
        )
    );
