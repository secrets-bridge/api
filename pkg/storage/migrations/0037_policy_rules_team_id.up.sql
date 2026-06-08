-- R-follow-up #3 (api#114) — team-anchored policy rules.
--
-- Adds `team_id` as a third anchor alongside `project_id`. A rule
-- attaches to exactly one of {platform, project, team}; the
-- mutually-exclusive constraint enforces this at the schema level.
--
-- Team rules cascade down to every descendant project of the team
-- subtree. Resolution semantics live in the service layer + the
-- repo's recursive-CTE query (extended in this same slice). Per the
-- §1 D3 lock the cascade is subtree-down only.
--
-- Default-NULL on existing rows = platform-owned OR project-owned
-- (preserving 0033 semantics byte-for-byte). Migration is purely
-- additive; zero behavior change until a team rule is created.
--
-- Selector restrictions for team rules (§1 C1):
--   - selector.project_id        MUST be absent
--   - selector.environment_id    MUST be absent
--   - selector.team_id           MUST be absent (v1 lock)
--   - selector.environment_kind  MUST equal "non_prod"
--
-- Rollback note: down migration is SAFE before any team-scoped rule
-- exists. After team-scoped rules exist, the down migration drops
-- both the column AND the rules — DESTRUCTIVE. Production rollback
-- after data creation requires explicit operator approval,
-- backup/export of team-scoped policy rows, and a written rollback
-- plan. Audit history is NOT a substitute for policy data recovery.

ALTER TABLE policy_rules
    ADD COLUMN team_id UUID NULL REFERENCES teams(id) ON DELETE CASCADE;

CREATE INDEX policy_rules_team_id_idx
    ON policy_rules (team_id)
    WHERE team_id IS NOT NULL;

-- §1 D2 — exactly one anchor at a time. Platform rules have both
-- NULL; project rules have project_id NOT NULL + team_id NULL; team
-- rules have project_id NULL + team_id NOT NULL.
ALTER TABLE policy_rules
    ADD CONSTRAINT policy_rules_one_anchor
    CHECK (NOT (project_id IS NOT NULL AND team_id IS NOT NULL));

-- §1 C1 — team rule's selector cannot pin a single project. A
-- team-scoped rule with selector.project_id collapses into a
-- project-scoped rule, defeating the team-cascade mental model.
ALTER TABLE policy_rules
    ADD CONSTRAINT policy_rules_team_no_project_pin
    CHECK (
        team_id IS NULL
        OR NOT (selector ? 'project_id')
    );

-- §1 C1 — team rule's selector cannot pin a single environment_id.
-- environment_id resolves to one project's env; team rules MUST
-- stay subtree-applicable.
ALTER TABLE policy_rules
    ADD CONSTRAINT policy_rules_team_no_env_id_pin
    CHECK (
        team_id IS NULL
        OR NOT (selector ? 'environment_id')
    );

-- §1 C1 / §3 C1 — team rule's selector cannot pin selector.team_id
-- in v1. The row column `team_id` is the anchor; allowing the
-- selector key creates a second source of truth and selector-vs-
-- resolver-scope ambiguity. If we need selector.team_id semantics
-- later, that's a separate design pass.
ALTER TABLE policy_rules
    ADD CONSTRAINT policy_rules_team_no_team_id_pin
    CHECK (
        team_id IS NULL
        OR NOT (selector ? 'team_id')
    );

-- Selector consistency mirror to 0033's project_id rule: if the
-- selector somehow pins team_id (won't in v1 — the previous CHECK
-- forbids it), it MUST equal the row column. Belt-and-suspenders
-- in case a future migration relaxes the no-pin rule without
-- thinking through the consistency requirement.
ALTER TABLE policy_rules
    ADD CONSTRAINT policy_rules_selector_team_matches_column
    CHECK (
        team_id IS NULL
        OR NOT (selector ? 'team_id')
        OR selector->>'team_id' = team_id::text
    );

-- §1 D8 — team rules MUST carry environment_kind="non_prod" in
-- their selector. Mirrors 0033's scoped_requires_env CHECK but
-- stricter — team rules can't fall back to environment_id (already
-- forbidden by no_env_id_pin) so non_prod is the only path.
ALTER TABLE policy_rules
    ADD CONSTRAINT policy_rules_team_requires_non_prod_env_kind
    CHECK (
        team_id IS NULL
        OR (
            selector ? 'environment_kind'
            AND selector->>'environment_kind' = 'non_prod'
        )
    );
