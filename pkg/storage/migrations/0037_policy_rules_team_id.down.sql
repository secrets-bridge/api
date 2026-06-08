-- R-follow-up #3 (api#114) down migration.
--
-- DESTRUCTIVE after team-scoped rules exist — drops both the column
-- and every team-scoped rule. Production rollback after data
-- creation requires explicit operator approval + backup/export.

ALTER TABLE policy_rules DROP CONSTRAINT IF EXISTS policy_rules_team_requires_non_prod_env_kind;
ALTER TABLE policy_rules DROP CONSTRAINT IF EXISTS policy_rules_selector_team_matches_column;
ALTER TABLE policy_rules DROP CONSTRAINT IF EXISTS policy_rules_team_no_team_id_pin;
ALTER TABLE policy_rules DROP CONSTRAINT IF EXISTS policy_rules_team_no_env_id_pin;
ALTER TABLE policy_rules DROP CONSTRAINT IF EXISTS policy_rules_team_no_project_pin;
ALTER TABLE policy_rules DROP CONSTRAINT IF EXISTS policy_rules_one_anchor;
DROP INDEX IF EXISTS policy_rules_team_id_idx;
ALTER TABLE policy_rules DROP COLUMN IF EXISTS team_id;
