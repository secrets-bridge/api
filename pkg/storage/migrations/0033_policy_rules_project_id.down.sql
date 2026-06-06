ALTER TABLE policy_rules DROP CONSTRAINT IF EXISTS policy_rules_scoped_requires_env;
ALTER TABLE policy_rules DROP CONSTRAINT IF EXISTS policy_rules_selector_project_matches_column;
DROP INDEX IF EXISTS policy_rules_project_id_idx;
ALTER TABLE policy_rules DROP COLUMN IF EXISTS project_id;
