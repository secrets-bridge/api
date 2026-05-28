BEGIN;

DROP TRIGGER IF EXISTS policy_rules_touch_updated_at ON policy_rules;
DROP TRIGGER IF EXISTS workflow_definitions_touch_updated_at ON workflow_definitions;
DROP TRIGGER IF EXISTS roles_touch_updated_at ON roles;

DROP INDEX IF EXISTS policy_rules_resolution_idx;
DROP INDEX IF EXISTS workflow_definitions_one_default;
DROP INDEX IF EXISTS user_roles_role_idx;
DROP INDEX IF EXISTS user_roles_user_idx;

DROP TABLE IF EXISTS policy_rules;
DROP TABLE IF EXISTS workflow_definitions;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS roles;

COMMIT;
