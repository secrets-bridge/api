-- 0029_cross_team_roles (down)
--
-- Removes the two Slice N seed roles. Safe to run only when no
-- user_roles assignment references them; the role row's FK from
-- user_roles is ON DELETE RESTRICT, so the DELETE will fail loudly
-- if any user still holds the role. Operators must revoke
-- assignments first.

BEGIN;

DELETE FROM roles WHERE name IN ('value_provider', 'security_approver') AND is_system = true;

COMMIT;
