BEGIN;

DELETE FROM user_roles WHERE role_id IN (
    SELECT id FROM roles WHERE name = 'policy_author'
);
DELETE FROM roles WHERE name = 'policy_author';

COMMIT;
