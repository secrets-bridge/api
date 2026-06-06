-- Down migration for EPIC Q seed role. Strips any user_roles assignments
-- before removing the role row so the FK doesn't reject the delete.
BEGIN;

DELETE FROM user_roles WHERE role_id IN (
    SELECT id FROM roles WHERE name = 'provider_connection_binder'
);
DELETE FROM roles WHERE name = 'provider_connection_binder';

COMMIT;
