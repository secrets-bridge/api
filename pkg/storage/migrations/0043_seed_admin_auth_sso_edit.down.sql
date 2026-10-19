-- Reverses 0043 by removing the permission from the admin role. Other
-- roles an operator granted it to are left untouched.

BEGIN;

UPDATE roles
SET permissions = (
    SELECT COALESCE(to_jsonb(array_agg(v)), '[]'::jsonb)
    FROM jsonb_array_elements_text(permissions) AS v
    WHERE v <> 'auth.sso.edit'
)
WHERE name = 'admin' AND is_system = true;

COMMIT;
