-- Reverses 0047 by removing the Gateway permissions from the admin role.
-- Other roles an operator granted them to are left untouched.

BEGIN;

UPDATE roles
SET permissions = (
    SELECT COALESCE(to_jsonb(array_agg(v)), '[]'::jsonb)
    FROM jsonb_array_elements_text(permissions) AS v
    WHERE v NOT IN ('gateway.mint','gateway.revoke','gateway.list','gateway.bind')
)
WHERE name = 'admin' AND is_system = true;

COMMIT;
