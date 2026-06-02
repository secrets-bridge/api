-- Reverses 0026_seed_secret_reveal_direct by removing the perm from
-- the developer role's array. Other roles that an operator may have
-- granted it to are left untouched.

BEGIN;

UPDATE roles
SET permissions = (
    SELECT COALESCE(to_jsonb(array_agg(v)), '[]'::jsonb)
    FROM jsonb_array_elements_text(permissions) AS v
    WHERE v <> 'secret.reveal.direct'
)
WHERE name = 'developer' AND is_system = true;

COMMIT;
