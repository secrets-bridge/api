-- 0043_seed_admin_auth_sso_edit
--
-- Seeds `auth.sso.edit` (api#267) into the bootstrap `admin` role, so
-- the first admin can connect Google from the console. It manages the
-- console's sign-in providers and the install's public address, and
-- every write also needs a fresh second factor.
--
-- Idempotent; the jsonb form keeps operator-added entries (same as 0026).

BEGIN;

UPDATE roles
SET permissions = (
    SELECT to_jsonb(array_agg(DISTINCT v))
    FROM jsonb_array_elements_text(permissions || '["auth.sso.edit"]'::jsonb) AS v
)
WHERE name = 'admin' AND is_system = true;

COMMIT;
