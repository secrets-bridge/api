-- 0047_seed_gateway_permissions
--
-- Seeds the Gateway permissions (api#293, gateway control-plane design
-- section 9) into the bootstrap `admin` role only:
--
--   gateway.mint    create a Gateway, mint and revoke enrollment tokens
--   gateway.revoke  revoke a Gateway
--   gateway.list    list Gateways, replicas and connectors
--   gateway.bind    approve connectors, create and delete bindings
--
-- Idempotent; the jsonb form keeps operator-added entries (same as 0043).

BEGIN;

UPDATE roles
SET permissions = (
    SELECT to_jsonb(array_agg(DISTINCT v))
    FROM jsonb_array_elements_text(
        permissions || '["gateway.mint","gateway.revoke","gateway.list","gateway.bind"]'::jsonb
    ) AS v
)
WHERE name = 'admin' AND is_system = true;

COMMIT;
