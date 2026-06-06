DROP INDEX IF EXISTS idx_provider_connections_self_service_bindable;
ALTER TABLE provider_connections DROP COLUMN IF EXISTS self_service_bindable;
