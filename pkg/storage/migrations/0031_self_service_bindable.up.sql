-- EPIC Q (api#99), Slice Q1 — adds the self-service binding safety flag
-- so platform admins can opt connections into scoped binding without
-- granting every section head global integration.edit. Default-deny:
-- every existing row stays invisible to integration.bind callers until
-- a platform admin flips the flag.
ALTER TABLE provider_connections
    ADD COLUMN self_service_bindable BOOLEAN NOT NULL DEFAULT false;

-- Index supports the binder picker's "active + self_service_bindable"
-- filter on the shared GET ?for_binding=true branch (api#101). Partial
-- to keep it small; only matters for the subset of rows opted-in.
CREATE INDEX idx_provider_connections_self_service_bindable
    ON provider_connections (status)
    WHERE self_service_bindable = true;
