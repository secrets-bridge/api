BEGIN;

DROP TABLE IF EXISTS gateway_connector_bindings;
DROP TABLE IF EXISTS gateway_connectors;
DROP TABLE IF EXISTS gateway_replicas;
DROP TABLE IF EXISTS gateway_enrollment_tokens;
DROP TABLE IF EXISTS gateways;

COMMIT;
