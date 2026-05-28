BEGIN;

DROP TRIGGER IF EXISTS secrets_touch_updated_at ON secrets;
DROP INDEX IF EXISTS secrets_last_seen_idx;
DROP INDEX IF EXISTS secrets_labels_gin_idx;
DROP INDEX IF EXISTS secrets_cluster_idx;
DROP INDEX IF EXISTS secrets_identity_idx;
DROP TABLE IF EXISTS secrets;

COMMIT;
