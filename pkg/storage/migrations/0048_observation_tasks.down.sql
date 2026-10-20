-- 0048_observation_tasks (down)

BEGIN;

DROP TABLE IF EXISTS observation_evidence;
DROP FUNCTION IF EXISTS observation_evidence_reject_mutations();
DROP TABLE IF EXISTS observation_task_attempts;
DROP TABLE IF EXISTS observation_tasks;
ALTER TABLE environments DROP COLUMN IF EXISTS observation_source;

COMMIT;
