-- 0022_environments_kind_classification
--
-- Slice L1 — first-class environment classification.
--
-- The `environments` table from 0001 carried a free-form `type`
-- column (dev/staging/uat/prod/other) that doubled as both lifecycle
-- label AND implicit risk signal. That conflation is the bug we
-- close here:
--
--   * `type` stays — operator-chosen lifecycle name. Free to evolve
--     with the team's conventions.
--
--   * `kind` is the HARD safety boundary. `non_prod` vs `prod`. The
--     PolicyEngine (Slice L2) zeroes `direct_reveal_allowed=true`
--     whenever a rule resolves against `kind='prod'`, regardless of
--     what the operator wrote. PROD direct-reveal becomes impossible
--     by construction.
--
--   * `risk_level` is the future fine-grain knob (0-4). Today only
--     used for UI badge intensity; future policy DSL can branch on
--     it for cases that don't cleanly split into the non_prod/prod
--     dichotomy.
--
--   * `description` — operator notes; no semantic load.
--
-- The backfill is the only safe automatic mapping: anything labelled
-- `prod` becomes `kind=prod`; everything else lands in `non_prod`.
-- Operators who labelled a true-prod environment with a non-prod
-- `type` (e.g. `type='staging'` but it carries customer data) MUST
-- correct via the new Update endpoint after running the migration.
--
-- `type` is NOT dropped — same pattern as `projects.owner_team_id`
-- kept after 0018 added typed `team_id`. A future migration removes
-- it once external tooling that reads `type` has been audited.

BEGIN;

CREATE TYPE environment_kind AS ENUM ('non_prod', 'prod');

ALTER TABLE environments
    ADD COLUMN kind        environment_kind,
    ADD COLUMN risk_level  SMALLINT CHECK (risk_level BETWEEN 0 AND 4),
    ADD COLUMN description TEXT;

-- Backfill. The single-mapping rule below is the only thing we can
-- derive from existing data; operators verify post-migration.
UPDATE environments
    SET kind = CASE
        WHEN type = 'prod' THEN 'prod'::environment_kind
        ELSE 'non_prod'::environment_kind
    END
    WHERE kind IS NULL;

UPDATE environments
    SET risk_level = CASE WHEN type = 'prod' THEN 4 ELSE 1 END
    WHERE risk_level IS NULL;

-- Lock in NOT NULL after backfill so the column is mandatory for all
-- new inserts. Default on risk_level keeps the API simple for the
-- common case (operator omits → 1 = lowest non-zero).
ALTER TABLE environments
    ALTER COLUMN kind SET NOT NULL,
    ALTER COLUMN risk_level SET NOT NULL,
    ALTER COLUMN risk_level SET DEFAULT 1;

COMMIT;
