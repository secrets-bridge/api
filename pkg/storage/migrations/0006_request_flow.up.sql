-- 0006 — extend access_requests for the patch flow.
--
-- The initial schema (migration 0001) shaped access_requests around
-- the secret_mapping concept (long-lived source↔destination sync
-- mappings). The new UI-driven secret-update flow (Piece 3b) is
-- different: a developer points directly at a provider+ref+keys and
-- the system patches it in place. No mapping needs to exist first.
--
-- Changes:
--   - Make secret_mapping_id NULLABLE so the patch flow doesn't need
--     one. The legacy fields stay reserved for sync-mapping flows.
--   - Add workflow_id (FK workflow_definitions) so the request is
--     pinned to the resolved workflow at submit time. Future policy
--     edits don't change which workflow already-pending requests
--     follow — important for predictability and audit.
--   - Add target_* columns describing where the patch goes
--     (provider type + opaque config + secret ref + key names + scope).
--     Keys are stored as a JSON array of NAMES only — the values live
--     in secret_wraps, one wrap per key.
--   - Add job_id so the approval handler can link the request to the
--     sync_job it created (NULL until approved).
--   - Add reject_reason for the approver's note on rejection.
--   - Add 'patch' to the type CHECK; 'cancelled' to the status CHECK.
--
-- Indexes added for the common list scenarios.

BEGIN;

ALTER TABLE access_requests
    ALTER COLUMN secret_mapping_id DROP NOT NULL;

ALTER TABLE access_requests
    ADD COLUMN workflow_id            UUID REFERENCES workflow_definitions(id),
    ADD COLUMN target_provider_type   TEXT,
    ADD COLUMN target_provider_config JSONB NOT NULL DEFAULT '{}',
    ADD COLUMN target_secret_ref      TEXT,
    ADD COLUMN target_keys            JSONB NOT NULL DEFAULT '[]',
    ADD COLUMN target_scope           JSONB NOT NULL DEFAULT '{}',
    ADD COLUMN job_id                 UUID REFERENCES sync_jobs(id) ON DELETE SET NULL,
    ADD COLUMN reject_reason          TEXT;

-- Replace the type CHECK to include 'patch'.
ALTER TABLE access_requests DROP CONSTRAINT access_requests_type_check;
ALTER TABLE access_requests ADD CONSTRAINT access_requests_type_check
    CHECK (type IN ('read', 'update', 'rotate', 'patch'));

-- Replace the status CHECK to include 'cancelled'.
ALTER TABLE access_requests DROP CONSTRAINT access_requests_status_check;
ALTER TABLE access_requests ADD CONSTRAINT access_requests_status_check
    CHECK (status IN ('pending', 'approved', 'rejected', 'cancelled',
                      'executed', 'failed', 'expired'));

-- Patch requests REQUIRE the workflow_id + target_* fields. The CHECK
-- enforces this at the schema level so a bad service-layer caller
-- can't insert a half-formed patch row.
ALTER TABLE access_requests ADD CONSTRAINT access_requests_patch_fields_present
    CHECK (
        type != 'patch'
        OR (workflow_id IS NOT NULL
            AND target_provider_type IS NOT NULL
            AND target_secret_ref IS NOT NULL)
    );

CREATE INDEX access_requests_status_idx
    ON access_requests (status);
CREATE INDEX access_requests_requester_status_idx
    ON access_requests (requester_id, status);
CREATE INDEX access_requests_workflow_idx
    ON access_requests (workflow_id)
    WHERE workflow_id IS NOT NULL;

-- Enforce one decision per approver per request at the schema level.
-- The service layer also rejects duplicate votes before INSERT, but the
-- index makes the property race-free even when concurrent approvers
-- vote simultaneously.
CREATE UNIQUE INDEX approvals_one_decision_per_approver
    ON approvals (request_id, approver_id);

COMMIT;
