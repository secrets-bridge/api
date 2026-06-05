-- 0028_cross_team_request_flow
--
-- Slice N1 — schema for the cross-team integration workflow.
--
-- This migration adds a fifth access_request type ('cross_team') with
-- its own state machine, target / destination scope binding, and
-- workflow snapshot columns that freeze policy semantics at submit
-- time so mid-flight workflow edits never change a request's
-- approval requirements.
--
-- Hard rules baked into the schema:
--   - cross_team-only statuses (pending_values / pending_verification /
--     refused) cannot be applied to other request types.
--   - cross_team requests MUST carry every target + destination FK
--     and the workflow snapshot columns.
--   - target_* / destination_* FKs ON DELETE RESTRICT so audit trails
--     survive team / project / environment / provider_connection
--     deletes — operators must cancel open requests first.
--   - Plaintext is forbidden in every new column. fill_comment +
--     refuse_reason hold operator text only; secret VALUES never reach
--     this layer (they flow through WrapService → secret_wraps).
--
-- See `docs/operations/cross-team-requests.md` (Slice N6) for the
-- operator-facing explanation of every column.

-- New request type
ALTER TABLE access_requests
    DROP CONSTRAINT access_requests_type_check;
ALTER TABLE access_requests
    ADD CONSTRAINT access_requests_type_check
        CHECK (type IN ('read', 'update', 'rotate', 'patch', 'cross_team'));

-- New statuses (3 cross_team-only)
ALTER TABLE access_requests
    DROP CONSTRAINT access_requests_status_check;
ALTER TABLE access_requests
    ADD CONSTRAINT access_requests_status_check
        CHECK (status IN (
            'pending', 'approved', 'rejected', 'cancelled',
            'executed', 'failed', 'expired',
            'pending_values', 'pending_verification', 'refused'
        ));

-- Gate the cross_team-only statuses to type='cross_team'.
-- A patch / read / update / rotate request cannot enter pending_values
-- / pending_verification / refused even by a misbehaving service-layer
-- caller.
ALTER TABLE access_requests
    ADD CONSTRAINT access_requests_cross_team_status_only
        CHECK (
            type = 'cross_team'
            OR status NOT IN ('pending_values', 'pending_verification', 'refused')
        );

-- target_* — who provides the values (Team B's scope)
-- destination_* — where the values land (writes against this provider
-- connection in the source project)
ALTER TABLE access_requests
    ADD COLUMN target_team_id                     UUID REFERENCES teams(id)                ON DELETE RESTRICT,
    ADD COLUMN target_project_id                  UUID REFERENCES projects(id)             ON DELETE RESTRICT,
    ADD COLUMN target_environment_id              UUID REFERENCES environments(id)         ON DELETE RESTRICT,
    ADD COLUMN destination_provider_connection_id UUID REFERENCES provider_connections(id) ON DELETE RESTRICT,
    ADD COLUMN destination_secret_ref             TEXT,
    ADD COLUMN destination_keys                   JSONB;

-- cross_team rows MUST carry the full target + destination chain.
-- Non-cross_team rows MUST leave these columns NULL.
ALTER TABLE access_requests
    ADD CONSTRAINT access_requests_cross_team_targets_required
        CHECK (
            type <> 'cross_team'
            OR (
                target_team_id IS NOT NULL
                AND target_project_id IS NOT NULL
                AND target_environment_id IS NOT NULL
                AND destination_provider_connection_id IS NOT NULL
                AND destination_secret_ref IS NOT NULL
                AND destination_keys IS NOT NULL
            )
        );

-- Fill / refuse breadcrumbs.
--
-- filled_by_user_id is TEXT (not FK to a users table) — matches the
-- existing requester_id / approver_id / consumed_by_user convention so
-- OIDC subjects and local-admin IDs both fit.
--
-- fill_expires_at is stamped at SubmitCrossTeam time from
-- workflow.fill_ttl_seconds — read at fill time, NEVER re-derived
-- from a possibly-edited workflow row.
ALTER TABLE access_requests
    ADD COLUMN refuse_reason     TEXT,
    ADD COLUMN fill_comment      TEXT,
    ADD COLUMN filled_at         TIMESTAMPTZ,
    ADD COLUMN filled_by_user_id TEXT,
    ADD COLUMN fill_expires_at   TIMESTAMPTZ;

-- Workflow snapshot — the columns Verify reads to decide thresholds.
-- These freeze the policy at submit time so admin edits to workflows
-- mid-flight never change a request's approval semantics.
--
-- matched_policy_rule_id is informational + audit-forensic; the actual
-- Verify logic reads the boolean + smallint snapshots.
ALTER TABLE access_requests
    ADD COLUMN matched_policy_rule_id          UUID REFERENCES policy_rules(id) ON DELETE SET NULL,
    ADD COLUMN snap_requires_security_approval BOOLEAN,
    ADD COLUMN snap_min_approvers              SMALLINT;

ALTER TABLE access_requests
    ADD CONSTRAINT access_requests_cross_team_snapshot_required
        CHECK (
            type <> 'cross_team'
            OR (
                snap_requires_security_approval IS NOT NULL
                AND snap_min_approvers IS NOT NULL
            )
        );

-- New workflow knobs.
--
-- fill_ttl_seconds — how long Team B has to fill an open request.
-- Default 24h is the PRD-suggested baseline; operators tune per
-- workflow. Must be positive (the CHECK guards against zero or
-- negative which would make the sweeper kill everything immediately).
--
-- requires_security_approval — when true, cross_team requests under
-- this workflow need a third-party Security vote in addition to the
-- source approval threshold. Default false so existing workflows
-- behave unchanged.
ALTER TABLE workflow_definitions
    ADD COLUMN fill_ttl_seconds INTEGER NOT NULL DEFAULT 86400
        CHECK (fill_ttl_seconds > 0),
    ADD COLUMN requires_security_approval BOOLEAN NOT NULL DEFAULT false;

-- Inbox hot path: Team B's pending fill list, ordered by created_at.
-- Partial index keeps the scan cheap — only a small fraction of
-- access_requests rows are in pending_values at any given moment.
CREATE INDEX access_requests_inbox_idx
    ON access_requests (target_team_id, status)
    WHERE status = 'pending_values';

-- Verification list hot path: Team A's awaiting-verify queue.
CREATE INDEX access_requests_pending_verify_idx
    ON access_requests (requester_id, status)
    WHERE status = 'pending_verification';

-- Sweeper hot path: rows whose fill window has elapsed.
-- The Slice N4 worker sweeper SELECTs over this index every 30s.
CREATE INDEX access_requests_fill_expiry_idx
    ON access_requests (fill_expires_at)
    WHERE status = 'pending_values';
