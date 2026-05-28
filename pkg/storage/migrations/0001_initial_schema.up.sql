-- Initial schema for the Secrets Bridge Control Plane.
--
-- This migration creates the ten core entities described in BRD §17.
-- The most important load-bearing invariant is documented in CLAUDE.md
-- and enforced by the schema itself: NO COLUMN ON ANY TABLE HOLDS AN
-- ACTUAL SECRET VALUE. Only references, opaque hashes, version IDs,
-- statuses, and metadata. Secret values stay inside the providers.

BEGIN;

-- ---------------------------------------------------------------
-- projects — top-level grouping by application or business unit.
-- ---------------------------------------------------------------
CREATE TABLE projects (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    owner_team_id   TEXT,
    status          TEXT NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'archived')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------
-- environments — lifecycle boundaries within a project (dev/uat/prod).
-- ---------------------------------------------------------------
CREATE TABLE environments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    type            TEXT NOT NULL
                        CHECK (type IN ('dev', 'staging', 'uat', 'prod', 'other')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, name)
);

-- ---------------------------------------------------------------
-- provider_connections — registered provider boundaries (an AWS account
-- region + role, a Vault address + role, etc.). NO credentials are
-- stored here — auth_method describes HOW the agent authenticates, not
-- the credentials themselves.
-- ---------------------------------------------------------------
CREATE TABLE provider_connections (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    type            TEXT NOT NULL
                        CHECK (type IN ('aws-sm', 'vault', 'gcp-sm', 'azure-kv', 'kubernetes')),
    auth_method     TEXT NOT NULL,
    -- Scope: a JSON blob the connector interprets. Stores things like
    -- {"region": "us-east-1", "roleArn": "arn:aws:iam::123:role/x"}.
    -- NEVER stores access keys, tokens, or any credential material.
    scope           JSONB NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'disabled')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (name)
);

-- ---------------------------------------------------------------
-- agents — registered execution agents (one per target boundary).
-- ---------------------------------------------------------------
CREATE TABLE agents (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                    TEXT NOT NULL UNIQUE,
    -- Scope: an opaque JSON describing where this agent runs and what
    -- it's allowed to act on (e.g. {"cluster": "prod-eu", "providers": ["vault","aws-sm"]}).
    scope                   JSONB NOT NULL DEFAULT '{}',
    status                  TEXT NOT NULL DEFAULT 'pending'
                                CHECK (status IN ('pending', 'active', 'stale', 'revoked')),
    -- Hashed registration token; the plaintext token is returned ONCE
    -- to the admin and never persisted. This column lets us validate a
    -- registration attempt without storing the token itself.
    registration_token_hash BYTEA,
    last_seen_at            TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------
-- secret_mappings — source ↔ destination relationships.
-- secret_ref is provider-specific (a Vault path, an AWS Secrets Manager
-- name, etc.) but is NEVER a value — it's a pointer.
-- ---------------------------------------------------------------
CREATE TABLE secret_mappings (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id                  UUID REFERENCES projects(id) ON DELETE SET NULL,
    environment_id              UUID REFERENCES environments(id) ON DELETE SET NULL,
    source_provider_id          UUID NOT NULL REFERENCES provider_connections(id) ON DELETE CASCADE,
    destination_provider_id     UUID NOT NULL REFERENCES provider_connections(id) ON DELETE CASCADE,
    secret_ref                  TEXT NOT NULL,
    -- Policy: opaque JSON describing direction, conflict strategy,
    -- refresh interval, label filter. Interpreted by the workflow
    -- engine; never contains values.
    policy                      JSONB NOT NULL DEFAULT '{}',
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (source_provider_id, destination_provider_id, secret_ref)
);

-- ---------------------------------------------------------------
-- access_requests — developer-initiated requests (read access or
-- update a secret). Body holds justification + the request shape.
-- New secret VALUES proposed during an update workflow are NOT stored
-- here; they're written directly to the provider after approval via
-- the agent.
-- ---------------------------------------------------------------
CREATE TABLE access_requests (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    requester_id        TEXT NOT NULL,
    secret_mapping_id   UUID NOT NULL REFERENCES secret_mappings(id) ON DELETE CASCADE,
    type                TEXT NOT NULL
                            CHECK (type IN ('read', 'update', 'rotate')),
    justification       TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'approved', 'rejected', 'executed', 'failed', 'expired')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------
-- approvals — per-request decisions. Separation of duties is enforced
-- at the application layer (requester_id ≠ approver_id), not in SQL,
-- so multi-approver workflows can layer on later.
-- ---------------------------------------------------------------
CREATE TABLE approvals (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id      UUID NOT NULL REFERENCES access_requests(id) ON DELETE CASCADE,
    approver_id     TEXT NOT NULL,
    decision        TEXT NOT NULL
                        CHECK (decision IN ('approve', 'reject')),
    comment         TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------
-- sync_jobs — work items dispatched to agents. correlation_id ties
-- a job to the originating request → approval → run → audit chain.
-- ---------------------------------------------------------------
CREATE TABLE sync_jobs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- agent_scope is queried by Agent.Claim() — could be a full agent
    -- ID (point assignment) or a scope expression (e.g. by cluster).
    agent_scope         JSONB NOT NULL DEFAULT '{}',
    job_type            TEXT NOT NULL
                            CHECK (job_type IN ('sync', 'discover', 'verify', 'delete')),
    status              TEXT NOT NULL DEFAULT 'queued'
                            CHECK (status IN ('queued', 'claimed', 'succeeded', 'failed', 'expired')),
    correlation_id      UUID NOT NULL,
    claimed_by          UUID REFERENCES agents(id) ON DELETE SET NULL,
    claim_expires_at    TIMESTAMPTZ,
    request_id          UUID REFERENCES access_requests(id) ON DELETE SET NULL,
    payload             JSONB NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX sync_jobs_queued_idx       ON sync_jobs (status, created_at) WHERE status = 'queued';
CREATE INDEX sync_jobs_correlation_idx  ON sync_jobs (correlation_id);

-- ---------------------------------------------------------------
-- sync_runs — execution history. source/destination_version and
-- content_hash let drift detection compare without reading values.
-- ---------------------------------------------------------------
CREATE TABLE sync_runs (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mapping_id              UUID NOT NULL REFERENCES secret_mappings(id) ON DELETE CASCADE,
    job_id                  UUID REFERENCES sync_jobs(id) ON DELETE SET NULL,
    status                  TEXT NOT NULL
                                CHECK (status IN ('succeeded', 'failed', 'conflict', 'skipped')),
    source_version          TEXT,
    destination_version     TEXT,
    -- content_hash is an opaque hex SHA-256 — never reversible to the
    -- value. Used purely for drift / conflict detection.
    content_hash            TEXT,
    error                   TEXT,
    started_at              TIMESTAMPTZ NOT NULL,
    finished_at             TIMESTAMPTZ
);

CREATE INDEX sync_runs_mapping_started_idx ON sync_runs (mapping_id, started_at DESC);

-- ---------------------------------------------------------------
-- audit_events — append-only activity log. NFR-07 requires
-- immutability where possible; we enforce it with a trigger that
-- rejects UPDATE and DELETE. INSERT-only at the SQL level; the Go
-- repository only exposes Append + Query.
-- ---------------------------------------------------------------
CREATE TABLE audit_events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor               TEXT NOT NULL,
    action              TEXT NOT NULL,
    resource            TEXT NOT NULL,
    status              TEXT NOT NULL
                            CHECK (status IN ('success', 'failure', 'denied')),
    correlation_id      UUID NOT NULL,
    -- metadata is opaque JSON for action-specific context. The
    -- repository layer is responsible for stripping any field that
    -- could leak secret values (CLAUDE.md hard rule §38).
    metadata            JSONB NOT NULL DEFAULT '{}',
    occurred_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX audit_events_correlation_idx ON audit_events (correlation_id);
CREATE INDEX audit_events_actor_time_idx  ON audit_events (actor, occurred_at DESC);
CREATE INDEX audit_events_resource_time_idx ON audit_events (resource, occurred_at DESC);

CREATE OR REPLACE FUNCTION audit_events_reject_mutations()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only: %, %', TG_OP, OLD.id;
END;
$$;

CREATE TRIGGER audit_events_no_update
    BEFORE UPDATE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_reject_mutations();

CREATE TRIGGER audit_events_no_delete
    BEFORE DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_reject_mutations();

-- ---------------------------------------------------------------
-- updated_at triggers for mutable tables.
-- ---------------------------------------------------------------
CREATE OR REPLACE FUNCTION touch_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;

CREATE TRIGGER projects_touch_updated_at              BEFORE UPDATE ON projects             FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER environments_touch_updated_at          BEFORE UPDATE ON environments         FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER provider_connections_touch_updated_at  BEFORE UPDATE ON provider_connections FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER agents_touch_updated_at                BEFORE UPDATE ON agents               FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER secret_mappings_touch_updated_at       BEFORE UPDATE ON secret_mappings      FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER access_requests_touch_updated_at       BEFORE UPDATE ON access_requests      FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER sync_jobs_touch_updated_at             BEFORE UPDATE ON sync_jobs            FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

COMMIT;
