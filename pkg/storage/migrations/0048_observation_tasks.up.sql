-- 0048_observation_tasks
--
-- Gateway observation queue (api#294, gateway control-plane design
-- sections 3.6 to 3.8 and 3.10, ADR 0001 sections 2.1 to 2.5).
--
--   observation_tasks          one row per (request, binding): delivery
--                              state, lease and attempt fence, deadline,
--                              per-stage CP outcomes and the verdict
--   observation_task_attempts  one row per claim; the replay key and
--                              the digest of the accepted result
--   observation_evidence       accepted stage observations, append-only
--                              by trigger (like audit_events)
--   environments.observation_source
--                              which observer handles a request executed
--                              in the environment: the existing control
--                              plane poller (default), the Gateway, or
--                              none
--
-- Nothing here holds a value, a hash of a value, a URL or free text:
-- tasks carry connector and target ids, evidence carries enums, ids,
-- timestamps and the validated, closed-schema stage object.

BEGIN;

ALTER TABLE environments ADD COLUMN observation_source TEXT NOT NULL DEFAULT 'control_plane'
    CHECK (observation_source IN ('control_plane','gateway','none'));

CREATE TABLE observation_tasks (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id             UUID NOT NULL REFERENCES access_requests(id) ON DELETE RESTRICT,
    -- sync_jobs.correlation_id of the job that completed the change.
    correlation_id         UUID NOT NULL,
    job_id                 UUID REFERENCES sync_jobs(id) ON DELETE SET NULL,
    gateway_id             UUID NOT NULL REFERENCES gateways(id) ON DELETE RESTRICT,
    binding_id             UUID NOT NULL REFERENCES gateway_connector_bindings(id) ON DELETE RESTRICT,
    -- The binding's environment, copied so the evidence check and the
    -- source switch never depend on a later binding edit.
    environment_id         UUID NOT NULL REFERENCES environments(id) ON DELETE RESTRICT,
    -- Snapshot from the binding at creation: [{connector_id, target_id,
    -- stage}] with the connector name as connector_id, as on the wire.
    connector_refs         JSONB NOT NULL CHECK (jsonb_typeof(connector_refs) = 'array'),
    expected_stages        JSONB NOT NULL CHECK (jsonb_typeof(expected_stages) = 'array'),
    provider_type          TEXT NOT NULL CHECK (provider_type IN ('aws-sm','vault')),
    -- secrets.id, or provider_connection_id:secret_ref.
    secret_scope_key       TEXT NOT NULL,
    secret_ref             TEXT NOT NULL CHECK (length(secret_ref) BETWEEN 1 AND 512 AND secret_ref !~ '://'),
    provider_connection_id UUID,
    -- Change marker. Never a value or a hash of one.
    provider_version_id    TEXT CHECK (provider_version_id IS NULL OR provider_version_id ~ '^[A-Za-z0-9-]{1,64}$'),
    provider_version_at    TIMESTAMPTZ,
    version_source         TEXT NOT NULL CHECK (version_source IN ('agent_reported','none')),
    executed_at            TIMESTAMPTZ NOT NULL,
    schema_version         TEXT NOT NULL DEFAULT 'gateway.observation-task/v1',

    state                  TEXT NOT NULL DEFAULT 'queued'
        CHECK (state IN ('queued','leased','done','dead','cancelled')),
    verdict                TEXT NOT NULL DEFAULT 'pending'
        CHECK (verdict IN ('pending','verified','partially_observed','unverified','timed_out')),
    verdict_reason         TEXT CHECK (verdict_reason IN (
        'no_provider_version','volume_refresh_not_observable','subpath_mount_not_refreshed',
        'reload_mechanism_unknown','refresh_interval_exceeds_deadline','failure_observed',
        'no_stage_observed','superseded_by_later_write','source_changed','connector_missing',
        'gateway_errors','gateway_over_privileged','gateway_unavailable','deadline_reached',
        'context_only','binding_removed')),
    -- Latest CP outcome per stage: {stage: {outcome, observed_at, evidence_id}}.
    stages                 JSONB NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(stages) = 'object'),
    rollout_baseline       JSONB,

    current_attempt_id     UUID,
    attempt_count          INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    -- Gateway-reported error stages and refused attempts only. Lease
    -- expiries and releases never count.
    failure_count          INTEGER NOT NULL DEFAULT 0 CHECK (failure_count >= 0),
    max_failures           INTEGER NOT NULL DEFAULT 5 CHECK (max_failures BETWEEN 1 AND 100),
    leased_replica_id      UUID,
    leased_at              TIMESTAMPTZ,
    lease_expires_at       TIMESTAMPTZ,
    not_before             TIMESTAMPTZ NOT NULL DEFAULT now(),
    deadline_at            TIMESTAMPTZ NOT NULL,
    last_result_at         TIMESTAMPTZ,

    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    terminal_at            TIMESTAMPTZ,
    UNIQUE (request_id, binding_id),
    CONSTRAINT observation_tasks_lease_consistent CHECK (
        (state = 'leased') = (current_attempt_id IS NOT NULL AND lease_expires_at IS NOT NULL)
    ),
    CONSTRAINT observation_tasks_terminal_stamped CHECK (
        (state IN ('done','dead','cancelled')) = (terminal_at IS NOT NULL)
    ),
    CONSTRAINT observation_tasks_verdict_matches_state CHECK (
        (state IN ('queued','leased') AND verdict = 'pending') OR
        (state IN ('done','dead','cancelled') AND verdict <> 'pending')
    )
);
-- The only claim index. No time function in the predicate (Postgres
-- refuses now() there); lease and not_before are checked in the query.
CREATE INDEX observation_tasks_claim_idx
    ON observation_tasks (gateway_id, not_before, created_at)
    WHERE state IN ('queued','leased');
CREATE INDEX observation_tasks_lease_idx      ON observation_tasks (lease_expires_at) WHERE state = 'leased';
CREATE INDEX observation_tasks_deadline_idx   ON observation_tasks (deadline_at) WHERE state IN ('queued','leased');
CREATE INDEX observation_tasks_request_idx    ON observation_tasks (request_id);
CREATE INDEX observation_tasks_open_scope_idx ON observation_tasks (secret_scope_key) WHERE state IN ('queued','leased');
CREATE INDEX observation_tasks_open_env_idx   ON observation_tasks (environment_id) WHERE state IN ('queued','leased');
CREATE INDEX observation_tasks_binding_idx    ON observation_tasks (binding_id) WHERE state IN ('queued','leased');
CREATE INDEX observation_tasks_gateway_idx    ON observation_tasks (gateway_id, created_at DESC);
CREATE TRIGGER observation_tasks_touch_updated_at BEFORE UPDATE ON observation_tasks
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

CREATE TABLE observation_task_attempts (
    attempt_id        UUID PRIMARY KEY,
    task_id           UUID NOT NULL REFERENCES observation_tasks(id) ON DELETE RESTRICT,
    attempt_count     INTEGER NOT NULL CHECK (attempt_count >= 1),
    gateway_id        UUID NOT NULL REFERENCES gateways(id) ON DELETE RESTRICT,
    replica_id        UUID NOT NULL,
    claimed_at        TIMESTAMPTZ NOT NULL,
    lease_expires_at  TIMESTAMPTZ NOT NULL,
    ended_at          TIMESTAMPTZ,
    outcome           TEXT CHECK (outcome IN ('result_accepted','result_rejected','lease_expired','released','deadline','cancelled')),
    release_reason    TEXT CHECK (release_reason IN ('shutdown','over_capacity','connector_unavailable')),
    -- SHA-256 of the RFC 8785 canonical JSON of the accepted body, and
    -- the response returned for it (replayed on a duplicate).
    result_sha256     BYTEA CHECK (result_sha256 IS NULL OR length(result_sha256) = 32),
    result_response   JSONB,
    UNIQUE (task_id, attempt_count),
    CONSTRAINT observation_task_attempts_accepted_digest CHECK (
        (outcome = 'result_accepted') = (result_sha256 IS NOT NULL AND result_response IS NOT NULL)
    ),
    CONSTRAINT observation_task_attempts_ended CHECK ((outcome IS NULL) = (ended_at IS NULL))
);

CREATE OR REPLACE FUNCTION observation_evidence_reject_mutations()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'observation_evidence is append-only: %, %', TG_OP, OLD.id;
END;
$$;

CREATE TABLE observation_evidence (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id            UUID NOT NULL REFERENCES observation_tasks(id) ON DELETE RESTRICT,
    attempt_id         UUID NOT NULL REFERENCES observation_task_attempts(attempt_id) ON DELETE RESTRICT,
    gateway_id         UUID NOT NULL REFERENCES gateways(id) ON DELETE RESTRICT,
    replica_id         UUID NOT NULL,
    gateway_version    TEXT NOT NULL,
    schema_version     TEXT NOT NULL,
    stage              TEXT NOT NULL CHECK (stage IN ('eso_sync','workload_rollout','argocd_context')),
    connector_id       UUID NOT NULL REFERENCES gateway_connectors(id) ON DELETE RESTRICT,
    reported_outcome   TEXT NOT NULL CHECK (reported_outcome IN ('observed','not_observed','not_applicable','unverifiable','failed','error')),
    cp_outcome         TEXT NOT NULL CHECK (cp_outcome       IN ('observed','not_observed','not_applicable','unverifiable','failed','error')),
    linkage            TEXT NOT NULL CHECK (linkage IN ('version_pinned','time_ordered','none')),
    -- Caveats the CP added (for example clock_skew_suspected), enums.
    cp_caveats         JSONB NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(cp_caveats) = 'array'),
    observed_at        TIMESTAMPTZ NOT NULL,
    received_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- The validated stage object (closed schema: ids, enums, timestamps).
    body               JSONB NOT NULL CHECK (jsonb_typeof(body) = 'object'),
    -- SHA-256 of the canonical JSON of the whole EvidenceResult body.
    body_sha256        BYTEA NOT NULL CHECK (length(body_sha256) = 32),
    UNIQUE (task_id, attempt_id, stage)
);
CREATE INDEX observation_evidence_task_idx ON observation_evidence (task_id, received_at);
CREATE TRIGGER observation_evidence_no_update BEFORE UPDATE ON observation_evidence
    FOR EACH ROW EXECUTE FUNCTION observation_evidence_reject_mutations();
CREATE TRIGGER observation_evidence_no_delete BEFORE DELETE ON observation_evidence
    FOR EACH ROW EXECUTE FUNCTION observation_evidence_reject_mutations();

COMMIT;
