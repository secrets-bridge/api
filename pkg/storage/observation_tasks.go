package storage

// Gateway observation queue (api#294): observation_tasks,
// observation_task_attempts and the append-only observation_evidence,
// plus environments.observation_source. See migration 0048 and the
// gateway control-plane design, sections 3.6 to 3.10, 4.5 to 4.8 and 5.
//
// The queue is the sync_jobs pattern with the three changes the design
// asks for (section 2.1):
//
//   - every claim is scoped to the authenticated Gateway
//     (gateway_id = $1 in the claim predicate, never a body field);
//   - every claim mints a new attempt_id, and renew, release and result
//     are fenced on it plus the lease expiry, not on the caller;
//   - an accepted result stores the digest of its canonical body, so a
//     replay is told apart from a conflicting second body.
//
// Times in the queue predicates use the database clock (now()), so the
// lease, the deadline and not_before are judged on one clock.
//
// Exported for secrets-bridge/worker (lease and deadline sweepers,
// worker#38): the state, verdict and reason constants, ObservationTask
// and its columns, ExpireDeadlines and ExpireLeases.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ObservationTaskState is observation_tasks.state, the delivery
// lifecycle.
type ObservationTaskState string

// Task states.
const (
	ObservationTaskQueued    ObservationTaskState = "queued"
	ObservationTaskLeased    ObservationTaskState = "leased"
	ObservationTaskDone      ObservationTaskState = "done"
	ObservationTaskDead      ObservationTaskState = "dead"
	ObservationTaskCancelled ObservationTaskState = "cancelled"
)

// Open reports whether the task can still be claimed or completed.
func (s ObservationTaskState) Open() bool {
	return s == ObservationTaskQueued || s == ObservationTaskLeased
}

// ObservationVerdict is observation_tasks.verdict: what the evidence
// supports, computed by the control plane only (ADR 0001 section 2.4).
type ObservationVerdict string

// Verdicts. There is no failed verdict.
const (
	ObservationVerdictPending           ObservationVerdict = "pending"
	ObservationVerdictVerified          ObservationVerdict = "verified"
	ObservationVerdictPartiallyObserved ObservationVerdict = "partially_observed"
	ObservationVerdictUnverified        ObservationVerdict = "unverified"
	ObservationVerdictTimedOut          ObservationVerdict = "timed_out"
)

// Verdict reasons (design section 5.4, plus context_only and
// binding_removed).
const (
	ObservationReasonNoProviderVersion      = "no_provider_version"
	ObservationReasonFailureObserved        = "failure_observed"
	ObservationReasonNoStageObserved        = "no_stage_observed"
	ObservationReasonSupersededByLaterWrite = "superseded_by_later_write"
	ObservationReasonSourceChanged          = "source_changed"
	ObservationReasonConnectorMissing       = "connector_missing"
	ObservationReasonGatewayErrors          = "gateway_errors"
	ObservationReasonGatewayOverPrivileged  = "gateway_over_privileged"
	ObservationReasonGatewayUnavailable     = "gateway_unavailable"
	ObservationReasonDeadlineReached        = "deadline_reached"
	// ObservationReasonContextOnly: every expected stage is context
	// (argocd_context in Release 1). Argo CD health and sync were seen,
	// which is operational state and never proof that the secret change
	// propagated, so the verdict stays unverified.
	ObservationReasonContextOnly = "context_only"
	// ObservationReasonBindingRemoved: the admin deleted the binding the
	// task came from while it was open.
	ObservationReasonBindingRemoved = "binding_removed"
)

// ObservationSource is environments.observation_source: which observer
// handles requests executed in the environment (design section 7).
type ObservationSource string

// Observation sources. The Gateway is the only observer; none is the
// default.
const (
	ObservationSourceGateway ObservationSource = "gateway"
	ObservationSourceNone    ObservationSource = "none"
)

// ObservationSourceRetiredControlPlane is the retired control_plane
// source: the control-plane Argo CD poller it selected was removed
// (secrets-bridge/gateway#13). Migration 0049 moved every environment
// off it and the schema refuses it. It is never valid.
const ObservationSourceRetiredControlPlane ObservationSource = "control_plane"

// Valid reports whether s is a stored observation source.
func (s ObservationSource) Valid() bool {
	return s == ObservationSourceGateway || s == ObservationSourceNone
}

// Attempt outcomes (observation_task_attempts.outcome).
const (
	ObservationAttemptResultAccepted = "result_accepted"
	ObservationAttemptLeaseExpired   = "lease_expired"
	ObservationAttemptReleased       = "released"
	ObservationAttemptDeadline       = "deadline"
	ObservationAttemptCancelled      = "cancelled"
)

// Observation queue errors.
var (
	// ErrNoObservationTask: nothing claimable for this Gateway (204).
	ErrNoObservationTask = errors.New("storage: no observation task to claim")
	// ErrObservationAtCapacity: the Gateway or the replica is at its
	// in-flight limit (429).
	ErrObservationAtCapacity = errors.New("storage: gateway at its in-flight task limit")
	// ErrObservationContractUnsupported: the Gateway listed contract
	// versions and none is the one tasks are written in (409).
	ErrObservationContractUnsupported = errors.New("storage: gateway contract version unsupported")
	ErrObservationAttemptSuperseded   = errors.New("storage: observation attempt superseded")
	ErrObservationLeaseExpired        = errors.New("storage: observation lease expired")
	ErrObservationTaskClosed          = errors.New("storage: observation task closed")
	// ErrObservationSourceNotGateway: the environment is no longer
	// observed by a Gateway; no task is created.
	ErrObservationSourceNotGateway = errors.New("storage: environment observation source is not gateway")
)

// ObservationConnectorRef is one {connector_id, target_id, stage} triple
// of a task, connector_id being the connector name as on the wire.
type ObservationConnectorRef struct {
	ConnectorID string `json:"connector_id"`
	TargetID    string `json:"target_id"`
	Stage       string `json:"stage"`
}

// ObservationStageState is the latest CP outcome of one stage.
type ObservationStageState struct {
	Outcome    string    `json:"outcome"`
	ObservedAt time.Time `json:"observed_at"`
	EvidenceID uuid.UUID `json:"evidence_id"`
}

// ObservationTask mirrors an observation_tasks row.
type ObservationTask struct {
	ID                   uuid.UUID
	RequestID            uuid.UUID
	CorrelationID        uuid.UUID
	JobID                *uuid.UUID
	GatewayID            uuid.UUID
	BindingID            uuid.UUID
	EnvironmentID        uuid.UUID
	ConnectorRefs        []ObservationConnectorRef
	ExpectedStages       []string
	ProviderType         string
	SecretScopeKey       string
	SecretRef            string
	ProviderConnectionID *uuid.UUID
	ProviderVersionID    *string
	ProviderVersionAt    *time.Time
	VersionSource        string
	ExecutedAt           time.Time
	SchemaVersion        string
	State                ObservationTaskState
	Verdict              ObservationVerdict
	VerdictReason        string
	Stages               map[string]ObservationStageState
	RolloutBaseline      json.RawMessage
	CurrentAttemptID     *uuid.UUID
	AttemptCount         int
	FailureCount         int
	MaxFailures          int
	LeasedReplicaID      *uuid.UUID
	LeasedAt             *time.Time
	LeaseExpiresAt       *time.Time
	NotBefore            time.Time
	DeadlineAt           time.Time
	LastResultAt         *time.Time
	CreatedAt            time.Time
	UpdatedAt            time.Time
	TerminalAt           *time.Time
	// GatewayName is joined from gateways by the read queries. Not a
	// column.
	GatewayName string
	// GatewayUnavailable is set by ListForRequest with the same rule
	// ExpireDeadlines uses for its reason: the Gateway is not active or
	// has not been seen since the task was created. Not a column.
	GatewayUnavailable bool
}

// ObservationTaskColumns is the column list every task query returns,
// for a table aliased t. Exported so worker sweepers can RETURNING it
// and scan with ScanObservationTask.
const ObservationTaskColumns = `
	t.id, t.request_id, t.correlation_id, t.job_id, t.gateway_id, t.binding_id, t.environment_id,
	t.connector_refs, t.expected_stages, t.provider_type, t.secret_scope_key, t.secret_ref,
	t.provider_connection_id, t.provider_version_id, t.provider_version_at, t.version_source,
	t.executed_at, t.schema_version, t.state, t.verdict, COALESCE(t.verdict_reason, ''), t.stages,
	t.rollout_baseline, t.current_attempt_id, t.attempt_count, t.failure_count, t.max_failures,
	t.leased_replica_id, t.leased_at, t.lease_expires_at, t.not_before, t.deadline_at,
	t.last_result_at, t.created_at, t.updated_at, t.terminal_at`

// ScanObservationTask scans one row of ObservationTaskColumns, plus any
// extra destinations after them.
func ScanObservationTask(row pgx.Row, extra ...any) (*ObservationTask, error) {
	var t ObservationTask
	var refs, stages, expected, baseline []byte
	dest := []any{
		&t.ID, &t.RequestID, &t.CorrelationID, &t.JobID, &t.GatewayID, &t.BindingID, &t.EnvironmentID,
		&refs, &expected, &t.ProviderType, &t.SecretScopeKey, &t.SecretRef,
		&t.ProviderConnectionID, &t.ProviderVersionID, &t.ProviderVersionAt, &t.VersionSource,
		&t.ExecutedAt, &t.SchemaVersion, &t.State, &t.Verdict, &t.VerdictReason, &stages,
		&baseline, &t.CurrentAttemptID, &t.AttemptCount, &t.FailureCount, &t.MaxFailures,
		&t.LeasedReplicaID, &t.LeasedAt, &t.LeaseExpiresAt, &t.NotBefore, &t.DeadlineAt,
		&t.LastResultAt, &t.CreatedAt, &t.UpdatedAt, &t.TerminalAt,
	}
	if err := row.Scan(append(dest, extra...)...); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("storage: scan observation task: %w", err)
	}
	if err := json.Unmarshal(refs, &t.ConnectorRefs); err != nil || t.ConnectorRefs == nil {
		t.ConnectorRefs = []ObservationConnectorRef{}
	}
	if err := json.Unmarshal(expected, &t.ExpectedStages); err != nil || t.ExpectedStages == nil {
		t.ExpectedStages = []string{}
	}
	if err := json.Unmarshal(stages, &t.Stages); err != nil || t.Stages == nil {
		t.Stages = map[string]ObservationStageState{}
	}
	if len(baseline) > 0 && string(baseline) != "null" {
		t.RolloutBaseline = json.RawMessage(baseline)
	}
	return &t, nil
}

func collectObservationTasks(rows pgx.Rows, withName bool) ([]*ObservationTask, error) {
	defer rows.Close()
	var out []*ObservationTask
	for rows.Next() {
		var t *ObservationTask
		var err error
		if withName {
			var name string
			t, err = ScanObservationTask(rows, &name)
			if t != nil {
				t.GatewayName = name
			}
		} else {
			t, err = ScanObservationTask(rows)
		}
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ObservationTaskAttempt mirrors an observation_task_attempts row.
type ObservationTaskAttempt struct {
	AttemptID      uuid.UUID
	TaskID         uuid.UUID
	AttemptCount   int
	GatewayID      uuid.UUID
	ReplicaID      uuid.UUID
	ClaimedAt      time.Time
	LeaseExpiresAt time.Time
	EndedAt        *time.Time
	Outcome        string
	ReleaseReason  string
	ResultSHA256   []byte
	ResultResponse json.RawMessage
}

const observationAttemptColumns = `
	attempt_id, task_id, attempt_count, gateway_id, replica_id, claimed_at, lease_expires_at,
	ended_at, COALESCE(outcome, ''), COALESCE(release_reason, ''), result_sha256, result_response`

func scanObservationAttempt(row pgx.Row) (*ObservationTaskAttempt, error) {
	var a ObservationTaskAttempt
	var resp []byte
	err := row.Scan(&a.AttemptID, &a.TaskID, &a.AttemptCount, &a.GatewayID, &a.ReplicaID, &a.ClaimedAt,
		&a.LeaseExpiresAt, &a.EndedAt, &a.Outcome, &a.ReleaseReason, &a.ResultSHA256, &resp)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("storage: scan observation attempt: %w", err)
	}
	if len(resp) > 0 {
		a.ResultResponse = json.RawMessage(resp)
	}
	return &a, nil
}

// ObservationEvidence mirrors an observation_evidence row.
type ObservationEvidence struct {
	ID              uuid.UUID
	TaskID          uuid.UUID
	AttemptID       uuid.UUID
	GatewayID       uuid.UUID
	ReplicaID       uuid.UUID
	GatewayVersion  string
	SchemaVersion   string
	Stage           string
	ConnectorID     uuid.UUID
	ReportedOutcome string
	CPOutcome       string
	Linkage         string
	CPCaveats       []string
	ObservedAt      time.Time
	ReceivedAt      time.Time
	Body            json.RawMessage
	BodySHA256      []byte
}

// ObservationTasks is the Postgres repository for the observation queue.
type ObservationTasks struct {
	pool *Pool
}

// NewObservationTasks binds the repository to a pool.
func NewObservationTasks(pool *Pool) *ObservationTasks { return &ObservationTasks{pool: pool} }

// ---- environments.observation_source ------------------------------------

// EnvironmentObservationSource returns the environment's observation
// source.
func (r *ObservationTasks) EnvironmentObservationSource(ctx context.Context, envID uuid.UUID) (ObservationSource, error) {
	var src ObservationSource
	err := r.pool.QueryRow(ctx, `SELECT observation_source FROM environments WHERE id = $1`, envID).Scan(&src)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("storage: environment observation source: %w", err)
	}
	return src, nil
}

// ObservationSourceChange is what SetEnvironmentObservationSource did.
type ObservationSourceChange struct {
	Previous  ObservationSource
	ProjectID uuid.UUID
	// Cancelled are the open Gateway tasks of the environment closed with
	// reason source_changed because the source left gateway.
	Cancelled []*ObservationTask
}

// SetEnvironmentObservationSource sets the source in one transaction.
// When the source leaves gateway, every open task of the environment is
// cancelled (verdict unverified, reason source_changed) and its open
// attempt closed, so a late result for it is refused (design section 7).
func (r *ObservationTasks) SetEnvironmentObservationSource(ctx context.Context, envID uuid.UUID, src ObservationSource, at time.Time) (*ObservationSourceChange, error) {
	if !src.Valid() {
		return nil, errors.New("storage: invalid observation source")
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("storage: begin observation source: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	out := &ObservationSourceChange{}
	err = tx.QueryRow(ctx, `SELECT observation_source, project_id FROM environments WHERE id = $1 FOR UPDATE`, envID).
		Scan(&out.Previous, &out.ProjectID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("storage: lock environment: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE environments SET observation_source = $2 WHERE id = $1`, envID, src); err != nil {
		return nil, fmt.Errorf("storage: set observation source: %w", err)
	}
	if out.Previous == ObservationSourceGateway && src != ObservationSourceGateway {
		out.Cancelled, err = cancelOpenTasks(ctx, tx, `t.environment_id = $1`, []any{envID}, ObservationReasonSourceChanged, at)
		if err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("storage: commit observation source: %w", err)
	}
	return out, nil
}

// cancelOpenTasks closes the open tasks matching where (over table t,
// arguments from $1) as cancelled with reason, and closes their open
// attempts as cancelled. at is $len(args)+1.
func cancelOpenTasks(ctx context.Context, q querier, where string, args []any, reason string, at time.Time) ([]*ObservationTask, error) {
	n := len(args) + 1
	atArg := fmt.Sprintf("$%d", n)
	reasonArg := fmt.Sprintf("$%d", n+1)
	sql := `
		WITH due AS (
			SELECT t.id, t.current_attempt_id FROM observation_tasks t
			WHERE t.state IN ('queued','leased') AND ` + where + `
			FOR UPDATE
		), closed AS (
			UPDATE observation_task_attempts a SET outcome = 'cancelled', ended_at = ` + atArg + `
			FROM due WHERE a.attempt_id = due.current_attempt_id AND a.outcome IS NULL
			RETURNING a.attempt_id
		)
		UPDATE observation_tasks t SET state = 'cancelled', verdict = 'unverified', verdict_reason = ` + reasonArg + `,
			terminal_at = ` + atArg + `, current_attempt_id = NULL, lease_expires_at = NULL,
			leased_replica_id = NULL, leased_at = NULL
		FROM due WHERE t.id = due.id
		RETURNING ` + ObservationTaskColumns
	rows, err := q.Query(ctx, sql, append(args, at, reason)...)
	if err != nil {
		return nil, fmt.Errorf("storage: cancel observation tasks: %w", err)
	}
	return collectObservationTasks(rows, false)
}

// ---- task creation -------------------------------------------------------

// ObservableScope is the secret scope of an executed request: a catalog
// secret, or a provider connection plus secret reference.
type ObservableScope struct {
	EnvironmentID        uuid.UUID
	SecretID             *uuid.UUID
	ProviderConnectionID *uuid.UUID
	SecretRef            string
}

// ObservableBinding is an enabled binding for a scope whose Gateway is
// not revoked or disabled and whose Argo CD connector is approved.
type ObservableBinding struct {
	BindingID           uuid.UUID
	GatewayID           uuid.UUID
	GatewayStatus       GatewayStatus
	EnvironmentID       uuid.UUID
	ExpectedStages      []string
	ObservationTimeoutS int
	ArgoCDConnectorName string
	ArgoCDTargetID      string
	ArgoCDTargets       []GatewayTarget
}

// ListObservableBindings returns the bindings a task may be created
// from for scope (design section 6, step 5). Release 1 binds Argo CD
// targets only, so a binding without an Argo CD pair is not returned.
func (r *ObservationTasks) ListObservableBindings(ctx context.Context, scope ObservableScope) ([]*ObservableBinding, error) {
	var secretRef any
	if scope.SecretRef != "" {
		secretRef = scope.SecretRef
	}
	rows, err := r.pool.Query(ctx, `
		SELECT b.id, b.gateway_id, g.status, b.environment_id, b.expected_stages, b.observation_timeout_s,
		       c.name, b.argocd_target_id, c.advertised_targets
		FROM gateway_connector_bindings b
		JOIN gateways g ON g.id = b.gateway_id
		JOIN gateway_connectors c ON c.id = b.argocd_connector_id AND c.gateway_id = b.gateway_id
		WHERE b.deleted_at IS NULL AND b.enabled AND b.environment_id = $1
		  AND b.suspended_reason IS NULL
		  AND (($2::uuid IS NOT NULL AND b.secret_id = $2) OR
		       ($3::uuid IS NOT NULL AND b.provider_connection_id = $3 AND b.secret_ref = $4::text))
		  AND g.status NOT IN ('revoked','disabled')
		  AND c.status = 'approved' AND c.kind = 'argocd'
		ORDER BY b.created_at, b.id`, scope.EnvironmentID, scope.SecretID, scope.ProviderConnectionID, secretRef)
	if err != nil {
		return nil, fmt.Errorf("storage: list observable bindings: %w", err)
	}
	defer rows.Close()
	var out []*ObservableBinding
	for rows.Next() {
		var b ObservableBinding
		var stages, targets []byte
		if err := rows.Scan(&b.BindingID, &b.GatewayID, &b.GatewayStatus, &b.EnvironmentID, &stages, &b.ObservationTimeoutS,
			&b.ArgoCDConnectorName, &b.ArgoCDTargetID, &targets); err != nil {
			return nil, fmt.Errorf("storage: scan observable binding: %w", err)
		}
		if err := json.Unmarshal(stages, &b.ExpectedStages); err != nil || b.ExpectedStages == nil {
			b.ExpectedStages = []string{}
		}
		if err := json.Unmarshal(targets, &b.ArgoCDTargets); err != nil || b.ArgoCDTargets == nil {
			b.ArgoCDTargets = []GatewayTarget{}
		}
		out = append(out, &b)
	}
	return out, rows.Err()
}

// CreateTask supersedes the open tasks of other requests for the same
// secret scope (design section 5.5) and inserts t, idempotently on
// (request_id, binding_id), in one transaction. created is false when
// the task already existed; nothing is superseded twice because the
// older tasks were closed the first time.
func (r *ObservationTasks) CreateTask(ctx context.Context, t *ObservationTask, at time.Time) (created bool, superseded []*ObservationTask, err error) {
	refs, err := json.Marshal(t.ConnectorRefs)
	if err != nil {
		return false, nil, fmt.Errorf("storage: marshal connector refs: %w", err)
	}
	expected, err := json.Marshal(t.ExpectedStages)
	if err != nil {
		return false, nil, fmt.Errorf("storage: marshal expected stages: %w", err)
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return false, nil, fmt.Errorf("storage: begin task create: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// The source is read again under a share lock, so a concurrent
	// switch away from gateway (which takes FOR UPDATE on the row and
	// then cancels open tasks) either commits first and is seen here, or
	// waits for this insert and cancels it.
	var src ObservationSource
	err = tx.QueryRow(ctx, `SELECT observation_source FROM environments WHERE id = $1 FOR SHARE`, t.EnvironmentID).Scan(&src)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil, ErrNotFound
	}
	if err != nil {
		return false, nil, fmt.Errorf("storage: environment source for task: %w", err)
	}
	if src != ObservationSourceGateway {
		return false, nil, ErrObservationSourceNotGateway
	}

	superseded, err = cancelOpenTasks(ctx, tx, `t.secret_scope_key = $1 AND t.request_id <> $2`,
		[]any{t.SecretScopeKey, t.RequestID}, ObservationReasonSupersededByLaterWrite, at)
	if err != nil {
		return false, nil, err
	}
	row := tx.QueryRow(ctx, `
		INSERT INTO observation_tasks AS t (
			request_id, correlation_id, job_id, gateway_id, binding_id, environment_id,
			connector_refs, expected_stages, provider_type, secret_scope_key, secret_ref,
			provider_connection_id, provider_version_id, provider_version_at, version_source,
			executed_at, not_before, deadline_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $19)
		ON CONFLICT (request_id, binding_id) DO NOTHING
		RETURNING `+ObservationTaskColumns,
		t.RequestID, t.CorrelationID, t.JobID, t.GatewayID, t.BindingID, t.EnvironmentID,
		refs, expected, t.ProviderType, t.SecretScopeKey, t.SecretRef,
		t.ProviderConnectionID, t.ProviderVersionID, t.ProviderVersionAt, t.VersionSource,
		t.ExecutedAt, t.NotBefore, t.DeadlineAt, at)
	got, err := ScanObservationTask(row)
	switch {
	case errors.Is(err, ErrNotFound):
		created = false
	case isFKViolation(err):
		return false, nil, ErrGatewayBindingReferenceNotFound
	case err != nil:
		return false, nil, err
	default:
		created = true
		*t = *got
	}
	if err := tx.Commit(ctx); err != nil {
		return false, nil, fmt.Errorf("storage: commit task create: %w", err)
	}
	return created, superseded, nil
}

// ---- E4 claim ------------------------------------------------------------

// connectorOverPrivilegedSQL is true when a replica of the task's
// Gateway seen within the replica window ($2) last reported connector c
// over_privileged, or reported over_privileged itself (api#312). It is
// part of the claim query, so every api replica pauses the connector on
// the first such heartbeat instead of waiting for the other Gateway
// replicas' own rechecks. The replica's next healthy heartbeat
// overwrites its row and lifts the pause. A replica that stops
// heartbeating holds the pause until it leaves the window.
const connectorOverPrivilegedSQL = `EXISTS (
		SELECT 1 FROM gateway_replicas rp
		WHERE rp.gateway_id = t.gateway_id AND rp.last_seen_at > now() - $2::interval
		  AND (rp.status = 'over_privileged'
		       OR rp.connector_health @> jsonb_build_array(jsonb_build_object('connector_id', c.name, 'status', 'over_privileged'))))`

// connectorScopeUnsettledSQL is true when a replica of the task's
// Gateway seen within the replica window ($2) reports a scope digest for
// connector c that is not the approved one, or c has no approved digest
// while a replica reports one (api#308, ADR 0002 C6). It covers both a
// changed scope that has not been re-approved yet and replicas that
// disagree. Decided in the claim query, like the over_privileged pause.
const connectorScopeUnsettledSQL = `EXISTS (
		SELECT 1 FROM gateway_replicas rs, jsonb_array_elements(rs.connector_health) sh
		WHERE rs.gateway_id = t.gateway_id AND rs.last_seen_at > now() - $2::interval
		  AND sh->>'connector_id' = c.name AND sh ? 'scope_digest'
		  AND (c.approved_scope_digest IS NULL OR sh->>'scope_digest' <> c.approved_scope_digest))`

// claimerScopeApprovedSQL is true when connector c has no approved
// digest (a contract 1 Gateway), or the claiming replica ($3), live in
// the window ($2), last reported exactly the approved digest for c. A
// replica that sent no digest yet (its first, contract 1 shaped
// heartbeat), one that never heartbeated, and one at another digest
// cannot claim (review on #317, item 1).
const claimerScopeApprovedSQL = `(c.approved_scope_digest IS NULL OR EXISTS (
		SELECT 1 FROM gateway_replicas ro, jsonb_array_elements(ro.connector_health) oh
		WHERE ro.gateway_id = t.gateway_id AND ro.replica_id = $3 AND ro.last_seen_at > now() - $2::interval
		  AND oh->>'connector_id' = c.name AND oh->>'scope_digest' = c.approved_scope_digest))`

// gatewayReplicaWindowSQL is GatewayReplicaLiveWindow as a Postgres
// interval.
var gatewayReplicaWindowSQL = fmt.Sprintf("%d seconds", int(GatewayReplicaLiveWindow/time.Second))

// ObservationClaim is what Claim leased.
type ObservationClaim struct {
	Task    *ObservationTask
	Attempt *ObservationTaskAttempt
	// Reclaimed is the attempt whose expired lease this claim replaced.
	Reclaimed *uuid.UUID
}

// Claim leases at most one task of gatewayID to replicaID (design
// section 4.5). The Gateway row is locked first, so claims of one
// Gateway serialise and max_inflight_tasks is a hard cap, and a revoke
// or disable that commits first is seen. The task row is taken with
// FOR UPDATE SKIP LOCKED, so two claims never lease the same task. An
// expired lease re-enters inline with a new attempt_id; the old attempt
// is closed as lease_expired and its late result is refused. A task is
// skipped while its binding is suspended (target identity_changed) or
// its connector is paused (over_privileged), both decided in this query
// so every api replica agrees (api#312).
func (r *ObservationTasks) Claim(ctx context.Context, gatewayID, replicaID uuid.UUID, lease time.Duration, perReplica int, contractVersion string) (*ObservationClaim, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("storage: begin claim: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var status GatewayStatus
	var maxInflight int
	var contracts []byte
	out := &ObservationClaim{}
	// FOR NO KEY UPDATE, not FOR UPDATE: it serialises claims of one
	// Gateway without blocking the FOR KEY SHARE that inserting a task
	// (foreign key to gateways) takes.
	err = tx.QueryRow(ctx, `SELECT status, max_inflight_tasks, contract_versions FROM gateways WHERE id = $1 FOR NO KEY UPDATE`, gatewayID).
		Scan(&status, &maxInflight, &contracts)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrGatewayNotLive
	}
	if err != nil {
		return nil, fmt.Errorf("storage: lock gateway for claim: %w", err)
	}
	if !status.Live() {
		return nil, ErrGatewayNotLive
	}
	var versions []string
	_ = json.Unmarshal(contracts, &versions)
	if len(versions) == 0 {
		// Not negotiated yet (no heartbeat accepted): nothing to hand out.
		return nil, ErrNoObservationTask
	}
	ok := false
	for _, v := range versions {
		ok = ok || v == contractVersion
	}
	if !ok {
		return nil, ErrObservationContractUnsupported
	}

	var inflight, replicaInflight int
	if err := tx.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE leased_replica_id = $2)
		FROM observation_tasks
		WHERE gateway_id = $1 AND state = 'leased' AND lease_expires_at > now()`, gatewayID, replicaID).
		Scan(&inflight, &replicaInflight); err != nil {
		return nil, fmt.Errorf("storage: count in-flight tasks: %w", err)
	}
	if inflight >= maxInflight || replicaInflight >= perReplica {
		return nil, ErrObservationAtCapacity
	}

	var taskID uuid.UUID
	var prevAttempt *uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT t.id, t.current_attempt_id
		FROM observation_tasks t
		WHERE t.gateway_id = $1
		  AND t.state IN ('queued','leased')
		  AND (t.state = 'queued' OR t.lease_expires_at < now())
		  AND t.not_before <= now()
		  AND t.deadline_at > now()
		  AND EXISTS (
			SELECT 1 FROM gateway_connector_bindings b
			JOIN gateway_connectors c ON c.id = b.argocd_connector_id
			WHERE b.id = t.binding_id AND b.deleted_at IS NULL AND b.enabled
			  AND c.gateway_id = t.gateway_id AND c.status = 'approved'
			  AND b.suspended_reason IS NULL
			  AND NOT `+bindingTargetIdentityChangedSQL+`
			  AND NOT `+connectorOverPrivilegedSQL+`
			  AND NOT `+connectorScopeUnsettledSQL+`
			  AND `+claimerScopeApprovedSQL+`)
		ORDER BY t.not_before, t.created_at
		LIMIT 1
		FOR UPDATE OF t SKIP LOCKED`, gatewayID, gatewayReplicaWindowSQL, replicaID).Scan(&taskID, &prevAttempt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoObservationTask
	}
	if err != nil {
		return nil, fmt.Errorf("storage: pick observation task: %w", err)
	}
	if prevAttempt != nil {
		if _, err := tx.Exec(ctx, `
			UPDATE observation_task_attempts SET outcome = 'lease_expired', ended_at = now()
			WHERE attempt_id = $1 AND outcome IS NULL`, *prevAttempt); err != nil {
			return nil, fmt.Errorf("storage: close expired attempt: %w", err)
		}
		out.Reclaimed = prevAttempt
	}
	attemptID := uuid.New()
	leaseInterval := fmt.Sprintf("%d milliseconds", lease.Milliseconds())
	out.Task, err = ScanObservationTask(tx.QueryRow(ctx, `
		UPDATE observation_tasks t
		SET state = 'leased', current_attempt_id = $2, attempt_count = t.attempt_count + 1,
		    leased_replica_id = $3, leased_at = now(),
		    lease_expires_at = LEAST(now() + $4::interval, t.deadline_at)
		WHERE t.id = $1
		RETURNING `+ObservationTaskColumns, taskID, attemptID, replicaID, leaseInterval))
	if err != nil {
		return nil, err
	}
	out.Attempt, err = scanObservationAttempt(tx.QueryRow(ctx, `
		INSERT INTO observation_task_attempts (attempt_id, task_id, attempt_count, gateway_id, replica_id, claimed_at, lease_expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING `+observationAttemptColumns,
		attemptID, taskID, out.Task.AttemptCount, gatewayID, replicaID, *out.Task.LeasedAt, *out.Task.LeaseExpiresAt))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("storage: commit claim: %w", err)
	}
	return out, nil
}

// lockTaskForGateway locks a task and checks that it belongs to
// gatewayID and that the Gateway is still live. A task of another
// Gateway is ErrNotFound, the same as an unknown one.
func lockTaskForGateway(ctx context.Context, tx pgx.Tx, gatewayID, taskID uuid.UUID) (*ObservationTask, time.Time, error) {
	var status GatewayStatus
	err := tx.QueryRow(ctx, `SELECT status FROM gateways WHERE id = $1 FOR SHARE`, gatewayID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !status.Live()) {
		return nil, time.Time{}, ErrGatewayNotLive
	}
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("storage: gateway status: %w", err)
	}
	// Another Gateway's task is not found, and is never locked.
	var now time.Time
	t, err := ScanObservationTask(tx.QueryRow(ctx, `SELECT `+ObservationTaskColumns+`, now()
		FROM observation_tasks t WHERE t.id = $1 AND t.gateway_id = $2 FOR UPDATE`, taskID, gatewayID), &now)
	if err != nil {
		return nil, time.Time{}, err
	}
	return t, now, nil
}

// fence checks attemptID against the task's live attempt: a closed or
// past-deadline task is ErrObservationTaskClosed, another attempt is
// ErrObservationAttemptSuperseded, an expired lease of this attempt is
// ErrObservationLeaseExpired.
func fence(t *ObservationTask, attemptID uuid.UUID, now time.Time) error {
	switch {
	case !t.State.Open() || !now.Before(t.DeadlineAt):
		return ErrObservationTaskClosed
	case t.State != ObservationTaskLeased || t.CurrentAttemptID == nil || *t.CurrentAttemptID != attemptID:
		return ErrObservationAttemptSuperseded
	case !now.Before(*t.LeaseExpiresAt):
		return ErrObservationLeaseExpired
	}
	return nil
}

// ---- E5 renew ------------------------------------------------------------

// Renew moves the lease of the current attempt to
// LEAST(now + lease, deadline_at) (design section 4.6).
func (r *ObservationTasks) Renew(ctx context.Context, gatewayID, taskID, attemptID uuid.UUID, lease time.Duration) (time.Time, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return time.Time{}, fmt.Errorf("storage: begin renew: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	t, now, err := lockTaskForGateway(ctx, tx, gatewayID, taskID)
	if err != nil {
		return time.Time{}, err
	}
	if err := fence(t, attemptID, now); err != nil {
		return time.Time{}, err
	}
	var exp time.Time
	leaseInterval := fmt.Sprintf("%d milliseconds", lease.Milliseconds())
	if err := tx.QueryRow(ctx, `
		UPDATE observation_tasks SET lease_expires_at = LEAST(now() + $2::interval, deadline_at)
		WHERE id = $1 RETURNING lease_expires_at`, taskID, leaseInterval).Scan(&exp); err != nil {
		return time.Time{}, fmt.Errorf("storage: renew lease: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE observation_task_attempts SET lease_expires_at = $2 WHERE attempt_id = $1`, attemptID, exp); err != nil {
		return time.Time{}, fmt.Errorf("storage: renew attempt lease: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return time.Time{}, fmt.Errorf("storage: commit renew: %w", err)
	}
	return exp, nil
}

// ---- E6 release ----------------------------------------------------------

// Release gives the current attempt's task back: queued, not_before now,
// the attempt closed as released (design section 4.7). Releases never
// change failure_count. A second release of the same attempt is a no-op
// (repeated true) while the task has not been claimed again; after a new
// claim it is ErrObservationAttemptSuperseded.
func (r *ObservationTasks) Release(ctx context.Context, gatewayID, taskID, attemptID uuid.UUID, reason string) (task *ObservationTask, repeated bool, err error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("storage: begin release: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	t, now, err := lockTaskForGateway(ctx, tx, gatewayID, taskID)
	if err != nil {
		return nil, false, err
	}
	if t.State == ObservationTaskLeased && t.CurrentAttemptID != nil && *t.CurrentAttemptID == attemptID {
		if _, err := tx.Exec(ctx, `
			UPDATE observation_task_attempts SET outcome = 'released', release_reason = $2, ended_at = $3
			WHERE attempt_id = $1 AND outcome IS NULL`, attemptID, reason, now); err != nil {
			return nil, false, fmt.Errorf("storage: close released attempt: %w", err)
		}
		t, err = ScanObservationTask(tx.QueryRow(ctx, `
			UPDATE observation_tasks t SET state = 'queued', current_attempt_id = NULL, lease_expires_at = NULL,
				leased_replica_id = NULL, leased_at = NULL, not_before = $2
			WHERE t.id = $1 RETURNING `+ObservationTaskColumns, taskID, now))
		if err != nil {
			return nil, false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, false, fmt.Errorf("storage: commit release: %w", err)
		}
		return t, false, nil
	}
	a, err := scanObservationAttempt(tx.QueryRow(ctx, `SELECT `+observationAttemptColumns+`
		FROM observation_task_attempts WHERE attempt_id = $1 AND task_id = $2`, attemptID, taskID))
	if err == nil && a.Outcome == ObservationAttemptReleased && a.AttemptCount == t.AttemptCount && t.State.Open() {
		return t, true, nil
	}
	if !t.State.Open() {
		return nil, false, ErrObservationTaskClosed
	}
	return nil, false, ErrObservationAttemptSuperseded
}

// ---- E7 result -------------------------------------------------------------

// ObservationResultTx is the transaction of one E7 result. It locks
// the Gateway row FOR SHARE and then the task row FOR UPDATE, the same
// order as every other path that touches both (claim, renew, release,
// revoke, disable), so a revoke and a result never deadlock. The
// service runs the checks of design section 4.8 in order and writes the
// evidence, the attempt, the task, the verdict and the audit rows
// through it before Commit, so the 200 is sent only after all of them
// are durable.
type ObservationResultTx struct {
	tx   pgx.Tx
	Task *ObservationTask
	// Now is the database clock at the start of the transaction.
	Now time.Time
}

// BeginResult opens the result transaction for gatewayID's task taskID.
// ErrGatewayNotLive when the Gateway is no longer active or stale (a
// revoke or disable that committed first), ErrNotFound when the task
// does not exist or belongs to another Gateway (that task is not locked).
func (r *ObservationTasks) BeginResult(ctx context.Context, gatewayID, taskID uuid.UUID) (*ObservationResultTx, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("storage: begin result: %w", err)
	}
	t, now, err := lockTaskForGateway(ctx, tx, gatewayID, taskID)
	if err != nil {
		_ = tx.Rollback(ctx)
		return nil, err
	}
	return &ObservationResultTx{tx: tx, Task: t, Now: now}, nil
}

// Attempt returns the task's attempt attemptID, or ErrNotFound.
func (rt *ObservationResultTx) Attempt(ctx context.Context, attemptID uuid.UUID) (*ObservationTaskAttempt, error) {
	return scanObservationAttempt(rt.tx.QueryRow(ctx, `SELECT `+observationAttemptColumns+`
		FROM observation_task_attempts WHERE attempt_id = $1 AND task_id = $2`, attemptID, rt.Task.ID))
}

// ObservationBindingScope is what the evidence-binding check reads about
// the task's binding, connector and request, inside the result
// transaction.
type ObservationBindingScope struct {
	BindingGatewayID     uuid.UUID
	BindingEnvironmentID uuid.UUID
	BindingProjectID     uuid.UUID
	BindingDeleted       bool
	BindingEnabled       bool
	ArgoCDConnectorID    *uuid.UUID
	ArgoCDTargetID       string
	RequestEnvironmentID *uuid.UUID
	RequestProjectID     string
}

// BindingScope reads the task's binding (deleted or not) and request.
func (rt *ObservationResultTx) BindingScope(ctx context.Context) (*ObservationBindingScope, error) {
	var s ObservationBindingScope
	var deletedAt *time.Time
	var scope []byte
	err := rt.tx.QueryRow(ctx, `
		SELECT b.gateway_id, b.environment_id, e.project_id, b.deleted_at, b.enabled,
		       b.argocd_connector_id, COALESCE(b.argocd_target_id, ''), ar.environment_id, ar.target_scope
		FROM gateway_connector_bindings b
		JOIN environments e ON e.id = b.environment_id
		JOIN access_requests ar ON ar.id = $2
		WHERE b.id = $1`, rt.Task.BindingID, rt.Task.RequestID).
		Scan(&s.BindingGatewayID, &s.BindingEnvironmentID, &s.BindingProjectID, &deletedAt, &s.BindingEnabled,
			&s.ArgoCDConnectorID, &s.ArgoCDTargetID, &s.RequestEnvironmentID, &scope)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("storage: binding scope: %w", err)
	}
	s.BindingDeleted = deletedAt != nil
	var ts map[string]any
	if json.Unmarshal(scope, &ts) == nil {
		s.RequestProjectID, _ = ts["project_id"].(string)
	}
	return &s, nil
}

// ConnectorByName returns the Gateway's connector named name.
func (rt *ObservationResultTx) ConnectorByName(ctx context.Context, gatewayID uuid.UUID, name string) (*GatewayConnector, error) {
	return scanGatewayConnector(rt.tx.QueryRow(ctx, `SELECT `+gatewayConnectorColumns+`
		FROM gateway_connectors WHERE gateway_id = $1 AND name = $2`, gatewayID, name))
}

// InsertEvidence appends one accepted stage observation.
func (rt *ObservationResultTx) InsertEvidence(ctx context.Context, e *ObservationEvidence) error {
	caveats, err := json.Marshal(e.CPCaveats)
	if err != nil {
		return fmt.Errorf("storage: marshal cp caveats: %w", err)
	}
	if e.CPCaveats == nil {
		caveats = []byte("[]")
	}
	err = rt.tx.QueryRow(ctx, `
		INSERT INTO observation_evidence (task_id, attempt_id, gateway_id, replica_id, gateway_version, schema_version,
			stage, connector_id, reported_outcome, cp_outcome, linkage, cp_caveats, observed_at, received_at, body, body_sha256)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		RETURNING id, received_at`,
		e.TaskID, e.AttemptID, e.GatewayID, e.ReplicaID, e.GatewayVersion, e.SchemaVersion,
		e.Stage, e.ConnectorID, e.ReportedOutcome, e.CPOutcome, e.Linkage, caveats, e.ObservedAt, rt.Now,
		[]byte(e.Body), e.BodySHA256).Scan(&e.ID, &e.ReceivedAt)
	if err != nil {
		return fmt.Errorf("storage: insert observation evidence: %w", err)
	}
	return nil
}

// ObservationTaskUpdate is the task state after an accepted result.
type ObservationTaskUpdate struct {
	State         ObservationTaskState
	Verdict       ObservationVerdict
	VerdictReason string
	Stages        map[string]ObservationStageState
	FailureCount  int
	NotBefore     time.Time
}

// AcceptResult closes the attempt as result_accepted with the digest and
// the response, and writes the task's new state. The lease is cleared:
// a rescheduled task goes back to queued and is claimed again with a new
// attempt.
func (rt *ObservationResultTx) AcceptResult(ctx context.Context, attemptID uuid.UUID, digest []byte, response any, upd ObservationTaskUpdate) error {
	resp, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("storage: marshal result response: %w", err)
	}
	stages, err := json.Marshal(upd.Stages)
	if err != nil {
		return fmt.Errorf("storage: marshal stages: %w", err)
	}
	tag, err := rt.tx.Exec(ctx, `
		UPDATE observation_task_attempts SET outcome = 'result_accepted', ended_at = $2, result_sha256 = $3, result_response = $4
		WHERE attempt_id = $1 AND outcome IS NULL`, attemptID, rt.Now, digest, resp)
	if err != nil {
		return fmt.Errorf("storage: close accepted attempt: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrObservationAttemptSuperseded
	}
	var terminal *time.Time
	if !upd.State.Open() {
		terminal = &rt.Now
	}
	t, err := ScanObservationTask(rt.tx.QueryRow(ctx, `
		UPDATE observation_tasks t SET state = $2, verdict = $3, verdict_reason = NULLIF($4, ''), stages = $5,
			failure_count = $6, not_before = $7, terminal_at = $8, last_result_at = $9,
			current_attempt_id = NULL, lease_expires_at = NULL, leased_replica_id = NULL, leased_at = NULL
		WHERE t.id = $1 RETURNING `+ObservationTaskColumns,
		rt.Task.ID, upd.State, upd.Verdict, upd.VerdictReason, stages, upd.FailureCount, upd.NotBefore, terminal, rt.Now))
	if err != nil {
		return err
	}
	rt.Task = t
	return nil
}

// TimeOut closes an open task whose deadline passed (verdict timed_out)
// and its open attempt (deadline), for the result path's deadline check.
func (rt *ObservationResultTx) TimeOut(ctx context.Context) error {
	if !rt.Task.State.Open() {
		return nil
	}
	if rt.Task.CurrentAttemptID != nil {
		if _, err := rt.tx.Exec(ctx, `UPDATE observation_task_attempts SET outcome = 'deadline', ended_at = $2
			WHERE attempt_id = $1 AND outcome IS NULL`, *rt.Task.CurrentAttemptID, rt.Now); err != nil {
			return fmt.Errorf("storage: close attempt at deadline: %w", err)
		}
	}
	t, err := ScanObservationTask(rt.tx.QueryRow(ctx, `
		UPDATE observation_tasks t SET state = 'done', verdict = 'timed_out', verdict_reason = 'deadline_reached',
			terminal_at = $2, current_attempt_id = NULL, lease_expires_at = NULL, leased_replica_id = NULL, leased_at = NULL
		WHERE t.id = $1 RETURNING `+ObservationTaskColumns, rt.Task.ID, rt.Now))
	if err != nil {
		return err
	}
	rt.Task = t
	return nil
}

// Audit appends an audit event inside the result transaction.
func (rt *ObservationResultTx) Audit(ctx context.Context, audit AuditEventRepository, evt *AuditEvent) error {
	return audit.AppendTx(ctx, rt.tx, evt)
}

// Commit commits the result transaction.
func (rt *ObservationResultTx) Commit(ctx context.Context) error {
	if err := rt.tx.Commit(ctx); err != nil {
		return fmt.Errorf("storage: commit result: %w", err)
	}
	return nil
}

// Rollback rolls the result transaction back. Safe after Commit.
func (rt *ObservationResultTx) Rollback(ctx context.Context) { _ = rt.tx.Rollback(ctx) }

// ---- sweeps (also used by worker#38) ----------------------------------------

// ExpireDeadlines closes open tasks whose deadline is at or before now as
// done with verdict timed_out and closes their open attempts (outcome
// deadline). The reason is gateway_unavailable when the Gateway has not
// been seen since the task was created or is not active, else
// deadline_reached. requestID narrows the sweep to one request when set.
// Rows locked by another transaction are skipped.
func (r *ObservationTasks) ExpireDeadlines(ctx context.Context, now time.Time, requestID *uuid.UUID, limit int) ([]*ObservationTask, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := r.pool.Query(ctx, `
		WITH due AS (
			SELECT id, current_attempt_id FROM observation_tasks
			WHERE state IN ('queued','leased') AND deadline_at <= $1
			  AND ($2::uuid IS NULL OR request_id = $2)
			ORDER BY deadline_at
			LIMIT $3
			FOR UPDATE SKIP LOCKED
		), closed AS (
			UPDATE observation_task_attempts a SET outcome = 'deadline', ended_at = $1
			FROM due WHERE a.attempt_id = due.current_attempt_id AND a.outcome IS NULL
			RETURNING a.attempt_id
		)
		UPDATE observation_tasks t SET state = 'done', verdict = 'timed_out',
			verdict_reason = CASE
				WHEN g.status <> 'active' OR g.last_seen_at IS NULL OR g.last_seen_at < t.created_at
				THEN 'gateway_unavailable' ELSE 'deadline_reached' END,
			terminal_at = $1, current_attempt_id = NULL, lease_expires_at = NULL,
			leased_replica_id = NULL, leased_at = NULL
		FROM due, gateways g
		WHERE t.id = due.id AND g.id = t.gateway_id
		RETURNING `+ObservationTaskColumns, now, requestID, limit)
	if err != nil {
		return nil, fmt.Errorf("storage: expire observation deadlines: %w", err)
	}
	return collectObservationTasks(rows, false)
}

// ExpireLeases puts leased tasks whose lease ended before now back to
// queued and closes their attempts as lease_expired. Not needed for
// correctness (claim re-enters expired leases inline); it keeps the
// state honest for the UI. failure_count is not changed.
func (r *ObservationTasks) ExpireLeases(ctx context.Context, now time.Time, limit int) ([]*ObservationTask, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := r.pool.Query(ctx, `
		WITH due AS (
			SELECT id, current_attempt_id FROM observation_tasks
			WHERE state = 'leased' AND lease_expires_at < $1
			ORDER BY lease_expires_at
			LIMIT $2
			FOR UPDATE SKIP LOCKED
		), closed AS (
			UPDATE observation_task_attempts a SET outcome = 'lease_expired', ended_at = $1
			FROM due WHERE a.attempt_id = due.current_attempt_id AND a.outcome IS NULL
			RETURNING a.attempt_id
		)
		UPDATE observation_tasks t SET state = 'queued', current_attempt_id = NULL, lease_expires_at = NULL,
			leased_replica_id = NULL, leased_at = NULL, not_before = $1
		FROM due WHERE t.id = due.id
		RETURNING `+ObservationTaskColumns, now, limit)
	if err != nil {
		return nil, fmt.Errorf("storage: expire observation leases: %w", err)
	}
	return collectObservationTasks(rows, false)
}

// requeueLeasedForGateway moves every leased task of a Gateway back to
// queued with no attempt, closing those attempts as cancelled, so a late
// result from the old attempt is refused (design section 8, revoke).
func requeueLeasedForGateway(ctx context.Context, tx pgx.Tx, gatewayID uuid.UUID, at time.Time) (int, error) {
	if _, err := tx.Exec(ctx, `
		UPDATE observation_task_attempts a SET outcome = 'cancelled', ended_at = $2
		FROM observation_tasks t
		WHERE t.gateway_id = $1 AND t.state = 'leased' AND a.attempt_id = t.current_attempt_id AND a.outcome IS NULL`,
		gatewayID, at); err != nil {
		return 0, fmt.Errorf("storage: cancel leased attempts: %w", err)
	}
	tag, err := tx.Exec(ctx, `
		UPDATE observation_tasks SET state = 'queued', current_attempt_id = NULL, lease_expires_at = NULL,
			leased_replica_id = NULL, leased_at = NULL, not_before = $2
		WHERE gateway_id = $1 AND state = 'leased'`, gatewayID, at)
	if err != nil {
		return 0, fmt.Errorf("storage: requeue leased tasks: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// ---- reads -----------------------------------------------------------------

// Get returns one task.
func (r *ObservationTasks) Get(ctx context.Context, id uuid.UUID) (*ObservationTask, error) {
	return ScanObservationTask(r.pool.QueryRow(ctx, `SELECT `+ObservationTaskColumns+` FROM observation_tasks t WHERE t.id = $1`, id))
}

// ListForRequest returns a request's tasks, oldest first, with the
// Gateway name.
func (r *ObservationTasks) ListForRequest(ctx context.Context, requestID uuid.UUID) ([]*ObservationTask, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+ObservationTaskColumns+`, g.name,
		(g.status <> 'active' OR g.last_seen_at IS NULL OR g.last_seen_at < t.created_at)
		FROM observation_tasks t JOIN gateways g ON g.id = t.gateway_id
		WHERE t.request_id = $1 ORDER BY t.created_at, t.id`, requestID)
	if err != nil {
		return nil, fmt.Errorf("storage: list request observation tasks: %w", err)
	}
	defer rows.Close()
	var out []*ObservationTask
	for rows.Next() {
		var name string
		var unavailable bool
		t, err := ScanObservationTask(rows, &name, &unavailable)
		if err != nil {
			return nil, err
		}
		t.GatewayName, t.GatewayUnavailable = name, unavailable
		out = append(out, t)
	}
	return out, rows.Err()
}

// ListForGateway returns a Gateway's tasks, newest first, optionally of
// one state.
func (r *ObservationTasks) ListForGateway(ctx context.Context, gatewayID uuid.UUID, state ObservationTaskState, limit int) ([]*ObservationTask, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var st any
	if state != "" {
		st = string(state)
	}
	rows, err := r.pool.Query(ctx, `SELECT `+ObservationTaskColumns+`, g.name
		FROM observation_tasks t JOIN gateways g ON g.id = t.gateway_id
		WHERE t.gateway_id = $1 AND ($2::text IS NULL OR t.state = $2)
		ORDER BY t.created_at DESC, t.id LIMIT $3`, gatewayID, st, limit)
	if err != nil {
		return nil, fmt.Errorf("storage: list gateway observation tasks: %w", err)
	}
	return collectObservationTasks(rows, true)
}

// CountForGateway returns the number of a Gateway's tasks in each state,
// over all of its tasks (not a page).
func (r *ObservationTasks) CountForGateway(ctx context.Context, gatewayID uuid.UUID) (map[ObservationTaskState]int, error) {
	rows, err := r.pool.Query(ctx, `SELECT state, count(*) FROM observation_tasks WHERE gateway_id = $1 GROUP BY state`, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("storage: count gateway observation tasks: %w", err)
	}
	defer rows.Close()
	out := map[ObservationTaskState]int{}
	for rows.Next() {
		var st ObservationTaskState
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, fmt.Errorf("storage: scan gateway observation task count: %w", err)
		}
		out[st] = n
	}
	return out, rows.Err()
}

// LatestEvidence returns, for each of taskIDs, the most recently
// received evidence row per stage.
func (r *ObservationTasks) LatestEvidence(ctx context.Context, taskIDs []uuid.UUID) ([]*ObservationEvidence, error) {
	if len(taskIDs) == 0 {
		return nil, nil
	}
	rows, err := r.pool.Query(ctx, `
		SELECT DISTINCT ON (task_id, stage)
		       id, task_id, attempt_id, gateway_id, replica_id, gateway_version, schema_version, stage,
		       connector_id, reported_outcome, cp_outcome, linkage, cp_caveats, observed_at, received_at,
		       body, body_sha256
		FROM observation_evidence WHERE task_id = ANY($1)
		ORDER BY task_id, stage, received_at DESC, id`, taskIDs)
	if err != nil {
		return nil, fmt.Errorf("storage: latest observation evidence: %w", err)
	}
	defer rows.Close()
	var out []*ObservationEvidence
	for rows.Next() {
		var e ObservationEvidence
		var caveats, body []byte
		if err := rows.Scan(&e.ID, &e.TaskID, &e.AttemptID, &e.GatewayID, &e.ReplicaID, &e.GatewayVersion,
			&e.SchemaVersion, &e.Stage, &e.ConnectorID, &e.ReportedOutcome, &e.CPOutcome, &e.Linkage, &caveats,
			&e.ObservedAt, &e.ReceivedAt, &body, &e.BodySHA256); err != nil {
			return nil, fmt.Errorf("storage: scan observation evidence: %w", err)
		}
		if err := json.Unmarshal(caveats, &e.CPCaveats); err != nil || e.CPCaveats == nil {
			e.CPCaveats = []string{}
		}
		e.Body = json.RawMessage(body)
		out = append(out, &e)
	}
	return out, rows.Err()
}
