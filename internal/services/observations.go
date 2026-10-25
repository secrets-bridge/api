package services

// GatewayObservationService owns the Gateway observation queue
// (api#294): task creation when a request reaches executed, the E4 to
// E7 machine endpoints (claim, renew, release, result), the CP-side
// stage outcomes and verdicts, the environment observation source and
// the read views for the request page and the Gateway admin page.
//
// Release 1 observes Argo CD only (secrets-bridge/gateway#12): the only
// stage a task carries is argocd_context. Argo CD Healthy and Synced is
// observed operational state. It is never a verified verdict and never
// proof that the secret change propagated: every argocd_context stage
// carries the argocd_health_not_proof caveat, and a task whose only
// expected stage is context ends unverified (reason context_only) even
// when Argo CD is Healthy and Synced. Stale, offline or missing evidence
// ends pending, unverified or timed_out, never verified or failed.
//
// Evidence binding (secrets-bridge/gateway#13): a result is accepted only
// for the attempt the CP dispatched to that same Gateway, for the
// connector and target the task snapshot names, through a binding of
// that Gateway in the request's own environment and project.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// Observation service errors. The handler maps each to a status and a
// closed error code.
var (
	ErrObservationInvalidRequest      = errors.New("services: invalid observation request")
	ErrObservationNotFound            = errors.New("services: observation task not found")
	ErrObservationNoTask              = errors.New("services: no observation task")
	ErrObservationAtCapacity          = errors.New("services: observation in-flight limit")
	ErrObservationContractUnsupported = errors.New("services: observation contract version unsupported")
	ErrObservationAttemptSuperseded   = errors.New("services: observation attempt superseded")
	ErrObservationLeaseExpired        = errors.New("services: observation lease expired")
	ErrObservationTaskClosed          = errors.New("services: observation task closed")
	ErrObservationResultConflict      = errors.New("services: observation result conflict")
	ErrObservationOutOfWindow         = errors.New("services: evidence out of window")
	ErrObservationGatewayNotLive      = errors.New("services: gateway not live")
	// ErrObservationIdentityRefused: the evidence does not match the
	// target's identity pin, or the target is identity_changed (api#312).
	// IdentityRefusalCode names which.
	ErrObservationIdentityRefused = errors.New("services: evidence refused by the target identity pin")
	ErrObservationInvalidSource   = errors.New("services: invalid observation source")
	// ErrObservationSourceRetired: control_plane selected the removed
	// control-plane Argo CD poller (secrets-bridge/gateway#13).
	ErrObservationSourceRetired = errors.New("services: observation source control_plane is retired")
)

// ObservationStore is the storage surface the service needs.
type ObservationStore interface {
	EnvironmentObservationSource(ctx context.Context, envID uuid.UUID) (storage.ObservationSource, error)
	SetEnvironmentObservationSource(ctx context.Context, envID uuid.UUID, src storage.ObservationSource, at time.Time) (*storage.ObservationSourceChange, error)
	ListObservableBindings(ctx context.Context, scope storage.ObservableScope) ([]*storage.ObservableBinding, error)
	CreateTask(ctx context.Context, t *storage.ObservationTask, at time.Time) (bool, []*storage.ObservationTask, error)
	Claim(ctx context.Context, gatewayID, replicaID uuid.UUID, lease time.Duration, perReplica int, contractVersion string) (*storage.ObservationClaim, error)
	Renew(ctx context.Context, gatewayID, taskID, attemptID uuid.UUID, lease time.Duration) (time.Time, error)
	Release(ctx context.Context, gatewayID, taskID, attemptID uuid.UUID, reason string) (*storage.ObservationTask, bool, error)
	BeginResult(ctx context.Context, gatewayID, taskID uuid.UUID) (*storage.ObservationResultTx, error)
	ListForRequest(ctx context.Context, requestID uuid.UUID) ([]*storage.ObservationTask, error)
	ListForGateway(ctx context.Context, gatewayID uuid.UUID, state storage.ObservationTaskState, limit int) ([]*storage.ObservationTask, error)
	CountForGateway(ctx context.Context, gatewayID uuid.UUID) (map[storage.ObservationTaskState]int, error)
	LatestEvidence(ctx context.Context, taskIDs []uuid.UUID) ([]*storage.ObservationEvidence, error)
}

// GatewayObservationConfig holds the fixed values of ADR 0001 section
// 2.5. Zero fields take the defaults.
type GatewayObservationConfig struct {
	// Lease is the claim lease, capped at the deadline. Default 60s.
	Lease time.Duration
	// PerReplicaInFlight is the in-flight limit per replica. Default 1.
	PerReplicaInFlight int
	// SkewMargin is the base clock-skew margin. Default 5s.
	SkewMargin time.Duration
	// ClockSkewBound is the measured offset above which a stage gets
	// clock_skew_suspected and cannot be observed. Default 30s.
	ClockSkewBound time.Duration
	// NotBeforeDelay is the wait between executed and the first claim.
	// Default 10s.
	NotBeforeDelay time.Duration
	// ClaimRetryAfter is the Retry-After sent on an idle claim. Default 5s.
	ClaimRetryAfter time.Duration
}

func (c *GatewayObservationConfig) defaults() {
	if c.Lease <= 0 {
		c.Lease = 60 * time.Second
	}
	if c.PerReplicaInFlight <= 0 {
		c.PerReplicaInFlight = 1
	}
	if c.SkewMargin <= 0 {
		c.SkewMargin = 5 * time.Second
	}
	if c.ClockSkewBound <= 0 {
		c.ClockSkewBound = 30 * time.Second
	}
	if c.NotBeforeDelay < 0 {
		c.NotBeforeDelay = 0
	} else if c.NotBeforeDelay == 0 {
		c.NotBeforeDelay = 10 * time.Second
	}
	if c.ClaimRetryAfter <= 0 {
		c.ClaimRetryAfter = 5 * time.Second
	}
}

const (
	observationMaxDeadline   = 24 * time.Hour
	observationDeadlineSlack = 5 * time.Minute
	observationSystemActor   = "system:gateway-observation"
)

// GatewayObservationService is the observation queue service.
type GatewayObservationService struct {
	store    ObservationStore
	audit    storage.AuditEventRepository
	bindings storage.ProjectSecretRepository
	secrets  storage.SecretRepository
	cfg      GatewayObservationConfig
	now      func() time.Time
}

// NewGatewayObservationService builds the service.
func NewGatewayObservationService(store ObservationStore, audit storage.AuditEventRepository, cfg GatewayObservationConfig) *GatewayObservationService {
	cfg.defaults()
	return &GatewayObservationService{store: store, audit: audit, cfg: cfg, now: time.Now}
}

// WithProjectBindings wires the project_secrets and catalog repositories
// that resolve a patch request to its catalog secret (the lookup
// boundProviderConfig uses).
func (s *GatewayObservationService) WithProjectBindings(bindings storage.ProjectSecretRepository, secrets storage.SecretRepository) *GatewayObservationService {
	s.bindings, s.secrets = bindings, secrets
	return s
}

// Config returns the effective configuration.
func (s *GatewayObservationService) Config() GatewayObservationConfig { return s.cfg }

func taskResource(id uuid.UUID) string { return "observation_task:" + id.String() }

func (s *GatewayObservationService) appendAudit(ctx context.Context, e *storage.AuditEvent) {
	_ = s.audit.Append(ctx, e)
}

// auditTaskClosed records a task closed outside the result path
// (cancelled, superseded, timed out, dead).
func auditTaskClosed(ctx context.Context, audit storage.AuditEventRepository, actor, action string, t *storage.ObservationTask) {
	_ = audit.Append(ctx, &storage.AuditEvent{
		Actor: actor, Action: action, Resource: taskResource(t.ID), Status: storage.AuditStatusSuccess,
		CorrelationID: t.CorrelationID,
		Metadata: map[string]any{
			"task_id": t.ID.String(), "request_id": t.RequestID.String(), "gateway_id": t.GatewayID.String(),
			"task_state": string(t.State), "verdict": string(t.Verdict), "verdict_reason": t.VerdictReason,
		},
	})
}

// ---- environment observation source ------------------------------------------

// Source returns the observation source of the environment a request
// was executed in. A request with no environment has none. An
// environment that cannot be read is an error: the caller starts no
// observer rather than guess.
func (s *GatewayObservationService) Source(ctx context.Context, envID *uuid.UUID) (storage.ObservationSource, error) {
	if s == nil || envID == nil {
		return storage.ObservationSourceNone, nil
	}
	src, err := s.store.EnvironmentObservationSource(ctx, *envID)
	if err != nil {
		return "", err
	}
	if !src.Valid() {
		return "", fmt.Errorf("observations: stored observation source %q is not valid", src)
	}
	return src, nil
}

// EnvironmentSource returns an environment's stored observation source
// (ErrNotFound for an unknown environment). It never returns the
// retired control_plane: the schema refuses it since migration 0049,
// and anything not valid reads as none.
func (s *GatewayObservationService) EnvironmentSource(ctx context.Context, envID uuid.UUID) (storage.ObservationSource, error) {
	src, err := s.store.EnvironmentObservationSource(ctx, envID)
	if err != nil {
		return "", err
	}
	if !src.Valid() {
		return storage.ObservationSourceNone, nil
	}
	return src, nil
}

// SetObservationSource sets an environment's observation source
// (design section 7, gateway.bind). Leaving gateway cancels the open
// Gateway tasks of the environment with reason source_changed.
func (s *GatewayObservationService) SetObservationSource(ctx context.Context, envID uuid.UUID, src storage.ObservationSource, by string) (*storage.ObservationSourceChange, error) {
	if src == storage.ObservationSourceRetiredControlPlane {
		return nil, ErrObservationSourceRetired
	}
	if !src.Valid() {
		return nil, ErrObservationInvalidSource
	}
	out, err := s.store.SetEnvironmentObservationSource(ctx, envID, src, s.now().UTC())
	if err != nil {
		return nil, err
	}
	actor := auditActor(ctx, by)
	s.appendAudit(ctx, &storage.AuditEvent{
		Actor: actor, Action: "environment.observation_source.update", Resource: "environment:" + envID.String(),
		Status: storage.AuditStatusSuccess,
		Metadata: map[string]any{
			"environment_id": envID.String(), "project_id": out.ProjectID.String(),
			"observation_source_before": string(out.Previous), "observation_source_after": string(src),
			"tasks_cancelled": len(out.Cancelled),
		},
	})
	for _, t := range out.Cancelled {
		auditTaskClosed(ctx, s.audit, actor, "observation.task.cancelled", t)
	}
	return out, nil
}

// ---- task creation (design section 6) ------------------------------------------

func (s *GatewayObservationService) auditSkipped(ctx context.Context, req *storage.AccessRequest, correlation uuid.UUID, reason string) {
	meta := map[string]any{"reason": reason, "request_id": req.ID.String(), "observation_source": string(storage.ObservationSourceGateway)}
	if req.EnvironmentID != nil {
		meta["environment_id"] = req.EnvironmentID.String()
	}
	s.appendAudit(ctx, &storage.AuditEvent{
		Actor: observationSystemActor, Action: "request.observation_skipped", Resource: "request:" + req.ID.String(),
		Status: storage.AuditStatusSuccess, CorrelationID: correlation, Metadata: meta,
	})
}

// resolveScope returns the secret scope of an executed request: the
// governing catalog secret for a patch request, the destination
// connection and reference for a cross-team request.
func (s *GatewayObservationService) resolveScope(ctx context.Context, req *storage.AccessRequest) (scope storage.ObservableScope, key, ref string, conn *uuid.UUID, ok bool) {
	if req.EnvironmentID == nil {
		return scope, "", "", nil, false
	}
	scope.EnvironmentID = *req.EnvironmentID
	switch req.Type {
	case storage.AccessRequestTypePatch:
		if s.bindings == nil || s.secrets == nil {
			return scope, "", "", nil, false
		}
		projectRaw, _ := req.TargetScope["project_id"].(string)
		projectID, err := uuid.Parse(projectRaw)
		if err != nil {
			return scope, "", "", nil, false
		}
		cands, err := findProjectBindings(ctx, s.bindings, s.secrets, projectID, req.TargetProviderType, req.TargetSecretRef)
		if err != nil {
			return scope, "", "", nil, false
		}
		sel := selectBinding(cands, req.EnvironmentID)
		if sel == nil {
			return scope, "", "", nil, false
		}
		id := sel.secret.ID
		scope.SecretID = &id
		return scope, id.String(), req.TargetSecretRef, nil, true
	case storage.AccessRequestTypeCrossTeam:
		if req.DestinationProviderConnectionID == nil || req.DestinationSecretRef == "" {
			return scope, "", "", nil, false
		}
		c := *req.DestinationProviderConnectionID
		scope.ProviderConnectionID, scope.SecretRef = &c, req.DestinationSecretRef
		return scope, c.String() + ":" + req.DestinationSecretRef, req.DestinationSecretRef, &c, true
	}
	return scope, "", "", nil, false
}

// deadlineFor is ADR 0001 section 2.5: min(24h, max(timeout,
// refresh_interval + progress_deadline + 5m)) with the intervals the
// bound targets advertise.
func deadlineFor(b *storage.ObservableBinding) time.Duration {
	extra := observationDeadlineSlack
	for _, t := range b.ArgoCDTargets {
		if t.TargetID != b.ArgoCDTargetID {
			continue
		}
		if t.RefreshIntervalSeconds != nil {
			extra += time.Duration(*t.RefreshIntervalSeconds) * time.Second
		}
		if t.ProgressDeadlineSeconds != nil {
			extra += time.Duration(*t.ProgressDeadlineSeconds) * time.Second
		}
	}
	d := max(time.Duration(b.ObservationTimeoutS)*time.Second, extra)
	return min(d, observationMaxDeadline)
}

func targetStale(b *storage.ObservableBinding) bool {
	for _, t := range b.ArgoCDTargets {
		if t.TargetID == b.ArgoCDTargetID {
			return t.Stale
		}
	}
	return true
}

// Start creates one task per matching binding for a request that just
// reached executed in an environment whose observation source is
// gateway. RequestService.OnJobCompleted calls it only after reading
// that source.
// Failures are audited, not returned to the request lifecycle.
func (s *GatewayObservationService) Start(ctx context.Context, req *storage.AccessRequest, job *storage.SyncJob) error {
	if s == nil || req == nil || job == nil {
		return nil
	}
	correlation := job.CorrelationID
	if req.Type != storage.AccessRequestTypePatch && req.Type != storage.AccessRequestTypeCrossTeam {
		s.auditSkipped(ctx, req, correlation, "request_type_not_observed")
		return nil
	}
	if req.TargetProviderType != string(storage.ProviderConnectionTypeAWSSM) && req.TargetProviderType != string(storage.ProviderConnectionTypeVault) {
		s.auditSkipped(ctx, req, correlation, "provider_type_not_supported")
		return nil
	}
	scope, key, ref, conn, ok := s.resolveScope(ctx, req)
	if !ok {
		s.auditSkipped(ctx, req, correlation, "scope_not_resolved")
		return nil
	}
	if !validTaskSecretRef(ref) {
		s.auditSkipped(ctx, req, correlation, "secret_ref_not_representable")
		return nil
	}
	bindings, err := s.store.ListObservableBindings(ctx, scope)
	if err != nil {
		s.auditSkipped(ctx, req, correlation, "binding_lookup_failed")
		return fmt.Errorf("observations: list bindings: %w", err)
	}
	now := s.now().UTC()
	created := 0
	for _, b := range bindings {
		// A discovered binding is listed only while dispatchable; a static
		// one is skipped while its advertised target is stale.
		if b.TargetSource != storage.GatewayTargetSourceDiscovered && targetStale(b) {
			continue
		}
		jobID := job.ID
		t := &storage.ObservationTask{
			RequestID: req.ID, CorrelationID: correlation, JobID: &jobID,
			GatewayID: b.GatewayID, BindingID: b.BindingID, EnvironmentID: b.EnvironmentID,
			ConnectorRefs:  []storage.ObservationConnectorRef{{ConnectorID: b.ArgoCDConnectorName, TargetID: b.ArgoCDTargetID, Stage: StageArgoCDContext}},
			ExpectedStages: []string{StageArgoCDContext},
			ProviderType:   req.TargetProviderType, SecretScopeKey: key, SecretRef: ref, ProviderConnectionID: conn,
			// The agent does not report the provider version yet (ADR
			// 0001 section 2.2, a separate change); no task can be
			// verified without it.
			VersionSource: "none",
			ExecutedAt:    now,
			NotBefore:     now.Add(s.cfg.NotBeforeDelay),
			DeadlineAt:    now.Add(deadlineFor(b)),
		}
		isNew, superseded, err := s.store.CreateTask(ctx, t, now)
		if errors.Is(err, storage.ErrObservationSourceNotGateway) {
			// The source left gateway after OnJobCompleted read it.
			s.auditSkipped(ctx, req, correlation, "source_changed")
			return nil
		}
		if err != nil {
			s.appendAudit(ctx, &storage.AuditEvent{
				Actor: observationSystemActor, Action: "observation.task.create_failed", Resource: "request:" + req.ID.String(),
				Status: storage.AuditStatusFailure, CorrelationID: correlation,
				Metadata: map[string]any{"request_id": req.ID.String(), "binding_id": b.BindingID.String(), "error": err.Error()},
			})
			continue
		}
		for _, old := range superseded {
			s.appendAudit(ctx, &storage.AuditEvent{
				Actor: observationSystemActor, Action: "observation.task.superseded", Resource: taskResource(old.ID),
				Status: storage.AuditStatusSuccess, CorrelationID: old.CorrelationID,
				Metadata: map[string]any{
					"task_id": old.ID.String(), "request_id": old.RequestID.String(), "gateway_id": old.GatewayID.String(),
					"superseding_task_id": t.ID.String(), "verdict": string(old.Verdict), "verdict_reason": old.VerdictReason,
				},
			})
		}
		if !isNew {
			continue
		}
		created++
		s.appendAudit(ctx, &storage.AuditEvent{
			Actor: observationSystemActor, Action: "observation.task.created", Resource: taskResource(t.ID),
			Status: storage.AuditStatusSuccess, CorrelationID: correlation,
			Metadata: map[string]any{
				"task_id": t.ID.String(), "request_id": req.ID.String(), "gateway_id": t.GatewayID.String(),
				"binding_id": t.BindingID.String(), "environment_id": t.EnvironmentID.String(),
				"version_source": t.VersionSource, "expected_stages": t.ExpectedStages,
				"deadline": t.DeadlineAt.UTC().Format(time.RFC3339),
			},
		})
	}
	if created == 0 && len(bindings) == 0 {
		s.auditSkipped(ctx, req, correlation, "no_gateway_binding")
	}
	return nil
}

// ---- E4 claim --------------------------------------------------------------------

// ObservationClaimInput is the E4 body.
type ObservationClaimInput struct {
	ReplicaID string
	MaxTasks  int
}

// ObservationTaskWire is the E4 200 body (observation-task.schema.json).
type ObservationTaskWire struct {
	SchemaVersion     string                            `json:"schema_version"`
	TaskID            string                            `json:"task_id"`
	AttemptID         string                            `json:"attempt_id"`
	AttemptCount      int                               `json:"attempt_count"`
	LeaseExpiresAt    string                            `json:"lease_expires_at"`
	DeadlineAt        string                            `json:"deadline_at"`
	RequestID         string                            `json:"request_id"`
	CorrelationID     string                            `json:"correlation_id"`
	SkewMarginSeconds int                               `json:"skew_margin_seconds"`
	GatewayScope      ObservationGatewayScopeWire       `json:"gateway_scope"`
	ConnectorRefs     []storage.ObservationConnectorRef `json:"connector_refs"`
	ExpectedChange    ObservationExpectedChangeWire     `json:"expected_change"`
	RolloutBaseline   json.RawMessage                   `json:"rollout_baseline"`
}

// ObservationGatewayScopeWire is gateway_scope.
type ObservationGatewayScopeWire struct {
	GatewayID     string `json:"gateway_id"`
	EnvironmentID string `json:"environment_id,omitempty"`
}

// ObservationExpectedChangeWire is expected_change.
type ObservationExpectedChangeWire struct {
	ProviderType      string                   `json:"provider_type"`
	SecretRef         ObservationSecretRefWire `json:"secret_ref"`
	ProviderVersionID *string                  `json:"provider_version_id"`
	ProviderVersionAt *string                  `json:"provider_version_at"`
	VersionSource     string                   `json:"version_source"`
	ExecutedAt        string                   `json:"executed_at"`
}

// ObservationSecretRefWire is expected_change.secret_ref.
type ObservationSecretRefWire struct {
	ProviderConnectionID string `json:"provider_connection_id,omitempty"`
	Name                 string `json:"name"`
}

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func taskWire(t *storage.ObservationTask, attempt *storage.ObservationTaskAttempt, skew time.Duration) *ObservationTaskWire {
	w := &ObservationTaskWire{
		SchemaVersion: ObservationTaskSchemaVersion, TaskID: t.ID.String(), AttemptID: attempt.AttemptID.String(),
		AttemptCount: t.AttemptCount, LeaseExpiresAt: rfc3339(*t.LeaseExpiresAt), DeadlineAt: rfc3339(t.DeadlineAt),
		RequestID: t.RequestID.String(), CorrelationID: t.CorrelationID.String(),
		SkewMarginSeconds: int(skew / time.Second),
		GatewayScope:      ObservationGatewayScopeWire{GatewayID: t.GatewayID.String(), EnvironmentID: t.EnvironmentID.String()},
		ConnectorRefs:     t.ConnectorRefs,
		ExpectedChange: ObservationExpectedChangeWire{
			ProviderType: t.ProviderType, SecretRef: ObservationSecretRefWire{Name: t.SecretRef},
			ProviderVersionID: t.ProviderVersionID, VersionSource: t.VersionSource, ExecutedAt: rfc3339(t.ExecutedAt),
		},
		RolloutBaseline: json.RawMessage("null"),
	}
	if t.ProviderConnectionID != nil {
		w.ExpectedChange.SecretRef.ProviderConnectionID = t.ProviderConnectionID.String()
	}
	if t.ProviderVersionAt != nil {
		v := rfc3339(*t.ProviderVersionAt)
		w.ExpectedChange.ProviderVersionAt = &v
	}
	if len(t.RolloutBaseline) > 0 {
		w.RolloutBaseline = t.RolloutBaseline
	}
	return w
}

func parseReplica(raw string) (uuid.UUID, error) {
	if !gatewayUUIDRe.MatchString(raw) {
		return uuid.Nil, ErrObservationInvalidRequest
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, ErrObservationInvalidRequest
	}
	return id, nil
}

// Claim leases at most one task of the authenticated Gateway (E4). The
// scope is the authenticated id; nothing in the body selects a task.
func (s *GatewayObservationService) Claim(ctx context.Context, gatewayID uuid.UUID, in ObservationClaimInput) (*ObservationTaskWire, error) {
	replica, err := parseReplica(in.ReplicaID)
	if err != nil {
		return nil, err
	}
	if in.MaxTasks != 1 {
		return nil, ErrObservationInvalidRequest
	}
	c, err := s.store.Claim(ctx, gatewayID, replica, s.cfg.Lease, s.cfg.PerReplicaInFlight, observationContractVersion)
	switch {
	case errors.Is(err, storage.ErrNoObservationTask):
		return nil, ErrObservationNoTask
	case errors.Is(err, storage.ErrObservationAtCapacity):
		return nil, ErrObservationAtCapacity
	case errors.Is(err, storage.ErrObservationContractUnsupported):
		return nil, ErrObservationContractUnsupported
	case errors.Is(err, storage.ErrGatewayNotLive):
		return nil, ErrObservationGatewayNotLive
	case err != nil:
		return nil, err
	}
	t := c.Task
	actor := gatewayActor(gatewayID)
	if c.Reclaimed != nil {
		s.appendAudit(ctx, &storage.AuditEvent{
			Actor: actor, Action: "observation.task.lease_expired", Resource: taskResource(t.ID),
			Status: storage.AuditStatusSuccess, CorrelationID: t.CorrelationID,
			Metadata: map[string]any{
				"task_id": t.ID.String(), "gateway_id": gatewayID.String(), "previous_attempt_id": c.Reclaimed.String(),
				"attempt_id": c.Attempt.AttemptID.String(), "attempt_count": t.AttemptCount,
			},
		})
	}
	if t.AttemptCount == 1 {
		s.appendAudit(ctx, &storage.AuditEvent{
			Actor: actor, Action: "observation.task.claimed", Resource: taskResource(t.ID),
			Status: storage.AuditStatusSuccess, CorrelationID: t.CorrelationID,
			Metadata: map[string]any{
				"task_id": t.ID.String(), "request_id": t.RequestID.String(), "gateway_id": gatewayID.String(),
				"attempt_id": c.Attempt.AttemptID.String(), "attempt_count": t.AttemptCount, "replica_id": replica.String(),
			},
		})
	}
	return taskWire(t, c.Attempt, s.cfg.SkewMargin), nil
}

// ---- E5 renew and E6 release ------------------------------------------------------

// ObservationAttemptInput is the E5 and E6 body.
type ObservationAttemptInput struct {
	ReplicaID string
	AttemptID string
	Reason    string
}

func (in ObservationAttemptInput) ids() (uuid.UUID, uuid.UUID, error) {
	replica, err := parseReplica(in.ReplicaID)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	attempt, err := parseReplica(in.AttemptID)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return replica, attempt, nil
}

func mapFenceErr(err error) error {
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return ErrObservationNotFound
	case errors.Is(err, storage.ErrGatewayNotLive):
		return ErrObservationGatewayNotLive
	case errors.Is(err, storage.ErrObservationAttemptSuperseded):
		return ErrObservationAttemptSuperseded
	case errors.Is(err, storage.ErrObservationLeaseExpired):
		return ErrObservationLeaseExpired
	case errors.Is(err, storage.ErrObservationTaskClosed):
		return ErrObservationTaskClosed
	}
	return err
}

// Renew extends the lease of the current attempt (E5).
func (s *GatewayObservationService) Renew(ctx context.Context, gatewayID, taskID uuid.UUID, in ObservationAttemptInput) (time.Time, error) {
	if in.Reason != "" {
		return time.Time{}, ErrObservationInvalidRequest
	}
	_, attempt, err := in.ids()
	if err != nil {
		return time.Time{}, err
	}
	exp, err := s.store.Renew(ctx, gatewayID, taskID, attempt, s.cfg.Lease)
	if err != nil {
		return time.Time{}, mapFenceErr(err)
	}
	return exp, nil
}

var observationReleaseReasons = []string{"shutdown", "over_capacity", "connector_unavailable"}

// Release gives a task back early (E6). Never a failure.
func (s *GatewayObservationService) Release(ctx context.Context, gatewayID, taskID uuid.UUID, in ObservationAttemptInput) error {
	if !slices.Contains(observationReleaseReasons, in.Reason) {
		return ErrObservationInvalidRequest
	}
	replica, attempt, err := in.ids()
	if err != nil {
		return err
	}
	t, repeated, err := s.store.Release(ctx, gatewayID, taskID, attempt, in.Reason)
	if err != nil {
		return mapFenceErr(err)
	}
	if !repeated {
		s.appendAudit(ctx, &storage.AuditEvent{
			Actor: gatewayActor(gatewayID), Action: "observation.task.released", Resource: taskResource(t.ID),
			Status: storage.AuditStatusSuccess, CorrelationID: t.CorrelationID,
			Metadata: map[string]any{
				"task_id": t.ID.String(), "gateway_id": gatewayID.String(), "attempt_id": attempt.String(),
				"replica_id": replica.String(), "release_reason": in.Reason,
			},
		})
	}
	return nil
}

// ---- E7 result --------------------------------------------------------------------

// ObservationResultResponse is the E7 200 body.
type ObservationResultResponse struct {
	Status    string `json:"status"`
	TaskState string `json:"task_state"`
	Verdict   string `json:"verdict"`
	Next      string `json:"next"`
}

// Rejection reasons for observation.evidence.rejected (design section 10).
const (
	rejectForeignTask    = "foreign_task"
	rejectStaleAttempt   = "stale_attempt"
	rejectUnknownAttempt = "unknown_attempt"
	rejectLeaseExpired   = "lease_expired"
	rejectTaskClosed     = "task_closed"
	rejectResultConflict = "result_conflict"
	rejectSchema         = "schema_violation"
	rejectScope          = "scope"
	rejectOutOfWindow    = "evidence_out_of_window"
)

func (s *GatewayObservationService) auditRejected(ctx context.Context, gatewayID uuid.UUID, task *storage.ObservationTask, taskID uuid.UUID, attemptID, reason string) {
	meta := map[string]any{"task_id": taskID.String(), "gateway_id": gatewayID.String(), "reason": reason}
	if gatewayUUIDRe.MatchString(attemptID) {
		meta["attempt_id"] = attemptID
	}
	e := &storage.AuditEvent{
		Actor: gatewayActor(gatewayID), Action: "observation.evidence.rejected", Resource: taskResource(taskID),
		Status: storage.AuditStatusDenied, Metadata: meta,
	}
	if task != nil && task.GatewayID == gatewayID {
		e.CorrelationID = task.CorrelationID
	}
	s.appendAudit(ctx, e)
}

// SubmitResult accepts one EvidenceResult (E7, design section 4.8). The
// checks run in the documented order inside one transaction that starts
// by locking the task; evidence, stage outcomes, task state, verdict and
// audit are committed together before the 200.
func (s *GatewayObservationService) SubmitResult(ctx context.Context, gatewayID, taskID uuid.UUID, body []byte) (*ObservationResultResponse, error) {
	var ids evidenceIDs
	if err := json.Unmarshal(body, &ids); err != nil {
		return nil, ErrObservationInvalidRequest
	}
	if ids.TaskID != taskID.String() || ids.GatewayID != gatewayID.String() {
		return nil, ErrObservationInvalidRequest
	}
	attemptID, err := uuid.Parse(ids.AttemptID)
	if err != nil || attemptID.String() != ids.AttemptID {
		// Not an attempt the CP could have minted.
		s.auditRejected(ctx, gatewayID, nil, taskID, "", rejectUnknownAttempt)
		return nil, ErrObservationAttemptSuperseded
	}
	digest, err := ResultDigest(body)
	if errors.Is(err, ErrObservationSchema) {
		// A duplicate key: RFC 8785 has no canonical form for it, and Go
		// would keep the last one.
		s.auditRejected(ctx, gatewayID, nil, taskID, ids.AttemptID, rejectSchema)
		return nil, err
	}
	if err != nil {
		return nil, ErrObservationInvalidRequest
	}

	// 1. Identity and 2. ownership: BeginResult locks the Gateway row
	// (still active or stale) and then the task, which must be this
	// Gateway's; another Gateway's task is not found and not locked.
	rt, err := s.store.BeginResult(ctx, gatewayID, taskID)
	switch {
	case errors.Is(err, storage.ErrGatewayNotLive):
		return nil, ErrObservationGatewayNotLive
	case errors.Is(err, storage.ErrNotFound):
		s.auditRejected(ctx, gatewayID, nil, taskID, ids.AttemptID, rejectForeignTask)
		return nil, ErrObservationNotFound
	case err != nil:
		return nil, err
	}
	defer rt.Rollback(ctx)
	task := rt.Task
	reject := func(reason string, out error) (*ObservationResultResponse, error) {
		rt.Rollback(ctx)
		s.auditRejected(ctx, gatewayID, task, taskID, ids.AttemptID, reason)
		return nil, out
	}
	// 3. Replay, before the current-attempt check: accepting a result
	// clears current_attempt_id.
	attempt, aerr := rt.Attempt(ctx, attemptID)
	if aerr != nil && !errors.Is(aerr, storage.ErrNotFound) {
		return nil, aerr
	}
	if aerr == nil && attempt.Outcome == storage.ObservationAttemptResultAccepted {
		if string(attempt.ResultSHA256) != string(digest) {
			return reject(rejectResultConflict, ErrObservationResultConflict)
		}
		var resp ObservationResultResponse
		if err := json.Unmarshal(attempt.ResultResponse, &resp); err != nil {
			return nil, fmt.Errorf("observations: stored response: %w", err)
		}
		resp.Status = "duplicate"
		return &resp, nil
	}
	// 4. Current attempt, dispatched by the CP to this Gateway.
	if aerr != nil || attempt.GatewayID != gatewayID {
		return reject(rejectUnknownAttempt, ErrObservationAttemptSuperseded)
	}
	if !task.State.Open() {
		// A closed task (done, dead, or cancelled by a later write, a
		// source change or a deleted binding) refuses every attempt that
		// was not accepted before.
		return reject(rejectTaskClosed, ErrObservationTaskClosed)
	}
	if task.State != storage.ObservationTaskLeased || task.CurrentAttemptID == nil || *task.CurrentAttemptID != attemptID {
		// An older attempt of this task: its lease expired and the task
		// was claimed again, or it was released, or the Gateway was
		// revoked or disabled while it held the lease.
		return reject(rejectStaleAttempt, ErrObservationAttemptSuperseded)
	}
	// 5. Lease.
	if !rt.Now.Before(*task.LeaseExpiresAt) {
		return reject(rejectLeaseExpired, ErrObservationLeaseExpired)
	}
	// 6. Deadline: the task is moved to timed_out in this transaction.
	if !rt.Now.Before(task.DeadlineAt) {
		if err := rt.TimeOut(ctx); err != nil {
			return nil, err
		}
		if err := rt.Audit(ctx, s.audit, &storage.AuditEvent{
			Actor: gatewayActor(gatewayID), Action: "observation.task.timed_out", Resource: taskResource(task.ID),
			Status: storage.AuditStatusSuccess, CorrelationID: task.CorrelationID,
			Metadata: map[string]any{
				"task_id": task.ID.String(), "request_id": task.RequestID.String(), "gateway_id": gatewayID.String(),
				"verdict": string(rt.Task.Verdict), "verdict_reason": rt.Task.VerdictReason,
			},
		}); err != nil {
			return nil, err
		}
		if err := rt.Commit(ctx); err != nil {
			return nil, err
		}
		s.auditRejected(ctx, gatewayID, task, taskID, ids.AttemptID, rejectTaskClosed)
		return nil, ErrObservationTaskClosed
	}
	// 7. Schema: closed, strict; stages within the task.
	res, err := DecodeEvidenceResult(body)
	if err != nil {
		return reject(rejectSchema, err)
	}
	refs := map[string]storage.ObservationConnectorRef{}
	for _, r := range task.ConnectorRefs {
		refs[r.Stage] = r
	}
	for _, st := range *res.Stages {
		if _, ok := refs[st.Stage]; !ok {
			return reject(rejectSchema, obsViolation("stages", "names a stage the task does not expect"))
		}
	}
	// 8. Scope: the evidence binding, then the target identity pin.
	connectors, err := s.checkEvidenceBinding(ctx, rt, res, refs)
	if err != nil {
		if code := IdentityRefusalCode(err); code != "" {
			return reject(code, err)
		}
		if errors.Is(err, ErrObservationSchema) {
			return reject(rejectScope, err)
		}
		return nil, err
	}
	// 9. Time window. The self-reported offsets widen the window at most
	// by the clock-skew bound; above it the stage cannot be observed
	// anyway (clock_skew_suspected).
	skew := s.cfg.SkewMargin + min(absMS(res.Clock.CPOffsetMS)+absMS(res.Clock.APIServerOffsetMS), s.cfg.ClockSkewBound)
	if err := checkWindow(res, attempt, rt.Now, skew); err != nil {
		return reject(rejectOutOfWindow, err)
	}

	resp, err := s.accept(ctx, rt, res, attempt, connectors, digest, skew)
	if err != nil {
		return nil, err
	}
	if err := rt.Commit(ctx); err != nil {
		return nil, err
	}
	return resp, nil
}

func absMS(p *int64) time.Duration {
	if p == nil {
		return 0
	}
	v := *p
	if v < 0 {
		v = -v
	}
	return time.Duration(v) * time.Millisecond
}

// checkEvidenceBinding is the evidence-binding rule (secrets-bridge/
// gateway#13): every stage's source must be exactly the connector and
// target the task snapshot names for it; that connector must be the
// approved connector of the task's binding, of the stage's kind, on the
// same Gateway; and the binding must be the Gateway's, in the task's
// environment, which is the request's environment and project. Returns
// the connector row per stage.
func (s *GatewayObservationService) checkEvidenceBinding(ctx context.Context, rt *storage.ObservationResultTx, res *EvidenceResult, refs map[string]storage.ObservationConnectorRef) (map[string]*storage.GatewayConnector, error) {
	task := rt.Task
	scope, err := rt.BindingScope(ctx)
	if errors.Is(err, storage.ErrNotFound) {
		return nil, obsViolation("binding", "is not the task's")
	}
	if err != nil {
		return nil, err
	}
	switch {
	case scope.BindingGatewayID != task.GatewayID:
		return nil, obsViolation("binding", "belongs to another gateway")
	case scope.BindingEnvironmentID != task.EnvironmentID:
		return nil, obsViolation("binding", "is in another environment")
	case scope.RequestEnvironmentID == nil || *scope.RequestEnvironmentID != task.EnvironmentID:
		return nil, obsViolation("binding", "is not in the request's environment")
	case scope.RequestProjectID != "" && scope.RequestProjectID != scope.BindingProjectID.String():
		return nil, obsViolation("binding", "is not in the request's project")
	case scope.BindingDeleted || !scope.BindingEnabled:
		return nil, obsViolation("binding", "is no longer live")
	}
	out := map[string]*storage.GatewayConnector{}
	for _, st := range *res.Stages {
		ref := refs[st.Stage]
		if st.Source.ConnectorID != ref.ConnectorID || st.Source.TargetID != ref.TargetID {
			return nil, obsViolation("source", "is not the connector and target the task names")
		}
		conn, err := rt.ConnectorByName(ctx, task.GatewayID, st.Source.ConnectorID)
		if errors.Is(err, storage.ErrNotFound) {
			return nil, obsViolation("source.connector_id", "is not a connector of this gateway")
		}
		if err != nil {
			return nil, err
		}
		rules := obsRulesByStage[st.Stage]
		switch {
		case conn.Status != storage.GatewayConnectorApproved:
			return nil, obsViolation("source.connector_id", "is not approved")
		case conn.Kind != rules.connectorKind:
			return nil, obsViolation("source.connector_id", "is not of the stage's kind")
		case st.Stage == StageArgoCDContext && (scope.ArgoCDConnectorID == nil || *scope.ArgoCDConnectorID != conn.ID || scope.ArgoCDTargetID != st.Source.TargetID):
			return nil, obsViolation("source", "is not the binding's connector and target")
		case st.Resource != nil && st.Resource.Kind != rules.kind:
			return nil, obsViolation("resource.kind", "does not match the connector kind")
		}
		if err := resourceMatchesTarget(conn, st); err != nil {
			return nil, err
		}
		if err := identityMatchesPin(conn, st); err != nil {
			return nil, err
		}
		out[st.Stage] = conn
	}
	return out, nil
}

// resourceMatchesTarget ties the object the evidence describes to the
// target the Gateway advertised: resource.name must be the advertised
// name, and resource.namespace the advertised namespace when the
// catalog carried one (an Argo CD target advertises its app namespace
// only for "apps in any namespace"). A target with no advertised name
// cannot be tied to an object and is refused. An error stage carries no
// resource and is not checked.
func resourceMatchesTarget(conn *storage.GatewayConnector, st StageEvidence) error {
	if st.Resource == nil {
		return nil
	}
	target, ok := conn.Target(st.Source.TargetID)
	switch {
	case !ok:
		return obsViolation("source.target_id", "is not advertised by the connector")
	case target.Name == "":
		return obsViolation("source.target_id", "has no advertised object name")
	case st.Resource.Name != target.Name:
		return obsViolation("resource.name", "is not the object the target advertises")
	case target.Namespace != "" && st.Resource.Namespace != target.Namespace:
		return obsViolation("resource.namespace", "is not the namespace the target advertises")
	}
	return nil
}

// Identity refusal codes (api#312), the 422 error code and the
// observation.evidence.rejected reason.
const (
	RefusalTargetIdentityChanged = "target_identity_changed"
	// RefusalTargetSnapshotStale is the E7 refusal reason of a replica
	// with no usable snapshot (api#308).
	RefusalTargetSnapshotStale   = "target_snapshot_stale"
	RefusalIdentityDigestMissing = "identity_digest_missing"
	RefusalIdentityDigestMatch   = "identity_digest_mismatch"
)

type identityRefusal struct{ code string }

func (e *identityRefusal) Error() string {
	return ErrObservationIdentityRefused.Error() + ": " + e.code
}
func (e *identityRefusal) Is(target error) bool { return target == ErrObservationIdentityRefused }

// IdentityRefusalCode returns the closed code of an identity refusal, or
// "" for any other error.
func IdentityRefusalCode(err error) string {
	var r *identityRefusal
	if errors.As(err, &r) {
		return r.code
	}
	return ""
}

// identityMatchesPin is the control-plane identity pin (api#312, ADR
// 0002 C3). A target that is identity_changed takes no evidence at all,
// an error stage included, until a platform admin re-confirms. A pinned
// target takes a stage that describes an object only when its
// resource.identity_digest is the pin; a missing digest is refused too.
// A target with no pin (a Gateway that predates the identity, or one
// that has not learned the uid yet) is checked by name as before.
func identityMatchesPin(conn *storage.GatewayConnector, st StageEvidence) error {
	target, ok := conn.Target(st.Source.TargetID)
	switch {
	case !ok:
		return nil // resourceMatchesTarget refuses a stage with a resource
	case target.Suspended():
		return &identityRefusal{RefusalTargetIdentityChanged}
	case target.IdentityDigest == "" || st.Resource == nil:
		return nil
	case st.Resource.IdentityDigest == "":
		return &identityRefusal{RefusalIdentityDigestMissing}
	case st.Resource.IdentityDigest != target.IdentityDigest:
		return &identityRefusal{RefusalIdentityDigestMatch}
	}
	return nil
}

// reportIdentityChanged is the Gateway-reported half of the identity
// pin (api#314). An integrator who pins applications[].uid in the
// Gateway settings makes the Gateway compute its catalog identity from
// that uid, so a recreated Application never changes the advertised
// digest: the Gateway refuses the object and posts an error stage with
// error_code target_identity_changed instead. An accepted such stage
// for a pinned Argo CD target marks the target identity_changed like a
// catalog change does (bindings suspended, dispatch skipped, new binds
// refused) and audits gateway.target.identity_changed once, with
// trigger gateway_reported, in this transaction. Later stages for the
// target are refused as target_identity_changed, and the storage call
// re-reads the target under a row lock, so the row is never repeated.
// Nothing from the stage is pinned: it carries no uid or digest.
func (s *GatewayObservationService) reportIdentityChanged(ctx context.Context, rt *storage.ObservationResultTx, res *EvidenceResult, attempt *storage.ObservationTaskAttempt, connectors map[string]*storage.GatewayConnector) error {
	task := rt.Task
	for _, st := range *res.Stages {
		conn := connectors[st.Stage]
		if st.Stage != StageArgoCDContext || conn == nil || conn.Kind != GatewayKindArgoCD ||
			st.Outcome != OutcomeError || st.ErrorCode != RefusalTargetIdentityChanged {
			continue
		}
		ch, err := rt.ReportTargetIdentityChanged(ctx, conn.ID, st.Source.TargetID)
		if err != nil {
			return err
		}
		if ch == nil {
			continue
		}
		if err := rt.Audit(ctx, s.audit, &storage.AuditEvent{
			Actor: gatewayActor(task.GatewayID), Action: "gateway.target.identity_changed", Resource: gatewayActor(task.GatewayID),
			Status: storage.AuditStatusFailure, CorrelationID: task.CorrelationID,
			Metadata: map[string]any{
				"gateway_id": task.GatewayID.String(), "connector_id": ch.ConnectorID.String(), "argocd_target_id": ch.TargetID,
				"identity_digest_before": ch.Old, "identity_digest_after": ch.New, "bindings_suspended": ch.Bindings,
				"trigger": storage.GatewayIdentityTriggerReported, "task_id": task.ID.String(), "attempt_id": attempt.AttemptID.String(),
			},
		}); err != nil {
			return err
		}
	}
	return nil
}

// checkWindow is design section 4.8 rule 9: observed_at within
// [started_at - skew, finished_at + skew], finished_at not after the CP
// clock plus skew, started_at not before the claim minus skew.
func checkWindow(res *EvidenceResult, attempt *storage.ObservationTaskAttempt, now time.Time, skew time.Duration) error {
	if res.finished.Before(res.started) {
		return fmt.Errorf("%w: finished_at is before started_at", ErrObservationOutOfWindow)
	}
	if res.finished.After(now.Add(skew)) {
		return fmt.Errorf("%w: finished_at is in the future", ErrObservationOutOfWindow)
	}
	if res.started.Before(attempt.ClaimedAt.Add(-skew)) {
		return fmt.Errorf("%w: started_at is before the claim", ErrObservationOutOfWindow)
	}
	for _, st := range *res.Stages {
		if st.observedAt.Before(res.started.Add(-skew)) || st.observedAt.After(res.finished.Add(skew)) {
			return fmt.Errorf("%w: observed_at is outside the attempt", ErrObservationOutOfWindow)
		}
	}
	return nil
}

func ceilSecond(t time.Time) time.Time {
	r := t.Truncate(time.Second)
	if r.Before(t) {
		r = r.Add(time.Second)
	}
	return r
}

// cpOutcome recomputes a stage outcome from its facts (ADR 0001 section
// 2.3). writeBound is ceil(executed_at + skew); skewSuspected bars
// observed.
func cpOutcome(st *StageEvidence, writeBound time.Time, skewSuspected bool) string {
	reported := st.Outcome
	switch reported {
	case OutcomeError, OutcomeUnverifiable, OutcomeNotApplicable:
		// The CP cannot see what made the Gateway say so (an unreadable
		// object, a project outside the allow list, a volume consumer);
		// these never claim more than the facts, so they stand.
		return reported
	}
	switch st.Stage {
	case StageArgoCDContext:
		f := st.argocd
		if f == nil {
			return OutcomeNotObserved
		}
		rec, ok := obsTime(f.ReconciledAt)
		idle := f.OperationPhase == "" || f.OperationPhase == "Succeeded"
		if !skewSuspected && f.HealthStatus == "Healthy" && f.SyncStatus == "Synced" && idle && ok && rec.After(writeBound) {
			return OutcomeObserved
		}
		return OutcomeNotObserved
	case StageESOSync:
		f := st.eso
		if f == nil {
			return OutcomeNotObserved
		}
		if lt, ok := obsTime(f.ReadyLastTransitionTime); ok && f.ReadyStatus == "False" && lt.After(writeBound) {
			return OutcomeFailed
		}
		ref, ok := obsTime(f.RefreshTime)
		if !skewSuspected && f.ReadyStatus == "True" && f.ReadyReason == "SecretSynced" && ok && ref.After(writeBound) &&
			f.RemoteRefMatch == "match" && f.RemoteVersionPin != "other_version" {
			return OutcomeObserved
		}
		return OutcomeNotObserved
	case StageWorkloadRollout:
		f := st.rollout
		if f == nil {
			return OutcomeNotObserved
		}
		if f.ProgressingReason == "ProgressDeadlineExceeded" && reported == OutcomeFailed {
			return OutcomeFailed
		}
		complete := f.UpdatedReplicas != nil && f.Replicas != nil && f.AvailableReplicas != nil &&
			*f.ObservedGeneration >= *f.Generation && *f.UpdatedReplicas == *f.SpecReplicas &&
			*f.Replicas == *f.UpdatedReplicas && *f.AvailableReplicas == *f.UpdatedReplicas
		rs, ok := obsTime(f.NewestReplicaSetCreatedAt)
		if !skewSuspected && reported == OutcomeObserved && complete && *f.SpecReplicas > 0 &&
			(f.RolloutTrigger == "replicaset_revision_bumped_after_change" || (ok && rs.After(writeBound))) {
			return OutcomeObserved
		}
		return OutcomeNotObserved
	}
	return OutcomeNotObserved
}

func terminalOutcome(o string) bool {
	return o == OutcomeObserved || o == OutcomeNotApplicable || o == OutcomeUnverifiable || o == OutcomeFailed
}

// computeVerdict is ADR 0001 section 2.4 over the task's latest CP
// outcome per expected stage. final is false while any expected stage
// is not terminal.
func computeVerdict(expected []string, stages map[string]storage.ObservationStageState, versionSource string) (final bool, verdict storage.ObservationVerdict, reason string) {
	for _, st := range expected {
		if !terminalOutcome(stages[st].Outcome) {
			return false, storage.ObservationVerdictPending, ""
		}
	}
	for _, st := range expected {
		if stages[st].Outcome == OutcomeFailed {
			return true, storage.ObservationVerdictUnverified, storage.ObservationReasonFailureObserved
		}
	}
	has := func(s string) bool { return slices.Contains(expected, s) }
	eso, rollout := stages[StageESOSync].Outcome, stages[StageWorkloadRollout].Outcome
	gatewayObserved := (has(StageESOSync) && eso == OutcomeObserved) || (has(StageWorkloadRollout) && rollout == OutcomeObserved)
	if has(StageESOSync) && eso == OutcomeObserved && (!has(StageWorkloadRollout) || rollout == OutcomeObserved) {
		if versionSource == "agent_reported" {
			return true, storage.ObservationVerdictVerified, ""
		}
		return true, storage.ObservationVerdictPartiallyObserved, storage.ObservationReasonNoProviderVersion
	}
	if gatewayObserved {
		reason = ""
		if versionSource != "agent_reported" {
			reason = storage.ObservationReasonNoProviderVersion
		}
		return true, storage.ObservationVerdictPartiallyObserved, reason
	}
	onlyContext := true
	for _, st := range expected {
		onlyContext = onlyContext && st == StageArgoCDContext
	}
	if onlyContext && stages[StageArgoCDContext].Outcome == OutcomeObserved {
		// Argo CD Healthy and Synced: observed operational state, never
		// proof that the secret change propagated.
		return true, storage.ObservationVerdictUnverified, storage.ObservationReasonContextOnly
	}
	return true, storage.ObservationVerdictUnverified, storage.ObservationReasonNoStageObserved
}

// rescheduleBackoff is design section 5.1: 15s, 30s, 60s, capped at
// 120s, by pass number.
func rescheduleBackoff(passes int) time.Duration {
	if passes < 1 {
		passes = 1
	}
	d := time.Duration(15*math.Pow(2, float64(min(passes-1, 4)))) * time.Second
	return min(d, 120*time.Second)
}

func (s *GatewayObservationService) accept(ctx context.Context, rt *storage.ObservationResultTx, res *EvidenceResult, attempt *storage.ObservationTaskAttempt, connectors map[string]*storage.GatewayConnector, digest []byte, skew time.Duration) (*ObservationResultResponse, error) {
	task := rt.Task
	gatewayID := task.GatewayID
	actor := gatewayActor(gatewayID)
	replica, _ := uuid.Parse(res.ReplicaID)
	offsets := absMS(res.Clock.CPOffsetMS) + absMS(res.Clock.APIServerOffsetMS)
	skewSuspected := offsets > s.cfg.ClockSkewBound
	writeBound := ceilSecond(task.ExecutedAt.Add(skew))

	stages := map[string]storage.ObservationStageState{}
	for k, v := range task.Stages {
		stages[k] = v
	}
	failures := task.FailureCount
	if res.AttemptStatus == "refused" && res.RefusalReason != RefusalTargetSnapshotStale {
		failures++
	}
	var stageNames, outcomes, linkages []string
	for i := range *res.Stages {
		st := &(*res.Stages)[i]
		cp := cpOutcome(st, writeBound, skewSuspected)
		var cpCaveats []string
		if st.Stage == StageArgoCDContext && !slices.Contains(*st.Caveats, CaveatArgoCDHealthNotProof) {
			cpCaveats = append(cpCaveats, CaveatArgoCDHealthNotProof)
		}
		if skewSuspected {
			cpCaveats = append(cpCaveats, CaveatClockSkewSuspected)
		}
		if cp == OutcomeError {
			failures++
		}
		body, err := st.stageBody()
		if err != nil {
			return nil, fmt.Errorf("observations: stage body: %w", err)
		}
		ev := &storage.ObservationEvidence{
			TaskID: task.ID, AttemptID: attempt.AttemptID, GatewayID: gatewayID, ReplicaID: replica,
			GatewayVersion: res.GatewayVersion, SchemaVersion: res.SchemaVersion, Stage: st.Stage,
			ConnectorID: connectors[st.Stage].ID, ReportedOutcome: st.Outcome, CPOutcome: cp, Linkage: st.Linkage,
			CPCaveats: cpCaveats, ObservedAt: st.observedAt, Body: body, BodySHA256: digest,
		}
		if err := rt.InsertEvidence(ctx, ev); err != nil {
			return nil, err
		}
		stages[st.Stage] = storage.ObservationStageState{Outcome: cp, ObservedAt: st.observedAt.UTC(), EvidenceID: ev.ID}
		stageNames = append(stageNames, st.Stage)
		outcomes = append(outcomes, st.Stage+":"+cp)
		linkages = append(linkages, st.Stage+":"+st.Linkage)
		if cp != st.Outcome {
			if err := rt.Audit(ctx, s.audit, &storage.AuditEvent{
				Actor: actor, Action: "gateway.evidence.outcome_mismatch", Resource: taskResource(task.ID),
				Status: storage.AuditStatusSuccess, CorrelationID: task.CorrelationID,
				Metadata: map[string]any{
					"task_id": task.ID.String(), "attempt_id": attempt.AttemptID.String(), "gateway_id": gatewayID.String(),
					"stage": st.Stage, "reported_outcome": st.Outcome, "cp_outcome": cp,
				},
			}); err != nil {
				return nil, err
			}
		}
	}

	if err := s.reportIdentityChanged(ctx, rt, res, attempt, connectors); err != nil {
		return nil, err
	}

	final, verdict, reason := computeVerdict(task.ExpectedStages, stages, task.VersionSource)
	upd := storage.ObservationTaskUpdate{Stages: stages, FailureCount: failures, NotBefore: rt.Now}
	next := "none"
	switch {
	case final:
		upd.State, upd.Verdict, upd.VerdictReason = storage.ObservationTaskDone, verdict, reason
	case failures >= task.MaxFailures:
		upd.State, upd.Verdict, upd.VerdictReason = storage.ObservationTaskDead, storage.ObservationVerdictUnverified, storage.ObservationReasonGatewayErrors
	default:
		upd.State, upd.Verdict = storage.ObservationTaskQueued, storage.ObservationVerdictPending
		upd.NotBefore = rt.Now.Add(rescheduleBackoff(task.AttemptCount))
		next = "rescheduled"
	}
	resp := &ObservationResultResponse{Status: "accepted", TaskState: string(upd.State), Verdict: string(upd.Verdict), Next: next}
	if err := rt.AcceptResult(ctx, attempt.AttemptID, digest, resp, upd); err != nil {
		return nil, err
	}

	meta := map[string]any{
		"task_id": task.ID.String(), "attempt_id": attempt.AttemptID.String(), "gateway_id": gatewayID.String(),
		"replica_id": res.ReplicaID, "attempt_status": res.AttemptStatus, "sha256": fmt.Sprintf("%x", digest),
		"task_state": string(upd.State), "verdict": string(upd.Verdict), "next": next, "failure_count": failures,
	}
	if res.RefusalReason != "" {
		meta["refusal_reason"] = res.RefusalReason
	}
	if len(stageNames) > 0 {
		meta["stages"], meta["outcomes"], meta["linkages"] = stageNames, outcomes, linkages
	}
	if err := rt.Audit(ctx, s.audit, &storage.AuditEvent{
		Actor: actor, Action: "observation.evidence.accepted", Resource: taskResource(task.ID),
		Status: storage.AuditStatusSuccess, CorrelationID: task.CorrelationID, Metadata: meta,
	}); err != nil {
		return nil, err
	}
	if upd.Verdict != storage.ObservationVerdictPending {
		action := "observation.task.verdict"
		if upd.State == storage.ObservationTaskDead {
			action = "observation.task.dead"
		}
		if err := rt.Audit(ctx, s.audit, &storage.AuditEvent{
			Actor: actor, Action: action, Resource: taskResource(task.ID),
			Status: storage.AuditStatusSuccess, CorrelationID: task.CorrelationID,
			Metadata: map[string]any{
				"task_id": task.ID.String(), "request_id": task.RequestID.String(), "gateway_id": gatewayID.String(),
				"task_state": string(upd.State), "verdict": string(upd.Verdict), "verdict_reason": upd.VerdictReason,
			},
		}); err != nil {
			return nil, err
		}
	}
	return resp, nil
}

// ---- deadline view -------------------------------------------------------------------

// Closing a task past its deadline is the worker's job: the
// observation-deadlines sweeper (worker#39) runs
// storage.ObservationTasks.ExpireDeadlines for every task and audits
// observation.task.timed_out; a claim or result on such a task closes it
// too. A read never writes. Between the deadline and the next sweep, or
// when the api runs with SB_GATEWAY_ENABLED but the worker sweepers are
// off, a read renders the overdue task as timed out instead (api#297),
// so an offline Gateway never shows pending past its deadline.

// timedOutAtRead returns the view of an open task whose deadline is at or
// before now: done, timed_out, with the reason ExpireDeadlines would
// write, and terminal at the deadline. The row is not changed. ok is
// false for a task that is not open or not overdue.
func timedOutAtRead(t *storage.ObservationTask, now time.Time) (view *storage.ObservationTask, ok bool) {
	if t.State != storage.ObservationTaskQueued && t.State != storage.ObservationTaskLeased {
		return t, false
	}
	if t.DeadlineAt.After(now) {
		return t, false
	}
	v := *t
	v.State, v.Verdict = storage.ObservationTaskDone, storage.ObservationVerdictTimedOut
	v.VerdictReason = storage.ObservationReasonDeadlineReached
	if t.GatewayUnavailable {
		v.VerdictReason = storage.ObservationReasonGatewayUnavailable
	}
	at := t.DeadlineAt
	v.TerminalAt = &at
	v.CurrentAttemptID, v.LeaseExpiresAt, v.LeasedReplicaID, v.LeasedAt = nil, nil, nil, nil
	return &v, true
}

// ---- reads --------------------------------------------------------------------------

// ObservationRollupNone is the request rollup when no task exists: no
// observation configured, which is not a failure.
const ObservationRollupNone = "none"

// RollupVerdict combines a request's task verdicts: pending while any
// task is pending; verified only if every task is; partially_observed if
// any is verified or partially observed; timed_out only if every task
// timed out; otherwise unverified. No task is "none" (no observation
// configured), which is not a failure.
func RollupVerdict(tasks []*storage.ObservationTask) string {
	if len(tasks) == 0 {
		return ObservationRollupNone
	}
	all := func(v storage.ObservationVerdict) bool {
		for _, t := range tasks {
			if t.Verdict != v {
				return false
			}
		}
		return true
	}
	anyOf := func(vs ...storage.ObservationVerdict) bool {
		for _, t := range tasks {
			if slices.Contains(vs, t.Verdict) {
				return true
			}
		}
		return false
	}
	switch {
	case anyOf(storage.ObservationVerdictPending):
		return string(storage.ObservationVerdictPending)
	case all(storage.ObservationVerdictVerified):
		return string(storage.ObservationVerdictVerified)
	case anyOf(storage.ObservationVerdictVerified, storage.ObservationVerdictPartiallyObserved):
		return string(storage.ObservationVerdictPartiallyObserved)
	case all(storage.ObservationVerdictTimedOut):
		return string(storage.ObservationVerdictTimedOut)
	}
	return string(storage.ObservationVerdictUnverified)
}

// RequestObservationView is the request page's evidence.
type RequestObservationView struct {
	Source   storage.ObservationSource
	Rollup   string
	Tasks    []*storage.ObservationTask
	Evidence map[uuid.UUID][]*storage.ObservationEvidence
	// TimedOutAtRead holds the tasks shown as timed out because their
	// deadline passed while the row is still open (not yet swept).
	TimedOutAtRead map[uuid.UUID]bool
}

// RequestObservations returns a request's Gateway tasks and their latest
// accepted evidence per stage. It never writes: an open task past its
// deadline is shown as timed out without closing it (see timedOutAtRead).
func (s *GatewayObservationService) RequestObservations(ctx context.Context, req *storage.AccessRequest) (*RequestObservationView, error) {
	rows, err := s.store.ListForRequest(ctx, req.ID)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	tasks := make([]*storage.ObservationTask, 0, len(rows))
	readTimedOut := map[uuid.UUID]bool{}
	ids := make([]uuid.UUID, 0, len(rows))
	for _, t := range rows {
		v, ok := timedOutAtRead(t, now)
		if ok {
			readTimedOut[t.ID] = true
		}
		tasks = append(tasks, v)
		ids = append(ids, t.ID)
	}
	evs, err := s.store.LatestEvidence(ctx, ids)
	if err != nil {
		return nil, err
	}
	v := &RequestObservationView{
		Rollup: RollupVerdict(tasks), Tasks: tasks,
		Evidence: map[uuid.UUID][]*storage.ObservationEvidence{}, TimedOutAtRead: readTimedOut,
	}
	for _, e := range evs {
		v.Evidence[e.TaskID] = append(v.Evidence[e.TaskID], e)
	}
	if src, err := s.Source(ctx, req.EnvironmentID); err == nil {
		v.Source = src
	}
	return v, nil
}

// GatewayTasks lists a Gateway's tasks for the admin page.
func (s *GatewayObservationService) GatewayTasks(ctx context.Context, gatewayID uuid.UUID, state string, limit int) ([]*storage.ObservationTask, error) {
	st := storage.ObservationTaskState(state)
	if st != "" && !slices.Contains(observationTaskStates, st) {
		return nil, ErrObservationInvalidRequest
	}
	return s.store.ListForGateway(ctx, gatewayID, st, limit)
}

// GatewayTaskCounts returns the number of a Gateway's tasks in every
// state, over all of its tasks; a state with none is 0.
func (s *GatewayObservationService) GatewayTaskCounts(ctx context.Context, gatewayID uuid.UUID) (map[string]int, error) {
	got, err := s.store.CountForGateway(ctx, gatewayID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]int, len(observationTaskStates))
	for _, st := range observationTaskStates {
		out[string(st)] = got[st]
	}
	return out, nil
}

// observationTaskStates is every task state, in lifecycle order.
var observationTaskStates = []storage.ObservationTaskState{
	storage.ObservationTaskQueued, storage.ObservationTaskLeased, storage.ObservationTaskDone,
	storage.ObservationTaskDead, storage.ObservationTaskCancelled,
}

// ObservationLabel is how every Gateway-sourced line is labelled: what
// the Gateway saw, attested from the customer side, as operational
// state. It is never proof that a secret value propagated.
const ObservationLabel = "observed_operational_state"

// evidenceStageFacts returns the display facts of an Argo CD stage: the
// enums and timestamps, never the resource namespace or name (those are
// admin display only, ADR 0001 section 11).
func evidenceStageFacts(body json.RawMessage) (facts map[string]any, caveats []string, confidence, linkage string) {
	var b struct {
		Facts      map[string]any `json:"facts"`
		Caveats    []string       `json:"caveats"`
		Confidence string         `json:"confidence"`
		Linkage    string         `json:"linkage"`
		ErrorCode  string         `json:"error_code"`
	}
	_ = json.Unmarshal(body, &b)
	if b.Facts == nil {
		b.Facts = map[string]any{}
	}
	if b.ErrorCode != "" {
		b.Facts["error_code"] = b.ErrorCode
	}
	return b.Facts, b.Caveats, b.Confidence, b.Linkage
}

// EvidenceDisplay is one stage line for the request page.
type EvidenceDisplay struct {
	Stage           string         `json:"stage"`
	Outcome         string         `json:"outcome"`
	ReportedOutcome string         `json:"reported_outcome"`
	ObservedAt      string         `json:"observed_at"`
	ReceivedAt      string         `json:"received_at"`
	GatewayID       string         `json:"gateway_id"`
	ReplicaID       string         `json:"replica_id"`
	AttemptID       string         `json:"attempt_id"`
	ConnectorID     string         `json:"connector_id"`
	TargetID        string         `json:"target_id"`
	Confidence      string         `json:"confidence"`
	Linkage         string         `json:"linkage"`
	Caveats         []string       `json:"caveats"`
	Facts           map[string]any `json:"facts"`
	Label           string         `json:"label"`
}

// DisplayEvidence turns an evidence row into its request-page line.
func DisplayEvidence(e *storage.ObservationEvidence, refs []storage.ObservationConnectorRef) EvidenceDisplay {
	facts, caveats, confidence, linkage := evidenceStageFacts(e.Body)
	all := append([]string{}, caveats...)
	for _, c := range e.CPCaveats {
		if !slices.Contains(all, c) {
			all = append(all, c)
		}
	}
	if e.Stage == StageArgoCDContext && !slices.Contains(all, CaveatArgoCDHealthNotProof) {
		all = append(all, CaveatArgoCDHealthNotProof)
	}
	d := EvidenceDisplay{
		Stage: e.Stage, Outcome: e.CPOutcome, ReportedOutcome: e.ReportedOutcome,
		ObservedAt: rfc3339(e.ObservedAt), ReceivedAt: rfc3339(e.ReceivedAt),
		GatewayID: e.GatewayID.String(), ReplicaID: e.ReplicaID.String(), AttemptID: e.AttemptID.String(),
		Confidence: confidence, Linkage: linkage, Caveats: all, Facts: facts, Label: ObservationLabel,
	}
	if linkage == "" {
		d.Linkage = e.Linkage
	}
	for _, r := range refs {
		if r.Stage == e.Stage {
			d.ConnectorID, d.TargetID = r.ConnectorID, r.TargetID
		}
	}
	return d
}
