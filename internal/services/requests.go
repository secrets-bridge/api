// Package services — requests.go: the secret-update request lifecycle.
//
// A "patch" request is the UI-driven flow where a developer proposes
// new values for one-or-more keys inside an existing provider secret
// (e.g. set DB_PASSWORD on `secret/data/app` in Vault). The plaintext
// never lands in PostgreSQL: the service wraps each value via
// WrapService.Wrap (envelope-encrypted in Postgres) and only stores
// the wrap IDs against the access_request row.
//
// State machine:
//
//	pending --approve(≥ MinApprovers)--> approved --(agent claims)--> executed
//	   |                  ^                  |
//	   |--reject------>rejected              |--fail-->failed
//	   |--cancel----->cancelled              |--ttl--->expired
//
// Every state transition emits an audit event with the same
// CorrelationID — the access_request UUID — so the entire lifecycle
// can be replayed from audit_events alone.
package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// JobEnqueuer is the slice of *JobService that RequestService needs.
// Decoupling the type lets the test harness inject a fake without
// dragging audit + repo plumbing.
type JobEnqueuer interface {
	Enqueue(ctx context.Context, req EnqueueRequest) (*storage.SyncJob, error)
}

// RequestService orchestrates the patch-request lifecycle.
type RequestService struct {
	requests  storage.AccessRequestRepository
	approvals storage.ApprovalRepository
	wraps     *WrapService
	workflows storage.WorkflowRepository
	policy    *PolicyEngine
	audit     storage.AuditEventRepository
	jobs      JobEnqueuer
	now       func() time.Time
}

// NewRequestService wires a RequestService to its dependencies. The
// jobs argument may be nil — when nil, Approve will not enqueue a
// follow-up job (useful for the older test harnesses; production
// always wires a JobService).
func NewRequestService(
	requests storage.AccessRequestRepository,
	approvals storage.ApprovalRepository,
	wraps *WrapService,
	workflows storage.WorkflowRepository,
	policy *PolicyEngine,
	audit storage.AuditEventRepository,
	jobs JobEnqueuer,
) *RequestService {
	return &RequestService{
		requests:  requests,
		approvals: approvals,
		wraps:     wraps,
		workflows: workflows,
		policy:    policy,
		audit:     audit,
		jobs:      jobs,
		now:       time.Now,
	}
}

// PatchInput is the data the UI POSTs to submit a patch request.
//
// KeyValues is map[keyName]plaintext. The service zeroes each entry
// after wrapping; callers MUST NOT reuse the slices.
type PatchInput struct {
	RequesterID          string
	ProjectID            string
	Environment          string
	TargetProviderType   string
	TargetProviderConfig map[string]any
	TargetSecretRef      string
	KeyValues            map[string][]byte
	Justification        string
}

// ReadInput is the data the UI POSTs to submit a read request. There
// are no values — the user is asking the system to FETCH them.
//
// TargetKeys lists the keys inside the provider's secret bundle the
// requester wants to view. An empty list means "all keys in the
// bundle" — the agent's ReadExecutor returns one wrap per key in
// whatever GetValue brings back.
type ReadInput struct {
	RequesterID          string
	ProjectID            string
	Environment          string
	TargetProviderType   string
	TargetProviderConfig map[string]any
	TargetSecretRef      string
	TargetKeys           []string
	Justification        string
}

// Sentinel errors. Map to HTTP at the handler layer.
var (
	ErrInvalidInput      = errors.New("services: invalid input")
	ErrSelfApprovalDenied = errors.New("services: requester cannot approve own request")
	ErrDuplicateVote     = errors.New("services: approver already voted")
	ErrRequestNotPending = errors.New("services: request is not pending")
	ErrNotRequester      = errors.New("services: only the requester can cancel")
)

// Submit creates a patch request, wraps each key's plaintext under
// the workflow's created-TTL, and persists everything in one logical
// operation. The returned AccessRequest has its ID + timestamps set.
//
// On any failure after wraps were created but before the request row
// was created, the orphan wraps will simply expire on their TTL — no
// rollback needed because nothing references them yet.
func (s *RequestService) Submit(ctx context.Context, in PatchInput) (*storage.AccessRequest, error) {
	if in.RequesterID == "" || in.TargetProviderType == "" || in.TargetSecretRef == "" {
		return nil, fmt.Errorf("%w: requester_id, target_provider_type, target_secret_ref required", ErrInvalidInput)
	}
	if len(in.KeyValues) == 0 {
		return nil, fmt.Errorf("%w: at least one key/value required", ErrInvalidInput)
	}
	if in.Justification == "" {
		return nil, fmt.Errorf("%w: justification required", ErrInvalidInput)
	}

	wf, _, err := s.policy.Resolve(ctx, Scope{
		ProjectID:       in.ProjectID,
		Environment:     in.Environment,
		ProviderType:    in.TargetProviderType,
		SecretRefPrefix: in.TargetSecretRef,
	})
	if err != nil {
		return nil, fmt.Errorf("services: resolve workflow: %w", err)
	}

	keys := make([]string, 0, len(in.KeyValues))
	for k := range in.KeyValues {
		keys = append(keys, k)
	}

	wfID := wf.ID
	req := &storage.AccessRequest{
		RequesterID:          in.RequesterID,
		Type:                 storage.AccessRequestTypePatch,
		Justification:        in.Justification,
		WorkflowID:           &wfID,
		TargetProviderType:   in.TargetProviderType,
		TargetProviderConfig: in.TargetProviderConfig,
		TargetSecretRef:      in.TargetSecretRef,
		TargetKeys:           keys,
		TargetScope: map[string]any{
			"project_id":  in.ProjectID,
			"environment": in.Environment,
		},
	}
	if err := s.requests.Create(ctx, req); err != nil {
		return nil, fmt.Errorf("services: create request: %w", err)
	}

	// Wrap each plaintext under the workflow's created-TTL. Each wrap
	// is tied back to req.ID via RequestID and tagged with the key
	// name so the agent retrieving them later knows which key inside
	// the provider's secret bundle each value belongs to.
	for k, v := range in.KeyValues {
		_, err := s.wraps.Wrap(ctx, WrapRequest{
			Plaintext: v,
			RequestID: &req.ID,
			KeyName:   k,
			TTL:       wf.WrapTTLCreated,
			Actor:     "user:" + in.RequesterID,
		})
		// Caller's slice is zeroed by Wrap on success, but make sure on
		// error too — never leave plaintext sitting in the caller's map.
		zero(v)
		if err != nil {
			return nil, fmt.Errorf("services: wrap key %q: %w", k, err)
		}
	}

	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:         "user:" + in.RequesterID,
		Action:        "request.submit",
		Resource:      "request:" + req.ID.String(),
		Status:        storage.AuditStatusSuccess,
		CorrelationID: req.ID,
		Metadata: map[string]any{
			"workflow_id":          wf.ID.String(),
			"target_provider_type": in.TargetProviderType,
			"target_secret_ref":    in.TargetSecretRef,
			"key_count":            len(keys),
			"min_approvers":        wf.MinApprovers,
		},
	})
	return req, nil
}

// SubmitRead creates a read request — the requester wants to VIEW
// existing values from the provider, not write new ones. No wraps are
// created at submit time; the agent's ReadExecutor produces wraps
// AFTER approval via the agent-side wrap-creation endpoint.
//
// TargetKeys may be empty — that signals "all keys in the bundle".
// The ReadExecutor decides what to do with that; the service layer
// stores it as-is so the audit trail captures the original intent.
func (s *RequestService) SubmitRead(ctx context.Context, in ReadInput) (*storage.AccessRequest, error) {
	if in.RequesterID == "" || in.TargetProviderType == "" || in.TargetSecretRef == "" {
		return nil, fmt.Errorf("%w: requester_id, target_provider_type, target_secret_ref required", ErrInvalidInput)
	}
	if in.Justification == "" {
		return nil, fmt.Errorf("%w: justification required", ErrInvalidInput)
	}

	wf, _, err := s.policy.Resolve(ctx, Scope{
		ProjectID:       in.ProjectID,
		Environment:     in.Environment,
		ProviderType:    in.TargetProviderType,
		SecretRefPrefix: in.TargetSecretRef,
	})
	if err != nil {
		return nil, fmt.Errorf("services: resolve workflow: %w", err)
	}

	keys := in.TargetKeys
	if keys == nil {
		keys = []string{}
	}

	wfID := wf.ID
	req := &storage.AccessRequest{
		RequesterID:          in.RequesterID,
		Type:                 storage.AccessRequestTypeRead,
		Justification:        in.Justification,
		WorkflowID:           &wfID,
		TargetProviderType:   in.TargetProviderType,
		TargetProviderConfig: in.TargetProviderConfig,
		TargetSecretRef:      in.TargetSecretRef,
		TargetKeys:           keys,
		TargetScope: map[string]any{
			"project_id":  in.ProjectID,
			"environment": in.Environment,
		},
	}
	if err := s.requests.Create(ctx, req); err != nil {
		return nil, fmt.Errorf("services: create read request: %w", err)
	}

	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:         "user:" + in.RequesterID,
		Action:        "request.submit",
		Resource:      "request:" + req.ID.String(),
		Status:        storage.AuditStatusSuccess,
		CorrelationID: req.ID,
		Metadata: map[string]any{
			"workflow_id":          wf.ID.String(),
			"request_type":         string(req.Type),
			"target_provider_type": in.TargetProviderType,
			"target_secret_ref":    in.TargetSecretRef,
			"key_count":            len(keys),
			"min_approvers":        wf.MinApprovers,
		},
	})
	return req, nil
}

// Approve records an approval vote. When the vote count crosses the
// workflow threshold the request transitions to approved and all
// associated wraps get their TTL refreshed to WrapTTLApproved.
//
// Errors:
//   - ErrRequestNotPending if request is already decided
//   - ErrSelfApprovalDenied if approverID == requesterID and the
//     workflow disallows self-approval
//   - ErrDuplicateVote if approverID has already voted on this request
func (s *RequestService) Approve(ctx context.Context, requestID uuid.UUID, approverID, comment string) (*storage.AccessRequest, error) {
	if approverID == "" {
		return nil, fmt.Errorf("%w: approver_id required", ErrInvalidInput)
	}
	req, err := s.requests.Get(ctx, requestID)
	if err != nil {
		return nil, err
	}
	if req.Status != storage.AccessRequestStatusPending {
		return nil, ErrRequestNotPending
	}
	if req.WorkflowID == nil {
		return nil, errors.New("services: request has no workflow (corrupt state)")
	}
	wf, err := s.workflows.Get(ctx, *req.WorkflowID)
	if err != nil {
		return nil, fmt.Errorf("services: load workflow: %w", err)
	}
	if approverID == req.RequesterID && !wf.AllowSelfApproval {
		return nil, ErrSelfApprovalDenied
	}

	// Idempotency: reject double-voting.
	existing, err := s.approvals.ListByRequest(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("services: list approvals: %w", err)
	}
	for _, a := range existing {
		if a.ApproverID == approverID {
			return nil, ErrDuplicateVote
		}
	}

	if err := s.approvals.Append(ctx, &storage.Approval{
		RequestID:  requestID,
		ApproverID: approverID,
		Decision:   storage.ApprovalDecisionApprove,
		Comment:    comment,
	}); err != nil {
		if errors.Is(err, storage.ErrApprovalExists) {
			return nil, ErrDuplicateVote
		}
		return nil, fmt.Errorf("services: append approval: %w", err)
	}

	counts, err := s.approvals.Counts(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("services: count approvals: %w", err)
	}

	threshold := wf.MinApprovers
	if threshold < 1 {
		threshold = 1
	}
	if counts.Approves >= threshold {
		if err := s.requests.UpdateStatus(ctx, requestID, storage.AccessRequestStatusApproved); err != nil {
			return nil, fmt.Errorf("services: mark approved: %w", err)
		}
		req.Status = storage.AccessRequestStatusApproved

		// Refresh every wrap tied to this request to the approved TTL.
		// On failure we log via audit but don't roll back the approval —
		// the wrap could still be picked up by the agent before its
		// shorter created-TTL expires; better to keep the approval and
		// emit a loud audit row than reject the user-visible action.
		if err := s.refreshWrapsForRequest(ctx, requestID, wf.WrapTTLApproved); err != nil {
			_ = s.audit.Append(ctx, &storage.AuditEvent{
				Actor:         "user:" + approverID,
				Action:        "request.refresh_ttl_failed",
				Resource:      "request:" + requestID.String(),
				Status:        storage.AuditStatusFailure,
				CorrelationID: requestID,
				Metadata:      map[string]any{"error": err.Error(), "phase": "approved"},
			})
		}

		// Enqueue the patch job so an agent can pick it up. Same
		// failure posture as TTL refresh: audit-on-failure but don't
		// roll back the approval — operators can re-issue the enqueue
		// out-of-band if the job persistence fails.
		if err := s.enqueueRequestJob(ctx, req); err != nil {
			_ = s.audit.Append(ctx, &storage.AuditEvent{
				Actor:         "user:" + approverID,
				Action:        "request.enqueue_job_failed",
				Resource:      "request:" + requestID.String(),
				Status:        storage.AuditStatusFailure,
				CorrelationID: requestID,
				Metadata:      map[string]any{"error": err.Error()},
			})
		}
	}

	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:         "user:" + approverID,
		Action:        "request.approve",
		Resource:      "request:" + requestID.String(),
		Status:        storage.AuditStatusSuccess,
		CorrelationID: requestID,
		Metadata: map[string]any{
			"approves":       counts.Approves,
			"required":       threshold,
			"became_approved": req.Status == storage.AccessRequestStatusApproved,
		},
	})
	return req, nil
}

// Reject closes the request and shortens wrap TTLs so the plaintext
// is purged sooner than the default 7d created-TTL.
func (s *RequestService) Reject(ctx context.Context, requestID uuid.UUID, approverID, reason string) (*storage.AccessRequest, error) {
	if approverID == "" {
		return nil, fmt.Errorf("%w: approver_id required", ErrInvalidInput)
	}
	if reason == "" {
		return nil, fmt.Errorf("%w: reason required", ErrInvalidInput)
	}
	req, err := s.requests.Get(ctx, requestID)
	if err != nil {
		return nil, err
	}
	if req.Status != storage.AccessRequestStatusPending {
		return nil, ErrRequestNotPending
	}
	if req.WorkflowID == nil {
		return nil, errors.New("services: request has no workflow (corrupt state)")
	}
	wf, err := s.workflows.Get(ctx, *req.WorkflowID)
	if err != nil {
		return nil, fmt.Errorf("services: load workflow: %w", err)
	}
	if approverID == req.RequesterID && !wf.AllowSelfApproval {
		return nil, ErrSelfApprovalDenied
	}

	if err := s.approvals.Append(ctx, &storage.Approval{
		RequestID:  requestID,
		ApproverID: approverID,
		Decision:   storage.ApprovalDecisionReject,
		Comment:    reason,
	}); err != nil {
		if errors.Is(err, storage.ErrApprovalExists) {
			return nil, ErrDuplicateVote
		}
		return nil, fmt.Errorf("services: append rejection: %w", err)
	}
	if err := s.requests.SetRejectReason(ctx, requestID, reason); err != nil {
		return nil, fmt.Errorf("services: set reject_reason: %w", err)
	}
	if err := s.requests.UpdateStatus(ctx, requestID, storage.AccessRequestStatusRejected); err != nil {
		return nil, fmt.Errorf("services: mark rejected: %w", err)
	}
	req.Status = storage.AccessRequestStatusRejected
	req.RejectReason = reason

	// Shrink TTL on every wrap so the encrypted plaintext is purged
	// quickly. 5 minutes matches the claimed-TTL constant — short
	// enough to be safe, long enough for the cleanup worker.
	if err := s.refreshWrapsForRequest(ctx, requestID, 5*time.Minute); err != nil {
		_ = s.audit.Append(ctx, &storage.AuditEvent{
			Actor:         "user:" + approverID,
			Action:        "request.refresh_ttl_failed",
			Resource:      "request:" + requestID.String(),
			Status:        storage.AuditStatusFailure,
			CorrelationID: requestID,
			Metadata:      map[string]any{"error": err.Error(), "phase": "rejected"},
		})
	}

	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:         "user:" + approverID,
		Action:        "request.reject",
		Resource:      "request:" + requestID.String(),
		Status:        storage.AuditStatusSuccess,
		CorrelationID: requestID,
	})
	return req, nil
}

// Cancel lets the original requester withdraw a pending request. The
// wraps get short-TTL'd just like a rejection so the plaintext doesn't
// linger.
func (s *RequestService) Cancel(ctx context.Context, requestID uuid.UUID, actorID string) (*storage.AccessRequest, error) {
	req, err := s.requests.Get(ctx, requestID)
	if err != nil {
		return nil, err
	}
	if req.Status != storage.AccessRequestStatusPending {
		return nil, ErrRequestNotPending
	}
	if actorID != req.RequesterID {
		return nil, ErrNotRequester
	}
	if err := s.requests.UpdateStatus(ctx, requestID, storage.AccessRequestStatusCancelled); err != nil {
		return nil, fmt.Errorf("services: cancel: %w", err)
	}
	req.Status = storage.AccessRequestStatusCancelled
	if err := s.refreshWrapsForRequest(ctx, requestID, 5*time.Minute); err != nil {
		_ = s.audit.Append(ctx, &storage.AuditEvent{
			Actor:         "user:" + actorID,
			Action:        "request.refresh_ttl_failed",
			Resource:      "request:" + requestID.String(),
			Status:        storage.AuditStatusFailure,
			CorrelationID: requestID,
			Metadata:      map[string]any{"error": err.Error(), "phase": "cancelled"},
		})
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:         "user:" + actorID,
		Action:        "request.cancel",
		Resource:      "request:" + requestID.String(),
		Status:        storage.AuditStatusSuccess,
		CorrelationID: requestID,
	})
	return req, nil
}

// Get returns one request by ID.
func (s *RequestService) Get(ctx context.Context, id uuid.UUID) (*storage.AccessRequest, error) {
	return s.requests.Get(ctx, id)
}

// List returns recent requests, optionally filtered.
func (s *RequestService) List(ctx context.Context, f storage.AccessRequestListFilter) ([]*storage.AccessRequest, error) {
	return s.requests.List(ctx, f)
}

// Approvals returns every vote for a request.
func (s *RequestService) Approvals(ctx context.Context, requestID uuid.UUID) ([]*storage.Approval, error) {
	return s.approvals.ListByRequest(ctx, requestID)
}

// WrapSummariesForRequest returns value-free wrap metadata for a
// request — used by the agent to discover which wraps to fetch.
func (s *RequestService) WrapSummariesForRequest(ctx context.Context, requestID uuid.UUID) ([]storage.WrapSummary, error) {
	return s.wraps.ListSummariesForRequest(ctx, requestID)
}

// WorkflowFor returns the workflow definition bound to a request at
// submit time. The wrap-creation handler uses it to pick the
// appropriate TTL when persisting agent-supplied plaintext.
func (s *RequestService) WorkflowFor(ctx context.Context, req *storage.AccessRequest) (*storage.WorkflowDefinition, error) {
	if req == nil || req.WorkflowID == nil {
		return nil, errors.New("services: request has no workflow")
	}
	return s.workflows.Get(ctx, *req.WorkflowID)
}

// RetrieveWrap is the agent-side single-wrap fetch. It guarantees
// the owning request is in a state where retrieval is allowed
// (approved) before the wrap layer's atomic MarkConsumed runs.
//
// Returns:
//   - plaintext bytes (caller is responsible for zeroing after use)
//   - the storage row (for content_hash / byte_length echo to client)
//
// On any failure that mutated visible state (consume succeeded but
// later step failed), the wrap is still marked consumed — same
// guarantee Piece 1 made: one-shot.
func (s *RequestService) RetrieveWrap(ctx context.Context, wrapID, agentID uuid.UUID) ([]byte, *storage.SecretWrap, error) {
	// Peek at the wrap row so we can look up the owning request and
	// validate its status BEFORE we trigger the single-shot consume.
	// There's a small race window where the request status could
	// change between this peek and the actual consume — but the
	// consume itself is atomic, and a status flip mid-call is
	// extremely rare in practice. We don't pretend to be perfect
	// here; we just want to refuse the common case of "wrap exists
	// but its request isn't approved yet" without burning the wrap.
	wrap, err := s.wraps.Peek(ctx, wrapID)
	if err != nil {
		return nil, nil, err
	}
	if wrap.RequestID != nil {
		req, err := s.requests.Get(ctx, *wrap.RequestID)
		if err != nil {
			return nil, nil, fmt.Errorf("services: load owning request: %w", err)
		}
		if req.Status != storage.AccessRequestStatusApproved {
			return nil, nil, ErrRequestNotApproved
		}
	}
	// Consume + decrypt is one shot; WrapService handles audit.
	return s.wraps.Retrieve(ctx, wrapID, agentID)
}

// ErrRequestNotApproved is returned by RetrieveWrap when the owning
// request hasn't transitioned to approved yet (or has transitioned
// past approved into a terminal state). Maps to HTTP 409 at the
// handler.
var ErrRequestNotApproved = errors.New("services: owning request is not approved")

// ErrNotRequestOwner is returned by RetrieveWrapForUser when the
// calling user isn't the requester who owns the wrap. Maps to 403.
var ErrNotRequestOwner = errors.New("services: caller is not the request owner")

// ErrWrongRequest is returned by RetrieveWrapForUser when the wrap's
// request_id doesn't match the requestID path param. Maps to 404 —
// from the user's perspective the wrap simply doesn't exist under
// that request.
var ErrWrongRequest = errors.New("services: wrap does not belong to the given request")

// RetrieveWrapForUser is the requester-facing single-shot fetch used
// by the read flow. The agent's ReadExecutor created the wrap; the
// user retrieves it through this method.
//
// Gating:
//   - Wrap must belong to the request named in the URL (defense
//     against a user enumerating other requests' wraps).
//   - Request must be of type 'read' (the patch flow's wraps are NOT
//     reachable through this endpoint).
//   - Request must be in `executed` or `approved` status — `executed`
//     once the agent has marked the job complete; `approved` allows
//     the user to retrieve incrementally as wraps land.
//   - userID must equal request.RequesterID.
//
// On success runs WrapService.Retrieve atomically (single-shot).
func (s *RequestService) RetrieveWrapForUser(ctx context.Context, requestID, wrapID uuid.UUID, userID string) ([]byte, *storage.SecretWrap, error) {
	wrap, err := s.wraps.Peek(ctx, wrapID)
	if err != nil {
		return nil, nil, err
	}
	if wrap.RequestID == nil || *wrap.RequestID != requestID {
		return nil, nil, ErrWrongRequest
	}
	req, err := s.requests.Get(ctx, requestID)
	if err != nil {
		return nil, nil, fmt.Errorf("services: load owning request: %w", err)
	}
	if req.Type != storage.AccessRequestTypeRead {
		return nil, nil, ErrWrongRequest
	}
	if req.RequesterID != userID {
		return nil, nil, ErrNotRequestOwner
	}
	switch req.Status {
	case storage.AccessRequestStatusApproved, storage.AccessRequestStatusExecuted:
		// retrievable
	default:
		return nil, nil, ErrRequestNotApproved
	}

	return s.wraps.RetrieveByUser(ctx, wrapID, userID)
}

// refreshWrapsForRequest extends/shrinks every wrap tied to the
// request. The wrap layer takes the new TTL relative to now, so this
// produces a consistent expires_at across all wraps in the request.
func (s *RequestService) refreshWrapsForRequest(ctx context.Context, requestID uuid.UUID, newTTL time.Duration) error {
	wrapIDs, err := s.wraps.ListIDsForRequest(ctx, requestID)
	if err != nil {
		return fmt.Errorf("list wraps for request: %w", err)
	}
	for _, id := range wrapIDs {
		if err := s.wraps.Refresh(ctx, id, newTTL); err != nil {
			return fmt.Errorf("refresh wrap %s: %w", id, err)
		}
	}
	return nil
}

// OnJobCompleted is the hook RequestService registers on JobService.
// It transitions the owning access_request to `executed` (on success)
// or `failed` (on failure) when the completed job was a patch job.
//
// Other job types are ignored — patch is the only flow that pins a
// request lifecycle to a job today.
//
// Wired in main.go via `jobSvc.OnCompleted(requestSvc.OnJobCompleted)`.
func (s *RequestService) OnJobCompleted(ctx context.Context, job *storage.SyncJob) {
	if job == nil {
		return
	}
	if job.RequestID == nil {
		return
	}
	if job.JobType != storage.JobTypePatch && job.JobType != storage.JobTypeRead {
		return
	}
	var target storage.AccessRequestStatus
	switch job.Status {
	case storage.JobStatusSucceeded:
		target = storage.AccessRequestStatusExecuted
	case storage.JobStatusFailed:
		target = storage.AccessRequestStatusFailed
	default:
		return
	}
	if err := s.requests.UpdateStatus(ctx, *job.RequestID, target); err != nil {
		_ = s.audit.Append(ctx, &storage.AuditEvent{
			Actor:         "system",
			Action:        "request.transition_failed",
			Resource:      "request:" + job.RequestID.String(),
			Status:        storage.AuditStatusFailure,
			CorrelationID: job.CorrelationID,
			Metadata: map[string]any{
				"error":  err.Error(),
				"target": string(target),
				"job_id": job.ID.String(),
			},
		})
		return
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:         "system",
		Action:        "request.transition",
		Resource:      "request:" + job.RequestID.String(),
		Status:        storage.AuditStatusSuccess,
		CorrelationID: job.CorrelationID,
		Metadata: map[string]any{
			"target": string(target),
			"job_id": job.ID.String(),
		},
	})
}

// enqueueRequestJob creates the sync_job that an agent will claim to
// service the approved request. Branches by request type:
//
//   - patch: emits JobTypePatch with payload.wraps listing the
//     pre-created write wraps the agent must fetch via Piece 3c.
//   - read:  emits JobTypeRead with payload.target_keys naming the
//     keys to fetch. The agent will create wraps post-fetch via the
//     agent-side wrap-creation endpoint (Piece 5a).
//
// Sets req.JobID on success so the UI can link request → job.
func (s *RequestService) enqueueRequestJob(ctx context.Context, req *storage.AccessRequest) error {
	if s.jobs == nil {
		return errors.New("services: no JobEnqueuer wired")
	}

	payload := map[string]any{
		"request_id":             req.ID.String(),
		"target_provider_type":   req.TargetProviderType,
		"target_provider_config": req.TargetProviderConfig,
		"target_secret_ref":      req.TargetSecretRef,
		"target_keys":            req.TargetKeys,
		"target_scope":           req.TargetScope,
	}

	var jobType storage.JobType
	switch req.Type {
	case storage.AccessRequestTypePatch:
		jobType = storage.JobTypePatch
		summaries, err := s.wraps.ListSummariesForRequest(ctx, req.ID)
		if err != nil {
			return fmt.Errorf("list wrap summaries: %w", err)
		}
		wraps := make([]map[string]any, 0, len(summaries))
		for _, sm := range summaries {
			wraps = append(wraps, map[string]any{
				"wrap_id":  sm.ID.String(),
				"key_name": sm.KeyName,
			})
		}
		payload["wraps"] = wraps
	case storage.AccessRequestTypeRead:
		jobType = storage.JobTypeRead
		// No pre-existing wraps for read; the agent creates them
		// after fetching the value.
	default:
		// Other types (update/rotate) don't yet have a job-emission
		// path. Skip silently — Approve still flips status to
		// approved; an operator can dispatch manually.
		return nil
	}

	reqID := req.ID
	job, err := s.jobs.Enqueue(ctx, EnqueueRequest{
		JobType:       jobType,
		AgentScope:    map[string]any{},
		Payload:       payload,
		RequestID:     &reqID,
		CorrelationID: reqID,
	})
	if err != nil {
		return fmt.Errorf("enqueue %s job: %w", jobType, err)
	}
	if err := s.requests.SetJobID(ctx, req.ID, job.ID); err != nil {
		return fmt.Errorf("set request job_id: %w", err)
	}
	req.JobID = &job.ID
	return nil
}
