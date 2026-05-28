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

// RequestService orchestrates the patch-request lifecycle.
type RequestService struct {
	requests  storage.AccessRequestRepository
	approvals storage.ApprovalRepository
	wraps     *WrapService
	workflows storage.WorkflowRepository
	policy    *PolicyEngine
	audit     storage.AuditEventRepository
	now       func() time.Time
}

// NewRequestService wires a RequestService to its dependencies.
func NewRequestService(
	requests storage.AccessRequestRepository,
	approvals storage.ApprovalRepository,
	wraps *WrapService,
	workflows storage.WorkflowRepository,
	policy *PolicyEngine,
	audit storage.AuditEventRepository,
) *RequestService {
	return &RequestService{
		requests:  requests,
		approvals: approvals,
		wraps:     wraps,
		workflows: workflows,
		policy:    policy,
		audit:     audit,
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
	// is tied back to req.ID via RequestID so an admin viewing the
	// request can enumerate all the wraps that belong to it.
	for k, v := range in.KeyValues {
		_, err := s.wraps.Wrap(ctx, WrapRequest{
			Plaintext: v,
			RequestID: &req.ID,
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
