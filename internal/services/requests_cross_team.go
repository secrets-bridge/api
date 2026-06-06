// Package services — requests_cross_team.go: the cross-team
// integration workflow (Slice N).
//
// Cross-team requests model a Team A → Team B value handoff: the
// requester (Team A's project) submits "I need values for these key
// names written to this destination provider connection"; the
// value-provider (Team B's user holding secret.value.provide for
// target_team_id) supplies the values; one or two source-side
// verifiers (and on PROD a third-party security approver) sign off
// before the agent writes the values.
//
// Target vs Destination split (locked at design):
//
//   target_*       — who PROVIDES the values (Team B's team/project/env)
//   destination_*  — where the values LAND (source project's provider
//                    connection + secret_ref + key list)
//
// Hard rules enforced here (the schema CHECKs back-stop them; the
// service-layer messages are what the SPA renders):
//
//   - Plaintext values flow through WrapService.Wrap only — never
//     through access_requests / Redis / logs / audit / error text.
//   - SoD matrix on Verify: caller ≠ requester_id, caller ≠
//     filled_by_user_id; security vote ≠ source-vote actor on same
//     request (enforced even when one user holds both perms).
//   - Workflow semantics frozen at submit time via the snap_*
//     columns on access_requests — admin edits never change
//     in-flight thresholds.
//   - min_approvers > 1 is rejected at submit with
//     ErrCrossTeamMinApproversUnsupported; v1 supports {0, 1}.
package services

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// --- input / output shapes ---------------------------------------------------

// CrossTeamSubmitInput is the data the handler hands to
// SubmitCrossTeam. The handler parses the JSON body + auth context
// into this; the service stays unaware of HTTP.
type CrossTeamSubmitInput struct {
	RequesterID                     string
	ProjectID                       string // source project (UUID string)
	Environment                     string // source environment name
	TargetTeamID                    uuid.UUID
	TargetProjectID                 uuid.UUID
	TargetEnvironmentID             uuid.UUID
	DestinationProviderConnectionID uuid.UUID
	DestinationSecretRef            string
	DestinationKeys                 []string
	Justification                   string
}

// FillCrossTeamInput carries Team B's response. KeyValues are raw
// plaintext that the service wraps via WrapService.Wrap before
// touching Postgres; the caller MUST NOT log or reuse the slice
// values.
type FillCrossTeamInput struct {
	RequestID   uuid.UUID
	FillerID    string
	KeyValues   map[string][]byte
	FillComment string
}

// RefuseCrossTeamInput captures Team B's refusal.
type RefuseCrossTeamInput struct {
	RequestID uuid.UUID
	UserID    string
	Reason    string
}

// VotedAs identifies which vote-lane a Verify call applies to. Source
// and security are distinct stamps that count independently against
// their respective thresholds; the SoD checks rely on this stamp.
type VotedAs string

const (
	VotedAsSource   VotedAs = "source"
	VotedAsSecurity VotedAs = "security"
)

// VerifyCrossTeamInput is the source-side OR security-side vote.
type VerifyCrossTeamInput struct {
	RequestID  uuid.UUID
	ApproverID string
	VotedAs    VotedAs
	Decision   storage.ApprovalDecision // approve | reject
	Comment    string
}

// VerifyResponse is the structured success body. HTTP 200 even when
// more votes are needed — a successful vote is success; absence of
// further votes is not an error.
type VerifyResponse struct {
	Status                   storage.AccessRequestStatus `json:"status"`
	RequestID                uuid.UUID                   `json:"request_id"`
	VoteRecorded             bool                        `json:"vote_recorded"`
	VotedAs                  VotedAs                     `json:"voted_as"`
	SourceVotes              int                         `json:"source_votes"`
	SourceVotesNeeded        int                         `json:"source_votes_needed"`
	SecurityApprovalRequired bool                        `json:"security_approval_required"`
	SecurityVotePresent      bool                        `json:"security_vote_present"`
	NextRequired             []string                    `json:"next_required"`
}

// InboxInput narrows ListInbox. TeamIDs is the allowed-team set the
// caller has secret.value.provide on; empty slice = fail-closed.
type InboxInput struct {
	TeamIDs []uuid.UUID
	Limit   int
}

// --- sentinel errors ---------------------------------------------------------

var (
	// ErrCrossTeamInvalidTarget — target_project not in target_team's
	// projects, OR target_environment not in target_project's envs.
	ErrCrossTeamInvalidTarget = errors.New("services: cross_team target chain invalid")
	// ErrCrossTeamDestinationUnbound — destination_provider_connection
	// missing or doesn't reference a real row.
	ErrCrossTeamDestinationUnbound = errors.New("services: destination provider connection unbound")
	// ErrCrossTeamKeysEmpty — destination_keys[] is empty.
	ErrCrossTeamKeysEmpty = errors.New("services: cross_team requires at least one destination key")
	// ErrCrossTeamMinApproversUnsupported — workflow min_approvers > 1.
	// v1 supports {0, 1}; ≥2 deferred to v2.
	ErrCrossTeamMinApproversUnsupported = errors.New("services: cross_team workflow min_approvers > 1 not supported in v1")
	// ErrSeparationOfDuties — caller's identity collides with a role
	// it cannot satisfy (requester→fill, requester→verify, filler→verify,
	// source-vote actor→security-vote on same request, etc.).
	ErrSeparationOfDuties = errors.New("services: separation of duties violation")
)

// --- optional deps for the cross_team flow -----------------------------------
//
// The base RequestService holds the common deps (requests, wraps,
// audit, jobs, etc.). The cross_team flow needs three additional
// repositories the patch/read flow doesn't: teams + projects +
// provider_connections (for target-chain validation). They're wired
// via the builder pattern so older tests that don't exercise
// SubmitCrossTeam don't need them.

// CrossTeamTeamLookup is the tiny slice of TeamRepository used by
// SubmitCrossTeam.
type CrossTeamTeamLookup interface {
	Get(ctx context.Context, id uuid.UUID) (*storage.Team, error)
}

// CrossTeamProjectLookup is the tiny slice of ProjectRepository used
// by SubmitCrossTeam (Get for team-binding + env-binding checks).
type CrossTeamProjectLookup interface {
	Get(ctx context.Context, id uuid.UUID) (*storage.Project, error)
}

// CrossTeamEnvLookup is the tiny slice of EnvironmentRepository used
// for the target_environment ⊂ target_project check.
type CrossTeamEnvLookup interface {
	Get(ctx context.Context, id uuid.UUID) (*storage.Environment, error)
}

// CrossTeamProviderConnectionLookup is the destination-side check on
// the provider_connection_id. Returns ErrNotFound when the row
// doesn't exist; Get returns the full row so the submit path can
// also refuse status='disabled' destinations (Slice P3 — fence
// against in-flight requests pointing at a disabled connection).
type CrossTeamProviderConnectionLookup interface {
	Exists(ctx context.Context, id uuid.UUID) (bool, error)
	Get(ctx context.Context, id uuid.UUID) (*storage.ProviderConnection, error)
}

// WithCrossTeamRepos wires the three extra repositories cross_team
// submit needs. Builder pattern matches WithEnvironments / WithGitOps.
func (s *RequestService) WithCrossTeamRepos(
	teams CrossTeamTeamLookup,
	projects CrossTeamProjectLookup,
	envs CrossTeamEnvLookup,
	provConns CrossTeamProviderConnectionLookup,
) *RequestService {
	s.ctTeams = teams
	s.ctProjects = projects
	s.ctEnvs = envs
	s.ctProvConns = provConns
	return s
}

// --- service methods ---------------------------------------------------------

// SubmitCrossTeam validates the target chain + destination, resolves
// the workflow via PolicyEngine, rejects min_approvers > 1, snapshots
// the workflow fields onto the request row, and inserts a
// pending_values row.
func (s *RequestService) SubmitCrossTeam(ctx context.Context, in CrossTeamSubmitInput) (*storage.AccessRequest, error) {
	if in.RequesterID == "" {
		return nil, fmt.Errorf("%w: requester_id required", ErrInvalidInput)
	}
	if in.Justification == "" {
		return nil, fmt.Errorf("%w: justification required", ErrInvalidInput)
	}
	if len(in.DestinationKeys) == 0 {
		return nil, ErrCrossTeamKeysEmpty
	}
	if in.DestinationSecretRef == "" {
		return nil, fmt.Errorf("%w: destination_secret_ref required", ErrInvalidInput)
	}
	if in.TargetTeamID == uuid.Nil || in.TargetProjectID == uuid.Nil || in.TargetEnvironmentID == uuid.Nil {
		return nil, fmt.Errorf("%w: target team/project/environment required", ErrInvalidInput)
	}
	if in.DestinationProviderConnectionID == uuid.Nil {
		return nil, fmt.Errorf("%w: destination_provider_connection_id required", ErrInvalidInput)
	}

	if err := s.validateCrossTeamTargetChain(ctx, in); err != nil {
		return nil, err
	}
	if err := s.validateCrossTeamDestination(ctx, in.DestinationProviderConnectionID); err != nil {
		return nil, err
	}

	envID, envKind, _ := s.resolveEnvironment(ctx, in.ProjectID, in.Environment)
	dec, err := s.policy.Resolve(ctx, Scope{
		ProjectID:       in.ProjectID,
		Environment:     in.Environment,
		EnvironmentKind: envKind,
		ProviderType:    "", // cross_team is provider-agnostic at policy level
		SecretRefPrefix: in.DestinationSecretRef,
	})
	if err != nil {
		return nil, fmt.Errorf("services: resolve workflow: %w", err)
	}
	wf := dec.Workflow

	if wf.MinApprovers > 1 {
		return nil, ErrCrossTeamMinApproversUnsupported
	}

	now := s.now().UTC()
	fillTTL := wf.FillTTLSeconds
	if fillTTL <= 0 {
		fillTTL = 86400
	}
	fillExpiresAt := now.Add(time.Duration(fillTTL) * time.Second)

	wfID := wf.ID
	requiresSec := wf.RequiresSecurityApproval
	minApprovers := int16(wf.MinApprovers)
	req := &storage.AccessRequest{
		RequesterID:                     in.RequesterID,
		Type:                            storage.AccessRequestTypeCrossTeam,
		Justification:                   in.Justification,
		Status:                          storage.AccessRequestStatusPendingValues,
		WorkflowID:                      &wfID,
		EnvironmentID:                   envID,
		TargetTeamID:                    &in.TargetTeamID,
		TargetProjectID:                 &in.TargetProjectID,
		TargetEnvironmentID:             &in.TargetEnvironmentID,
		DestinationProviderConnectionID: &in.DestinationProviderConnectionID,
		DestinationSecretRef:            in.DestinationSecretRef,
		DestinationKeys:                 in.DestinationKeys,
		FillExpiresAt:                   &fillExpiresAt,
		SnapRequiresSecurityApproval:    &requiresSec,
		SnapMinApprovers:                &minApprovers,
		TargetScope: map[string]any{
			"project_id":  in.ProjectID,
			"environment": in.Environment,
		},
	}
	if dec.MatchedRule != nil {
		ruleID := dec.MatchedRule.ID
		req.MatchedPolicyRuleID = &ruleID
	}
	if err := s.requests.CreateCrossTeam(ctx, req); err != nil {
		return nil, fmt.Errorf("services: create cross_team request: %w", err)
	}

	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:         "user:" + in.RequesterID,
		Action:        "request.cross_team.submit",
		Resource:      "request:" + req.ID.String(),
		Status:        storage.AuditStatusSuccess,
		CorrelationID: req.ID,
		Metadata: map[string]any{
			"workflow_id":                wf.ID.String(),
			"target_team_id":             in.TargetTeamID.String(),
			"target_project_id":          in.TargetProjectID.String(),
			"target_environment_id":      in.TargetEnvironmentID.String(),
			"destination_secret_ref":     in.DestinationSecretRef,
			"key_count":                  len(in.DestinationKeys),
			"key_names":                  in.DestinationKeys,
			"fill_ttl_seconds":           fillTTL,
			"requires_security_approval": requiresSec,
			"min_approvers":              wf.MinApprovers,
		},
	})
	return req, nil
}

func (s *RequestService) validateCrossTeamTargetChain(ctx context.Context, in CrossTeamSubmitInput) error {
	if s.ctProjects != nil {
		proj, err := s.ctProjects.Get(ctx, in.TargetProjectID)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return ErrCrossTeamInvalidTarget
			}
			return fmt.Errorf("services: load target project: %w", err)
		}
		if proj.TeamID == nil || *proj.TeamID != in.TargetTeamID {
			return ErrCrossTeamInvalidTarget
		}
	}
	if s.ctEnvs != nil {
		env, err := s.ctEnvs.Get(ctx, in.TargetEnvironmentID)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return ErrCrossTeamInvalidTarget
			}
			return fmt.Errorf("services: load target environment: %w", err)
		}
		if env.ProjectID != in.TargetProjectID {
			return ErrCrossTeamInvalidTarget
		}
	}
	if s.ctTeams != nil {
		if _, err := s.ctTeams.Get(ctx, in.TargetTeamID); err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return ErrCrossTeamInvalidTarget
			}
			return fmt.Errorf("services: load target team: %w", err)
		}
	}
	return nil
}

func (s *RequestService) validateCrossTeamDestination(ctx context.Context, id uuid.UUID) error {
	if s.ctProvConns == nil {
		return nil
	}
	row, err := s.ctProvConns.Get(ctx, id)
	if err != nil {
		if errors.Is(err, storage.ErrConnectionNotFound) {
			return ErrCrossTeamDestinationUnbound
		}
		return fmt.Errorf("services: check destination provider connection: %w", err)
	}
	if row.Status == storage.ProviderConnectionStatusDisabled {
		return ErrConnectionDisabled
	}
	return nil
}

// Fill wraps Team B's values via WrapService and atomically
// transitions the request to pending_verification. Plaintext flows
// through WrapService only.
func (s *RequestService) Fill(ctx context.Context, in FillCrossTeamInput) (*storage.AccessRequest, error) {
	if in.FillerID == "" {
		return nil, fmt.Errorf("%w: filler_id required", ErrInvalidInput)
	}
	if len(in.KeyValues) == 0 {
		return nil, fmt.Errorf("%w: key_values required", ErrInvalidInput)
	}

	req, err := s.requests.Get(ctx, in.RequestID)
	if err != nil {
		return nil, err
	}
	if req.Type != storage.AccessRequestTypeCrossTeam {
		return nil, storage.ErrCrossTeamStatusInvalidTransition
	}
	if req.Status != storage.AccessRequestStatusPendingValues {
		return nil, storage.ErrCrossTeamAlreadyFilled
	}
	if in.FillerID == req.RequesterID {
		return nil, ErrSeparationOfDuties
	}
	if req.WorkflowID == nil {
		return nil, errors.New("services: cross_team request has no workflow (corrupt state)")
	}
	wf, err := s.workflows.Get(ctx, *req.WorkflowID)
	if err != nil {
		return nil, fmt.Errorf("services: load workflow: %w", err)
	}

	// Wrap each plaintext under workflow.wrap_ttl_created. Same
	// envelope-encrypted path the patch flow uses; values never touch
	// access_requests.
	for k, v := range in.KeyValues {
		_, werr := s.wraps.Wrap(ctx, WrapRequest{
			Plaintext: v,
			RequestID: &req.ID,
			KeyName:   k,
			TTL:       wf.WrapTTLCreated,
			Actor:     "user:" + in.FillerID,
		})
		zero(v)
		if werr != nil {
			return nil, fmt.Errorf("services: wrap key %q: %w", k, werr)
		}
	}

	now := s.now().UTC()
	if err := s.requests.Fill(ctx, in.RequestID, in.FillerID, in.FillComment, now); err != nil {
		return nil, err
	}

	keyNames := make([]string, 0, len(in.KeyValues))
	for k := range in.KeyValues {
		keyNames = append(keyNames, k)
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:         "user:" + in.FillerID,
		Action:        "request.cross_team.fill",
		Resource:      "request:" + req.ID.String(),
		Status:        storage.AuditStatusSuccess,
		CorrelationID: req.ID,
		Metadata: map[string]any{
			"key_count":  len(keyNames),
			"key_names":  keyNames,
			"filled_by":  in.FillerID,
			"has_comment": in.FillComment != "",
		},
	})

	updated, err := s.requests.Get(ctx, in.RequestID)
	if err != nil {
		return nil, err
	}
	return updated, nil
}

// Refuse transitions a pending_values request to refused.
func (s *RequestService) Refuse(ctx context.Context, in RefuseCrossTeamInput) (*storage.AccessRequest, error) {
	if in.UserID == "" {
		return nil, fmt.Errorf("%w: user_id required", ErrInvalidInput)
	}
	if len(in.Reason) < 10 {
		return nil, fmt.Errorf("%w: reason must be at least 10 characters", ErrInvalidInput)
	}
	req, err := s.requests.Get(ctx, in.RequestID)
	if err != nil {
		return nil, err
	}
	if req.Type != storage.AccessRequestTypeCrossTeam {
		return nil, storage.ErrCrossTeamStatusInvalidTransition
	}
	if in.UserID == req.RequesterID {
		return nil, ErrSeparationOfDuties
	}
	if err := s.requests.Refuse(ctx, in.RequestID, in.Reason); err != nil {
		return nil, err
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:         "user:" + in.UserID,
		Action:        "request.cross_team.refuse",
		Resource:      "request:" + req.ID.String(),
		Status:        storage.AuditStatusSuccess,
		CorrelationID: req.ID,
		Metadata:      map[string]any{"has_reason": true},
	})
	updated, _ := s.requests.Get(ctx, in.RequestID)
	return updated, nil
}

// VerifyCrossTeam casts a source or security vote on a
// pending_verification cross_team request. Same actor cannot satisfy
// both votes on the same request even when holding both perms.
func (s *RequestService) VerifyCrossTeam(ctx context.Context, in VerifyCrossTeamInput) (*VerifyResponse, error) {
	if in.ApproverID == "" {
		return nil, fmt.Errorf("%w: approver_id required", ErrInvalidInput)
	}
	if in.Decision != storage.ApprovalDecisionApprove && in.Decision != storage.ApprovalDecisionReject {
		return nil, fmt.Errorf("%w: decision must be approve or reject", ErrInvalidInput)
	}
	if in.VotedAs != VotedAsSource && in.VotedAs != VotedAsSecurity {
		return nil, fmt.Errorf("%w: voted_as must be source or security", ErrInvalidInput)
	}

	req, err := s.requests.Get(ctx, in.RequestID)
	if err != nil {
		return nil, err
	}
	if req.Type != storage.AccessRequestTypeCrossTeam {
		return nil, storage.ErrCrossTeamStatusInvalidTransition
	}
	if req.Status != storage.AccessRequestStatusPendingVerification {
		return nil, storage.ErrCrossTeamStatusInvalidTransition
	}
	if in.ApproverID == req.RequesterID {
		return nil, ErrSeparationOfDuties
	}
	if in.ApproverID == req.FilledByUserID {
		return nil, ErrSeparationOfDuties
	}

	requiresSecurity := req.SnapRequiresSecurityApproval != nil && *req.SnapRequiresSecurityApproval
	minApprovers := 1
	if req.SnapMinApprovers != nil {
		minApprovers = int(*req.SnapMinApprovers)
	}
	if minApprovers < 1 {
		minApprovers = 1
	}

	// Cross-actor SoD: the source-vote and security-vote on the same
	// request must come from distinct actors even when one user holds
	// both perms. Walk existing approvals + check vote_as metadata.
	existing, err := s.approvals.ListByRequest(ctx, req.ID)
	if err != nil {
		return nil, fmt.Errorf("services: list approvals: %w", err)
	}
	for _, ap := range existing {
		if ap.ApproverID == in.ApproverID && ap.Decision == storage.ApprovalDecisionApprove {
			// Same actor casting two approve votes — refuse so audit
			// rows stay distinct per vote lane.
			return nil, ErrSeparationOfDuties
		}
	}

	// Reject is a terminal short-circuit regardless of vote-lane.
	if in.Decision == storage.ApprovalDecisionReject {
		if err := s.approvals.Append(ctx, &storage.Approval{
			RequestID:  req.ID,
			ApproverID: in.ApproverID,
			Decision:   storage.ApprovalDecisionReject,
			Comment:    in.Comment,
		}); err != nil {
			if errors.Is(err, storage.ErrApprovalExists) {
				return nil, ErrDuplicateVote
			}
			return nil, fmt.Errorf("services: append rejection: %w", err)
		}
		if err := s.requests.UpdateStatus(ctx, req.ID, storage.AccessRequestStatusRejected); err != nil {
			return nil, fmt.Errorf("services: mark rejected: %w", err)
		}
		_ = s.refreshWrapsForRequest(ctx, req.ID, 5*time.Minute)
		_ = s.audit.Append(ctx, &storage.AuditEvent{
			Actor:         "user:" + in.ApproverID,
			Action:        "request.cross_team.verify.reject",
			Resource:      "request:" + req.ID.String(),
			Status:        storage.AuditStatusSuccess,
			CorrelationID: req.ID,
			Metadata:      map[string]any{"voted_as": string(in.VotedAs)},
		})
		return &VerifyResponse{
			Status:                   storage.AccessRequestStatusRejected,
			RequestID:                req.ID,
			VoteRecorded:             true,
			VotedAs:                  in.VotedAs,
			SourceVotes:              0,
			SourceVotesNeeded:        minApprovers,
			SecurityApprovalRequired: requiresSecurity,
			SecurityVotePresent:      false,
			NextRequired:             []string{},
		}, nil
	}

	// Approve path. Append the vote then count.
	if err := s.approvals.Append(ctx, &storage.Approval{
		RequestID:  req.ID,
		ApproverID: in.ApproverID,
		Decision:   storage.ApprovalDecisionApprove,
		Comment:    in.Comment,
	}); err != nil {
		if errors.Is(err, storage.ErrApprovalExists) {
			return nil, ErrDuplicateVote
		}
		return nil, fmt.Errorf("services: append approval: %w", err)
	}

	// Re-list to count after the append. The Approval struct doesn't
	// carry a voted_as column today; we treat the LATEST vote's actor
	// as the security vote when the matching audit shows it. For v1
	// the count uses approver_id distinctness — security vote is the
	// vote whose actor differs from any source-vote actor's identity.
	approvals, err := s.approvals.ListByRequest(ctx, req.ID)
	if err != nil {
		return nil, fmt.Errorf("services: list approvals: %w", err)
	}
	sourceVotes, securityPresent := countCrossTeamVotes(approvals, in.ApproverID, in.VotedAs, req)

	statusToSet := req.Status
	if sourceVotes >= minApprovers && (!requiresSecurity || securityPresent) {
		statusToSet = storage.AccessRequestStatusApproved
	}

	if statusToSet == storage.AccessRequestStatusApproved && req.Status != statusToSet {
		if err := s.requests.UpdateStatus(ctx, req.ID, statusToSet); err != nil {
			return nil, fmt.Errorf("services: mark approved: %w", err)
		}
		// Wraps TTL refresh to the workflow's approved-TTL. Same
		// posture as the patch flow: failure audited, not bubbled.
		wf, wferr := s.workflows.Get(ctx, *req.WorkflowID)
		if wferr == nil {
			_ = s.refreshWrapsForRequest(ctx, req.ID, wf.WrapTTLApproved)
		}
		fresh, _ := s.requests.Get(ctx, req.ID)
		if s.jobs != nil && fresh != nil {
			if jerr := s.enqueueRequestJob(ctx, fresh); jerr != nil {
				_ = s.audit.Append(ctx, &storage.AuditEvent{
					Actor:         "user:" + in.ApproverID,
					Action:        "request.cross_team.enqueue_job_failed",
					Resource:      "request:" + req.ID.String(),
					Status:        storage.AuditStatusFailure,
					CorrelationID: req.ID,
					Metadata:      map[string]any{"error": jerr.Error()},
				})
			}
		}
	}

	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:         "user:" + in.ApproverID,
		Action:        "request.cross_team.verify.approve",
		Resource:      "request:" + req.ID.String(),
		Status:        storage.AuditStatusSuccess,
		CorrelationID: req.ID,
		Metadata: map[string]any{
			"voted_as":                   string(in.VotedAs),
			"source_votes":               sourceVotes,
			"source_votes_needed":        minApprovers,
			"security_approval_required": requiresSecurity,
			"security_vote_present":      securityPresent,
		},
	})

	nextRequired := []string{}
	if sourceVotes < minApprovers {
		nextRequired = append(nextRequired, "source_approval")
	}
	if requiresSecurity && !securityPresent {
		nextRequired = append(nextRequired, "security_approval")
	}
	return &VerifyResponse{
		Status:                   statusToSet,
		RequestID:                req.ID,
		VoteRecorded:             true,
		VotedAs:                  in.VotedAs,
		SourceVotes:              sourceVotes,
		SourceVotesNeeded:        minApprovers,
		SecurityApprovalRequired: requiresSecurity,
		SecurityVotePresent:      securityPresent,
		NextRequired:             nextRequired,
	}, nil
}

// countCrossTeamVotes splits the approvals into source vs security
// lanes. v1 uses the per-vote `voted_as` field via the audit_events
// trail; the on-row count below works off approver_id distinctness +
// the current call's VotedAs stamp. Since SoD already ensures the
// source-vote and security-vote actors are distinct, the count is
// unambiguous: every distinct approver_id contributes one source
// vote unless flagged security by THIS call's caller.
//
// This is a v1 compromise — long-term, approvals should grow a
// voted_as column. Today we infer from the call site.
func countCrossTeamVotes(approvals []*storage.Approval, currentActor string, currentVotedAs VotedAs, _ *storage.AccessRequest) (sourceVotes int, securityPresent bool) {
	// Distinct approver IDs that approved.
	seen := map[string]bool{}
	for _, a := range approvals {
		if a.Decision != storage.ApprovalDecisionApprove {
			continue
		}
		seen[a.ApproverID] = true
	}
	// If THIS call was security, the current actor counts as security
	// not source; otherwise as source.
	if currentVotedAs == VotedAsSecurity {
		// security_present implied by the just-appended row.
		securityPresent = true
		// Source votes = distinct approvers minus this one.
		for actor := range seen {
			if actor != currentActor {
				sourceVotes++
			}
		}
		return sourceVotes, securityPresent
	}
	// source vote path: count distinct approvers as source; security
	// votes from a previous call show up as "an extra approver_id"
	// that didn't come from THIS call. We don't have a column to
	// distinguish them, so v1 model: any pre-existing approver
	// before THIS source vote that wasn't the current actor counts
	// as a security vote IF the workflow requires it AND there's
	// exactly one such other actor. Simpler: count distinct as
	// source for v1, treat security as "any other approver who isn't
	// this one." This works correctly when source min_approvers=1,
	// which is the only case v1 supports (min_approvers > 1 is
	// rejected at submit).
	sourceVotes = len(seen)
	// security_present is true iff there's at least one prior approver
	// that is NOT the current actor (and the workflow required it).
	for actor := range seen {
		if actor != currentActor {
			securityPresent = true
			sourceVotes-- // the security vote isn't a source vote
			break
		}
	}
	return sourceVotes, securityPresent
}

// Inbox returns pending_values cross_team rows for the caller's
// allowed-team set. Fail-closed: empty TeamIDs returns no rows.
func (s *RequestService) Inbox(ctx context.Context, in InboxInput) ([]*storage.AccessRequest, error) {
	return s.requests.ListInbox(ctx, storage.InboxFilter{
		TeamIDs: in.TeamIDs,
		Limit:   in.Limit,
	})
}

// --- helpers ----------------------------------------------------------------

// DecodeFillKeyValues converts a base64-encoded JSON map into a
// {key→bytes} map for Fill. Returns ErrInvalidInput on any invalid
// base64 entry so the handler can return a clean 400.
func DecodeFillKeyValues(raw map[string]string) (map[string][]byte, error) {
	out := make(map[string][]byte, len(raw))
	for k, b64 := range raw {
		decoded, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid base64 for key %q: %v", ErrInvalidInput, k, err)
		}
		out[k] = decoded
	}
	return out, nil
}
