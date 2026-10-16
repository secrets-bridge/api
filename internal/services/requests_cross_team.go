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
//   - Verify lanes are permission-gated (API-N-01): source needs
//     secret.approve, security needs secret.security.approve, both at a
//     scope covering the source project. Lanes are fixed by vote order
//     (source first, then security) because approvals has no lane column.
//   - The destination connection must be bound to the source project
//     (API-N-03) and fill only accepts declared keys (API-S-07).
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

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/pkg/storage"
	"github.com/secrets-bridge/api/pkg/workflow"
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
	// ErrCrossTeamLaneForbidden — the caller does not hold the permission
	// for the verify lane they named: secret.approve covering the source
	// project for `source`, secret.security.approve covering it for
	// `security` (API-N-01).
	ErrCrossTeamLaneForbidden = errors.New("services: caller lacks the permission for this verify lane")
	// ErrCrossTeamVoteOutOfTurn — the vote is not the lane the request
	// needs next. The approvals table has no lane column, so lanes are
	// fixed by order: the first approve is the source vote, the second
	// (only when security approval is required) the security vote.
	ErrCrossTeamVoteOutOfTurn = errors.New("services: cross_team vote is not the lane this request needs next")
	// ErrCrossTeamPriorVoteInvalid — an approve already recorded on the
	// request was cast by someone who does not hold that lane's
	// permission (a vote written before API-N-01 was fixed, or a grant
	// revoked since). It cannot count, so the request cannot complete;
	// it must be rejected or cancelled and resubmitted.
	ErrCrossTeamPriorVoteInvalid = errors.New("services: a recorded cross_team vote no longer holds its lane permission")
	// ErrCrossTeamKeyNotDeclared — fill named a key outside the request's
	// destination_keys (API-S-07).
	ErrCrossTeamKeyNotDeclared = errors.New("services: fill key not declared on the request")
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

// CrossTeamDestinationBindingLookup is the slice of the
// project_provider_connections repository used to prove the destination
// connection is bound to the request's SOURCE project (API-N-03). The
// storage repo's ListForProject satisfies it.
type CrossTeamDestinationBindingLookup interface {
	ListForProject(ctx context.Context, projectID uuid.UUID, envID *uuid.UUID) ([]storage.ProjectBindingDetail, error)
}

// WithCrossTeamRepos wires the extra repositories cross_team submit
// needs. Builder pattern matches WithEnvironments / WithGitOps. A nil
// destBindings makes every cross-team submit fail closed with
// ErrCrossTeamDestinationUnbound.
func (s *RequestService) WithCrossTeamRepos(
	teams CrossTeamTeamLookup,
	projects CrossTeamProjectLookup,
	envs CrossTeamEnvLookup,
	provConns CrossTeamProviderConnectionLookup,
	destBindings CrossTeamDestinationBindingLookup,
) *RequestService {
	s.ctTeams = teams
	s.ctProjects = projects
	s.ctEnvs = envs
	s.ctProvConns = provConns
	s.ctDestBindings = destBindings
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
	// API-N-03: the source project anchors both the destination binding
	// check below and the source approver's scope at verify time, so it
	// is required. Stored in canonical form so policy selectors and the
	// verify-time scope check compare like with like.
	srcProjectID, err := uuid.Parse(in.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("%w: project_id (source project) must be a UUID", ErrInvalidInput)
	}
	in.ProjectID = srcProjectID.String()

	if err := s.validateCrossTeamTargetChain(ctx, in); err != nil {
		return nil, err
	}
	if err := s.validateCrossTeamDestination(ctx, in.DestinationProviderConnectionID); err != nil {
		return nil, err
	}
	envID, envKind, _ := s.resolveEnvironment(ctx, in.ProjectID, in.Environment)
	if err := s.requireCrossTeamDestinationBinding(ctx, srcProjectID, envID, in.DestinationProviderConnectionID); err != nil {
		return nil, err
	}
	if err := s.enforceCrossTeamDestinationKeys(ctx, in); err != nil {
		return nil, err
	}

	dec, err := s.policy.Resolve(ctx, Scope{
		ProjectID:       in.ProjectID,
		Environment:     in.Environment,
		EnvironmentKind: envKind,
		ProviderType:    "", // cross_team is provider-agnostic at policy level
		SecretRefPrefix: in.DestinationSecretRef,
		// api#141 D5 — cross-team provisions/writes values into a
		// destination, so the underlying operation is patch. cross_team
		// itself is a routing flavor (D6), NOT an operation value.
		Operation: PolicySelectorOperationPatch,
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

// enforceCrossTeamDestinationKeys refuses a cross-team submit whose
// destination_keys fall outside the target project's binding allowlist
// for the destination secret — the same gate direct-reveal and patch
// requests already apply (api#153). It resolves the destination
// provider type from the bound connection, then delegates to the shared
// enforceBindingAllowedKeys. No-op when the binding repos are unwired or
// the destination secret carries no restrictive allowlist, so callers
// without a bound catalog secret behave exactly as before.
func (s *RequestService) enforceCrossTeamDestinationKeys(ctx context.Context, in CrossTeamSubmitInput) error {
	if s.ctProvConns == nil || s.bindings == nil || s.secrets == nil {
		return nil
	}
	conn, err := s.ctProvConns.Get(ctx, in.DestinationProviderConnectionID)
	if err != nil {
		if errors.Is(err, storage.ErrConnectionNotFound) {
			return ErrCrossTeamDestinationUnbound
		}
		return fmt.Errorf("services: resolve destination provider type: %w", err)
	}
	return s.enforceBindingAllowedKeys(ctx, in.TargetProjectID, string(conn.Type), in.DestinationSecretRef, in.DestinationKeys)
}

// enforceCrossTeamDestinationKeysForRequest re-runs the destination-key
// allowlist gate against a STORED cross_team request. api#168 blocks
// non-allowlisted keys at submit; this defense-in-depth re-check (api#169)
// runs again at the fill and execute boundaries so a request created before
// api#168 — or one whose binding allowlist was tightened after submit —
// cannot slip a disallowed key past those later stages. Same no-op posture
// as enforceBindingAllowedKeys: when the binding repos are unwired or the
// destination secret carries no restrictive allowlist, it passes cleanly.
func (s *RequestService) enforceCrossTeamDestinationKeysForRequest(ctx context.Context, req *storage.AccessRequest) error {
	if s.ctProvConns == nil || s.bindings == nil || s.secrets == nil {
		return nil
	}
	if req.DestinationProviderConnectionID == nil || req.TargetProjectID == nil {
		return nil
	}
	conn, err := s.ctProvConns.Get(ctx, *req.DestinationProviderConnectionID)
	if err != nil {
		if errors.Is(err, storage.ErrConnectionNotFound) {
			return ErrCrossTeamDestinationUnbound
		}
		return fmt.Errorf("services: resolve destination provider type: %w", err)
	}
	return s.enforceBindingAllowedKeys(ctx, *req.TargetProjectID, string(conn.Type), req.DestinationSecretRef, req.DestinationKeys)
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

// requireCrossTeamDestinationBinding refuses a destination provider
// connection that is not bound to the source project (API-N-03 /
// API-S-15). Same semantics as the submit drawer's destination dropdown:
// a project-wide binding (environment_id NULL) always counts; an
// environment-specific binding counts only for that source environment.
// When the source environment is unknown only project-wide bindings
// count. Fails closed when the binding repository isn't wired.
func (s *RequestService) requireCrossTeamDestinationBinding(ctx context.Context, sourceProjectID uuid.UUID, sourceEnvID *uuid.UUID, connID uuid.UUID) error {
	if s.ctDestBindings == nil {
		return ErrCrossTeamDestinationUnbound
	}
	rows, err := s.ctDestBindings.ListForProject(ctx, sourceProjectID, sourceEnvID)
	if err != nil {
		return fmt.Errorf("services: check destination binding: %w", err)
	}
	for _, b := range rows {
		if b.ProjectID != sourceProjectID || b.ProviderConnectionID != connID ||
			b.Purpose != storage.ProjectProviderConnectionPurposeDestination {
			continue
		}
		if b.EnvironmentID == nil {
			return nil
		}
		if sourceEnvID != nil && *b.EnvironmentID == *sourceEnvID {
			return nil
		}
	}
	return ErrCrossTeamDestinationUnbound
}

// crossTeamSourceProject returns the request's source project — the
// project the requester submitted from, whose provider connection is the
// destination. It lives in target_scope.project_id (target_project_id is
// the value provider's side). ok=false for legacy rows submitted without
// one.
func crossTeamSourceProject(req *storage.AccessRequest) (uuid.UUID, bool) {
	raw, ok := req.TargetScope["project_id"].(string)
	if !ok || raw == "" {
		return uuid.Nil, false
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, false
	}
	return id, true
}

// Fill wraps Team B's values via WrapService and atomically
// transitions the request to pending_verification. Plaintext flows
// through WrapService only.
func (s *RequestService) Fill(ctx context.Context, in FillCrossTeamInput) (*storage.AccessRequest, error) {
	// Every exit path, including the refusals below, leaves no plaintext
	// in the caller's map. zero is idempotent with the per-wrap zero.
	defer func() {
		for _, v := range in.KeyValues {
			zero(v)
		}
	}()
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

	// api#169 defense-in-depth: re-validate the request's destination keys
	// against the binding allowlist BEFORE wrapping any value. If a key is no
	// longer allowed (pre-api#168 row, or the allowlist was tightened after
	// submit), refuse the fill with ErrKeyNotAllowed → 403
	// cross_team_key_not_allowed. Runs before the wrap loop and before the
	// Fill transition, so no plaintext is persisted and the request stays
	// pending_values.
	if err := s.enforceCrossTeamDestinationKeysForRequest(ctx, req); err != nil {
		return nil, err
	}

	// API-S-07: the value provider may only supply the keys the request
	// declared. Anything else would be wrapped and handed to the agent's
	// patch job, writing keys nobody asked for or approved.
	declared := make(map[string]struct{}, len(req.DestinationKeys))
	for _, k := range req.DestinationKeys {
		declared[k] = struct{}{}
	}
	undeclared := 0
	for k := range in.KeyValues {
		if _, ok := declared[k]; !ok {
			undeclared++
		}
	}
	if undeclared > 0 {
		_ = s.audit.Append(ctx, &storage.AuditEvent{
			Actor:         "user:" + in.FillerID,
			Action:        "request.cross_team.fill.rejected",
			Resource:      "request:" + req.ID.String(),
			Status:        storage.AuditStatusDenied,
			CorrelationID: req.ID,
			Metadata: map[string]any{
				"reason":           "undeclared_key",
				"undeclared_count": undeclared,
			},
		})
		return nil, ErrCrossTeamKeyNotDeclared
	}

	if err := s.enforceRequestTTL(ctx, req, wf, in.FillerID, "fill"); err != nil {
		if errors.Is(err, storage.ErrStatusConflict) {
			return nil, fmt.Errorf("%w: %w", storage.ErrCrossTeamAlreadyFilled, err)
		}
		return nil, err
	}

	// Seal each plaintext under workflow.wrap_ttl_created (same envelope
	// path the patch flow uses; values never touch access_requests),
	// then store the wraps and the status change in one transaction.
	// Wrapping first and transitioning after used to leave a losing
	// filler's wraps attached to the request, where they rode along in
	// the patch job next to the winner's.
	sealed := make([]*storage.SecretWrap, 0, len(in.KeyValues))
	for k, v := range in.KeyValues {
		w, werr := s.wraps.Seal(ctx, WrapRequest{
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
		sealed = append(sealed, w)
	}

	fill := workflow.For(workflow.ActionFill)
	if err := s.requests.FillWithWraps(ctx, storage.FillInput{
		ID:             in.RequestID,
		From:           fill.From,
		To:             fill.To,
		FilledByUserID: in.FillerID,
		FillComment:    in.FillComment,
		FilledAt:       s.now().UTC(),
		Wraps:          sealed,
	}); err != nil {
		return nil, err
	}
	for _, w := range sealed {
		s.wraps.RecordCreated(ctx, w, "user:"+in.FillerID, wf.WrapTTLCreated)
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

// crossTeamLanes is the ordered list of votes a cross_team request needs.
// v1 supports min_approvers ∈ {0, 1}, so it is one source vote, followed
// by one security vote when the frozen workflow requires it.
func crossTeamLanes(requiresSecurity bool) []VotedAs {
	if requiresSecurity {
		return []VotedAs{VotedAsSource, VotedAsSecurity}
	}
	return []VotedAs{VotedAsSource}
}

// crossTeamLaneHolder reports whether userID holds the permission behind
// a verify lane on this request: secret.approve for the source lane,
// secret.security.approve for the security lane, in both cases at a scope
// covering the request's SOURCE project (the project whose destination
// gets written). A global grant covers every project; project- and
// team-scoped grants cover their projects, so scoped approvers keep
// working. A legacy request with no source project needs a global grant.
// Fails closed (false) when the approver resolver isn't wired.
func (s *RequestService) crossTeamLaneHolder(ctx context.Context, userID string, lane VotedAs, req *storage.AccessRequest) (bool, error) {
	if s.approverResolver == nil || userID == "" {
		return false, nil
	}
	perm := auth.PermSecretApprove
	if lane == VotedAsSecurity {
		perm = auth.PermSecretSecurityApprove
	}
	access, err := auth.EffectiveProjectAccess(ctx, userID, perm, s.approverResolver, s.approverTeamScope)
	if err != nil {
		return false, fmt.Errorf("services: resolve %s lane access: %w", lane, err)
	}
	if pid, ok := crossTeamSourceProject(req); ok {
		return access.Covers(pid), nil
	}
	return access.IsGlobal, nil
}

// approveVotes keeps the approve decisions, in the order they were cast.
func approveVotes(approvals []*storage.Approval) []*storage.Approval {
	out := make([]*storage.Approval, 0, len(approvals))
	for _, a := range approvals {
		if a.Decision == storage.ApprovalDecisionApprove {
			out = append(out, a)
		}
	}
	return out
}

// VerifyCrossTeam casts a source or security vote on a
// pending_verification cross_team request.
//
// API-N-01: the caller must hold the permission of the lane they name
// (see crossTeamLaneHolder) — the body can no longer pick a lane the
// caller has no right to. The approvals table has no lane column, so the
// lane of each approve is fixed by its position: the first approve is
// the source vote and, when security approval is required, the second is
// the security vote. A vote for any other lane is out of turn. Votes
// already on the request are re-checked against their positional lane, so
// one cast before this fix by someone without the permission never counts.
// The same actor can never cast both votes, and neither the requester nor
// the filler can vote at all.
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

	holds, err := s.crossTeamLaneHolder(ctx, in.ApproverID, in.VotedAs, req)
	if err != nil {
		return nil, err
	}
	if !holds {
		_ = s.audit.Append(ctx, &storage.AuditEvent{
			Actor:         "user:" + in.ApproverID,
			Action:        "request.cross_team.verify.denied",
			Resource:      "request:" + req.ID.String(),
			Status:        storage.AuditStatusDenied,
			CorrelationID: req.ID,
			Metadata: map[string]any{
				"voted_as": string(in.VotedAs),
				"decision": string(in.Decision),
				"reason":   "lane_permission_missing",
			},
		})
		return nil, ErrCrossTeamLaneForbidden
	}

	if req.SnapMinApprovers != nil && *req.SnapMinApprovers > 1 {
		// Rejected at submit since Slice N; refuse rather than mis-count.
		return nil, ErrCrossTeamMinApproversUnsupported
	}
	requiresSecurity := req.SnapRequiresSecurityApproval != nil && *req.SnapRequiresSecurityApproval
	lanes := crossTeamLanes(requiresSecurity)
	const sourceVotesNeeded = 1

	// Same actor casting a second vote on the same request (even in the
	// other lane, even holding both perms) is refused.
	existing, err := s.approvals.ListByRequest(ctx, req.ID)
	if err != nil {
		return nil, fmt.Errorf("services: list approvals: %w", err)
	}
	for _, ap := range existing {
		if ap.ApproverID == in.ApproverID && ap.Decision == storage.ApprovalDecisionApprove {
			return nil, ErrSeparationOfDuties
		}
	}

	// Reject is a terminal short-circuit from either lane, by anyone who
	// holds the lane they named. The vote and the transition are one
	// conditional transaction, so a reject racing an approve or a cancel
	// either wins outright or writes nothing.
	if in.Decision == storage.ApprovalDecisionReject {
		reject := workflow.For(workflow.ActionVerifyReject)
		if _, err := s.requests.CastVote(ctx, storage.CastVoteInput{
			Vote: &storage.Approval{
				RequestID:  req.ID,
				ApproverID: in.ApproverID,
				Decision:   storage.ApprovalDecisionReject,
				Comment:    in.Comment,
			},
			From:   reject.From,
			Decide: func(*storage.AccessRequest, []*storage.Approval) storage.AccessRequestStatus { return reject.To },
		}); err != nil {
			return nil, crossTeamVoteErr(err, "rejection")
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
			SourceVotesNeeded:        sourceVotesNeeded,
			SecurityApprovalRequired: requiresSecurity,
			SecurityVotePresent:      false,
			NextRequired:             []string{},
		}, nil
	}

	// Approve path. The vote must be for the next open lane, and every
	// approve already recorded must still hold its positional lane.
	prior := approveVotes(existing)
	if len(prior) >= len(lanes) || in.VotedAs != lanes[len(prior)] {
		return nil, ErrCrossTeamVoteOutOfTurn
	}
	for i, ap := range prior {
		ok, err := s.crossTeamLaneHolder(ctx, ap.ApproverID, lanes[i], req)
		if err != nil {
			return nil, err
		}
		if !ok {
			_ = s.audit.Append(ctx, &storage.AuditEvent{
				Actor:         "user:" + in.ApproverID,
				Action:        "request.cross_team.verify.denied",
				Resource:      "request:" + req.ID.String(),
				Status:        storage.AuditStatusDenied,
				CorrelationID: req.ID,
				Metadata: map[string]any{
					"voted_as":   string(in.VotedAs),
					"reason":     "prior_vote_lane_permission_missing",
					"prior_lane": string(lanes[i]),
				},
			})
			return nil, ErrCrossTeamPriorVoteInvalid
		}
	}

	// request_ttl bounds how long a request may wait for approval. Only
	// the approve vote moves it forward; a reject still closes it.
	if req.WorkflowID != nil {
		wf, err := s.workflows.Get(ctx, *req.WorkflowID)
		if err != nil {
			return nil, fmt.Errorf("services: load workflow: %w", err)
		}
		if err := s.enforceRequestTTL(ctx, req, wf, in.ApproverID, "verify"); err != nil {
			if errors.Is(err, storage.ErrStatusConflict) {
				return nil, fmt.Errorf("%w: %w", storage.ErrCrossTeamStatusInvalidTransition, err)
			}
			return nil, err
		}
	}

	// The vote, the lane count and the transition run in one transaction
	// under the request row lock, so concurrent votes are counted one at
	// a time and exactly one caller can approve. Lanes are counted by
	// position against the votes as locked (crossTeamLanesFilled): the
	// prior votes verified above and this caller's own vote fill their
	// lane; a vote that landed between the checks above and the lock was
	// never verified and fills nothing, so a race can only leave the
	// request short of a lane, never approve it on a vote that doesn't
	// hold it. Decide must not do I/O, hence no permission lookups inside.
	verify := workflow.For(workflow.ActionVerifyApprove)
	var filled []bool
	vote, err := s.requests.CastVote(ctx, storage.CastVoteInput{
		Vote: &storage.Approval{
			RequestID:  req.ID,
			ApproverID: in.ApproverID,
			Decision:   storage.ApprovalDecisionApprove,
			Comment:    in.Comment,
		},
		From: verify.From,
		Decide: func(_ *storage.AccessRequest, votes []*storage.Approval) storage.AccessRequestStatus {
			filled = crossTeamLanesFilled(approveVotes(votes), prior, lanes, in)
			for _, f := range filled {
				if !f {
					return ""
				}
			}
			return verify.To
		},
	})
	if err != nil {
		return nil, crossTeamVoteErr(err, "approval")
	}
	sourceVotes := 0
	if filled[0] {
		sourceVotes = 1
	}
	securityPresent := requiresSecurity && filled[1]

	statusToSet := vote.Request.Status
	if vote.Transitioned {
		// Wraps TTL refresh to the workflow's approved-TTL. Same
		// posture as the patch flow: failure audited, not bubbled.
		wf, wferr := s.workflows.Get(ctx, *req.WorkflowID)
		if wferr == nil {
			_ = s.refreshWrapsForRequest(ctx, req.ID, wf.WrapTTLApproved)
		}
		if s.jobs != nil {
			if jerr := s.enqueueRequestJob(ctx, vote.Request); jerr != nil {
				switch {
				case errors.Is(jerr, ErrKeyNotAllowed), errors.Is(jerr, ErrCrossTeamDestinationUnbound):
					// api#169 / API-N-03: a destination-key allowlist
					// rejection, or a destination no longer bound to the
					// source project, at the execute boundary is a policy
					// failure, not a transient enqueue error. No job was
					// created (no provider write); transition the request to
					// failed so it can't sit at approved waiting for a
					// dispatch that must never run. Metadata-only — never
					// the value, wrap, or payload.
					fail := workflow.For(workflow.ActionFail)
					if uerr := s.requests.TransitionStatus(ctx, req.ID, fail.From, fail.To); uerr == nil {
						statusToSet = fail.To
					}
					action, reason := "request.cross_team.execute.key_rejected", "destination_key_not_allowed"
					if errors.Is(jerr, ErrCrossTeamDestinationUnbound) {
						action, reason = "request.cross_team.execute.destination_rejected", "destination_not_bound_to_source_project"
					}
					_ = s.audit.Append(ctx, &storage.AuditEvent{
						Actor:         "user:" + in.ApproverID,
						Action:        action,
						Resource:      "request:" + req.ID.String(),
						Status:        storage.AuditStatusFailure,
						CorrelationID: req.ID,
						Metadata:      map[string]any{"reason": reason},
					})
				default:
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
			"source_votes_needed":        sourceVotesNeeded,
			"security_approval_required": requiresSecurity,
			"security_vote_present":      securityPresent,
		},
	})

	nextRequired := []string{}
	if sourceVotes < sourceVotesNeeded {
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
		SourceVotesNeeded:        sourceVotesNeeded,
		SecurityApprovalRequired: requiresSecurity,
		SecurityVotePresent:      securityPresent,
		NextRequired:             nextRequired,
	}, nil
}

// crossTeamVoteErr maps a CastVote failure on the verify path to the
// cross-team error vocabulary: a duplicate vote stays ErrDuplicateVote,
// a status conflict (someone else decided, cancelled or expired the
// request first) becomes ErrCrossTeamStatusInvalidTransition (409).
func crossTeamVoteErr(err error, what string) error {
	switch {
	case errors.Is(err, storage.ErrApprovalExists):
		return ErrDuplicateVote
	case errors.Is(err, storage.ErrStatusConflict):
		return fmt.Errorf("%w: %w", storage.ErrCrossTeamStatusInvalidTransition, err)
	default:
		return fmt.Errorf("services: record %s: %w", what, err)
	}
}

// crossTeamLanesFilled maps the ordered approve votes onto the required
// lanes. Position i fills lanes[i] when it holds the same vote that was
// verified for that position before the vote was cast (verified[i],
// checked against the lane's permission by VerifyCrossTeam); the
// current caller's position fills it only if it is the lane they named.
// Any other vote at a position was not verified for it and fills
// nothing. Votes past the last lane fill nothing. Pure, because it runs
// inside CastVote's Decide under the request row lock.
func crossTeamLanesFilled(approves, verified []*storage.Approval, lanes []VotedAs, current VerifyCrossTeamInput) []bool {
	filled := make([]bool, len(lanes))
	for i := 0; i < len(lanes) && i < len(approves); i++ {
		switch {
		case approves[i].ApproverID == current.ApproverID:
			filled[i] = lanes[i] == current.VotedAs
		case i < len(verified) && approves[i].ID == verified[i].ID:
			filled[i] = true
		}
	}
	return filled
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
