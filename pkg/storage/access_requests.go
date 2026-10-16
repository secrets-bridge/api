package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AccessRequest mirrors a row in access_requests. For the patch flow,
// the legacy `secret_mapping_id` column is nullable; the patch-specific
// fields (workflow_id, target_*) describe where the patch lands.
//
// Importantly: AccessRequest carries NO secret VALUES. The values live
// in secret_wraps (one wrap per key in TargetKeys), keyed by request_id.
type AccessRequest struct {
	ID                   uuid.UUID
	RequesterID          string
	Type                 AccessRequestType
	Justification        string
	Status               AccessRequestStatus
	WorkflowID           *uuid.UUID
	SecretMappingID      *uuid.UUID
	// EnvironmentID is the authoritative binding to environments(id)
	// added by Slice L3. Nullable while the codepath migrates off the
	// free-string `TargetScope["environment"]` join; a later migration
	// flips it NOT NULL once all callers populate it.
	EnvironmentID        *uuid.UUID
	TargetProviderType   string
	TargetProviderConfig map[string]any
	TargetSecretRef      string
	TargetKeys           []string
	TargetScope          map[string]any
	JobID                *uuid.UUID
	RejectReason         string

	// --- Slice N1 cross_team fields ---
	//
	// All NULL on non-cross_team rows; a CHECK constraint enforces that
	// cross_team rows carry every binding + snapshot column.

	// Target = who provides the values (Team B's scope).
	TargetTeamID        *uuid.UUID
	TargetProjectID     *uuid.UUID
	TargetEnvironmentID *uuid.UUID

	// Destination = where the values land (source project's provider
	// connection + secret ref + key list).
	DestinationProviderConnectionID *uuid.UUID
	DestinationSecretRef            string
	DestinationKeys                 []string

	// Fill / refuse breadcrumbs.
	RefuseReason    string
	FillComment     string
	FilledAt        *time.Time
	FilledByUserID  string
	FillExpiresAt   *time.Time

	// Workflow snapshot — frozen at SubmitCrossTeam time so admin
	// edits to the workflow row don't change in-flight semantics.
	MatchedPolicyRuleID          *uuid.UUID
	SnapRequiresSecurityApproval *bool
	SnapMinApprovers             *int16

	CreatedAt time.Time
	UpdatedAt time.Time
}

// AccessRequestType is constrained by the schema CHECK.
type AccessRequestType string

const (
	AccessRequestTypeRead      AccessRequestType = "read"
	AccessRequestTypeUpdate    AccessRequestType = "update"
	AccessRequestTypeRotate    AccessRequestType = "rotate"
	AccessRequestTypePatch     AccessRequestType = "patch"
	AccessRequestTypeCrossTeam AccessRequestType = "cross_team"
)

// AccessRequestStatus is constrained by the schema CHECK.
type AccessRequestStatus string

const (
	AccessRequestStatusPending             AccessRequestStatus = "pending"
	AccessRequestStatusApproved            AccessRequestStatus = "approved"
	AccessRequestStatusRejected            AccessRequestStatus = "rejected"
	AccessRequestStatusCancelled           AccessRequestStatus = "cancelled"
	AccessRequestStatusExecuted            AccessRequestStatus = "executed"
	AccessRequestStatusFailed              AccessRequestStatus = "failed"
	AccessRequestStatusExpired             AccessRequestStatus = "expired"
	// Slice N1 — cross_team-only statuses. Schema CHECK
	// access_requests_cross_team_status_only refuses these on
	// non-cross_team rows.
	AccessRequestStatusPendingValues       AccessRequestStatus = "pending_values"
	AccessRequestStatusPendingVerification AccessRequestStatus = "pending_verification"
	AccessRequestStatusRefused             AccessRequestStatus = "refused"
)

// AccessRequestListFilter narrows List queries. All fields optional.
type AccessRequestListFilter struct {
	RequesterID string
	Status      AccessRequestStatus
	Limit       int // defaults to 100, capped at 500
}

// AccessRequestRepository is the read/write surface.
//
// Every status change goes through a conditional write: TransitionStatus,
// CastVote, FillWithWraps, Fill, Refuse and SweepFillExpired all match
// on the current status, so a caller acting on a stale read can't
// overwrite a decision that already landed. There is deliberately no
// unconditional status setter on this interface.
type AccessRequestRepository interface {
	Create(ctx context.Context, r *AccessRequest) error
	Get(ctx context.Context, id uuid.UUID) (*AccessRequest, error)
	List(ctx context.Context, f AccessRequestListFilter) ([]*AccessRequest, error)
	SetJobID(ctx context.Context, id, jobID uuid.UUID) error
	SetRejectReason(ctx context.Context, id uuid.UUID, reason string) error

	// TransitionStatus moves the request to `to` only while its status
	// is one of `from`. Returns ErrStatusConflict when the row exists in
	// another status, ErrNotFound when it doesn't exist.
	TransitionStatus(ctx context.Context, id uuid.UUID, from []AccessRequestStatus, to AccessRequestStatus) error
	// CastVote records one approve/reject vote and, when the caller's
	// Decide says so, the status transition it triggers, in a single
	// transaction holding the request row lock. See CastVoteInput.
	CastVote(ctx context.Context, in CastVoteInput) (*CastVoteResult, error)
	// FillWithWraps stores Team B's sealed wraps and moves a cross_team
	// request out of pending_values in one transaction, so the wraps
	// exist only if the fill wins. See FillInput.
	FillWithWraps(ctx context.Context, in FillInput) error

	// --- Slice N1 cross_team methods ---

	// CreateCrossTeam inserts a type='cross_team' row with status
	// 'pending_values'. The caller is responsible for stamping
	// fill_expires_at + workflow snapshot fields before calling.
	CreateCrossTeam(ctx context.Context, r *AccessRequest) error
	// Fill atomically transitions a 'pending_values' row to
	// 'pending_verification'. Returns ErrCrossTeamAlreadyFilled when
	// the row is no longer pending_values (race with refuse / cancel /
	// expiry / a previous fill). Returns ErrFillWindowExpired when
	// fill_expires_at has passed.
	Fill(ctx context.Context, id uuid.UUID, filledByUserID, fillComment string, filledAt time.Time) error
	// Refuse atomically transitions a 'pending_values' row to
	// 'refused' + stores the reason. Returns
	// ErrCrossTeamStatusInvalidTransition when not in pending_values.
	Refuse(ctx context.Context, id uuid.UUID, reason string) error
	// SweepFillExpired flips every cross_team 'pending_values' row
	// whose fill_expires_at <= now to 'expired'. Returns the affected
	// row identities for the worker sweeper's audit emission.
	SweepFillExpired(ctx context.Context, now time.Time) ([]SweptFillExpired, error)
	// ListInbox returns 'pending_values' cross_team rows for the given
	// team filter, oldest first. Caller is responsible for filtering
	// by the caller's allowed team_id set (authorization concern).
	ListInbox(ctx context.Context, f InboxFilter) ([]*AccessRequest, error)
}

// SweptFillExpired carries the (id, requester_id) pair returned by
// SweepFillExpired so the worker sweeper can audit per-row without
// loading the full request.
type SweptFillExpired struct {
	ID          uuid.UUID
	RequesterID string
}

// InboxFilter narrows ListInbox queries. TeamIDs is the allowed-team
// set the caller has secret.value.provide on; an empty slice means
// no rows are returned (fail-closed). Limit defaults to 100, capped
// at 500.
type InboxFilter struct {
	TeamIDs []uuid.UUID
	Limit   int
}

// ErrCrossTeamAlreadyFilled is returned by Fill when the request is
// no longer in pending_values (already filled, refused, cancelled,
// expired, or another race).
var ErrCrossTeamAlreadyFilled = errors.New("storage: cross_team request already filled or no longer pending_values")

// ErrFillWindowExpired is returned by Fill when fill_expires_at has
// elapsed. Distinct from ErrCrossTeamAlreadyFilled so the service
// layer can return the correct stable error code to the client.
var ErrFillWindowExpired = errors.New("storage: cross_team fill window expired")

// ErrCrossTeamStatusInvalidTransition is returned by Refuse when the
// row isn't in pending_values, or by any future cross_team state
// mutation that doesn't match the expected source state.
var ErrCrossTeamStatusInvalidTransition = errors.New("storage: cross_team status invalid transition")

// ErrStatusConflict is returned by the conditional status writes when
// the request exists but its current status is not one the transition
// may start from: another caller approved, rejected, cancelled or
// expired it first. Handlers map it to 409.
var ErrStatusConflict = errors.New("storage: access_request status does not allow this transition")

// CastVoteInput is one approve/reject vote for CastVote.
type CastVoteInput struct {
	// Vote is the row to insert. RequestID, ApproverID and Decision are
	// required; ID and CreatedAt are filled in.
	Vote *Approval
	// From lists the statuses the vote may be cast in. Checked against
	// the locked row, so it is authoritative.
	From []AccessRequestStatus
	// Decide runs inside the transaction after the vote row is written,
	// with the locked request and every vote on it (the new one
	// included). It returns the status to move to, or "" to leave the
	// status alone. It must not do I/O.
	Decide func(req *AccessRequest, votes []*Approval) AccessRequestStatus
	// RejectReason, when non-empty, is stamped on the row together with
	// the transition.
	RejectReason string
}

// CastVoteResult reports what CastVote did.
type CastVoteResult struct {
	// Request is the row as of the commit (status updated when
	// Transitioned).
	Request *AccessRequest
	// Votes is every vote on the request, the new one included.
	Votes []*Approval
	// Transitioned is true only for the one caller whose vote moved the
	// status. Side effects of the transition (job enqueue, wrap TTLs)
	// belong to that caller alone.
	Transitioned bool
}

// FillInput is the data FillWithWraps writes.
type FillInput struct {
	ID             uuid.UUID
	From           []AccessRequestStatus
	To             AccessRequestStatus
	FilledByUserID string
	FillComment    string
	FilledAt       time.Time
	// Wraps are sealed but not yet stored. Each one is inserted with
	// RequestID = ID inside the fill transaction.
	Wraps []*SecretWrap
}

// AccessRequests is the Postgres implementation.
type AccessRequests struct {
	pool *Pool
}

// NewAccessRequests binds a repository to the pool.
func NewAccessRequests(pool *Pool) *AccessRequests { return &AccessRequests{pool: pool} }

func (r *AccessRequests) Create(ctx context.Context, req *AccessRequest) error {
	if req.RequesterID == "" {
		return errors.New("storage: RequesterID is required")
	}
	if req.Type == "" {
		return errors.New("storage: Type is required")
	}
	if req.Justification == "" {
		return errors.New("storage: Justification is required")
	}
	if req.Status == "" {
		req.Status = AccessRequestStatusPending
	}
	if req.TargetProviderConfig == nil {
		req.TargetProviderConfig = map[string]any{}
	}
	if req.TargetKeys == nil {
		req.TargetKeys = []string{}
	}
	if req.TargetScope == nil {
		req.TargetScope = map[string]any{}
	}
	providerCfg, err := json.Marshal(req.TargetProviderConfig)
	if err != nil {
		return fmt.Errorf("storage: marshal target_provider_config: %w", err)
	}
	keys, err := json.Marshal(req.TargetKeys)
	if err != nil {
		return fmt.Errorf("storage: marshal target_keys: %w", err)
	}
	scope, err := json.Marshal(req.TargetScope)
	if err != nil {
		return fmt.Errorf("storage: marshal target_scope: %w", err)
	}

	const q = `
		INSERT INTO access_requests (
		    requester_id, type, justification, status, workflow_id,
		    secret_mapping_id, environment_id, target_provider_type, target_provider_config,
		    target_secret_ref, target_keys, target_scope
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), $9, NULLIF($10, ''), $11, $12)
		RETURNING id, created_at, updated_at`
	return r.pool.QueryRow(ctx, q,
		req.RequesterID, req.Type, req.Justification, req.Status, req.WorkflowID,
		req.SecretMappingID, req.EnvironmentID, req.TargetProviderType, providerCfg,
		req.TargetSecretRef, keys, scope,
	).Scan(&req.ID, &req.CreatedAt, &req.UpdatedAt)
}

func (r *AccessRequests) Get(ctx context.Context, id uuid.UUID) (*AccessRequest, error) {
	return scanAccessRequest(r.pool.QueryRow(ctx, accessRequestSelect+` WHERE id = $1`, id))
}

func (r *AccessRequests) List(ctx context.Context, f AccessRequestListFilter) ([]*AccessRequest, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	if f.Limit > 500 {
		f.Limit = 500
	}

	clauses := make([]string, 0, 2)
	args := make([]any, 0, 3)
	if f.RequesterID != "" {
		args = append(args, f.RequesterID)
		clauses = append(clauses, fmt.Sprintf("requester_id = $%d", len(args)))
	}
	if f.Status != "" {
		args = append(args, f.Status)
		clauses = append(clauses, fmt.Sprintf("status = $%d", len(args)))
	}

	q := accessRequestSelect
	if len(clauses) > 0 {
		q += " WHERE " + clauses[0]
		for _, c := range clauses[1:] {
			q += " AND " + c
		}
	}
	args = append(args, f.Limit)
	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", len(args))

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("storage: list access_requests: %w", err)
	}
	defer rows.Close()
	var out []*AccessRequest
	for rows.Next() {
		ar, err := scanAccessRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ar)
	}
	return out, rows.Err()
}

// UpdateStatus overwrites the status unconditionally. It is NOT part of
// AccessRequestRepository, so lifecycle code can't reach it; it stays
// on the concrete type for test fixtures that need to force a row into
// a given state. Lifecycle code uses TransitionStatus / CastVote.
func (r *AccessRequests) UpdateStatus(ctx context.Context, id uuid.UUID, status AccessRequestStatus) error {
	const q = `UPDATE access_requests SET status = $2 WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q, id, status)
	if err != nil {
		return fmt.Errorf("storage: update access_request status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *AccessRequests) SetJobID(ctx context.Context, id, jobID uuid.UUID) error {
	const q = `UPDATE access_requests SET job_id = $2 WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q, id, jobID)
	if err != nil {
		return fmt.Errorf("storage: set access_request job_id: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *AccessRequests) SetRejectReason(ctx context.Context, id uuid.UUID, reason string) error {
	const q = `UPDATE access_requests SET reject_reason = $2 WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q, id, reason)
	if err != nil {
		return fmt.Errorf("storage: set reject_reason: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// TransitionStatus is the single-statement conditional status write:
// `UPDATE … WHERE id = $1 AND status = ANY($from)`. When nothing
// matched it tells "gone" (ErrNotFound) apart from "someone else moved
// it first" (ErrStatusConflict).
func (r *AccessRequests) TransitionStatus(ctx context.Context, id uuid.UUID, from []AccessRequestStatus, to AccessRequestStatus) error {
	if len(from) == 0 || to == "" {
		return errors.New("storage: TransitionStatus needs from and to statuses")
	}
	const q = `UPDATE access_requests SET status = $2 WHERE id = $1 AND status = ANY($3::text[])`
	tag, err := r.pool.Exec(ctx, q, id, string(to), statusStrings(from))
	if err != nil {
		return fmt.Errorf("storage: transition access_request status: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	return statusConflict(ctx, r.pool, id)
}

// CastVote inserts the vote and applies the transition Decide asks for
// in one transaction that holds the access_requests row lock
// (SELECT … FOR NO KEY UPDATE). Concurrent votes on the same request
// queue on that lock, so each one sees the status and the vote count
// the previous one committed:
//
//   - a vote that arrives after the request left From fails with
//     ErrStatusConflict and its vote row is never written;
//   - the threshold is crossed by exactly one caller, which is the only
//     one with Transitioned = true;
//   - a duplicate vote by the same approver fails with
//     ErrApprovalExists (unique index), the transaction rolls back.
func (r *AccessRequests) CastVote(ctx context.Context, in CastVoteInput) (*CastVoteResult, error) {
	if in.Vote == nil || in.Decide == nil || len(in.From) == 0 {
		return nil, errors.New("storage: CastVote needs a vote, a from-status set and a Decide func")
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("storage: begin vote tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	cur, err := scanAccessRequest(tx.QueryRow(ctx, accessRequestSelect+` WHERE id = $1 FOR NO KEY UPDATE`, in.Vote.RequestID))
	if err != nil {
		return nil, err
	}
	if !statusIn(cur.Status, in.From) {
		return nil, fmt.Errorf("%w (current status %q)", ErrStatusConflict, cur.Status)
	}
	if err := insertApproval(ctx, tx, in.Vote); err != nil {
		return nil, err
	}
	votes, err := listApprovals(ctx, tx, cur.ID)
	if err != nil {
		return nil, err
	}

	res := &CastVoteResult{Request: cur, Votes: votes}
	if to := in.Decide(cur, votes); to != "" {
		// The row is locked, so the status guard can't miss; it stays as
		// a second line of defence.
		const q = `
			UPDATE access_requests
			SET status = $2,
			    reject_reason = COALESCE(NULLIF($4, ''), reject_reason)
			WHERE id = $1 AND status = ANY($3::text[])
			RETURNING updated_at`
		err := tx.QueryRow(ctx, q, cur.ID, string(to), statusStrings(in.From), in.RejectReason).Scan(&cur.UpdatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrStatusConflict
		}
		if err != nil {
			return nil, fmt.Errorf("storage: apply vote transition: %w", err)
		}
		cur.Status = to
		if in.RejectReason != "" {
			cur.RejectReason = in.RejectReason
		}
		res.Transitioned = true
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("storage: commit vote: %w", err)
	}
	return res, nil
}

// FillWithWraps is the transactional Fill: under the request row lock
// it checks type, status and fill window, inserts every sealed wrap
// against the request and moves it to in.To. If any step fails nothing
// is written, so a filler that loses a race (to another filler, a
// refuse, a cancel or the fill-window sweeper) leaves no wraps behind.
//
// Errors mirror Fill: ErrCrossTeamStatusInvalidTransition for a
// non-cross_team row, ErrCrossTeamAlreadyFilled when the status is not
// in From, ErrFillWindowExpired when fill_expires_at has passed.
func (r *AccessRequests) FillWithWraps(ctx context.Context, in FillInput) error {
	if len(in.From) == 0 || in.To == "" {
		return errors.New("storage: FillWithWraps needs from and to statuses")
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("storage: begin fill tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	cur, err := scanAccessRequest(tx.QueryRow(ctx, accessRequestSelect+` WHERE id = $1 FOR NO KEY UPDATE`, in.ID))
	if err != nil {
		return err
	}
	if cur.Type != AccessRequestTypeCrossTeam {
		return ErrCrossTeamStatusInvalidTransition
	}
	if !statusIn(cur.Status, in.From) {
		return ErrCrossTeamAlreadyFilled
	}
	if cur.FillExpiresAt == nil || !cur.FillExpiresAt.After(in.FilledAt) {
		return ErrFillWindowExpired
	}

	for _, w := range in.Wraps {
		id := in.ID
		w.RequestID = &id
		if err := insertSecretWrap(ctx, tx, w); err != nil {
			return fmt.Errorf("storage: insert fill wrap: %w", err)
		}
	}

	const q = `
		UPDATE access_requests
		SET status = $2,
		    filled_by_user_id = $3,
		    fill_comment = NULLIF($4, ''),
		    filled_at = $5
		WHERE id = $1
		  AND type = 'cross_team'
		  AND status = ANY($6::text[])
		  AND fill_expires_at > $5`
	tag, err := tx.Exec(ctx, q, in.ID, string(in.To), in.FilledByUserID, in.FillComment, in.FilledAt, statusStrings(in.From))
	if err != nil {
		return fmt.Errorf("storage: fill cross_team request: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrCrossTeamAlreadyFilled
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("storage: commit fill: %w", err)
	}
	return nil
}

// statusConflict runs after a conditional write matched no row and
// tells a missing request apart from one in another status.
func statusConflict(ctx context.Context, q querier, id uuid.UUID) error {
	var cur AccessRequestStatus
	err := q.QueryRow(ctx, `SELECT status FROM access_requests WHERE id = $1`, id).Scan(&cur)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("storage: probe access_request status: %w", err)
	}
	return fmt.Errorf("%w (current status %q)", ErrStatusConflict, cur)
}

func statusIn(s AccessRequestStatus, set []AccessRequestStatus) bool {
	for _, x := range set {
		if x == s {
			return true
		}
	}
	return false
}

func statusStrings(set []AccessRequestStatus) []string {
	out := make([]string, len(set))
	for i, s := range set {
		out[i] = string(s)
	}
	return out
}

const accessRequestSelect = `
	SELECT id, requester_id, type, COALESCE(justification, ''), status,
	       workflow_id, secret_mapping_id, environment_id,
	       COALESCE(target_provider_type, ''), target_provider_config,
	       COALESCE(target_secret_ref, ''), target_keys, target_scope,
	       job_id, COALESCE(reject_reason, ''), created_at, updated_at,
	       target_team_id, target_project_id, target_environment_id,
	       destination_provider_connection_id,
	       COALESCE(destination_secret_ref, ''), destination_keys,
	       COALESCE(fill_comment, ''), filled_at,
	       COALESCE(filled_by_user_id, ''), fill_expires_at,
	       matched_policy_rule_id, snap_requires_security_approval,
	       snap_min_approvers
	FROM access_requests`

func scanAccessRequest(row interface {
	Scan(dest ...any) error
}) (*AccessRequest, error) {
	var (
		ar                AccessRequest
		workflowID        *uuid.UUID
		mappingID         *uuid.UUID
		envID             *uuid.UUID
		providerCfg       []byte
		keys              []byte
		scope             []byte
		jobID             *uuid.UUID
		targetTeamID      *uuid.UUID
		targetProjectID   *uuid.UUID
		targetEnvID       *uuid.UUID
		destProvConnID    *uuid.UUID
		destKeys          []byte
		filledAt          *time.Time
		fillExpiresAt     *time.Time
		policyRuleID      *uuid.UUID
		snapRequiresSec   *bool
		snapMinApprovers  *int16
	)
	err := row.Scan(
		&ar.ID, &ar.RequesterID, &ar.Type, &ar.Justification, &ar.Status,
		&workflowID, &mappingID, &envID,
		&ar.TargetProviderType, &providerCfg,
		&ar.TargetSecretRef, &keys, &scope,
		&jobID, &ar.RejectReason, &ar.CreatedAt, &ar.UpdatedAt,
		&targetTeamID, &targetProjectID, &targetEnvID,
		&destProvConnID, &ar.DestinationSecretRef, &destKeys,
		&ar.FillComment, &filledAt, &ar.FilledByUserID, &fillExpiresAt,
		&policyRuleID, &snapRequiresSec, &snapMinApprovers,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("storage: scan access_request: %w", err)
	}
	ar.WorkflowID = workflowID
	ar.SecretMappingID = mappingID
	ar.EnvironmentID = envID
	ar.JobID = jobID
	if len(providerCfg) > 0 {
		_ = json.Unmarshal(providerCfg, &ar.TargetProviderConfig)
	}
	if len(keys) > 0 {
		_ = json.Unmarshal(keys, &ar.TargetKeys)
	}
	if len(scope) > 0 {
		_ = json.Unmarshal(scope, &ar.TargetScope)
	}
	ar.TargetTeamID = targetTeamID
	ar.TargetProjectID = targetProjectID
	ar.TargetEnvironmentID = targetEnvID
	ar.DestinationProviderConnectionID = destProvConnID
	if len(destKeys) > 0 {
		_ = json.Unmarshal(destKeys, &ar.DestinationKeys)
	}
	ar.FilledAt = filledAt
	ar.FillExpiresAt = fillExpiresAt
	ar.MatchedPolicyRuleID = policyRuleID
	ar.SnapRequiresSecurityApproval = snapRequiresSec
	ar.SnapMinApprovers = snapMinApprovers
	return &ar, nil
}

// --- Slice N1 cross_team method implementations ---

// CreateCrossTeam inserts a type='cross_team' row with status
// 'pending_values'. Caller stamps every cross_team-required column
// before calling: target_*, destination_*, fill_expires_at, snapshot
// columns. The schema CHECKs reject any missing field.
func (r *AccessRequests) CreateCrossTeam(ctx context.Context, req *AccessRequest) error {
	if req.RequesterID == "" {
		return errors.New("storage: RequesterID is required")
	}
	if req.Type != AccessRequestTypeCrossTeam {
		return fmt.Errorf("storage: CreateCrossTeam called with type=%q", req.Type)
	}
	if req.Justification == "" {
		return errors.New("storage: Justification is required")
	}
	if req.Status == "" {
		req.Status = AccessRequestStatusPendingValues
	}
	if req.TargetTeamID == nil || req.TargetProjectID == nil || req.TargetEnvironmentID == nil {
		return errors.New("storage: cross_team requires target team/project/environment")
	}
	if req.DestinationProviderConnectionID == nil || req.DestinationSecretRef == "" {
		return errors.New("storage: cross_team requires destination provider connection and secret_ref")
	}
	if len(req.DestinationKeys) == 0 {
		return errors.New("storage: cross_team requires at least one destination key")
	}
	if req.FillExpiresAt == nil {
		return errors.New("storage: cross_team requires FillExpiresAt")
	}
	if req.SnapRequiresSecurityApproval == nil || req.SnapMinApprovers == nil {
		return errors.New("storage: cross_team requires workflow snapshot fields")
	}

	destKeys, err := json.Marshal(req.DestinationKeys)
	if err != nil {
		return fmt.Errorf("storage: marshal destination_keys: %w", err)
	}
	if req.TargetScope == nil {
		req.TargetScope = map[string]any{}
	}
	scope, err := json.Marshal(req.TargetScope)
	if err != nil {
		return fmt.Errorf("storage: marshal target_scope: %w", err)
	}

	const q = `
		INSERT INTO access_requests (
		    requester_id, type, justification, status, workflow_id,
		    environment_id, target_scope,
		    target_team_id, target_project_id, target_environment_id,
		    destination_provider_connection_id, destination_secret_ref, destination_keys,
		    fill_expires_at,
		    matched_policy_rule_id, snap_requires_security_approval, snap_min_approvers
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
		RETURNING id, created_at, updated_at`
	return r.pool.QueryRow(ctx, q,
		req.RequesterID, req.Type, req.Justification, req.Status, req.WorkflowID,
		req.EnvironmentID, scope,
		req.TargetTeamID, req.TargetProjectID, req.TargetEnvironmentID,
		req.DestinationProviderConnectionID, req.DestinationSecretRef, destKeys,
		req.FillExpiresAt,
		req.MatchedPolicyRuleID, req.SnapRequiresSecurityApproval, req.SnapMinApprovers,
	).Scan(&req.ID, &req.CreatedAt, &req.UpdatedAt)
}

// Fill atomically transitions a pending_values row to
// pending_verification. Distinguishes "already filled" from "fill
// window expired" by looking at the row state after a no-op UPDATE.
func (r *AccessRequests) Fill(ctx context.Context, id uuid.UUID, filledByUserID, fillComment string, filledAt time.Time) error {
	const q = `
		UPDATE access_requests
		SET status = 'pending_verification',
		    filled_by_user_id = $2,
		    fill_comment = NULLIF($3, ''),
		    filled_at = $4
		WHERE id = $1
		  AND type = 'cross_team'
		  AND status = 'pending_values'
		  AND fill_expires_at > $4`
	tag, err := r.pool.Exec(ctx, q, id, filledByUserID, fillComment, filledAt)
	if err != nil {
		return fmt.Errorf("storage: fill cross_team request: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	// Branch on the actual state.
	cur, getErr := r.Get(ctx, id)
	if getErr != nil {
		return getErr
	}
	if cur.Type != AccessRequestTypeCrossTeam {
		return ErrCrossTeamStatusInvalidTransition
	}
	if cur.Status != AccessRequestStatusPendingValues {
		return ErrCrossTeamAlreadyFilled
	}
	// status is still pending_values → only the TTL gate could have
	// blocked the UPDATE.
	if cur.FillExpiresAt != nil && !cur.FillExpiresAt.After(filledAt) {
		return ErrFillWindowExpired
	}
	// Unreachable — defensive fallback so the caller never sees a
	// silently-failed UPDATE.
	return ErrCrossTeamStatusInvalidTransition
}

// Refuse atomically transitions a pending_values row to refused.
func (r *AccessRequests) Refuse(ctx context.Context, id uuid.UUID, reason string) error {
	const q = `
		UPDATE access_requests
		SET status = 'refused',
		    refuse_reason = $2
		WHERE id = $1
		  AND type = 'cross_team'
		  AND status = 'pending_values'`
	tag, err := r.pool.Exec(ctx, q, id, reason)
	if err != nil {
		return fmt.Errorf("storage: refuse cross_team request: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	// Distinguish absent from already-transitioned.
	if _, getErr := r.Get(ctx, id); getErr != nil {
		return getErr
	}
	return ErrCrossTeamStatusInvalidTransition
}

// SweepFillExpired transitions every cross_team pending_values row
// whose fill_expires_at <= now to 'expired'. Single round-trip
// UPDATE … RETURNING — same distributed-safe pattern Slice M3 uses
// for reveal_sessions.
func (r *AccessRequests) SweepFillExpired(ctx context.Context, now time.Time) ([]SweptFillExpired, error) {
	const q = `
		UPDATE access_requests
		SET status = 'expired'
		WHERE type = 'cross_team'
		  AND status = 'pending_values'
		  AND fill_expires_at <= $1
		RETURNING id, requester_id`
	rows, err := r.pool.Query(ctx, q, now)
	if err != nil {
		return nil, fmt.Errorf("storage: sweep cross_team fill expired: %w", err)
	}
	defer rows.Close()

	var out []SweptFillExpired
	for rows.Next() {
		var s SweptFillExpired
		if err := rows.Scan(&s.ID, &s.RequesterID); err != nil {
			return nil, fmt.Errorf("storage: scan swept fill expired: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ListInbox returns pending_values cross_team rows for the given
// team filter, oldest first (FIFO inbox ordering).
func (r *AccessRequests) ListInbox(ctx context.Context, f InboxFilter) ([]*AccessRequest, error) {
	if len(f.TeamIDs) == 0 {
		// Fail-closed — caller didn't tell us which teams they cover.
		return nil, nil
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}

	q := accessRequestSelect + `
		WHERE type = 'cross_team'
		  AND status = 'pending_values'
		  AND target_team_id = ANY($1)
		ORDER BY created_at ASC
		LIMIT $2`
	rows, err := r.pool.Query(ctx, q, f.TeamIDs, limit)
	if err != nil {
		return nil, fmt.Errorf("storage: list cross_team inbox: %w", err)
	}
	defer rows.Close()
	var out []*AccessRequest
	for rows.Next() {
		ar, err := scanAccessRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ar)
	}
	return out, rows.Err()
}
