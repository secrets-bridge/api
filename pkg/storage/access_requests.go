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
type AccessRequestRepository interface {
	Create(ctx context.Context, r *AccessRequest) error
	Get(ctx context.Context, id uuid.UUID) (*AccessRequest, error)
	List(ctx context.Context, f AccessRequestListFilter) ([]*AccessRequest, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status AccessRequestStatus) error
	SetJobID(ctx context.Context, id, jobID uuid.UUID) error
	SetRejectReason(ctx context.Context, id uuid.UUID, reason string) error

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
