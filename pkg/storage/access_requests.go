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
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// AccessRequestType is constrained by the schema CHECK.
type AccessRequestType string

const (
	AccessRequestTypeRead   AccessRequestType = "read"
	AccessRequestTypeUpdate AccessRequestType = "update"
	AccessRequestTypeRotate AccessRequestType = "rotate"
	AccessRequestTypePatch  AccessRequestType = "patch"
)

// AccessRequestStatus is constrained by the schema CHECK.
type AccessRequestStatus string

const (
	AccessRequestStatusPending   AccessRequestStatus = "pending"
	AccessRequestStatusApproved  AccessRequestStatus = "approved"
	AccessRequestStatusRejected  AccessRequestStatus = "rejected"
	AccessRequestStatusCancelled AccessRequestStatus = "cancelled"
	AccessRequestStatusExecuted  AccessRequestStatus = "executed"
	AccessRequestStatusFailed    AccessRequestStatus = "failed"
	AccessRequestStatusExpired   AccessRequestStatus = "expired"
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
	       job_id, COALESCE(reject_reason, ''), created_at, updated_at
	FROM access_requests`

func scanAccessRequest(row interface {
	Scan(dest ...any) error
}) (*AccessRequest, error) {
	var (
		ar             AccessRequest
		workflowID     *uuid.UUID
		mappingID      *uuid.UUID
		envID          *uuid.UUID
		providerCfg    []byte
		keys           []byte
		scope          []byte
		jobID          *uuid.UUID
	)
	err := row.Scan(
		&ar.ID, &ar.RequesterID, &ar.Type, &ar.Justification, &ar.Status,
		&workflowID, &mappingID, &envID,
		&ar.TargetProviderType, &providerCfg,
		&ar.TargetSecretRef, &keys, &scope,
		&jobID, &ar.RejectReason, &ar.CreatedAt, &ar.UpdatedAt,
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
	return &ar, nil
}
