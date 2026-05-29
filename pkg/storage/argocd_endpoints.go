package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ArgoCDEndpoint is the per-environment ArgoCD instance configuration.
// The token is held as a KMS-wrapped envelope (same pattern as
// secret_wraps); the unwrap happens at observation time inside the
// service layer. PostgreSQL NEVER sees the plaintext token.
type ArgoCDEndpoint struct {
	ID                       uuid.UUID
	Name                     string
	EnvironmentID            *uuid.UUID
	BaseURL                  string
	TokenCiphertext          []byte // AES-256-GCM ciphertext of the token
	TokenDataKeyCiphertext   []byte // KMS-wrapped DEK
	TokenNonce               []byte
	TokenKMSKeyID            string
	TLSCAPEM                 string
	TLSServerName            string
	Enabled                  bool
	LastHealthAt             *time.Time
	LastHealthError          string
	CreatedAt                time.Time
	UpdatedAt                time.Time
	DeletedAt                *time.Time
}

// ArgoCDEndpointRepository is the read/write surface for argocd_endpoints.
type ArgoCDEndpointRepository interface {
	Create(ctx context.Context, e *ArgoCDEndpoint) error
	Get(ctx context.Context, id uuid.UUID) (*ArgoCDEndpoint, error)
	GetByName(ctx context.Context, name string) (*ArgoCDEndpoint, error)
	List(ctx context.Context) ([]*ArgoCDEndpoint, error)
	UpdateHealth(ctx context.Context, id uuid.UUID, healthAt time.Time, healthErr string) error
	SetEnabled(ctx context.Context, id uuid.UUID, enabled bool) error
	SoftDelete(ctx context.Context, id uuid.UUID) error
}

// ArgoCDEndpoints is the Postgres impl.
type ArgoCDEndpoints struct {
	pool *Pool
}

// NewArgoCDEndpoints binds the repository to the pool.
func NewArgoCDEndpoints(pool *Pool) *ArgoCDEndpoints { return &ArgoCDEndpoints{pool: pool} }

// Create inserts a new endpoint. token_* fields MUST be the wrapped
// form — never the raw token.
func (r *ArgoCDEndpoints) Create(ctx context.Context, e *ArgoCDEndpoint) error {
	if e.Name == "" {
		return errors.New("storage: argocd endpoint Name required")
	}
	if e.BaseURL == "" {
		return errors.New("storage: argocd endpoint BaseURL required")
	}
	if len(e.TokenCiphertext) == 0 || len(e.TokenDataKeyCiphertext) == 0 || len(e.TokenNonce) == 0 || e.TokenKMSKeyID == "" {
		return errors.New("storage: argocd endpoint token envelope required (token_ciphertext + dek + nonce + kms_key_id)")
	}
	const q = `
		INSERT INTO argocd_endpoints (
			name, environment_id, base_url,
			token_ciphertext, token_data_key_ciphertext, token_nonce, token_kms_key_id,
			tls_ca_pem, tls_server_name, enabled
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, created_at, updated_at`
	row := r.pool.QueryRow(ctx, q,
		e.Name, e.EnvironmentID, e.BaseURL,
		e.TokenCiphertext, e.TokenDataKeyCiphertext, e.TokenNonce, e.TokenKMSKeyID,
		nullString(e.TLSCAPEM), nullString(e.TLSServerName), e.Enabled,
	)
	return row.Scan(&e.ID, &e.CreatedAt, &e.UpdatedAt)
}

// Get fetches by id (returns soft-deleted rows too — callers filter).
func (r *ArgoCDEndpoints) Get(ctx context.Context, id uuid.UUID) (*ArgoCDEndpoint, error) {
	const q = `
		SELECT id, name, environment_id, base_url,
		       token_ciphertext, token_data_key_ciphertext, token_nonce, token_kms_key_id,
		       COALESCE(tls_ca_pem, ''), COALESCE(tls_server_name, ''),
		       enabled, last_health_at, COALESCE(last_health_error, ''),
		       created_at, updated_at, deleted_at
		FROM argocd_endpoints WHERE id = $1`
	return scanArgoCDEndpoint(r.pool.QueryRow(ctx, q, id))
}

// GetByName looks up an active (non-deleted) endpoint by name.
func (r *ArgoCDEndpoints) GetByName(ctx context.Context, name string) (*ArgoCDEndpoint, error) {
	const q = `
		SELECT id, name, environment_id, base_url,
		       token_ciphertext, token_data_key_ciphertext, token_nonce, token_kms_key_id,
		       COALESCE(tls_ca_pem, ''), COALESCE(tls_server_name, ''),
		       enabled, last_health_at, COALESCE(last_health_error, ''),
		       created_at, updated_at, deleted_at
		FROM argocd_endpoints WHERE name = $1 AND deleted_at IS NULL`
	return scanArgoCDEndpoint(r.pool.QueryRow(ctx, q, name))
}

// List returns every active endpoint.
func (r *ArgoCDEndpoints) List(ctx context.Context) ([]*ArgoCDEndpoint, error) {
	const q = `
		SELECT id, name, environment_id, base_url,
		       token_ciphertext, token_data_key_ciphertext, token_nonce, token_kms_key_id,
		       COALESCE(tls_ca_pem, ''), COALESCE(tls_server_name, ''),
		       enabled, last_health_at, COALESCE(last_health_error, ''),
		       created_at, updated_at, deleted_at
		FROM argocd_endpoints WHERE deleted_at IS NULL ORDER BY name`
	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("storage: list argocd endpoints: %w", err)
	}
	defer rows.Close()
	var out []*ArgoCDEndpoint
	for rows.Next() {
		e, err := scanArgoCDEndpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// UpdateHealth records the latest health-check outcome. healthErr is
// blank when the check succeeded.
func (r *ArgoCDEndpoints) UpdateHealth(ctx context.Context, id uuid.UUID, healthAt time.Time, healthErr string) error {
	const q = `
		UPDATE argocd_endpoints
		SET last_health_at = $2, last_health_error = NULLIF($3, '')
		WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q, id, healthAt, healthErr)
	if err != nil {
		return fmt.Errorf("storage: update argocd endpoint health: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetEnabled toggles the enabled flag.
func (r *ArgoCDEndpoints) SetEnabled(ctx context.Context, id uuid.UUID, enabled bool) error {
	tag, err := r.pool.Exec(ctx, `UPDATE argocd_endpoints SET enabled = $2 WHERE id = $1 AND deleted_at IS NULL`, id, enabled)
	if err != nil {
		return fmt.Errorf("storage: argocd endpoint set enabled: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SoftDelete marks the row deleted but leaves it in place so audit
// history that references it stays resolvable.
func (r *ArgoCDEndpoints) SoftDelete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `UPDATE argocd_endpoints SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("storage: argocd endpoint soft delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func scanArgoCDEndpoint(row pgx.Row) (*ArgoCDEndpoint, error) {
	var e ArgoCDEndpoint
	err := row.Scan(
		&e.ID, &e.Name, &e.EnvironmentID, &e.BaseURL,
		&e.TokenCiphertext, &e.TokenDataKeyCiphertext, &e.TokenNonce, &e.TokenKMSKeyID,
		&e.TLSCAPEM, &e.TLSServerName,
		&e.Enabled, &e.LastHealthAt, &e.LastHealthError,
		&e.CreatedAt, &e.UpdatedAt, &e.DeletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("storage: scan argocd endpoint: %w", err)
	}
	return &e, nil
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
