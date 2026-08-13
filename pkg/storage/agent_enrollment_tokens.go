package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AgentEnrollmentToken mirrors a row in agent_enrollment_tokens. Only the
// SHA-256 hash of the one-time token is stored — the plaintext is returned
// to the admin exactly ONCE at creation and never persisted or logged.
type AgentEnrollmentToken struct {
	ID                   uuid.UUID
	ProviderConnectionID uuid.UUID
	Name                 string
	TokenHash            []byte
	ExpectedClusterName  string
	ExpectedProviderType string
	ExpiresAt            time.Time
	ConsumedAt           *time.Time
	ConsumedByAgentID    *uuid.UUID
	RevokedAt            *time.Time
	RevokedBy            *string // actor identity (TEXT), not a UUID FK
	CreatedBy            string  // actor identity (TEXT)
	CreatedAt            time.Time
}

// ErrEnrollmentTokenNotFound is returned when no token matches the presented
// hash. The handler collapses it to a generic 401 so an attacker cannot
// enumerate valid tokens.
var ErrEnrollmentTokenNotFound = errors.New("storage: agent enrollment token not found")

// AgentEnrollmentTokenRepository is the read/write surface for the
// agent_enrollment_tokens table. The caller hashes the plaintext token
// before Create; the repository never touches plaintext.
type AgentEnrollmentTokenRepository interface {
	Create(ctx context.Context, t *AgentEnrollmentToken) error
	// GetByHash resolves a token by its SHA-256 hash. Returns
	// ErrEnrollmentTokenNotFound when no row matches.
	GetByHash(ctx context.Context, tokenHash []byte) (*AgentEnrollmentToken, error)
	// MarkConsumed atomically stamps consumed_at + consumed_by_agent_id
	// only if the token is still unconsumed (single-use guard). Returns
	// ErrEnrollmentTokenNotFound when the row is already consumed / gone.
	MarkConsumed(ctx context.Context, id, agentID uuid.UUID, at time.Time) error
}

// AgentEnrollmentTokens is the Postgres implementation.
type AgentEnrollmentTokens struct {
	pool *Pool
}

// NewAgentEnrollmentTokens binds the repository to a pool.
func NewAgentEnrollmentTokens(pool *Pool) *AgentEnrollmentTokens {
	return &AgentEnrollmentTokens{pool: pool}
}

const agentEnrollmentTokenColumns = `
	id, provider_connection_id, COALESCE(name, ''), token_hash,
	COALESCE(expected_cluster_name, ''), COALESCE(expected_provider_type, ''),
	expires_at, consumed_at, consumed_by_agent_id, revoked_at, revoked_by,
	created_by, created_at`

// Create inserts a new enrollment token row (hash only).
func (r *AgentEnrollmentTokens) Create(ctx context.Context, t *AgentEnrollmentToken) error {
	if t.ProviderConnectionID == uuid.Nil {
		return errors.New("storage: enrollment token ProviderConnectionID is required")
	}
	if len(t.TokenHash) == 0 {
		return errors.New("storage: enrollment token TokenHash is required")
	}
	if t.CreatedBy == "" {
		return errors.New("storage: enrollment token CreatedBy is required")
	}
	if t.ExpiresAt.IsZero() {
		return errors.New("storage: enrollment token ExpiresAt is required")
	}
	const q = `
		INSERT INTO agent_enrollment_tokens (
			provider_connection_id, name, token_hash,
			expected_cluster_name, expected_provider_type,
			expires_at, created_by)
		VALUES ($1, NULLIF($2, ''), $3, NULLIF($4, ''), NULLIF($5, ''), $6, $7)
		RETURNING id, created_at`
	row := r.pool.QueryRow(ctx, q,
		t.ProviderConnectionID, t.Name, t.TokenHash,
		t.ExpectedClusterName, t.ExpectedProviderType, t.ExpiresAt, t.CreatedBy)
	if err := row.Scan(&t.ID, &t.CreatedAt); err != nil {
		return fmt.Errorf("storage: create enrollment token: %w", err)
	}
	return nil
}

// GetByHash resolves a token by its hash.
func (r *AgentEnrollmentTokens) GetByHash(ctx context.Context, tokenHash []byte) (*AgentEnrollmentToken, error) {
	q := `SELECT ` + agentEnrollmentTokenColumns + `
		FROM agent_enrollment_tokens WHERE token_hash = $1`
	return scanEnrollmentToken(r.pool.QueryRow(ctx, q, tokenHash))
}

// MarkConsumed atomically burns the token (single-use). A no-op affecting
// zero rows (already consumed) surfaces as ErrEnrollmentTokenNotFound.
func (r *AgentEnrollmentTokens) MarkConsumed(ctx context.Context, id, agentID uuid.UUID, at time.Time) error {
	const q = `
		UPDATE agent_enrollment_tokens
		SET    consumed_at = $2, consumed_by_agent_id = $3
		WHERE  id = $1 AND consumed_at IS NULL`
	tag, err := r.pool.Exec(ctx, q, id, at, agentID)
	if err != nil {
		return fmt.Errorf("storage: mark enrollment token consumed: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrEnrollmentTokenNotFound
	}
	return nil
}

func scanEnrollmentToken(row interface {
	Scan(dest ...any) error
}) (*AgentEnrollmentToken, error) {
	var t AgentEnrollmentToken
	err := row.Scan(
		&t.ID, &t.ProviderConnectionID, &t.Name, &t.TokenHash,
		&t.ExpectedClusterName, &t.ExpectedProviderType,
		&t.ExpiresAt, &t.ConsumedAt, &t.ConsumedByAgentID, &t.RevokedAt, &t.RevokedBy,
		&t.CreatedBy, &t.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrEnrollmentTokenNotFound
		}
		return nil, fmt.Errorf("storage: scan enrollment token: %w", err)
	}
	return &t, nil
}
