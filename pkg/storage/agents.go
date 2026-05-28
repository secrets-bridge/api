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

// Agent mirrors a row in the agents table. Neither the registration
// token nor the agent secret is stored in plaintext — only their
// SHA-256 hashes. Both plaintexts are returned to the admin / agent
// exactly once at issuance.
type Agent struct {
	ID                    uuid.UUID
	Name                  string
	Scope                 map[string]any
	Status                AgentStatus
	RegistrationTokenHash []byte // cleared after the agent redeems the token
	SecretHash            []byte // set by Register; checked by Heartbeat
	LastSeenAt            *time.Time
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// AgentStatus is constrained by a CHECK in the schema.
type AgentStatus string

const (
	AgentStatusPending AgentStatus = "pending"
	AgentStatusActive  AgentStatus = "active"
	AgentStatusStale   AgentStatus = "stale"
	AgentStatusRevoked AgentStatus = "revoked"
)

// AgentRepository is the read/write surface for the agents table.
type AgentRepository interface {
	// Create inserts a new agent and stores its one-time registration
	// token hash. The caller is responsible for hashing the plaintext
	// token before this call — the repository never touches plaintext.
	Create(ctx context.Context, a *Agent) error

	// Get returns one agent by ID.
	Get(ctx context.Context, id uuid.UUID) (*Agent, error)

	// GetByName returns one agent by its admin-chosen name.
	GetByName(ctx context.Context, name string) (*Agent, error)

	// List returns every agent ordered by created_at ASC.
	List(ctx context.Context) ([]*Agent, error)

	// RedeemRegistrationToken transitions the agent from pending →
	// active. The presented registration_token_hash is compared
	// against the stored hash; on match it is cleared and the
	// supplied secret_hash is stored for subsequent heartbeats.
	// Returns ErrNotFound when no agent matches the ID, ErrUnauthorized
	// when the agent exists but the registration hash is wrong.
	RedeemRegistrationToken(ctx context.Context, id uuid.UUID, registrationHash, secretHash []byte) error

	// TouchLastSeen records that an agent has heartbeated. No-op if
	// the agent has been revoked.
	TouchLastSeen(ctx context.Context, id uuid.UUID, at time.Time) error

	// UpdateStatus transitions an agent to a new status.
	UpdateStatus(ctx context.Context, id uuid.UUID, status AgentStatus) error
}

// ErrUnauthorized is returned when authentication material is presented
// for a known agent but does not match the stored hash.
var ErrUnauthorized = errors.New("storage: unauthorized")

// Agents is the Postgres implementation of AgentRepository.
type Agents struct {
	pool *Pool
}

// NewAgents binds an Agents repository to the given pool.
func NewAgents(pool *Pool) *Agents { return &Agents{pool: pool} }

// Create inserts a new agent row. ID is assigned by the database when
// a.ID is uuid.Nil. Scope is JSON-marshalled.
func (r *Agents) Create(ctx context.Context, a *Agent) error {
	if a.Name == "" {
		return errors.New("storage: agent Name is required")
	}
	if a.Status == "" {
		a.Status = AgentStatusPending
	}
	if a.Scope == nil {
		a.Scope = map[string]any{}
	}
	scope, err := json.Marshal(a.Scope)
	if err != nil {
		return fmt.Errorf("storage: marshal agent scope: %w", err)
	}

	const insertGenerated = `
		INSERT INTO agents (name, scope, status, registration_token_hash)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at, updated_at`
	const insertWithID = `
		INSERT INTO agents (id, name, scope, status, registration_token_hash)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING created_at, updated_at`

	var row pgx.Row
	if a.ID == uuid.Nil {
		row = r.pool.QueryRow(ctx, insertGenerated, a.Name, scope, a.Status, a.RegistrationTokenHash)
		return row.Scan(&a.ID, &a.CreatedAt, &a.UpdatedAt)
	}
	row = r.pool.QueryRow(ctx, insertWithID, a.ID, a.Name, scope, a.Status, a.RegistrationTokenHash)
	return row.Scan(&a.CreatedAt, &a.UpdatedAt)
}

// Get fetches one agent by ID. Returns ErrNotFound when no row matches.
func (r *Agents) Get(ctx context.Context, id uuid.UUID) (*Agent, error) {
	const q = `
		SELECT id, name, scope, status, registration_token_hash, secret_hash, last_seen_at, created_at, updated_at
		FROM agents WHERE id = $1`
	return scanAgent(r.pool.QueryRow(ctx, q, id))
}

// GetByName fetches one agent by name. Names are UNIQUE in the schema.
func (r *Agents) GetByName(ctx context.Context, name string) (*Agent, error) {
	const q = `
		SELECT id, name, scope, status, registration_token_hash, secret_hash, last_seen_at, created_at, updated_at
		FROM agents WHERE name = $1`
	return scanAgent(r.pool.QueryRow(ctx, q, name))
}

// List returns every agent ordered by created_at ASC.
func (r *Agents) List(ctx context.Context) ([]*Agent, error) {
	const q = `
		SELECT id, name, scope, status, registration_token_hash, secret_hash, last_seen_at, created_at, updated_at
		FROM agents ORDER BY created_at ASC`
	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("storage: list agents: %w", err)
	}
	defer rows.Close()

	var out []*Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// RedeemRegistrationToken transitions a pending agent → active when
// the presented registration hash matches. The registration hash is
// cleared on success so the token cannot be replayed; the supplied
// secret_hash is stored for subsequent heartbeat validation.
func (r *Agents) RedeemRegistrationToken(ctx context.Context, id uuid.UUID, registrationHash, secretHash []byte) error {
	const q = `
		UPDATE agents
		SET    status = 'active',
		       registration_token_hash = NULL,
		       secret_hash = $3,
		       last_seen_at = now()
		WHERE  id = $1
		  AND  registration_token_hash = $2
		  AND  status = 'pending'`
	tag, err := r.pool.Exec(ctx, q, id, registrationHash, secretHash)
	if err != nil {
		return fmt.Errorf("storage: redeem registration token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Distinguish "no agent" from "wrong hash" so the service
		// layer can return distinct error responses.
		_, err := r.Get(ctx, id)
		if err != nil {
			return err // ErrNotFound or a real DB error
		}
		return ErrUnauthorized
	}
	return nil
}

// TouchLastSeen records a heartbeat. Bumps updated_at via the trigger.
func (r *Agents) TouchLastSeen(ctx context.Context, id uuid.UUID, at time.Time) error {
	const q = `
		UPDATE agents
		SET    last_seen_at = $2,
		       status = CASE WHEN status = 'stale' THEN 'active' ELSE status END
		WHERE  id = $1
		  AND  status != 'revoked'`
	tag, err := r.pool.Exec(ctx, q, id, at)
	if err != nil {
		return fmt.Errorf("storage: touch agent last seen: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateStatus transitions an agent to a new status.
func (r *Agents) UpdateStatus(ctx context.Context, id uuid.UUID, status AgentStatus) error {
	const q = `UPDATE agents SET status = $2 WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q, id, status)
	if err != nil {
		return fmt.Errorf("storage: update agent status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func scanAgent(row interface {
	Scan(dest ...any) error
}) (*Agent, error) {
	var (
		a          Agent
		scopeRaw   []byte
		regHash    []byte
		secretHash []byte
		lastSeen   *time.Time
	)
	err := row.Scan(&a.ID, &a.Name, &scopeRaw, &a.Status, &regHash, &secretHash, &lastSeen, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("storage: scan agent: %w", err)
	}
	if len(scopeRaw) > 0 {
		if err := json.Unmarshal(scopeRaw, &a.Scope); err != nil {
			return nil, fmt.Errorf("storage: unmarshal agent scope: %w", err)
		}
	}
	a.RegistrationTokenHash = regHash
	a.SecretHash = secretHash
	a.LastSeenAt = lastSeen
	return &a, nil
}
