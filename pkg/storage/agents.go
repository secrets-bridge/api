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

// Agent mirrors a row in the agents table. The plaintext agent secret
// is NEVER stored — only its SHA-256 hash. The plaintext is returned to
// the admin exactly ONCE at mint time and from then on lives only in
// the K8s Secret / env vars the agent reads at startup.
type Agent struct {
	ID         uuid.UUID
	Name       string
	Scope      map[string]any
	Status     AgentStatus
	SecretHash []byte
	// PublicKey is the agent's X25519 public key (32 bytes) used by
	// the CP to seal wrap retrieval responses (Piece 8b). NULL means
	// the agent registered before wire-envelope encryption was wired;
	// the CP falls back to plaintext-over-TLS for those.
	PublicKey          []byte
	PublicKeyAlgorithm string
	LastSeenAt         *time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time

	// Agent Onboarding MVP (migration 0038) — all nullable/additive so
	// the certified mint path (which leaves them zero) is unaffected.
	// ProviderConnectionID binds an ENROLLED agent to exactly one
	// provider connection; it is set at enroll time and never changed.
	ProviderConnectionID *uuid.UUID
	ClusterName          string
	ProviderType         string
	Region               string
	AgentVersion         string
	PublicKeyFingerprint string
	Capabilities         []string
}

// AgentStatus is constrained by a CHECK in the schema. Migration 0003
// dropped the 'pending' value; migration 0038 widened it back with
// enrolled/error/disabled for the onboarding flow.
type AgentStatus string

const (
	AgentStatusEnrolled AgentStatus = "enrolled"
	AgentStatusActive   AgentStatus = "active"
	AgentStatusStale    AgentStatus = "stale"
	AgentStatusError    AgentStatus = "error"
	AgentStatusDisabled AgentStatus = "disabled"
	AgentStatusRevoked  AgentStatus = "revoked"
)

// AgentRepository is the read/write surface for the agents table.
type AgentRepository interface {
	// Create inserts a new agent with its hashed long-lived secret.
	// The caller (services.AgentService) generates the plaintext
	// secret and computes the hash before this call — the repository
	// never touches plaintext.
	Create(ctx context.Context, a *Agent) error

	// CreateEnrolled inserts an agent produced by the enrollment flow —
	// bound to a provider connection, carrying cluster/provider/region/
	// version/capabilities. Reuses the same secret_hash credential column
	// as Create; the certified mint path is unchanged.
	CreateEnrolled(ctx context.Context, a *Agent) error

	// Get returns one agent by ID.
	Get(ctx context.Context, id uuid.UUID) (*Agent, error)

	// GetByName returns one agent by its admin-chosen name.
	GetByName(ctx context.Context, name string) (*Agent, error)

	// List returns every agent ordered by created_at ASC.
	List(ctx context.Context) ([]*Agent, error)

	// TouchLastSeen records a heartbeat. No-op on revoked agents.
	TouchLastSeen(ctx context.Context, id uuid.UUID, at time.Time) error

	// UpdateStatus transitions an agent to a new status.
	UpdateStatus(ctx context.Context, id uuid.UUID, status AgentStatus) error

	// UpdatePublicKey upserts an agent's X25519 public key. Used by
	// the agent self-registration endpoint so an existing minted
	// agent can flip into the sealed-wire path without a re-mint.
	UpdatePublicKey(ctx context.Context, id uuid.UUID, publicKey []byte, algorithm string) error
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

// Create inserts a new agent row.
func (r *Agents) Create(ctx context.Context, a *Agent) error {
	if a.Name == "" {
		return errors.New("storage: agent Name is required")
	}
	if len(a.SecretHash) == 0 {
		return errors.New("storage: agent SecretHash is required")
	}
	if a.Status == "" {
		a.Status = AgentStatusActive
	}
	if a.Scope == nil {
		a.Scope = map[string]any{}
	}
	scope, err := json.Marshal(a.Scope)
	if err != nil {
		return fmt.Errorf("storage: marshal agent scope: %w", err)
	}

	const insertGenerated = `
		INSERT INTO agents (name, scope, status, secret_hash, public_key, public_key_algorithm)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''))
		RETURNING id, created_at, updated_at`
	const insertWithID = `
		INSERT INTO agents (id, name, scope, status, secret_hash, public_key, public_key_algorithm)
		VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''))
		RETURNING created_at, updated_at`

	var row pgx.Row
	if a.ID == uuid.Nil {
		row = r.pool.QueryRow(ctx, insertGenerated, a.Name, scope, a.Status, a.SecretHash, a.PublicKey, a.PublicKeyAlgorithm)
		return row.Scan(&a.ID, &a.CreatedAt, &a.UpdatedAt)
	}
	row = r.pool.QueryRow(ctx, insertWithID, a.ID, a.Name, scope, a.Status, a.SecretHash, a.PublicKey, a.PublicKeyAlgorithm)
	return row.Scan(&a.CreatedAt, &a.UpdatedAt)
}

// CreateEnrolled inserts an enrolled agent bound to a provider connection.
// The credential (secret_hash) is generated + hashed by the caller, exactly
// like Create. All the onboarding columns are nullable in the schema; empty
// values land as NULL (capabilities defaults to []).
func (r *Agents) CreateEnrolled(ctx context.Context, a *Agent) error {
	if a.Name == "" {
		return errors.New("storage: agent Name is required")
	}
	if len(a.SecretHash) == 0 {
		return errors.New("storage: agent SecretHash is required")
	}
	if a.ProviderConnectionID == nil {
		return errors.New("storage: enrolled agent ProviderConnectionID is required")
	}
	if a.Status == "" {
		a.Status = AgentStatusEnrolled
	}
	if a.Scope == nil {
		a.Scope = map[string]any{}
	}
	scope, err := json.Marshal(a.Scope)
	if err != nil {
		return fmt.Errorf("storage: marshal agent scope: %w", err)
	}
	if a.Capabilities == nil {
		a.Capabilities = []string{}
	}
	caps, err := json.Marshal(a.Capabilities)
	if err != nil {
		return fmt.Errorf("storage: marshal agent capabilities: %w", err)
	}

	const q = `
		INSERT INTO agents (
			name, scope, status, secret_hash, public_key, public_key_algorithm,
			provider_connection_id, cluster_name, provider_type, region,
			agent_version, public_key_fingerprint, capabilities)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''),
			$7, NULLIF($8, ''), NULLIF($9, ''), NULLIF($10, ''),
			NULLIF($11, ''), NULLIF($12, ''), $13)
		RETURNING id, created_at, updated_at`
	row := r.pool.QueryRow(ctx, q,
		a.Name, scope, a.Status, a.SecretHash, a.PublicKey, a.PublicKeyAlgorithm,
		a.ProviderConnectionID, a.ClusterName, a.ProviderType, a.Region,
		a.AgentVersion, a.PublicKeyFingerprint, caps)
	return row.Scan(&a.ID, &a.CreatedAt, &a.UpdatedAt)
}

// Get fetches one agent by ID. Returns ErrNotFound when no row matches.
func (r *Agents) Get(ctx context.Context, id uuid.UUID) (*Agent, error) {
	const q = `
		SELECT id, name, scope, status, secret_hash,
		       public_key, COALESCE(public_key_algorithm, ''),
		       last_seen_at, created_at, updated_at
		FROM agents WHERE id = $1`
	return scanAgent(r.pool.QueryRow(ctx, q, id))
}

// GetByName fetches one agent by name. Names are UNIQUE in the schema.
func (r *Agents) GetByName(ctx context.Context, name string) (*Agent, error) {
	const q = `
		SELECT id, name, scope, status, secret_hash,
		       public_key, COALESCE(public_key_algorithm, ''),
		       last_seen_at, created_at, updated_at
		FROM agents WHERE name = $1`
	return scanAgent(r.pool.QueryRow(ctx, q, name))
}

// List returns every agent ordered by created_at ASC.
func (r *Agents) List(ctx context.Context) ([]*Agent, error) {
	const q = `
		SELECT id, name, scope, status, secret_hash,
		       public_key, COALESCE(public_key_algorithm, ''),
		       last_seen_at, created_at, updated_at
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

// UpdatePublicKey upserts the agent's wire-envelope public key. Used
// by the agent self-registration endpoint so existing agents can opt
// into the sealed-wire path without an admin re-mint.
func (r *Agents) UpdatePublicKey(ctx context.Context, id uuid.UUID, publicKey []byte, algorithm string) error {
	const q = `
		UPDATE agents
		SET public_key = $2,
		    public_key_algorithm = NULLIF($3, '')
		WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q, id, publicKey, algorithm)
	if err != nil {
		return fmt.Errorf("storage: update agent public key: %w", err)
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
		secretHash []byte
		publicKey  []byte
		lastSeen   *time.Time
	)
	err := row.Scan(&a.ID, &a.Name, &scopeRaw, &a.Status, &secretHash,
		&publicKey, &a.PublicKeyAlgorithm,
		&lastSeen, &a.CreatedAt, &a.UpdatedAt)
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
	a.SecretHash = secretHash
	a.PublicKey = publicKey
	a.LastSeenAt = lastSeen
	return &a, nil
}
