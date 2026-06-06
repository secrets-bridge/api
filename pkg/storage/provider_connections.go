package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ProviderConnection mirrors a row in the provider_connections table.
//
// Hard rule: scope is METADATA only. Never holds tokens, access keys,
// or passwords. The service layer's credential-shaped key refusal +
// secret-shaped value detection enforce this on write; the canary
// test in storage_test.go scans every scope row for credential-shaped
// substrings on read.
type ProviderConnection struct {
	ID         uuid.UUID
	Name       string
	Type       ProviderConnectionType
	AuthMethod string
	Scope      map[string]string
	Status     ProviderConnectionStatus

	// EPIC P additions.
	ClusterName             string
	Description             string
	DiscoverEnabled         bool
	DiscoverIntervalSeconds int
	LastDiscoverAt          *time.Time
	LastDiscoverStatus      string
	LastDiscoverError       string
	LastDiscoverStartedAt   *time.Time
	LastDiscoverFinishedAt  *time.Time

	// EPIC Q (api#99) — platform admins opt-in per connection so
	// integration.bind callers can self-serve binds. Default-deny:
	// existing rows stay at false until platform flips.
	SelfServiceBindable bool

	CreatedAt time.Time
	UpdatedAt time.Time
}

// ProviderConnectionType is constrained by a CHECK on the schema
// (migration 0001). Adding a new provider type requires a schema
// migration + the new ProviderConnectionType constant + the service
// layer's scope-shape map.
type ProviderConnectionType string

const (
	ProviderConnectionTypeAWSSM      ProviderConnectionType = "aws-sm"
	ProviderConnectionTypeVault      ProviderConnectionType = "vault"
	ProviderConnectionTypeGCPSM      ProviderConnectionType = "gcp-sm"
	ProviderConnectionTypeAzureKV    ProviderConnectionType = "azure-kv"
	ProviderConnectionTypeKubernetes ProviderConnectionType = "kubernetes"
)

// ProviderConnectionStatus is constrained by a CHECK on the schema.
type ProviderConnectionStatus string

const (
	ProviderConnectionStatusActive   ProviderConnectionStatus = "active"
	ProviderConnectionStatusDisabled ProviderConnectionStatus = "disabled"
)

// DiscoverStatus values match the CHECK on last_discover_status.
const (
	DiscoverStatusSuccess = "success"
	DiscoverStatusFailure = "failure"
	DiscoverStatusRunning = "running"
)

// ProviderConnectionInput is what the service layer hands the
// repository on Create / Update.
type ProviderConnectionInput struct {
	Name                    string
	Type                    ProviderConnectionType
	AuthMethod              string
	Scope                   map[string]string
	Status                  ProviderConnectionStatus
	ClusterName             string
	Description             string
	DiscoverEnabled         bool
	DiscoverIntervalSeconds int
	// SelfServiceBindable is `nil` on Update to mean "don't touch" so
	// callers that don't know about EPIC Q can't accidentally flip it.
	// Create reads the dereferenced value (nil → false).
	SelfServiceBindable *bool
}

// ProviderConnectionListFilter narrows List results. Empty values
// (zero value) act as wildcards.
type ProviderConnectionListFilter struct {
	Type            string
	Status          string
	DiscoverEnabled *bool
	Limit           int
	Offset          int
}

// DiscoverTarget is the value-free shape ListDueForDiscovery returns
// to the worker scheduler. Scope is metadata only; cluster_name is
// the agent-routing key.
type DiscoverTarget struct {
	ID                      uuid.UUID
	Name                    string
	Type                    ProviderConnectionType
	Scope                   map[string]string
	ClusterName             string
	DiscoverIntervalSeconds int
	LastDiscoverAt          *time.Time
}

// ProviderConnectionRepository is the read/write surface for the
// provider_connections table.
type ProviderConnectionRepository interface {
	Create(ctx context.Context, in ProviderConnectionInput) (*ProviderConnection, error)
	Get(ctx context.Context, id uuid.UUID) (*ProviderConnection, error)
	GetByName(ctx context.Context, name string) (*ProviderConnection, error)
	List(ctx context.Context, f ProviderConnectionListFilter) ([]*ProviderConnection, error)
	Update(ctx context.Context, id uuid.UUID, in ProviderConnectionInput) (*ProviderConnection, error)
	Delete(ctx context.Context, id uuid.UUID) error
	Exists(ctx context.Context, id uuid.UUID) (bool, error)

	ListDueForDiscovery(ctx context.Context, now time.Time) ([]DiscoverTarget, error)
	MarkDiscoverStarted(ctx context.Context, id uuid.UUID, now time.Time) error
	MarkDiscoverFinished(ctx context.Context, id uuid.UUID, status, sanitizedErr string, now time.Time) error

	CountBindings(ctx context.Context, id uuid.UUID) (int, error)
	CountOpenRequests(ctx context.Context, id uuid.UUID) (int, error)

	// Bindable is the narrow read the EPIC Q scoped bind gate uses to
	// decide between connection_disabled and
	// connection_not_self_service_bindable without paying for the full
	// row scan + scope JSON unmarshal. Returns ErrConnectionNotFound
	// when the id doesn't exist.
	Bindable(ctx context.Context, id uuid.UUID) (active bool, selfServiceBindable bool, err error)
}

// ProviderConnections is the Postgres implementation.
type ProviderConnections struct {
	pool *Pool
}

// NewProviderConnections binds the repository to a pool.
func NewProviderConnections(pool *Pool) *ProviderConnections {
	return &ProviderConnections{pool: pool}
}

// Compile-time interface check.
var _ ProviderConnectionRepository = (*ProviderConnections)(nil)

// ErrInvalidDiscoverStatus is returned by MarkDiscoverFinished when
// the caller hands it a non-terminal status (e.g. "running"). The
// CHECK on last_discover_status accepts running, but the finish
// method MUST reject it — running is an in-flight state, allowing
// it through hides worker lifecycle bugs.
var ErrInvalidDiscoverStatus = errors.New("storage: discover status must be success or failure")

// Create inserts a new provider_connections row. Service-layer
// validation (scope shape, credential refusal, URL semantics, etc.)
// runs BEFORE this call — the repository trusts the inputs.
func (r *ProviderConnections) Create(ctx context.Context, in ProviderConnectionInput) (*ProviderConnection, error) {
	scopeJSON, err := json.Marshal(in.Scope)
	if err != nil {
		return nil, fmt.Errorf("storage: marshal scope: %w", err)
	}
	status := in.Status
	if status == "" {
		status = ProviderConnectionStatusActive
	}
	selfServiceBindable := false
	if in.SelfServiceBindable != nil {
		selfServiceBindable = *in.SelfServiceBindable
	}
	const q = `
INSERT INTO provider_connections
	(name, type, auth_method, scope, status,
	 cluster_name, description, discover_enabled, discover_interval_seconds,
	 self_service_bindable)
VALUES ($1, $2, $3, $4, $5,
	NULLIF($6, ''), NULLIF($7, ''), $8, $9,
	$10)
RETURNING id, name, type, auth_method, scope, status,
	cluster_name, description, discover_enabled, discover_interval_seconds,
	last_discover_at, last_discover_status, last_discover_error,
	last_discover_started_at, last_discover_finished_at,
	self_service_bindable,
	created_at, updated_at
`
	row := r.pool.QueryRow(ctx, q,
		in.Name, in.Type, in.AuthMethod, scopeJSON, status,
		in.ClusterName, in.Description, in.DiscoverEnabled, in.DiscoverIntervalSeconds,
		selfServiceBindable,
	)
	pc, err := scanProviderConnection(row)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrConnectionNameTaken
		}
		return nil, fmt.Errorf("storage: create provider_connection: %w", err)
	}
	return pc, nil
}

// Get returns a single row by id.
func (r *ProviderConnections) Get(ctx context.Context, id uuid.UUID) (*ProviderConnection, error) {
	const q = providerConnectionSelect + ` WHERE id = $1`
	pc, err := scanProviderConnection(r.pool.QueryRow(ctx, q, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrConnectionNotFound
		}
		return nil, fmt.Errorf("storage: get provider_connection: %w", err)
	}
	return pc, nil
}

// GetByName returns a single row by its unique name.
func (r *ProviderConnections) GetByName(ctx context.Context, name string) (*ProviderConnection, error) {
	const q = providerConnectionSelect + ` WHERE name = $1`
	pc, err := scanProviderConnection(r.pool.QueryRow(ctx, q, name))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrConnectionNotFound
		}
		return nil, fmt.Errorf("storage: get provider_connection by name: %w", err)
	}
	return pc, nil
}

// List returns rows matching the filter, ordered by name.
func (r *ProviderConnections) List(ctx context.Context, f ProviderConnectionListFilter) ([]*ProviderConnection, error) {
	q := providerConnectionSelect + ` WHERE 1=1`
	args := []any{}
	i := 1
	if f.Type != "" {
		q += fmt.Sprintf(` AND type = $%d`, i)
		args = append(args, f.Type)
		i++
	}
	if f.Status != "" {
		q += fmt.Sprintf(` AND status = $%d`, i)
		args = append(args, f.Status)
		i++
	}
	if f.DiscoverEnabled != nil {
		q += fmt.Sprintf(` AND discover_enabled = $%d`, i)
		args = append(args, *f.DiscoverEnabled)
		i++
	}
	q += ` ORDER BY name`
	if f.Limit > 0 {
		q += fmt.Sprintf(` LIMIT $%d`, i)
		args = append(args, f.Limit)
		i++
	} else {
		q += ` LIMIT 200`
	}
	if f.Offset > 0 {
		q += fmt.Sprintf(` OFFSET $%d`, i)
		args = append(args, f.Offset)
	}
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("storage: list provider_connections: %w", err)
	}
	defer rows.Close()
	out := []*ProviderConnection{}
	for rows.Next() {
		pc, err := scanProviderConnection(rows)
		if err != nil {
			return nil, fmt.Errorf("storage: scan provider_connection: %w", err)
		}
		out = append(out, pc)
	}
	return out, rows.Err()
}

// Update mutates the row. Type is immutable at the service layer; the
// repository overwrites every other field in the input. Name change
// is allowed (unique-name conflict surfaces as ErrConnectionNameTaken).
func (r *ProviderConnections) Update(ctx context.Context, id uuid.UUID, in ProviderConnectionInput) (*ProviderConnection, error) {
	scopeJSON, err := json.Marshal(in.Scope)
	if err != nil {
		return nil, fmt.Errorf("storage: marshal scope: %w", err)
	}
	// EPIC Q: nil means "don't touch" — Update keeps the existing
	// value via COALESCE. This lets P3 handler bodies omit the flag
	// without flipping it back to false.
	const q = `
UPDATE provider_connections
SET name = $2,
	auth_method = $3,
	scope = $4,
	status = $5,
	cluster_name = NULLIF($6, ''),
	description = NULLIF($7, ''),
	discover_enabled = $8,
	discover_interval_seconds = $9,
	self_service_bindable = COALESCE($10, self_service_bindable)
WHERE id = $1
RETURNING id, name, type, auth_method, scope, status,
	cluster_name, description, discover_enabled, discover_interval_seconds,
	last_discover_at, last_discover_status, last_discover_error,
	last_discover_started_at, last_discover_finished_at,
	self_service_bindable,
	created_at, updated_at
`
	row := r.pool.QueryRow(ctx, q, id,
		in.Name, in.AuthMethod, scopeJSON, in.Status,
		in.ClusterName, in.Description, in.DiscoverEnabled, in.DiscoverIntervalSeconds,
		in.SelfServiceBindable,
	)
	pc, err := scanProviderConnection(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrConnectionNotFound
		}
		if isUniqueViolation(err) {
			return nil, ErrConnectionNameTaken
		}
		return nil, fmt.Errorf("storage: update provider_connection: %w", err)
	}
	return pc, nil
}

// Delete removes a row. The FK RESTRICT on project_provider_connections
// + on access_requests.destination_provider_connection_id is the
// safety net behind the service-layer pre-flight count.
func (r *ProviderConnections) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM provider_connections WHERE id = $1`, id)
	if err != nil {
		// FK RESTRICT violations surface as 23503 — translate to a
		// caller-readable sentinel even though the service layer
		// should have caught it earlier via CountBindings.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return ErrConnectionInUse
		}
		return fmt.Errorf("storage: delete provider_connection: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrConnectionNotFound
	}
	return nil
}

// Exists returns whether a row with the given id is present.
// Used by RequestService.SubmitCrossTeam to reject destination
// connection ids that don't map to a real row.
func (r *ProviderConnections) Exists(ctx context.Context, id uuid.UUID) (bool, error) {
	const q = `SELECT 1 FROM provider_connections WHERE id = $1`
	var one int
	err := r.pool.QueryRow(ctx, q, id).Scan(&one)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return false, fmt.Errorf("storage: provider_connection exists: %w", err)
}

// Bindable returns the narrow (status='active', self_service_bindable)
// tuple the EPIC Q scoped bind gate needs at step 5 + step 6. Avoids
// the full row scan + scope JSON unmarshal at the cost of one round
// trip. Caller uses ErrConnectionNotFound to distinguish a missing
// row from a row that's just disabled.
func (r *ProviderConnections) Bindable(ctx context.Context, id uuid.UUID) (bool, bool, error) {
	const q = `SELECT status, self_service_bindable FROM provider_connections WHERE id = $1`
	var status string
	var selfServiceBindable bool
	if err := r.pool.QueryRow(ctx, q, id).Scan(&status, &selfServiceBindable); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, false, ErrConnectionNotFound
		}
		return false, false, fmt.Errorf("storage: provider_connection bindable: %w", err)
	}
	return status == string(ProviderConnectionStatusActive), selfServiceBindable, nil
}

// ListDueForDiscovery returns up to 100 connections that are
// active + discover-enabled + cluster-bound and whose last_discover_at
// is past (now - interval). Hits the partial index
// provider_connections_discover_enabled_idx. NULLS FIRST orders
// never-discovered rows first.
func (r *ProviderConnections) ListDueForDiscovery(ctx context.Context, now time.Time) ([]DiscoverTarget, error) {
	const q = `
SELECT id, name, type, scope, cluster_name,
	discover_interval_seconds, last_discover_at
FROM provider_connections
WHERE status = 'active'
  AND discover_enabled = true
  AND cluster_name IS NOT NULL
  AND (
    last_discover_at IS NULL
    OR last_discover_at + (discover_interval_seconds * INTERVAL '1 second') <= $1
  )
ORDER BY last_discover_at NULLS FIRST
LIMIT 100
`
	rows, err := r.pool.Query(ctx, q, now)
	if err != nil {
		return nil, fmt.Errorf("storage: list due for discovery: %w", err)
	}
	defer rows.Close()
	out := []DiscoverTarget{}
	for rows.Next() {
		var t DiscoverTarget
		var scopeJSON []byte
		var clusterName *string
		if err := rows.Scan(&t.ID, &t.Name, &t.Type, &scopeJSON, &clusterName,
			&t.DiscoverIntervalSeconds, &t.LastDiscoverAt); err != nil {
			return nil, fmt.Errorf("storage: scan discover target: %w", err)
		}
		if err := json.Unmarshal(scopeJSON, &t.Scope); err != nil {
			return nil, fmt.Errorf("storage: unmarshal scope: %w", err)
		}
		if clusterName != nil {
			t.ClusterName = *clusterName
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// MarkDiscoverStarted flips the row to status='running' and stamps
// last_discover_started_at. Called by the worker scheduler BEFORE
// enqueueing the discover job; if enqueue fails the service layer
// immediately calls MarkDiscoverFinished(failure, ...).
func (r *ProviderConnections) MarkDiscoverStarted(ctx context.Context, id uuid.UUID, now time.Time) error {
	const q = `
UPDATE provider_connections
SET last_discover_status = 'running',
	last_discover_started_at = $2,
	last_discover_error = NULL
WHERE id = $1
`
	tag, err := r.pool.Exec(ctx, q, id, now)
	if err != nil {
		return fmt.Errorf("storage: mark discover started: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrConnectionNotFound
	}
	return nil
}

// MarkDiscoverFinished writes a terminal status. The status MUST be
// 'success' or 'failure' — 'running' returns ErrInvalidDiscoverStatus
// because allowing it in the finish method hides worker lifecycle
// bugs. The sanitizedErr value is the API-side service's pre-cleansed
// error string; the storage layer trusts it (the service layer is
// responsible for stripping credentials + response bodies before
// the value lands here).
func (r *ProviderConnections) MarkDiscoverFinished(ctx context.Context, id uuid.UUID, status, sanitizedErr string, now time.Time) error {
	if status != DiscoverStatusSuccess && status != DiscoverStatusFailure {
		return ErrInvalidDiscoverStatus
	}
	const q = `
UPDATE provider_connections
SET last_discover_status = $2,
	last_discover_error = NULLIF($3, ''),
	last_discover_at = $4,
	last_discover_finished_at = $4
WHERE id = $1
`
	tag, err := r.pool.Exec(ctx, q, id, status, sanitizedErr, now)
	if err != nil {
		return fmt.Errorf("storage: mark discover finished: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrConnectionNotFound
	}
	return nil
}

// CountBindings returns the number of project_provider_connections
// rows referencing this connection. Used by the admin DELETE handler
// to surface "in use by N bindings" in the 409 connection_in_use
// response body BEFORE the FK error fires.
func (r *ProviderConnections) CountBindings(ctx context.Context, id uuid.UUID) (int, error) {
	const q = `SELECT count(*) FROM project_provider_connections WHERE provider_connection_id = $1`
	var n int
	if err := r.pool.QueryRow(ctx, q, id).Scan(&n); err != nil {
		return 0, fmt.Errorf("storage: count bindings: %w", err)
	}
	return n, nil
}

// CountOpenRequests returns the number of open access_requests
// (pending_values / pending_verification / approved) referencing this
// connection as their cross-team destination. Used alongside
// CountBindings by the admin DELETE handler.
func (r *ProviderConnections) CountOpenRequests(ctx context.Context, id uuid.UUID) (int, error) {
	const q = `
SELECT count(*) FROM access_requests
WHERE destination_provider_connection_id = $1
  AND status IN ('pending_values', 'pending_verification', 'approved')
`
	var n int
	if err := r.pool.QueryRow(ctx, q, id).Scan(&n); err != nil {
		return 0, fmt.Errorf("storage: count open requests: %w", err)
	}
	return n, nil
}

// providerConnectionSelect is the column list shared by Get / List /
// GetByName / Update / Create. Keeping it in one place means scan
// shape changes track the SELECT shape automatically.
const providerConnectionSelect = `
SELECT id, name, type, auth_method, scope, status,
	cluster_name, description, discover_enabled, discover_interval_seconds,
	last_discover_at, last_discover_status, last_discover_error,
	last_discover_started_at, last_discover_finished_at,
	self_service_bindable,
	created_at, updated_at
FROM provider_connections
`

// scanProviderConnection reads from a pgx Row / Rows into a
// *ProviderConnection. Used by every SELECT-style method so a column-
// shape change updates in one place.
func scanProviderConnection(row interface {
	Scan(dest ...any) error
}) (*ProviderConnection, error) {
	var pc ProviderConnection
	var scopeJSON []byte
	var clusterName, description, lastDiscoverStatus, lastDiscoverError *string
	if err := row.Scan(
		&pc.ID, &pc.Name, &pc.Type, &pc.AuthMethod, &scopeJSON, &pc.Status,
		&clusterName, &description, &pc.DiscoverEnabled, &pc.DiscoverIntervalSeconds,
		&pc.LastDiscoverAt, &lastDiscoverStatus, &lastDiscoverError,
		&pc.LastDiscoverStartedAt, &pc.LastDiscoverFinishedAt,
		&pc.SelfServiceBindable,
		&pc.CreatedAt, &pc.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(scopeJSON, &pc.Scope); err != nil {
		return nil, fmt.Errorf("storage: unmarshal scope: %w", err)
	}
	if clusterName != nil {
		pc.ClusterName = *clusterName
	}
	if description != nil {
		pc.Description = *description
	}
	if lastDiscoverStatus != nil {
		pc.LastDiscoverStatus = *lastDiscoverStatus
	}
	if lastDiscoverError != nil {
		pc.LastDiscoverError = *lastDiscoverError
	}
	return &pc, nil
}

// Sentinels — declared here so the package surface is the single
// source of truth. The service layer maps to HTTP codes in
// internal/handlers/provider_connections.go (P3).
var (
	ErrConnectionNotFound  = errors.New("storage: provider_connection not found")
	ErrConnectionNameTaken = errors.New("storage: provider_connection name already taken")
	ErrConnectionInUse     = errors.New("storage: provider_connection is in use")

	// EPIC Q (api#99). Reserved here so any caller (service, worker)
	// can route via errors.Is without depending on the service layer.
	// ErrConnectionDisabled mirrors the cross-team flow's sentinel
	// from N3 — see services.ErrConnectionDisabled. Kept duplicated
	// at the storage layer for symmetry with the others.
	ErrConnectionNotSelfServiceBindable = errors.New("storage: provider_connection is not self-service bindable")
	ErrProdBindingNotAllowedForScope    = errors.New("storage: scoped binders cannot bind to prod environments")
	ErrOutOfScopeBinding                = errors.New("storage: actor does not cover the target project/environment")
)

// isUniqueViolation returns true when err wraps a PG unique-violation
// (23505). Used to translate Create / Update name collisions to the
// service-readable ErrConnectionNameTaken sentinel.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
