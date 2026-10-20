package storage

// Gateway registry (api#293): gateways, their one-time enrollment
// tokens, replicas, advertised connectors and admin-made bindings. See
// migration 0046 and the gateway control-plane design, sections 3.1 to
// 3.5.
//
// Only SHA-256 hashes of the enrollment token and of the gateway secret
// are stored; the plaintext never reaches this package. Connector and
// target ids are DNS labels checked by the service before they get here,
// and nothing in these rows is a URL, a credential path or a value.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// GatewayStatus is gateways.status.
type GatewayStatus string

// Gateway statuses.
const (
	GatewayStatusPending  GatewayStatus = "pending"
	GatewayStatusActive   GatewayStatus = "active"
	GatewayStatusStale    GatewayStatus = "stale"
	GatewayStatusDisabled GatewayStatus = "disabled"
	GatewayStatusRevoked  GatewayStatus = "revoked"
)

// Live reports whether a Gateway in this status may authenticate.
func (s GatewayStatus) Live() bool {
	return s == GatewayStatusActive || s == GatewayStatusStale
}

// Gateway connector statuses.
const (
	GatewayConnectorAdvertised = "advertised"
	GatewayConnectorApproved   = "approved"
	GatewayConnectorDisabled   = "disabled"
	GatewayConnectorMissing    = "missing"
)

// Gateway errors.
var (
	ErrGatewayNameTaken                = errors.New("storage: gateway name already in use")
	ErrGatewayEnrollmentTokenNotFound  = errors.New("storage: gateway enrollment token not found or not consumable")
	ErrGatewayAlreadyEnrolled          = errors.New("storage: gateway already enrolled")
	ErrGatewayNotLive                  = errors.New("storage: gateway is not active")
	ErrGatewayReplicaLimit             = errors.New("storage: gateway replica limit reached")
	ErrGatewayAlreadyRevoked           = errors.New("storage: gateway already revoked")
	ErrGatewayConnectorNotApprovable   = errors.New("storage: gateway connector is not in the advertised state")
	ErrGatewayBindingExists            = errors.New("storage: an equal gateway binding already exists")
	ErrGatewayBindingReferenceNotFound = errors.New("storage: a gateway binding reference does not exist")
)

// Gateway mirrors a gateways row. SecretHash is loaded only by GetAuth.
type Gateway struct {
	ID               uuid.UUID
	Name             string
	Boundary         string
	EnvironmentID    *uuid.UUID
	SecretHash       []byte
	Status           GatewayStatus
	GatewayVersion   string
	ContractVersions []string
	MaxInflightTasks int
	MaxReplicas      int
	CatalogVersion   string
	CatalogUpdatedAt *time.Time
	LastSeenAt       *time.Time
	LastStatus       string
	LastError        string
	EnrolledAt       *time.Time
	RevokedAt        *time.Time
	RevokedBy        string
	CreatedBy        string
	CreatedAt        time.Time
	UpdatedAt        time.Time
	// ReplicasSeen is the number of replicas seen within the window the
	// list query was given. Not a column.
	ReplicasSeen int
}

// GatewayEnrollmentToken mirrors a gateway_enrollment_tokens row.
type GatewayEnrollmentToken struct {
	ID                  uuid.UUID
	GatewayID           uuid.UUID
	TokenHash           []byte
	ExpectedClusterName string
	ExpiresAt           time.Time
	ConsumedAt          *time.Time
	RevokedAt           *time.Time
	RevokedBy           string
	CreatedBy           string
	CreatedAt           time.Time
}

// GatewayConnectorHealth is one connector's state in a heartbeat. Enums
// only.
type GatewayConnectorHealth struct {
	ConnectorID string `json:"connector_id"`
	Kind        string `json:"kind"`
	Status      string `json:"status"`
}

// GatewayReplica mirrors a gateway_replicas row.
type GatewayReplica struct {
	GatewayID       uuid.UUID
	ReplicaID       uuid.UUID
	GatewayVersion  string
	Status          string
	InFlight        int
	CatalogVersion  string
	ConnectorHealth []GatewayConnectorHealth
	FirstSeenAt     time.Time
	LastSeenAt      time.Time
}

// GatewayTarget is one advertised target of a connector. Namespace and
// Name are for admin display only.
type GatewayTarget struct {
	TargetID                string `json:"target_id"`
	Namespace               string `json:"namespace,omitempty"`
	Name                    string `json:"name,omitempty"`
	RefreshIntervalSeconds  *int   `json:"refresh_interval_seconds,omitempty"`
	ProgressDeadlineSeconds *int   `json:"progress_deadline_seconds,omitempty"`
	Stale                   bool   `json:"stale"`
}

// GatewayConnector mirrors a gateway_connectors row.
type GatewayConnector struct {
	ID               uuid.UUID
	GatewayID        uuid.UUID
	Name             string
	Kind             string
	Targets          []GatewayTarget
	Status           string
	ApprovedBy       string
	ApprovedAt       *time.Time
	LastAdvertisedAt *time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// Target returns the advertised target with id, if any.
func (c *GatewayConnector) Target(id string) (GatewayTarget, bool) {
	for _, t := range c.Targets {
		if t.TargetID == id {
			return t, true
		}
	}
	return GatewayTarget{}, false
}

// GatewayBinding mirrors a gateway_connector_bindings row.
type GatewayBinding struct {
	ID                   uuid.UUID
	GatewayID            uuid.UUID
	EnvironmentID        uuid.UUID
	ProjectID            uuid.UUID // from environments, not a column
	SecretID             *uuid.UUID
	ProviderConnectionID *uuid.UUID
	SecretRef            string
	ExpectedStages       []string
	ESOConnectorID       *uuid.UUID
	ESOTargetID          string
	RolloutConnectorID   *uuid.UUID
	RolloutTargetID      string
	ArgoCDConnectorID    *uuid.UUID
	ArgoCDTargetID       string
	ObservationTimeoutS  int
	Enabled              bool
	CreatedBy            string
	CreatedAt            time.Time
}

// GatewayHeartbeat is what one replica reported, already validated.
type GatewayHeartbeat struct {
	GatewayID        uuid.UUID
	ReplicaID        uuid.UUID
	GatewayVersion   string
	ContractVersions []string
	Status           string
	InFlight         int
	CatalogVersion   string
	Connectors       []GatewayConnectorHealth
}

// GatewayHeartbeatOutcome is what RecordHeartbeat found.
type GatewayHeartbeatOutcome struct {
	NewReplica        bool
	PrevReplicaStatus string
	CatalogVersion    string
	MaxReplicas       int
}

// GatewayCatalogConnector is one connector of a validated catalog.
type GatewayCatalogConnector struct {
	ConnectorID string
	Kind        string
	Targets     []GatewayTarget
}

// GatewayCatalogOutcome is what ReplaceCatalog changed.
type GatewayCatalogOutcome struct {
	Changed      bool // the digest differs from the stored one
	Accepted     int
	Targets      int
	TargetsStale int
	Missing      []*GatewayConnector // connectors that left the catalog now
	Reset        []*GatewayConnector // approved connectors that went back to advertised
}

// Gateways is the Postgres repository for the gateway registry.
type Gateways struct {
	pool *Pool
}

// NewGateways binds the repository to a pool.
func NewGateways(pool *Pool) *Gateways { return &Gateways{pool: pool} }

const gatewayColumns = `
	g.id, g.name, g.boundary, g.environment_id, g.status,
	COALESCE(g.gateway_version, ''), g.contract_versions,
	g.max_inflight_tasks, g.max_replicas,
	COALESCE(g.catalog_version, ''), g.catalog_updated_at,
	g.last_seen_at, COALESCE(g.last_status, ''), COALESCE(g.last_error, ''),
	g.enrolled_at, g.revoked_at, COALESCE(g.revoked_by, ''),
	g.created_by, g.created_at, g.updated_at`

func scanGateway(row pgx.Row, extra ...any) (*Gateway, error) {
	var g Gateway
	var cv []byte
	dest := []any{
		&g.ID, &g.Name, &g.Boundary, &g.EnvironmentID, &g.Status,
		&g.GatewayVersion, &cv,
		&g.MaxInflightTasks, &g.MaxReplicas,
		&g.CatalogVersion, &g.CatalogUpdatedAt,
		&g.LastSeenAt, &g.LastStatus, &g.LastError,
		&g.EnrolledAt, &g.RevokedAt, &g.RevokedBy,
		&g.CreatedBy, &g.CreatedAt, &g.UpdatedAt,
	}
	if err := row.Scan(append(dest, extra...)...); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("storage: scan gateway: %w", err)
	}
	if err := json.Unmarshal(cv, &g.ContractVersions); err != nil || g.ContractVersions == nil {
		g.ContractVersions = []string{}
	}
	return &g, nil
}

func isFKViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

// Create inserts a pending Gateway with no credential.
func (r *Gateways) Create(ctx context.Context, g *Gateway) error {
	if g.Name == "" || g.Boundary == "" || g.CreatedBy == "" {
		return errors.New("storage: gateway name, boundary and created_by are required")
	}
	const q = `
		INSERT INTO gateways (name, boundary, environment_id, max_inflight_tasks, max_replicas, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, status, created_at, updated_at`
	err := r.pool.QueryRow(ctx, q, g.Name, g.Boundary, g.EnvironmentID, g.MaxInflightTasks, g.MaxReplicas, g.CreatedBy).
		Scan(&g.ID, &g.Status, &g.CreatedAt, &g.UpdatedAt)
	switch {
	case isUniqueViolation(err):
		return ErrGatewayNameTaken
	case isFKViolation(err):
		return ErrGatewayBindingReferenceNotFound
	case err != nil:
		return fmt.Errorf("storage: create gateway: %w", err)
	}
	g.ContractVersions = []string{}
	return nil
}

// Get returns a Gateway without its secret hash.
func (r *Gateways) Get(ctx context.Context, id uuid.UUID) (*Gateway, error) {
	return scanGateway(r.pool.QueryRow(ctx, `SELECT `+gatewayColumns+` FROM gateways g WHERE g.id = $1`, id))
}

// GetAuth returns only what authentication needs: status and hash.
func (r *Gateways) GetAuth(ctx context.Context, id uuid.UUID) (GatewayStatus, []byte, error) {
	var status GatewayStatus
	var hash []byte
	err := r.pool.QueryRow(ctx, `SELECT status, secret_hash FROM gateways WHERE id = $1`, id).Scan(&status, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, ErrNotFound
	}
	if err != nil {
		return "", nil, fmt.Errorf("storage: gateway auth lookup: %w", err)
	}
	return status, hash, nil
}

// List returns every Gateway, newest first, with the number of replicas
// seen since seenSince.
func (r *Gateways) List(ctx context.Context, seenSince time.Time) ([]*Gateway, error) {
	q := `SELECT ` + gatewayColumns + `,
		(SELECT count(*) FROM gateway_replicas rp WHERE rp.gateway_id = g.id AND rp.last_seen_at > $1)
		FROM gateways g ORDER BY g.created_at DESC, g.id`
	rows, err := r.pool.Query(ctx, q, seenSince)
	if err != nil {
		return nil, fmt.Errorf("storage: list gateways: %w", err)
	}
	defer rows.Close()
	var out []*Gateway
	for rows.Next() {
		var n int
		g, err := scanGateway(rows, &n)
		if err != nil {
			return nil, err
		}
		g.ReplicasSeen = n
		out = append(out, g)
	}
	return out, rows.Err()
}

// --- enrollment tokens -------------------------------------------------

const gatewayTokenColumns = `
	id, gateway_id, token_hash, COALESCE(expected_cluster_name, ''), expires_at,
	consumed_at, revoked_at, COALESCE(revoked_by, ''), created_by, created_at`

func scanGatewayToken(row pgx.Row) (*GatewayEnrollmentToken, error) {
	var t GatewayEnrollmentToken
	err := row.Scan(&t.ID, &t.GatewayID, &t.TokenHash, &t.ExpectedClusterName, &t.ExpiresAt,
		&t.ConsumedAt, &t.RevokedAt, &t.RevokedBy, &t.CreatedBy, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrGatewayEnrollmentTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("storage: scan gateway enrollment token: %w", err)
	}
	return &t, nil
}

// CreateEnrollmentToken stores a token hash for a pending Gateway. It
// refuses (ErrGatewayAlreadyEnrolled) when the Gateway is not pending.
func (r *Gateways) CreateEnrollmentToken(ctx context.Context, t *GatewayEnrollmentToken) error {
	if len(t.TokenHash) == 0 || t.CreatedBy == "" || t.ExpiresAt.IsZero() {
		return errors.New("storage: gateway enrollment token hash, created_by and expires_at are required")
	}
	const q = `
		INSERT INTO gateway_enrollment_tokens (gateway_id, token_hash, expected_cluster_name, expires_at, created_by)
		SELECT id, $2, NULLIF($3, ''), $4, $5 FROM gateways WHERE id = $1 AND status = 'pending'
		RETURNING id, created_at`
	err := r.pool.QueryRow(ctx, q, t.GatewayID, t.TokenHash, t.ExpectedClusterName, t.ExpiresAt, t.CreatedBy).
		Scan(&t.ID, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		if _, gerr := r.Get(ctx, t.GatewayID); gerr != nil {
			return gerr
		}
		return ErrGatewayAlreadyEnrolled
	}
	if err != nil {
		return fmt.Errorf("storage: create gateway enrollment token: %w", err)
	}
	return nil
}

// GetEnrollmentTokenByHash resolves a token by its SHA-256 hash.
func (r *Gateways) GetEnrollmentTokenByHash(ctx context.Context, hash []byte) (*GatewayEnrollmentToken, error) {
	return scanGatewayToken(r.pool.QueryRow(ctx,
		`SELECT `+gatewayTokenColumns+` FROM gateway_enrollment_tokens WHERE token_hash = $1`, hash))
}

// GetEnrollmentToken resolves a token by id.
func (r *Gateways) GetEnrollmentToken(ctx context.Context, id uuid.UUID) (*GatewayEnrollmentToken, error) {
	return scanGatewayToken(r.pool.QueryRow(ctx,
		`SELECT `+gatewayTokenColumns+` FROM gateway_enrollment_tokens WHERE id = $1`, id))
}

// ListEnrollmentTokens returns a Gateway's tokens, newest first.
func (r *Gateways) ListEnrollmentTokens(ctx context.Context, gatewayID uuid.UUID) ([]*GatewayEnrollmentToken, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+gatewayTokenColumns+`
		FROM gateway_enrollment_tokens WHERE gateway_id = $1 ORDER BY created_at DESC, id`, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("storage: list gateway enrollment tokens: %w", err)
	}
	defer rows.Close()
	var out []*GatewayEnrollmentToken
	for rows.Next() {
		t, err := scanGatewayToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeEnrollmentToken revokes an unused, unrevoked token.
func (r *Gateways) RevokeEnrollmentToken(ctx context.Context, id uuid.UUID, by string, at time.Time) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE gateway_enrollment_tokens SET revoked_at = $2, revoked_by = NULLIF($3, '')
		WHERE id = $1 AND consumed_at IS NULL AND revoked_at IS NULL`, id, at, by)
	if err != nil {
		return fmt.Errorf("storage: revoke gateway enrollment token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrGatewayEnrollmentTokenNotFound
	}
	return nil
}

// gatewayConsumableTokenSQL is the single-use guard, the same as
// consumableTokenSQL for agent tokens: unconsumed, unrevoked and not
// expired at $2.
const gatewayConsumableTokenSQL = `consumed_at IS NULL AND revoked_at IS NULL AND expires_at > $2`

// ConsumeTokenAndEnroll burns the token and sets the Gateway's secret
// hash in one transaction. The token is consumed first and holds its row
// lock, so concurrent enrolls with one token serialise: the first
// commits, the rest match nothing. The Gateway update requires a pending
// row with no credential; if it matches nothing the consume is rolled
// back and ErrGatewayAlreadyEnrolled is returned.
func (r *Gateways) ConsumeTokenAndEnroll(ctx context.Context, tokenID uuid.UUID, at time.Time, secretHash []byte) (uuid.UUID, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, fmt.Errorf("storage: begin gateway enrollment: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var gatewayID uuid.UUID
	err = tx.QueryRow(ctx, `
		UPDATE gateway_enrollment_tokens SET consumed_at = $2
		WHERE id = $1 AND `+gatewayConsumableTokenSQL+`
		RETURNING gateway_id`, tokenID, at).Scan(&gatewayID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrGatewayEnrollmentTokenNotFound
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("storage: consume gateway enrollment token: %w", err)
	}
	tag, err := tx.Exec(ctx, `
		UPDATE gateways SET secret_hash = $2, status = 'active', enrolled_at = $3
		WHERE id = $1 AND secret_hash IS NULL AND status = 'pending'`, gatewayID, secretHash, at)
	if err != nil {
		return uuid.Nil, fmt.Errorf("storage: enroll gateway: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return uuid.Nil, ErrGatewayAlreadyEnrolled
	}
	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, fmt.Errorf("storage: commit gateway enrollment: %w", err)
	}
	return gatewayID, nil
}

// Revoke sets the Gateway to revoked and revokes its unused enrollment
// tokens in one transaction. Returns the number of tokens revoked.
func (r *Gateways) Revoke(ctx context.Context, id uuid.UUID, by string, at time.Time) (int, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("storage: begin gateway revoke: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var status GatewayStatus
	err = tx.QueryRow(ctx, `SELECT status FROM gateways WHERE id = $1 FOR UPDATE`, id).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("storage: lock gateway: %w", err)
	}
	if status == GatewayStatusRevoked {
		return 0, ErrGatewayAlreadyRevoked
	}
	if _, err := tx.Exec(ctx, `
		UPDATE gateways SET status = 'revoked', revoked_at = $2, revoked_by = NULLIF($3, '')
		WHERE id = $1`, id, at, by); err != nil {
		return 0, fmt.Errorf("storage: revoke gateway: %w", err)
	}
	tag, err := tx.Exec(ctx, `
		UPDATE gateway_enrollment_tokens SET revoked_at = $2, revoked_by = NULLIF($3, '')
		WHERE gateway_id = $1 AND consumed_at IS NULL AND revoked_at IS NULL`, id, at, by)
	if err != nil {
		return 0, fmt.Errorf("storage: revoke gateway enrollment tokens: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("storage: commit gateway revoke: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// --- heartbeat ---------------------------------------------------------

// RecordHeartbeat upserts the replica and updates the Gateway's liveness
// columns. A replica id not seen before is refused with
// ErrGatewayReplicaLimit when max_replicas replicas were already seen
// since seenSince. A Gateway that is no longer active or stale (revoked
// after the auth check) gets ErrGatewayNotLive and nothing is written.
func (r *Gateways) RecordHeartbeat(ctx context.Context, hb GatewayHeartbeat, at, seenSince time.Time) (*GatewayHeartbeatOutcome, error) {
	health, err := json.Marshal(hb.Connectors)
	if err != nil {
		return nil, fmt.Errorf("storage: marshal connector health: %w", err)
	}
	contract, err := json.Marshal(hb.ContractVersions)
	if err != nil {
		return nil, fmt.Errorf("storage: marshal contract versions: %w", err)
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("storage: begin heartbeat: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	out := &GatewayHeartbeatOutcome{}
	var status GatewayStatus
	err = tx.QueryRow(ctx, `SELECT status, max_replicas, COALESCE(catalog_version, '') FROM gateways WHERE id = $1 FOR UPDATE`,
		hb.GatewayID).Scan(&status, &out.MaxReplicas, &out.CatalogVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrGatewayNotLive
	}
	if err != nil {
		return nil, fmt.Errorf("storage: lock gateway: %w", err)
	}
	if !status.Live() {
		return nil, ErrGatewayNotLive
	}

	err = tx.QueryRow(ctx, `SELECT status FROM gateway_replicas WHERE gateway_id = $1 AND replica_id = $2`,
		hb.GatewayID, hb.ReplicaID).Scan(&out.PrevReplicaStatus)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		out.NewReplica = true
		var seen int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM gateway_replicas WHERE gateway_id = $1 AND last_seen_at > $2`,
			hb.GatewayID, seenSince).Scan(&seen); err != nil {
			return nil, fmt.Errorf("storage: count gateway replicas: %w", err)
		}
		if seen >= out.MaxReplicas {
			return out, ErrGatewayReplicaLimit
		}
	case err != nil:
		return nil, fmt.Errorf("storage: read gateway replica: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO gateway_replicas (gateway_id, replica_id, gateway_version, status, in_flight, catalog_version, connector_health, first_seen_at, last_seen_at)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), $7, $8, $8)
		ON CONFLICT (gateway_id, replica_id) DO UPDATE SET
			gateway_version = EXCLUDED.gateway_version, status = EXCLUDED.status,
			in_flight = EXCLUDED.in_flight, catalog_version = EXCLUDED.catalog_version,
			connector_health = EXCLUDED.connector_health, last_seen_at = EXCLUDED.last_seen_at`,
		hb.GatewayID, hb.ReplicaID, hb.GatewayVersion, hb.Status, hb.InFlight, hb.CatalogVersion, health, at); err != nil {
		return nil, fmt.Errorf("storage: upsert gateway replica: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE gateways SET last_seen_at = $2, last_status = $3, gateway_version = $4, contract_versions = $5,
			status = CASE WHEN status = 'stale' THEN 'active' ELSE status END
		WHERE id = $1`, hb.GatewayID, at, hb.Status, hb.GatewayVersion, contract); err != nil {
		return nil, fmt.Errorf("storage: update gateway liveness: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("storage: commit heartbeat: %w", err)
	}
	return out, nil
}

// ListReplicas returns a Gateway's replicas, most recently seen first.
func (r *Gateways) ListReplicas(ctx context.Context, gatewayID uuid.UUID) ([]*GatewayReplica, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT gateway_id, replica_id, COALESCE(gateway_version, ''), status, in_flight,
		       COALESCE(catalog_version, ''), connector_health, first_seen_at, last_seen_at
		FROM gateway_replicas WHERE gateway_id = $1 ORDER BY last_seen_at DESC, replica_id`, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("storage: list gateway replicas: %w", err)
	}
	defer rows.Close()
	var out []*GatewayReplica
	for rows.Next() {
		var rp GatewayReplica
		var health []byte
		if err := rows.Scan(&rp.GatewayID, &rp.ReplicaID, &rp.GatewayVersion, &rp.Status, &rp.InFlight,
			&rp.CatalogVersion, &health, &rp.FirstSeenAt, &rp.LastSeenAt); err != nil {
			return nil, fmt.Errorf("storage: scan gateway replica: %w", err)
		}
		if err := json.Unmarshal(health, &rp.ConnectorHealth); err != nil || rp.ConnectorHealth == nil {
			rp.ConnectorHealth = []GatewayConnectorHealth{}
		}
		out = append(out, &rp)
	}
	return out, rows.Err()
}

// --- connectors and catalog -------------------------------------------

const gatewayConnectorColumns = `
	id, gateway_id, name, kind, advertised_targets, status,
	COALESCE(approved_by, ''), approved_at, last_advertised_at, created_at, updated_at`

func scanGatewayConnector(row pgx.Row) (*GatewayConnector, error) {
	var c GatewayConnector
	var targets []byte
	err := row.Scan(&c.ID, &c.GatewayID, &c.Name, &c.Kind, &targets, &c.Status,
		&c.ApprovedBy, &c.ApprovedAt, &c.LastAdvertisedAt, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("storage: scan gateway connector: %w", err)
	}
	if err := json.Unmarshal(targets, &c.Targets); err != nil || c.Targets == nil {
		c.Targets = []GatewayTarget{}
	}
	return &c, nil
}

func listGatewayConnectors(ctx context.Context, q querier, gatewayID uuid.UUID) ([]*GatewayConnector, error) {
	rows, err := q.Query(ctx, `SELECT `+gatewayConnectorColumns+`
		FROM gateway_connectors WHERE gateway_id = $1 ORDER BY name`, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("storage: list gateway connectors: %w", err)
	}
	defer rows.Close()
	var out []*GatewayConnector
	for rows.Next() {
		c, err := scanGatewayConnector(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListConnectors returns a Gateway's connectors by name.
func (r *Gateways) ListConnectors(ctx context.Context, gatewayID uuid.UUID) ([]*GatewayConnector, error) {
	return listGatewayConnectors(ctx, r.pool, gatewayID)
}

// GetConnector returns one connector by id.
func (r *Gateways) GetConnector(ctx context.Context, id uuid.UUID) (*GatewayConnector, error) {
	return scanGatewayConnector(r.pool.QueryRow(ctx, `SELECT `+gatewayConnectorColumns+` FROM gateway_connectors WHERE id = $1`, id))
}

// mergeTargets returns the incoming targets (not stale) plus every
// previously advertised target that is no longer advertised (stale),
// sorted by target id.
func mergeTargets(prev, incoming []GatewayTarget) []GatewayTarget {
	out := make([]GatewayTarget, 0, len(prev)+len(incoming))
	seen := make(map[string]bool, len(incoming))
	for _, t := range incoming {
		t.Stale = false
		out = append(out, t)
		seen[t.TargetID] = true
	}
	for _, t := range prev {
		if !seen[t.TargetID] {
			t.Stale = true
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TargetID < out[j].TargetID })
	return out
}

// ReplaceCatalog records a full catalog for a live Gateway in one
// transaction. Advertising never approves anything:
//
//   - a new connector is inserted as advertised;
//   - a known connector keeps its status, unless its kind changed or it
//     was missing, in which case it goes back to advertised and loses its
//     approval (an admin approves it again);
//   - a target that is no longer advertised stays, marked stale;
//   - a connector that is no longer advertised becomes missing, with
//     every target stale.
func (r *Gateways) ReplaceCatalog(ctx context.Context, gatewayID uuid.UUID, conns []GatewayCatalogConnector, digest string, at time.Time) (*GatewayCatalogOutcome, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("storage: begin catalog: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var status GatewayStatus
	var prevDigest string
	err = tx.QueryRow(ctx, `SELECT status, COALESCE(catalog_version, '') FROM gateways WHERE id = $1 FOR UPDATE`, gatewayID).
		Scan(&status, &prevDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrGatewayNotLive
	}
	if err != nil {
		return nil, fmt.Errorf("storage: lock gateway: %w", err)
	}
	if !status.Live() {
		return nil, ErrGatewayNotLive
	}

	existing, err := listGatewayConnectors(ctx, tx, gatewayID)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]*GatewayConnector, len(existing))
	for _, c := range existing {
		byName[c.Name] = c
	}

	out := &GatewayCatalogOutcome{Changed: digest != prevDigest, Accepted: len(conns)}
	advertised := make(map[string]bool, len(conns))
	for _, in := range conns {
		advertised[in.ConnectorID] = true
		prev := byName[in.ConnectorID]
		if prev == nil {
			targets := mergeTargets(nil, in.Targets)
			raw, err := json.Marshal(targets)
			if err != nil {
				return nil, fmt.Errorf("storage: marshal targets: %w", err)
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO gateway_connectors (gateway_id, name, kind, advertised_targets, status, last_advertised_at)
				VALUES ($1, $2, $3, $4, 'advertised', $5)`, gatewayID, in.ConnectorID, in.Kind, raw, at); err != nil {
				return nil, fmt.Errorf("storage: insert gateway connector: %w", err)
			}
			out.Targets += len(targets)
			continue
		}
		reset := prev.Kind != in.Kind || prev.Status == GatewayConnectorMissing
		var targets []GatewayTarget
		if prev.Kind != in.Kind {
			targets = mergeTargets(nil, in.Targets) // another kind's targets mean nothing here
		} else {
			targets = mergeTargets(prev.Targets, in.Targets)
		}
		raw, err := json.Marshal(targets)
		if err != nil {
			return nil, fmt.Errorf("storage: marshal targets: %w", err)
		}
		newStatus := prev.Status
		if reset && prev.Status != GatewayConnectorDisabled {
			newStatus = GatewayConnectorAdvertised
		}
		if _, err := tx.Exec(ctx, `
			UPDATE gateway_connectors SET kind = $2, advertised_targets = $3, status = $4, last_advertised_at = $5,
				approved_by = CASE WHEN $6 THEN NULL ELSE approved_by END,
				approved_at = CASE WHEN $6 THEN NULL ELSE approved_at END
			WHERE id = $1`, prev.ID, in.Kind, raw, newStatus, at, reset); err != nil {
			return nil, fmt.Errorf("storage: update gateway connector: %w", err)
		}
		if reset && prev.Status == GatewayConnectorApproved {
			out.Reset = append(out.Reset, prev)
		}
		out.Targets += len(targets)
		for _, t := range targets {
			if t.Stale {
				out.TargetsStale++
			}
		}
	}
	for _, c := range existing {
		if advertised[c.Name] || c.Status == GatewayConnectorMissing {
			continue
		}
		targets := mergeTargets(c.Targets, nil)
		raw, err := json.Marshal(targets)
		if err != nil {
			return nil, fmt.Errorf("storage: marshal targets: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE gateway_connectors SET status = 'missing', advertised_targets = $2 WHERE id = $1`,
			c.ID, raw); err != nil {
			return nil, fmt.Errorf("storage: mark gateway connector missing: %w", err)
		}
		out.Missing = append(out.Missing, c)
	}
	if _, err := tx.Exec(ctx, `UPDATE gateways SET catalog_version = $2, catalog_updated_at = $3 WHERE id = $1`,
		gatewayID, digest, at); err != nil {
		return nil, fmt.Errorf("storage: store catalog version: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("storage: commit catalog: %w", err)
	}
	return out, nil
}

// ApproveConnector moves an advertised connector of gatewayID to
// approved.
func (r *Gateways) ApproveConnector(ctx context.Context, gatewayID, connectorID uuid.UUID, by string, at time.Time) (*GatewayConnector, error) {
	c, err := scanGatewayConnector(r.pool.QueryRow(ctx, `
		UPDATE gateway_connectors SET status = 'approved', approved_by = $3, approved_at = $4
		WHERE id = $1 AND gateway_id = $2 AND status = 'advertised'
		RETURNING `+gatewayConnectorColumns, connectorID, gatewayID, by, at))
	if !errors.Is(err, ErrNotFound) {
		return c, err
	}
	prev, gerr := r.GetConnector(ctx, connectorID)
	if gerr != nil || prev.GatewayID != gatewayID {
		return nil, ErrNotFound
	}
	return nil, ErrGatewayConnectorNotApprovable
}

// --- bindings ----------------------------------------------------------

const gatewayBindingColumns = `
	b.id, b.gateway_id, b.environment_id, e.project_id, b.secret_id, b.provider_connection_id,
	COALESCE(b.secret_ref, ''), b.expected_stages,
	b.eso_connector_id, COALESCE(b.eso_target_id, ''),
	b.rollout_connector_id, COALESCE(b.rollout_target_id, ''),
	b.argocd_connector_id, COALESCE(b.argocd_target_id, ''),
	b.observation_timeout_s, b.enabled, b.created_by, b.created_at`

func scanGatewayBinding(row pgx.Row) (*GatewayBinding, error) {
	var b GatewayBinding
	var stages []byte
	err := row.Scan(&b.ID, &b.GatewayID, &b.EnvironmentID, &b.ProjectID, &b.SecretID, &b.ProviderConnectionID,
		&b.SecretRef, &stages,
		&b.ESOConnectorID, &b.ESOTargetID,
		&b.RolloutConnectorID, &b.RolloutTargetID,
		&b.ArgoCDConnectorID, &b.ArgoCDTargetID,
		&b.ObservationTimeoutS, &b.Enabled, &b.CreatedBy, &b.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("storage: scan gateway binding: %w", err)
	}
	if err := json.Unmarshal(stages, &b.ExpectedStages); err != nil || b.ExpectedStages == nil {
		b.ExpectedStages = []string{}
	}
	return &b, nil
}

// CreateBinding inserts a binding. The service has already checked that
// every connector belongs to the Gateway, is approved, has the right kind
// and advertises the target.
func (r *Gateways) CreateBinding(ctx context.Context, b *GatewayBinding) error {
	stages, err := json.Marshal(b.ExpectedStages)
	if err != nil {
		return fmt.Errorf("storage: marshal expected stages: %w", err)
	}
	nullable := func(s string) any {
		if s == "" {
			return nil
		}
		return s
	}
	err = r.pool.QueryRow(ctx, `
		INSERT INTO gateway_connector_bindings (
			gateway_id, environment_id, secret_id, provider_connection_id, secret_ref, expected_stages,
			eso_connector_id, eso_target_id, rollout_connector_id, rollout_target_id,
			argocd_connector_id, argocd_target_id, observation_timeout_s, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING id, enabled, created_at`,
		b.GatewayID, b.EnvironmentID, b.SecretID, b.ProviderConnectionID, nullable(b.SecretRef), stages,
		b.ESOConnectorID, nullable(b.ESOTargetID), b.RolloutConnectorID, nullable(b.RolloutTargetID),
		b.ArgoCDConnectorID, nullable(b.ArgoCDTargetID), b.ObservationTimeoutS, b.CreatedBy).
		Scan(&b.ID, &b.Enabled, &b.CreatedAt)
	switch {
	case isUniqueViolation(err):
		return ErrGatewayBindingExists
	case isFKViolation(err):
		return ErrGatewayBindingReferenceNotFound
	case err != nil:
		return fmt.Errorf("storage: create gateway binding: %w", err)
	}
	return nil
}

// GetBinding returns one live (not deleted) binding.
func (r *Gateways) GetBinding(ctx context.Context, id uuid.UUID) (*GatewayBinding, error) {
	return scanGatewayBinding(r.pool.QueryRow(ctx, `SELECT `+gatewayBindingColumns+`
		FROM gateway_connector_bindings b JOIN environments e ON e.id = b.environment_id
		WHERE b.id = $1 AND b.deleted_at IS NULL`, id))
}

// ListBindings returns live bindings, for one Gateway when gatewayID is
// set.
func (r *Gateways) ListBindings(ctx context.Context, gatewayID *uuid.UUID) ([]*GatewayBinding, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+gatewayBindingColumns+`
		FROM gateway_connector_bindings b JOIN environments e ON e.id = b.environment_id
		WHERE b.deleted_at IS NULL AND ($1::uuid IS NULL OR b.gateway_id = $1)
		ORDER BY b.created_at DESC, b.id`, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("storage: list gateway bindings: %w", err)
	}
	defer rows.Close()
	var out []*GatewayBinding
	for rows.Next() {
		b, err := scanGatewayBinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// DeleteBinding soft-deletes a live binding.
func (r *Gateways) DeleteBinding(ctx context.Context, id uuid.UUID, at time.Time) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE gateway_connector_bindings SET deleted_at = $2, enabled = false
		WHERE id = $1 AND deleted_at IS NULL`, id, at)
	if err != nil {
		return fmt.Errorf("storage: delete gateway binding: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// EnvironmentProject returns the project an environment belongs to.
func (r *Gateways) EnvironmentProject(ctx context.Context, envID uuid.UUID) (uuid.UUID, error) {
	var projectID uuid.UUID
	err := r.pool.QueryRow(ctx, `SELECT project_id FROM environments WHERE id = $1`, envID).Scan(&projectID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("storage: environment project: %w", err)
	}
	return projectID, nil
}

// SecretBoundToProject reports whether a catalog secret is bound to the
// project (project_secrets).
func (r *Gateways) SecretBoundToProject(ctx context.Context, secretID, projectID uuid.UUID) (bool, error) {
	var ok bool
	err := r.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM project_secrets WHERE secret_id = $1 AND project_id = $2)`, secretID, projectID).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("storage: secret project binding: %w", err)
	}
	return ok, nil
}

// ProviderConnectionExists reports whether a provider connection exists.
func (r *Gateways) ProviderConnectionExists(ctx context.Context, id uuid.UUID) (bool, error) {
	var ok bool
	if err := r.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM provider_connections WHERE id = $1)`, id).Scan(&ok); err != nil {
		return false, fmt.Errorf("storage: provider connection lookup: %w", err)
	}
	return ok, nil
}
