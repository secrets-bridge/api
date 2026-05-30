package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Secret is the CP-side cache of a secret the agent has discovered
// via core/providers.ListMetadata. The metadata-only contract holds:
// Secret carries NO value, no ciphertext, no content hash that could
// recover the value — only descriptive metadata safe to expose in the
// dashboard.
type Secret struct {
	ID                uuid.UUID
	ClusterName       string
	ProviderType      string
	SecretRef         string
	ProviderConfig    map[string]any
	Labels            map[string]any
	Version           string
	Checksum          string
	CreatedAtSource   *time.Time
	UpdatedAtSource   *time.Time
	Status            SecretStatus
	FirstSeenAt       time.Time
	LastSeenAt        time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// SecretStatus is constrained by the schema CHECK.
type SecretStatus string

const (
	SecretStatusPresent SecretStatus = "present"
	SecretStatusMissing SecretStatus = "missing"
)

// SecretsListFilter narrows a List query. All fields optional.
//
// LabelEquals is an ANDed conjunction of {key, value} predicates. Each
// pair is checked via the jsonb containment operator (labels @> '{k:v}'),
// which makes the GIN index do the heavy lifting.
//
// SecretIDs, when non-nil, restricts results to that id set (intersected
// with the other filters). A nil slice means "no id restriction" — every
// secret can match. An EMPTY (non-nil) slice means "no rows" — useful
// for the multi-tenancy filter at the handler layer when the caller
// has zero project bindings.
type SecretsListFilter struct {
	ClusterName     string
	ProviderType    string
	SecretRefPrefix string
	Status          SecretStatus
	LabelEquals     map[string]string
	SecretIDs       []uuid.UUID
	Limit           int
	Offset          int
}

// SecretRepository is the read/write surface for the secrets table.
type SecretRepository interface {
	// Upsert inserts a new row or refreshes labels / version /
	// checksum / last_seen_at on an existing one keyed by
	// (cluster_name, provider_type, secret_ref). Returns the
	// resulting row so callers can echo IDs back.
	Upsert(ctx context.Context, s *Secret) error

	// Get returns a row by id.
	Get(ctx context.Context, id uuid.UUID) (*Secret, error)

	// List returns rows matching the filter, ordered by
	// (cluster_name, secret_ref) for stable pagination.
	List(ctx context.Context, f SecretsListFilter) ([]*Secret, error)

	// Count returns the total number of rows matching the filter —
	// for pagination UIs that need a total.
	Count(ctx context.Context, f SecretsListFilter) (int, error)

	// MarkStaleAsMissing flips status to 'missing' for rows whose
	// last_seen_at is older than `cutoff`. Returns the number of rows
	// updated. Used by the background sweeper.
	MarkStaleAsMissing(ctx context.Context, cutoff time.Time) (int64, error)

	// ListByRef returns every catalog row matching the
	// (provider_type, secret_ref) pair, across all clusters. Used by
	// the submit-time multi-tenancy gate (api#43 Slice C) where the
	// caller's body carries the ref but not the cluster.
	ListByRef(ctx context.Context, providerType, secretRef string) ([]*Secret, error)
}

// Secrets is the Postgres implementation.
type Secrets struct {
	pool *Pool
}

// NewSecrets binds the repository to a pool.
func NewSecrets(pool *Pool) *Secrets { return &Secrets{pool: pool} }

func (r *Secrets) Upsert(ctx context.Context, s *Secret) error {
	if s.ClusterName == "" {
		return errors.New("storage: ClusterName is required")
	}
	if s.ProviderType == "" {
		return errors.New("storage: ProviderType is required")
	}
	if s.SecretRef == "" {
		return errors.New("storage: SecretRef is required")
	}
	if s.Labels == nil {
		s.Labels = map[string]any{}
	}
	if s.ProviderConfig == nil {
		s.ProviderConfig = map[string]any{}
	}
	if s.Status == "" {
		s.Status = SecretStatusPresent
	}

	labels, err := json.Marshal(s.Labels)
	if err != nil {
		return fmt.Errorf("storage: marshal labels: %w", err)
	}
	cfg, err := json.Marshal(s.ProviderConfig)
	if err != nil {
		return fmt.Errorf("storage: marshal provider_config: %w", err)
	}

	const q = `
		INSERT INTO secrets (
		    cluster_name, provider_type, secret_ref,
		    provider_config, labels,
		    version, checksum,
		    created_at_source, updated_at_source,
		    status, last_seen_at
		) VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), NULLIF($7, ''), $8, $9, $10, now())
		ON CONFLICT (cluster_name, provider_type, secret_ref) DO UPDATE
		SET provider_config   = EXCLUDED.provider_config,
		    labels            = EXCLUDED.labels,
		    version           = EXCLUDED.version,
		    checksum          = EXCLUDED.checksum,
		    created_at_source = COALESCE(EXCLUDED.created_at_source, secrets.created_at_source),
		    updated_at_source = COALESCE(EXCLUDED.updated_at_source, secrets.updated_at_source),
		    status            = EXCLUDED.status,
		    last_seen_at      = now()
		RETURNING id, first_seen_at, last_seen_at, created_at, updated_at`
	return r.pool.QueryRow(ctx, q,
		s.ClusterName, s.ProviderType, s.SecretRef,
		cfg, labels,
		s.Version, s.Checksum,
		s.CreatedAtSource, s.UpdatedAtSource,
		s.Status,
	).Scan(&s.ID, &s.FirstSeenAt, &s.LastSeenAt, &s.CreatedAt, &s.UpdatedAt)
}

func (r *Secrets) Get(ctx context.Context, id uuid.UUID) (*Secret, error) {
	const q = secretSelect + ` WHERE id = $1`
	return scanSecret(r.pool.QueryRow(ctx, q, id))
}

func (r *Secrets) List(ctx context.Context, f SecretsListFilter) ([]*Secret, error) {
	q, args := buildSecretsQuery(secretSelect, f)
	if f.Limit <= 0 {
		f.Limit = 100
	}
	if f.Limit > 1000 {
		f.Limit = 1000
	}
	args = append(args, f.Limit, f.Offset)
	q += fmt.Sprintf(" ORDER BY cluster_name, secret_ref LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("storage: list secrets: %w", err)
	}
	defer rows.Close()
	var out []*Secret
	for rows.Next() {
		s, err := scanSecret(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *Secrets) Count(ctx context.Context, f SecretsListFilter) (int, error) {
	q, args := buildSecretsQuery(`SELECT COUNT(*) FROM secrets`, f)
	var n int
	if err := r.pool.QueryRow(ctx, q, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("storage: count secrets: %w", err)
	}
	return n, nil
}

func (r *Secrets) ListByRef(ctx context.Context, providerType, secretRef string) ([]*Secret, error) {
	q := secretSelect + " WHERE provider_type = $1 AND secret_ref = $2 ORDER BY cluster_name"
	rows, err := r.pool.Query(ctx, q, providerType, secretRef)
	if err != nil {
		return nil, fmt.Errorf("storage: list secrets by ref: %w", err)
	}
	defer rows.Close()
	var out []*Secret
	for rows.Next() {
		s, err := scanSecret(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *Secrets) MarkStaleAsMissing(ctx context.Context, cutoff time.Time) (int64, error) {
	const q = `
		UPDATE secrets
		SET status = 'missing'
		WHERE status = 'present' AND last_seen_at < $1`
	tag, err := r.pool.Exec(ctx, q, cutoff)
	if err != nil {
		return 0, fmt.Errorf("storage: mark stale missing: %w", err)
	}
	return tag.RowsAffected(), nil
}

// secretSelect is the shared SELECT used by Get and List. Keeping it
// in one place means the scanner stays in lockstep with the columns.
const secretSelect = `
	SELECT id, cluster_name, provider_type, secret_ref,
	       provider_config, labels,
	       COALESCE(version, ''), COALESCE(checksum, ''),
	       created_at_source, updated_at_source,
	       status, first_seen_at, last_seen_at, created_at, updated_at
	FROM secrets`

func scanSecret(row interface {
	Scan(dest ...any) error
}) (*Secret, error) {
	var (
		s       Secret
		cfgRaw  []byte
		lblsRaw []byte
		csrc    *time.Time
		usrc    *time.Time
	)
	err := row.Scan(
		&s.ID, &s.ClusterName, &s.ProviderType, &s.SecretRef,
		&cfgRaw, &lblsRaw,
		&s.Version, &s.Checksum,
		&csrc, &usrc,
		&s.Status, &s.FirstSeenAt, &s.LastSeenAt, &s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("storage: scan secret: %w", err)
	}
	s.CreatedAtSource = csrc
	s.UpdatedAtSource = usrc
	if len(cfgRaw) > 0 {
		_ = json.Unmarshal(cfgRaw, &s.ProviderConfig)
	}
	if len(lblsRaw) > 0 {
		_ = json.Unmarshal(lblsRaw, &s.Labels)
	}
	return &s, nil
}

// buildSecretsQuery composes the WHERE clause and args for a filter.
// Returned query has no LIMIT/OFFSET — callers append those after
// inspecting the args length.
func buildSecretsQuery(base string, f SecretsListFilter) (string, []any) {
	var clauses []string
	var args []any

	add := func(clause string, val any) {
		args = append(args, val)
		clauses = append(clauses, fmt.Sprintf(clause, len(args)))
	}

	if f.ClusterName != "" {
		add("cluster_name = $%d", f.ClusterName)
	}
	if f.ProviderType != "" {
		add("provider_type = $%d", f.ProviderType)
	}
	if f.SecretRefPrefix != "" {
		add("secret_ref LIKE $%d", f.SecretRefPrefix+"%")
	}
	if f.Status != "" {
		add("status = $%d", string(f.Status))
	}
	if len(f.LabelEquals) > 0 {
		// Build a single jsonb containment predicate combining all
		// label-equals pairs. labels @> '{"k1":"v1","k2":"v2"}' is
		// satisfied iff BOTH pairs match, so a single arg suffices.
		merged := map[string]string{}
		for k, v := range f.LabelEquals {
			merged[k] = v
		}
		raw, _ := json.Marshal(merged)
		add("labels @> $%d::jsonb", string(raw))
	}
	if f.SecretIDs != nil {
		// Multi-tenancy gate: non-nil slice restricts results to this
		// id set. An empty slice is a deliberate "no rows" — encode
		// it as `id = ANY('{}'::uuid[])` which always evaluates false.
		add("id = ANY($%d::uuid[])", f.SecretIDs)
	}

	q := base
	if len(clauses) > 0 {
		q += " WHERE " + strings.Join(clauses, " AND ")
	}
	return q, args
}
