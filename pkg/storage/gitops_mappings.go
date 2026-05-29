package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// GitOpsAppMapping binds a Secrets Bridge scope (secret_mapping OR
// provider_connection — exactly one) to one or more ArgoCD
// applications. The observation worker resolves an access_request to
// its mapping(s) and polls each application.
type GitOpsAppMapping struct {
	ID                      uuid.UUID
	SecretMappingID         *uuid.UUID
	ProviderConnectionID    *uuid.UUID
	ArgoCDEndpointID        uuid.UUID
	ApplicationName         string
	ApplicationNamespace    string
	ProjectName             string
	ClusterName             string
	Enabled                 bool
	CreatedAt               time.Time
	UpdatedAt               time.Time
	DeletedAt               *time.Time
}

// GitOpsAppMappingRepository is the read/write surface.
type GitOpsAppMappingRepository interface {
	Create(ctx context.Context, m *GitOpsAppMapping) error
	Get(ctx context.Context, id uuid.UUID) (*GitOpsAppMapping, error)
	ListForSecretMapping(ctx context.Context, secretMappingID uuid.UUID) ([]*GitOpsAppMapping, error)
	ListForProviderConnection(ctx context.Context, providerConnID uuid.UUID) ([]*GitOpsAppMapping, error)
	List(ctx context.Context) ([]*GitOpsAppMapping, error)
	SetEnabled(ctx context.Context, id uuid.UUID, enabled bool) error
	SoftDelete(ctx context.Context, id uuid.UUID) error
}

// GitOpsAppMappings is the Postgres impl.
type GitOpsAppMappings struct {
	pool *Pool
}

// NewGitOpsAppMappings binds the repository to the pool.
func NewGitOpsAppMappings(pool *Pool) *GitOpsAppMappings { return &GitOpsAppMappings{pool: pool} }

// Create inserts a new mapping. Schema CHECK enforces exactly one of
// SecretMappingID / ProviderConnectionID; the service layer's input
// validation should catch this earlier.
func (r *GitOpsAppMappings) Create(ctx context.Context, m *GitOpsAppMapping) error {
	if m.ArgoCDEndpointID == uuid.Nil {
		return errors.New("storage: gitops mapping ArgoCDEndpointID required")
	}
	if m.ApplicationName == "" {
		return errors.New("storage: gitops mapping ApplicationName required")
	}
	if (m.SecretMappingID == nil) == (m.ProviderConnectionID == nil) {
		return errors.New("storage: gitops mapping requires exactly one of SecretMappingID or ProviderConnectionID")
	}
	const q = `
		INSERT INTO gitops_app_mappings (
			secret_mapping_id, provider_connection_id, argocd_endpoint_id,
			application_name, application_namespace, project_name, cluster_name, enabled
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, created_at, updated_at`
	row := r.pool.QueryRow(ctx, q,
		m.SecretMappingID, m.ProviderConnectionID, m.ArgoCDEndpointID,
		m.ApplicationName,
		nullString(m.ApplicationNamespace), nullString(m.ProjectName), nullString(m.ClusterName),
		m.Enabled,
	)
	return row.Scan(&m.ID, &m.CreatedAt, &m.UpdatedAt)
}

// Get fetches a mapping by id.
func (r *GitOpsAppMappings) Get(ctx context.Context, id uuid.UUID) (*GitOpsAppMapping, error) {
	const q = baseSelectGitOpsMapping + ` WHERE id = $1`
	return scanGitOpsMapping(r.pool.QueryRow(ctx, q, id))
}

// ListForSecretMapping returns every enabled mapping for the given
// secret_mapping_id. Used at request.transition(executed) to fan out
// observation rows.
func (r *GitOpsAppMappings) ListForSecretMapping(ctx context.Context, smID uuid.UUID) ([]*GitOpsAppMapping, error) {
	const q = baseSelectGitOpsMapping + ` WHERE secret_mapping_id = $1 AND deleted_at IS NULL AND enabled = TRUE ORDER BY application_name`
	return r.runList(ctx, q, smID)
}

// ListForProviderConnection returns every enabled mapping for the
// given provider_connection_id.
func (r *GitOpsAppMappings) ListForProviderConnection(ctx context.Context, pcID uuid.UUID) ([]*GitOpsAppMapping, error) {
	const q = baseSelectGitOpsMapping + ` WHERE provider_connection_id = $1 AND deleted_at IS NULL AND enabled = TRUE ORDER BY application_name`
	return r.runList(ctx, q, pcID)
}

// List returns every active mapping for the admin UI.
func (r *GitOpsAppMappings) List(ctx context.Context) ([]*GitOpsAppMapping, error) {
	const q = baseSelectGitOpsMapping + ` WHERE deleted_at IS NULL ORDER BY application_name`
	return r.runList(ctx, q)
}

// SetEnabled toggles the enabled flag.
func (r *GitOpsAppMappings) SetEnabled(ctx context.Context, id uuid.UUID, enabled bool) error {
	tag, err := r.pool.Exec(ctx, `UPDATE gitops_app_mappings SET enabled = $2 WHERE id = $1 AND deleted_at IS NULL`, id, enabled)
	if err != nil {
		return fmt.Errorf("storage: gitops mapping set enabled: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SoftDelete marks the row deleted.
func (r *GitOpsAppMappings) SoftDelete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `UPDATE gitops_app_mappings SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("storage: gitops mapping soft delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

const baseSelectGitOpsMapping = `
	SELECT id, secret_mapping_id, provider_connection_id, argocd_endpoint_id,
	       application_name,
	       COALESCE(application_namespace, ''), COALESCE(project_name, ''), COALESCE(cluster_name, ''),
	       enabled, created_at, updated_at, deleted_at
	FROM gitops_app_mappings`

func (r *GitOpsAppMappings) runList(ctx context.Context, q string, args ...any) ([]*GitOpsAppMapping, error) {
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("storage: list gitops mappings: %w", err)
	}
	defer rows.Close()
	var out []*GitOpsAppMapping
	for rows.Next() {
		m, err := scanGitOpsMapping(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func scanGitOpsMapping(row pgx.Row) (*GitOpsAppMapping, error) {
	var m GitOpsAppMapping
	err := row.Scan(
		&m.ID, &m.SecretMappingID, &m.ProviderConnectionID, &m.ArgoCDEndpointID,
		&m.ApplicationName,
		&m.ApplicationNamespace, &m.ProjectName, &m.ClusterName,
		&m.Enabled, &m.CreatedAt, &m.UpdatedAt, &m.DeletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("storage: scan gitops mapping: %w", err)
	}
	return &m, nil
}
