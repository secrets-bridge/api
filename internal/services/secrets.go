// Package services — secrets.go: discovery surface.
//
// SecretsService is a thin orchestrator over the storage layer. The
// agent posts batches of discovered secrets via the agent-side bulk
// endpoint; admins read the cache via GET /api/v1/secrets.
//
// NO secret values flow through this service. Every field is
// metadata-only: cluster, provider, ref, labels, version, checksum.
package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// SecretsService is the discovery orchestrator.
type SecretsService struct {
	secrets storage.SecretRepository
	audit   storage.AuditEventRepository
	now     func() time.Time
}

// NewSecretsService binds the service to its dependencies.
func NewSecretsService(secrets storage.SecretRepository, audit storage.AuditEventRepository) *SecretsService {
	return &SecretsService{
		secrets: secrets,
		audit:   audit,
		now:     time.Now,
	}
}

// BulkInput describes one discovery batch posted by an agent. The
// outer envelope carries the connection identity (cluster, provider,
// config) so individual entries don't have to repeat it.
type BulkInput struct {
	ClusterName    string
	ProviderType   string
	ProviderConfig map[string]any
	Items          []BulkItem
}

// BulkItem is one secret in a discovery batch.
type BulkItem struct {
	SecretRef       string
	Labels          map[string]any
	Version         string
	Checksum        string
	CreatedAtSource *time.Time
	UpdatedAtSource *time.Time
}

// BulkResult summarises what changed after the upsert. UpsertedIDs is
// in the same order as the input Items so the agent can correlate.
type BulkResult struct {
	UpsertedIDs []string
	Count       int
}

// Upsert persists each item via the storage repo's UPSERT and emits
// a single discovery.upsert audit row capturing the batch.
func (s *SecretsService) Upsert(ctx context.Context, agentActor string, in BulkInput) (*BulkResult, error) {
	if in.ClusterName == "" || in.ProviderType == "" {
		return nil, fmt.Errorf("%w: cluster_name and provider_type required", ErrInvalidInput)
	}
	if len(in.Items) == 0 {
		return &BulkResult{}, nil
	}

	ids := make([]string, 0, len(in.Items))
	for i, item := range in.Items {
		if item.SecretRef == "" {
			return nil, fmt.Errorf("%w: items[%d].secret_ref empty", ErrInvalidInput, i)
		}
		row := &storage.Secret{
			ClusterName:     in.ClusterName,
			ProviderType:    in.ProviderType,
			ProviderConfig:  in.ProviderConfig,
			SecretRef:       item.SecretRef,
			Labels:          item.Labels,
			Version:         item.Version,
			Checksum:        item.Checksum,
			CreatedAtSource: item.CreatedAtSource,
			UpdatedAtSource: item.UpdatedAtSource,
		}
		if err := s.secrets.Upsert(ctx, row); err != nil {
			return nil, fmt.Errorf("services: upsert items[%d]: %w", i, err)
		}
		ids = append(ids, row.ID.String())
	}

	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    agentActor,
		Action:   "discovery.upsert",
		Resource: "cluster:" + in.ClusterName,
		Status:   storage.AuditStatusSuccess,
		Metadata: map[string]any{
			"provider_type": in.ProviderType,
			"count":         len(in.Items),
		},
	})
	return &BulkResult{UpsertedIDs: ids, Count: len(in.Items)}, nil
}

// List returns secrets matching the filter.
func (s *SecretsService) List(ctx context.Context, f storage.SecretsListFilter) ([]*storage.Secret, error) {
	return s.secrets.List(ctx, f)
}

// Count returns the total matching the filter, ignoring pagination.
func (s *SecretsService) Count(ctx context.Context, f storage.SecretsListFilter) (int, error) {
	return s.secrets.Count(ctx, f)
}

// Get returns one secret by id.
func (s *SecretsService) Get(ctx context.Context, id string) (*storage.Secret, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("%w: id is not a uuid", ErrInvalidInput)
	}
	return s.secrets.Get(ctx, parsed)
}
