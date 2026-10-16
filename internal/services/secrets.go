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
	"errors"
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

	// Agent identity for the agent-side upload. Both nil unless
	// WithAgentIdentity is called; UpsertForAgent refuses without them.
	agents    DiscoveryAgentLookup
	provConns AgentProviderConnectionLookup
}

// DiscoveryAgentLookup is the slice of the agents repository discovery
// needs: the admin projection (cluster_name, provider_type, bound
// connection) and the legacy row with its scope.
type DiscoveryAgentLookup interface {
	Get(ctx context.Context, id uuid.UUID) (*storage.Agent, error)
	GetAdmin(ctx context.Context, id uuid.UUID) (*storage.AgentAdminRow, error)
}

// WithAgentIdentity wires the lookups UpsertForAgent uses to pin a
// discovery batch to the uploading agent's own cluster + provider type.
// Returns the service for chaining.
func (s *SecretsService) WithAgentIdentity(agents DiscoveryAgentLookup, provConns AgentProviderConnectionLookup) *SecretsService {
	s.agents = agents
	s.provConns = provConns
	return s
}

// Discovery identity sentinels. Both map to HTTP 403.
var (
	// ErrDiscoveryIdentityMismatch: the batch names a cluster or provider
	// type that is not the uploading agent's own.
	ErrDiscoveryIdentityMismatch = errors.New("services: discovery batch does not match the agent's cluster or provider")
	// ErrDiscoveryIdentityUnknown: the agent's record carries no cluster
	// or no provider type to pin the batch to (including an enrolled
	// agent whose connection was deleted).
	ErrDiscoveryIdentityUnknown = errors.New("services: agent has no cluster or provider identity for discovery")
	// ErrDiscoveryConnectionDisabled: the agent's bound connection is
	// disabled. Enroll and discover-now refuse it too.
	ErrDiscoveryConnectionDisabled = errors.New("services: agent's provider connection is disabled")
)

// UpsertForAgent is the agent-side discovery upload. cluster_name and
// provider_type are not taken from the batch: they come from the
// authenticated agent's own record, so one agent cannot write or
// overwrite catalog rows (keyed by cluster, provider, ref) that belong
// to another agent's cluster or provider.
//
//   - cluster: the bound provider connection's cluster_name, which an
//     admin set. Never agents.cluster_name: that is whatever the agent
//     declared at enroll, checked only against an optional
//     expected_cluster_name on the token. A legacy minted agent (no
//     bound connection) uses its admin-set scope.cluster.
//   - provider type: the bound provider connection's type, else a legacy
//     agent's scope.provider / scope.providers.
//
// A disabled connection refuses (ErrDiscoveryConnectionDisabled), the
// same as enroll and discover-now.
//
// A batch that names a different cluster or provider type is refused
// (ErrDiscoveryIdentityMismatch); an omitted cluster_name is filled in.
// An agent whose record yields no cluster or no provider type cannot
// upload (ErrDiscoveryIdentityUnknown). Refusals are audited.
func (s *SecretsService) UpsertForAgent(ctx context.Context, agentID uuid.UUID, in BulkInput) (*BulkResult, error) {
	actor := "agent:" + agentID.String()
	cluster, providers, err := s.agentDiscoveryIdentity(ctx, agentID)
	if err != nil {
		switch {
		case errors.Is(err, ErrDiscoveryIdentityUnknown):
			s.auditDiscoveryRefused(ctx, actor, "agent_identity_unknown")
		case errors.Is(err, ErrDiscoveryConnectionDisabled):
			s.auditDiscoveryRefused(ctx, actor, "connection_disabled")
		}
		return nil, err
	}
	if in.ClusterName != "" && in.ClusterName != cluster {
		s.auditDiscoveryRefused(ctx, actor, "cluster_mismatch")
		return nil, ErrDiscoveryIdentityMismatch
	}
	providerType := in.ProviderType
	if providerType == "" && len(providers) == 1 {
		providerType = providers[0]
	}
	if !stringIn(providers, providerType) {
		s.auditDiscoveryRefused(ctx, actor, "provider_type_mismatch")
		return nil, ErrDiscoveryIdentityMismatch
	}
	in.ClusterName = cluster
	in.ProviderType = providerType
	return s.Upsert(ctx, actor, in)
}

// agentDiscoveryIdentity resolves the cluster and the provider types an
// agent may publish discovery for. See UpsertForAgent for the order.
func (s *SecretsService) agentDiscoveryIdentity(ctx context.Context, agentID uuid.UUID) (string, []string, error) {
	if s.agents == nil || s.provConns == nil {
		return "", nil, errors.New("services: discovery agent identity not configured")
	}
	row, err := s.agents.GetAdmin(ctx, agentID)
	if err != nil {
		return "", nil, fmt.Errorf("services: load agent for discovery: %w", err)
	}
	agent, err := s.agents.Get(ctx, agentID)
	if err != nil {
		return "", nil, fmt.Errorf("services: load agent for discovery: %w", err)
	}

	var cluster string
	var providers []string
	if row.ProviderConnectionID != nil {
		// Enrolled agent: both come from the bound connection. A
		// connection with no cluster_name leaves the agent without a
		// discovery identity rather than falling back to its own claim.
		conn, err := s.provConns.Get(ctx, *row.ProviderConnectionID)
		if errors.Is(err, storage.ErrConnectionNotFound) {
			return "", nil, ErrDiscoveryIdentityUnknown
		}
		if err != nil {
			return "", nil, fmt.Errorf("services: load agent provider connection: %w", err)
		}
		if conn.Status == storage.ProviderConnectionStatusDisabled {
			return "", nil, ErrDiscoveryConnectionDisabled
		}
		cluster = conn.ClusterName
		providers = []string{string(conn.Type)}
	} else {
		// No bound connection: a legacy minted agent, whose cluster and
		// provider an admin put in its scope. agents.cluster_name and
		// provider_type are only ever written at enroll, so an agent with
		// those set and no connection had its connection deleted
		// (ON DELETE SET NULL); its own claim is not trusted here either.
		cluster, _ = agent.Scope["cluster"].(string)
		providers = scopeProviders(agent.Scope)
	}
	if cluster == "" || len(providers) == 0 {
		return "", nil, ErrDiscoveryIdentityUnknown
	}
	return cluster, providers, nil
}

// scopeProviders reads a legacy minted agent's scope.provider (string)
// and scope.providers (list of strings). Anything else is ignored.
func scopeProviders(scope map[string]any) []string {
	var out []string
	if p, ok := scope["provider"].(string); ok && p != "" {
		out = append(out, p)
	}
	if list, ok := scope["providers"].([]any); ok {
		for _, v := range list {
			if p, ok := v.(string); ok && p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

func stringIn(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// auditDiscoveryRefused records a metadata-only denial: actor + reason
// code, never the batch's claimed values or any ref.
func (s *SecretsService) auditDiscoveryRefused(ctx context.Context, actor, reason string) {
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    actor,
		Action:   "discovery.upsert",
		Resource: actor,
		Status:   storage.AuditStatusDenied,
		Metadata: map[string]any{"reason": reason},
	})
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
