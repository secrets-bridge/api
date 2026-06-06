// EPIC Q Slice Q1 (api#100) — scoped self-service binding paths.
//
// BindForScopedActor + UnbindForScopedActor are the integration.bind
// surface. They run the LOCKED gate chains from the §3 sign-off:
//
//   Bind:
//     1. environment_id resolves to a row in the target project
//     2. actor covers (project, env) via EffectiveProjectAccess
//     3. environment.kind != 'prod'
//     4. connection exists
//     5. connection.status = 'active'
//     6. connection.self_service_bindable = true
//     7. no existing binding for the pair
//     8. INSERT + emit binding.create audit
//
//   Unbind (Q7=B: skips self_service_bindable, enforces scope + non-prod):
//     1. binding exists + binding.project_id == URL projectID
//        (mismatch returns ErrBindingNotFound — never leaks existence)
//     2. actor covers (binding.project, binding.env) via EffectiveProjectAccess
//     3. binding env.kind != 'prod'
//     4. DELETE + emit binding.delete audit
//
// The ORDER is enumeration-leak-safe: a scoped probe of any connection
// ID through the bind endpoint without coverage of the target project
// returns out_of_scope_binding at step 2 — connection state never
// leaks. This is the §3 correction baked into code.
//
// The platform-admin Bind / Unbind methods stay in provider_connections.go
// untouched. Two methods, not one, because the gates are fundamentally
// different and conflating them invites a future "simplification" that
// silently drops a safety check.

package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/pkg/storage"
)

// BindForScopedActorInput is the shape the integration.bind handler
// (api#101) hands the service. environment_id is REQUIRED — scoped
// users cannot create project-wide bindings per §4 correction.
type BindForScopedActorInput struct {
	ConnectionID  uuid.UUID
	ProjectID     uuid.UUID
	EnvironmentID uuid.UUID
	Purpose       storage.ProjectProviderConnectionPurpose
	ActorID       string
	CorrelationID uuid.UUID
}

// UnbindForScopedActorInput carries the URL projectID so the service
// can validate binding.project_id == URL projectID. The mismatch case
// returns ErrBindingNotFound (NOT ErrOutOfScopeBinding) per §4 —
// the latter would leak that the binding exists under another project.
type UnbindForScopedActorInput struct {
	BindingID     uuid.UUID
	ProjectID     uuid.UUID
	ActorID       string
	CorrelationID uuid.UUID
}

// BindForScopedActor runs the 7-gate chain locked at §3 and returns
// the binding on success. Wraps the audit emission so the handler
// only deals with the result + sentinel.
func (s *ProviderConnectionsService) BindForScopedActor(ctx context.Context, in BindForScopedActorInput) (*storage.ProjectProviderConnectionBinding, error) {
	if s.environments == nil || s.binderResolver == nil {
		return nil, errors.New("services: scoped bind path requires WithEnvironments + WithBinderScope wiring")
	}

	// Gate 1 — env exists in project.
	env, err := s.environments.Get(ctx, in.EnvironmentID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrEnvironmentNotInProject
		}
		return nil, fmt.Errorf("services: load environment: %w", err)
	}
	if env.ProjectID != in.ProjectID {
		return nil, ErrEnvironmentNotInProject
	}

	// Gate 2 — actor covers (project, env). Audit the denial because
	// it's an SoD-adjacent security signal worth platform's attention.
	access, err := auth.EffectiveProjectAccess(ctx, in.ActorID, auth.PermIntegrationBind, s.binderResolver, s.binderTeamScope)
	if err != nil {
		return nil, fmt.Errorf("services: resolve scoped binder access: %w", err)
	}
	if !projectAccessCovers(access, in.ProjectID) {
		s.auditDeniedOutOfScope(ctx, in.ActorID, in.ProjectID, in.EnvironmentID, in.CorrelationID)
		return nil, ErrOutOfScopeBinding
	}

	// Gate 3 — env.kind != 'prod' (scoped binders never bind prod).
	if env.Kind == storage.EnvironmentKindProd {
		return nil, ErrProdBindingNotAllowedForScope
	}

	// Gates 4–6 — connection exists, active, self-service-bindable.
	active, ssb, err := s.repo.Bindable(ctx, in.ConnectionID)
	if err != nil {
		if errors.Is(err, storage.ErrConnectionNotFound) {
			return nil, storage.ErrConnectionNotFound
		}
		return nil, fmt.Errorf("services: read bindable: %w", err)
	}
	if !active {
		return nil, ErrConnectionDisabled
	}
	if !ssb {
		return nil, ErrConnectionNotSelfServiceBindable
	}

	// Gate 7 — no existing binding (env-specific OR project-wide).
	// The binding repo's Bind will catch this too via the unique
	// indexes, but pre-checking gives the stable error code without
	// translating a 23505.
	envID := in.EnvironmentID
	binding, err := s.bindings.Bind(ctx, storage.ProjectProviderConnectionBindingInput{
		ProjectID:            in.ProjectID,
		EnvironmentID:        &envID,
		ProviderConnectionID: in.ConnectionID,
		Purpose:              defaultBindingPurpose(in.Purpose),
		CreatedBy:            in.ActorID,
	})
	if err != nil {
		return nil, err
	}

	// Gate 8 — emit binding.create.
	s.auditBindingCreate(ctx, in.ActorID, binding, in.CorrelationID, auth.PermIntegrationBind, ssb, string(env.Kind))
	return binding, nil
}

// UnbindForScopedActor runs the 3-gate chain locked at §3 Q7=B.
// No self_service_bindable re-check (unbind is cleanup; scoped users
// own their existing bindings even if platform later flipped the flag).
func (s *ProviderConnectionsService) UnbindForScopedActor(ctx context.Context, in UnbindForScopedActorInput) error {
	if s.environments == nil || s.binderResolver == nil {
		return errors.New("services: scoped unbind path requires WithEnvironments + WithBinderScope wiring")
	}

	// Gate 1 — binding exists AND binding.project_id == URL projectID.
	// Mismatch returns ErrBindingNotFound — never leaks that the
	// binding lives under another project.
	binding, err := s.bindings.GetBinding(ctx, in.BindingID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return storage.ErrBindingNotFound
		}
		return fmt.Errorf("services: load binding: %w", err)
	}
	if binding.ProjectID != in.ProjectID {
		return storage.ErrBindingNotFound
	}

	// Gate 2 — actor covers (binding.project, binding.env).
	access, err := auth.EffectiveProjectAccess(ctx, in.ActorID, auth.PermIntegrationBind, s.binderResolver, s.binderTeamScope)
	if err != nil {
		return fmt.Errorf("services: resolve scoped binder access: %w", err)
	}
	if !projectAccessCovers(access, binding.ProjectID) {
		envIDForAudit := uuid.Nil
		if binding.EnvironmentID != nil {
			envIDForAudit = *binding.EnvironmentID
		}
		s.auditDeniedOutOfScope(ctx, in.ActorID, binding.ProjectID, envIDForAudit, in.CorrelationID)
		return ErrOutOfScopeBinding
	}

	// Gate 3 — env.kind != 'prod'. Scoped users cannot unbind
	// project-wide bindings either (env_id is NULL for those;
	// platform-managed).
	if binding.EnvironmentID == nil {
		return ErrProdBindingNotAllowedForScope
	}
	env, err := s.environments.Get(ctx, *binding.EnvironmentID)
	if err != nil {
		return fmt.Errorf("services: load binding env: %w", err)
	}
	if env.Kind == storage.EnvironmentKindProd {
		return ErrProdBindingNotAllowedForScope
	}

	// Best-effort read of the connection's current self_service_bindable
	// flag for the audit. Per §6 correction: include when available,
	// omit when not — never fail the unbind on a missing connection
	// row.
	ssb := false
	if active, b, err := s.repo.Bindable(ctx, binding.ProviderConnectionID); err == nil {
		_ = active
		ssb = b
	}

	if err := s.bindings.Unbind(ctx, in.BindingID); err != nil {
		return err
	}
	s.auditBindingDelete(ctx, in.ActorID, binding, in.CorrelationID, auth.PermIntegrationBind, ssb, string(env.Kind))
	return nil
}

// projectAccessCovers returns whether the resolved ProjectAccess covers
// the target projectID. Global access wins; otherwise the project must
// appear in the resolved set.
func projectAccessCovers(access auth.ProjectAccess, target uuid.UUID) bool {
	if access.IsGlobal {
		return true
	}
	for _, id := range access.ProjectIDs {
		if id == target {
			return true
		}
	}
	return false
}

func defaultBindingPurpose(p storage.ProjectProviderConnectionPurpose) storage.ProjectProviderConnectionPurpose {
	if p == "" {
		return storage.ProjectProviderConnectionPurposeDestination
	}
	return p
}

// ---- audit emission ------------------------------------------------

func (s *ProviderConnectionsService) auditBindingCreate(
	ctx context.Context,
	actorID string,
	b *storage.ProjectProviderConnectionBinding,
	correlationID uuid.UUID,
	permUsed auth.Permission,
	selfServiceBindable bool,
	envKind string,
) {
	envIDMeta := ""
	if b.EnvironmentID != nil {
		envIDMeta = b.EnvironmentID.String()
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:         actorOrAdmin(actorID),
		Action:        "binding.create",
		Resource:      "provider_connection_binding:" + b.ID.String(),
		Status:        storage.AuditStatusSuccess,
		CorrelationID: correlationID,
		Metadata: map[string]any{
			"provider_connection_id": b.ProviderConnectionID.String(),
			"binding_id":             b.ID.String(),
			"project_id":             b.ProjectID.String(),
			"environment_id":         envIDMeta,
			"actor_permission_used":  string(permUsed),
			"self_service_bindable":  selfServiceBindable,
			"env_kind":               envKind,
		},
	})
}

func (s *ProviderConnectionsService) auditBindingDelete(
	ctx context.Context,
	actorID string,
	b *storage.ProjectProviderConnectionBinding,
	correlationID uuid.UUID,
	permUsed auth.Permission,
	selfServiceBindable bool,
	envKind string,
) {
	envIDMeta := ""
	if b.EnvironmentID != nil {
		envIDMeta = b.EnvironmentID.String()
	}
	meta := map[string]any{
		"provider_connection_id": b.ProviderConnectionID.String(),
		"binding_id":             b.ID.String(),
		"project_id":             b.ProjectID.String(),
		"environment_id":         envIDMeta,
		"actor_permission_used":  string(permUsed),
		"env_kind":               envKind,
	}
	// Include self_service_bindable ONLY when we could read it
	// successfully — never fail the audit on a missing connection.
	// envKind is always present (we just dereferenced env to get here).
	meta["self_service_bindable"] = selfServiceBindable
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:         actorOrAdmin(actorID),
		Action:        "binding.delete",
		Resource:      "provider_connection_binding:" + b.ID.String(),
		Status:        storage.AuditStatusSuccess,
		CorrelationID: correlationID,
		Metadata:      meta,
	})
}

// auditDeniedOutOfScope emits the security-signal event. Per §6
// correction: NO provider_connection_id field (gate-order protection —
// the actor hasn't passed coverage yet, so even logging connection_id
// would defeat the leak prevention).
func (s *ProviderConnectionsService) auditDeniedOutOfScope(
	ctx context.Context,
	actorID string,
	projectID uuid.UUID,
	envID uuid.UUID,
	correlationID uuid.UUID,
) {
	envIDMeta := ""
	if envID != uuid.Nil {
		envIDMeta = envID.String()
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:         actorOrAdmin(actorID),
		Action:        "binding.denied_out_of_scope",
		Resource:      "project:" + projectID.String(),
		Status:        storage.AuditStatusFailure,
		CorrelationID: correlationID,
		Metadata: map[string]any{
			"attempted_project_id":      projectID.String(),
			"attempted_environment_id":  envIDMeta,
			"actor_permission_attempted": string(auth.PermIntegrationBind),
		},
	})
}
