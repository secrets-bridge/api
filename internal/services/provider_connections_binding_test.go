// EPIC Q (api#99) Slice Q1 tests — BindForScopedActor +
// UnbindForScopedActor gate chains. One test per locked gate in the
// §3 order so a future regression that swaps gates 4 and 6 fails on
// a specific test name.
//
// Each test bootstraps Postgres + truncates + creates a project,
// non-prod env, prod env, and a couple of connections. The
// stubResolver pattern (cloned from requests_test.go) carries an
// integration.bind grant scoped to either project_id or a team_id
// covering the project.

package services_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

func setupScopedBindEnv(t *testing.T) scopedBindEnv {
	t.Helper()
	dbDSN := os.Getenv("TEST_DATABASE_URL")
	if dbDSN == "" {
		t.Skip("TEST_DATABASE_URL is required; skipping")
	}
	ctx := t.Context()
	cfg := storage.Config{DSN: dbDSN, MaxConns: 5, ConnLifetime: 5 * time.Minute}
	if err := storage.Migrate(ctx, cfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pool, err := storage.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(pool.Close)
	const truncate = `
		TRUNCATE TABLE
			audit_events, sync_runs, sync_jobs, approvals,
			access_requests, secret_mappings, agents,
			project_provider_connections,
			provider_connections, environments, projects
		RESTART IDENTITY CASCADE`
	if _, err := pool.Exec(ctx, truncate); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	// Seed: one project, one non_prod env, one prod env, two connections
	// (one with self_service_bindable=true, one with =false).
	var projectID uuid.UUID
	if err := pool.QueryRow(ctx,
		`INSERT INTO projects (name) VALUES ('p1') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	var nonProdEnvID, prodEnvID uuid.UUID
	if err := pool.QueryRow(ctx,
		`INSERT INTO environments (project_id, name, type, kind, risk_level)
			VALUES ($1, 'dev', 'dev', 'non_prod', 1) RETURNING id`,
		projectID,
	).Scan(&nonProdEnvID); err != nil {
		t.Fatalf("insert non_prod env: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO environments (project_id, name, type, kind, risk_level)
			VALUES ($1, 'prod', 'prod', 'prod', 4) RETURNING id`,
		projectID,
	).Scan(&prodEnvID); err != nil {
		t.Fatalf("insert prod env: %v", err)
	}

	repo := storage.NewProviderConnections(pool)
	envRepo := storage.NewEnvironments(pool)
	bindings := storage.NewProjectProviderConnections(pool)
	audit := storage.NewAuditEvents(pool)

	mustTrue := true
	bindable, err := repo.Create(ctx, storage.ProviderConnectionInput{
		Name:                    "vault-bindable",
		Type:                    storage.ProviderConnectionTypeVault,
		AuthMethod:              "token",
		Scope:                   map[string]string{"address": "https://vault.example.com", "kvMount": "secret"},
		Status:                  storage.ProviderConnectionStatusActive,
		DiscoverIntervalSeconds: 3600,
		SelfServiceBindable:     &mustTrue,
	})
	if err != nil {
		t.Fatalf("create bindable conn: %v", err)
	}
	mustFalse := false
	platformOnly, err := repo.Create(ctx, storage.ProviderConnectionInput{
		Name:                    "vault-platform-only",
		Type:                    storage.ProviderConnectionTypeVault,
		AuthMethod:              "token",
		Scope:                   map[string]string{"address": "https://vault.example.com", "kvMount": "secret"},
		Status:                  storage.ProviderConnectionStatusActive,
		DiscoverIntervalSeconds: 3600,
		SelfServiceBindable:     &mustFalse,
	})
	if err != nil {
		t.Fatalf("create platform-only conn: %v", err)
	}
	disabled, err := repo.Create(ctx, storage.ProviderConnectionInput{
		Name:                    "vault-disabled",
		Type:                    storage.ProviderConnectionTypeVault,
		AuthMethod:              "token",
		Scope:                   map[string]string{"address": "https://vault.example.com", "kvMount": "secret"},
		Status:                  storage.ProviderConnectionStatusDisabled,
		DiscoverIntervalSeconds: 3600,
		SelfServiceBindable:     &mustTrue,
	})
	if err != nil {
		t.Fatalf("create disabled conn: %v", err)
	}

	svc := services.NewProviderConnections(repo, bindings, audit).
		WithEnvironments(envRepo)

	return scopedBindEnv{
		ctx:          ctx,
		pool:         pool,
		repo:         repo,
		bindings:     bindings,
		svc:          svc,
		projectID:    projectID,
		nonProdEnvID: nonProdEnvID,
		prodEnvID:    prodEnvID,
		bindableID:   bindable.ID,
		platformID:   platformOnly.ID,
		disabledID:   disabled.ID,
	}
}

type scopedBindEnv struct {
	ctx          context.Context
	pool         *storage.Pool
	repo         storage.ProviderConnectionRepository
	bindings     storage.ProviderConnectionBindingRepository
	svc          *services.ProviderConnectionsService
	projectID    uuid.UUID
	nonProdEnvID uuid.UUID
	prodEnvID    uuid.UUID
	bindableID   uuid.UUID
	platformID   uuid.UUID
	disabledID   uuid.UUID
}

// withCovers wires the resolver pair so the actor "alice" covers
// the project via a direct integration.bind grant at project scope.
func (e *scopedBindEnv) withCovers(_ *testing.T) *services.ProviderConnectionsService {
	return e.svc.WithBinderScope(
		&stubResolver{grants: []auth.Grant{
			{Permission: string(auth.PermIntegrationBind), Scope: map[string]string{"project_id": e.projectID.String()}},
		}},
		&stubTeamScope{},
	)
}

// withoutCoverage wires a resolver that has the grant but at a
// different project — actor lookups for the test project will miss.
func (e *scopedBindEnv) withoutCoverage(_ *testing.T) *services.ProviderConnectionsService {
	otherProject := uuid.New()
	return e.svc.WithBinderScope(
		&stubResolver{grants: []auth.Grant{
			{Permission: string(auth.PermIntegrationBind), Scope: map[string]string{"project_id": otherProject.String()}},
		}},
		&stubTeamScope{},
	)
}

// --- BIND chain: one test per gate, in order --------------------------

func TestBindForScopedActor_Gate1_EnvNotInProject(t *testing.T) {
	e := setupScopedBindEnv(t)
	// Create a second project + env that belongs to it, then pass the
	// wrong projectID. Service must refuse at gate 1.
	var otherProjectID, otherEnvID uuid.UUID
	if err := e.pool.QueryRow(e.ctx,
		`INSERT INTO projects (name) VALUES ('p2') RETURNING id`,
	).Scan(&otherProjectID); err != nil {
		t.Fatal(err)
	}
	if err := e.pool.QueryRow(e.ctx,
		`INSERT INTO environments (project_id, name, type, kind, risk_level)
			VALUES ($1, 'dev', 'dev', 'non_prod', 1) RETURNING id`,
		otherProjectID,
	).Scan(&otherEnvID); err != nil {
		t.Fatal(err)
	}
	svc := e.withCovers(t)
	_, err := svc.BindForScopedActor(e.ctx, services.BindForScopedActorInput{
		ConnectionID:  e.bindableID,
		ProjectID:     e.projectID, // wrong — env lives in otherProjectID
		EnvironmentID: otherEnvID,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, services.ErrEnvironmentNotInProject) {
		t.Fatalf("want ErrEnvironmentNotInProject, got %v", err)
	}
}

func TestBindForScopedActor_Gate2_OutOfScope_EmitsDeniedAudit(t *testing.T) {
	e := setupScopedBindEnv(t)
	svc := e.withoutCoverage(t)
	_, err := svc.BindForScopedActor(e.ctx, services.BindForScopedActorInput{
		ConnectionID:  e.bindableID,
		ProjectID:     e.projectID,
		EnvironmentID: e.nonProdEnvID,
		ActorID:       "mallory",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, services.ErrOutOfScopeBinding) {
		t.Fatalf("want ErrOutOfScopeBinding, got %v", err)
	}
	// Audit emit verified — security signal lands.
	var count int
	if err := e.pool.QueryRow(e.ctx,
		`SELECT count(*) FROM audit_events WHERE action='binding.denied_out_of_scope' AND actor=$1`,
		"mallory",
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("want 1 binding.denied_out_of_scope event, got %d", count)
	}
	// Per §6: NO provider_connection_id in the denied audit row.
	var hasConn bool
	if err := e.pool.QueryRow(e.ctx,
		`SELECT metadata ? 'provider_connection_id' FROM audit_events WHERE action='binding.denied_out_of_scope' LIMIT 1`,
	).Scan(&hasConn); err != nil {
		t.Fatal(err)
	}
	if hasConn {
		t.Fatalf("denied audit must NOT include provider_connection_id (gate-order protection)")
	}
}

func TestBindForScopedActor_Gate2_RunsBeforeConnectionGates(t *testing.T) {
	// Pass an obviously-bogus ConnectionID. If gate 2 (coverage) runs
	// AFTER connection load, we'd get ErrConnectionNotFound — leaking
	// existence. Correct order: out_of_scope_binding first.
	e := setupScopedBindEnv(t)
	svc := e.withoutCoverage(t)
	bogusConn := uuid.New()
	_, err := svc.BindForScopedActor(e.ctx, services.BindForScopedActorInput{
		ConnectionID:  bogusConn,
		ProjectID:     e.projectID,
		EnvironmentID: e.nonProdEnvID,
		ActorID:       "mallory",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, services.ErrOutOfScopeBinding) {
		t.Fatalf("want ErrOutOfScopeBinding (gate order: project coverage before connection load); got %v", err)
	}
}

func TestBindForScopedActor_Gate3_ProdBlocked(t *testing.T) {
	e := setupScopedBindEnv(t)
	svc := e.withCovers(t)
	_, err := svc.BindForScopedActor(e.ctx, services.BindForScopedActorInput{
		ConnectionID:  e.bindableID,
		ProjectID:     e.projectID,
		EnvironmentID: e.prodEnvID,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, services.ErrProdBindingNotAllowedForScope) {
		t.Fatalf("want ErrProdBindingNotAllowedForScope, got %v", err)
	}
}

func TestBindForScopedActor_Gate4_ConnectionNotFound(t *testing.T) {
	e := setupScopedBindEnv(t)
	svc := e.withCovers(t)
	bogus := uuid.New()
	_, err := svc.BindForScopedActor(e.ctx, services.BindForScopedActorInput{
		ConnectionID:  bogus,
		ProjectID:     e.projectID,
		EnvironmentID: e.nonProdEnvID,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, storage.ErrConnectionNotFound) {
		t.Fatalf("want storage.ErrConnectionNotFound, got %v", err)
	}
}

func TestBindForScopedActor_Gate5_ConnectionDisabled(t *testing.T) {
	e := setupScopedBindEnv(t)
	svc := e.withCovers(t)
	_, err := svc.BindForScopedActor(e.ctx, services.BindForScopedActorInput{
		ConnectionID:  e.disabledID,
		ProjectID:     e.projectID,
		EnvironmentID: e.nonProdEnvID,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, services.ErrConnectionDisabled) {
		t.Fatalf("want ErrConnectionDisabled, got %v", err)
	}
}

func TestBindForScopedActor_Gate6_NotSelfServiceBindable(t *testing.T) {
	e := setupScopedBindEnv(t)
	svc := e.withCovers(t)
	_, err := svc.BindForScopedActor(e.ctx, services.BindForScopedActorInput{
		ConnectionID:  e.platformID,
		ProjectID:     e.projectID,
		EnvironmentID: e.nonProdEnvID,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, services.ErrConnectionNotSelfServiceBindable) {
		t.Fatalf("want ErrConnectionNotSelfServiceBindable, got %v", err)
	}
}

func TestBindForScopedActor_HappyPath_EmitsCreateAudit(t *testing.T) {
	e := setupScopedBindEnv(t)
	svc := e.withCovers(t)
	b, err := svc.BindForScopedActor(e.ctx, services.BindForScopedActorInput{
		ConnectionID:  e.bindableID,
		ProjectID:     e.projectID,
		EnvironmentID: e.nonProdEnvID,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("BindForScopedActor: %v", err)
	}
	if b == nil || b.ProjectID != e.projectID {
		t.Fatalf("binding shape unexpected: %+v", b)
	}
	if b.EnvironmentID == nil || *b.EnvironmentID != e.nonProdEnvID {
		t.Fatalf("environment_id mismatch: got %v want %s", b.EnvironmentID, e.nonProdEnvID)
	}
	// Audit: binding.create, actor_permission_used=integration.bind,
	// self_service_bindable=true, env_kind=non_prod.
	var permUsed, envKind string
	var ssb bool
	if err := e.pool.QueryRow(e.ctx,
		`SELECT metadata->>'actor_permission_used',
		        (metadata->>'self_service_bindable')::bool,
		        metadata->>'env_kind'
		   FROM audit_events
		  WHERE action='binding.create'
		  ORDER BY occurred_at DESC LIMIT 1`,
	).Scan(&permUsed, &ssb, &envKind); err != nil {
		t.Fatal(err)
	}
	if permUsed != string(auth.PermIntegrationBind) || !ssb || envKind != string(storage.EnvironmentKindNonProd) {
		t.Fatalf("audit metadata mismatch: perm=%s ssb=%v env_kind=%s", permUsed, ssb, envKind)
	}
}

func TestBindForScopedActor_Gate7_DuplicateBinding(t *testing.T) {
	e := setupScopedBindEnv(t)
	svc := e.withCovers(t)
	in := services.BindForScopedActorInput{
		ConnectionID:  e.bindableID,
		ProjectID:     e.projectID,
		EnvironmentID: e.nonProdEnvID,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	}
	if _, err := svc.BindForScopedActor(e.ctx, in); err != nil {
		t.Fatalf("first bind: %v", err)
	}
	_, err := svc.BindForScopedActor(e.ctx, in)
	if !errors.Is(err, storage.ErrBindingExists) {
		t.Fatalf("want storage.ErrBindingExists, got %v", err)
	}
}

// --- UNBIND chain: 3 gates, Q7=B (no self_service_bindable re-check) ---

func TestUnbindForScopedActor_Gate1_BindingMissingReturnsNotFound(t *testing.T) {
	e := setupScopedBindEnv(t)
	svc := e.withCovers(t)
	err := svc.UnbindForScopedActor(e.ctx, services.UnbindForScopedActorInput{
		BindingID:     uuid.New(),
		ProjectID:     e.projectID,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, storage.ErrBindingNotFound) {
		t.Fatalf("want storage.ErrBindingNotFound, got %v", err)
	}
}

func TestUnbindForScopedActor_Gate1_WrongProjectMismatchReturnsNotFound(t *testing.T) {
	// Critical §4 correction: project mismatch returns binding_not_found,
	// NOT out_of_scope_binding (latter would leak that the binding
	// exists under another project).
	e := setupScopedBindEnv(t)
	svc := e.withCovers(t)
	b, err := svc.BindForScopedActor(e.ctx, services.BindForScopedActorInput{
		ConnectionID:  e.bindableID,
		ProjectID:     e.projectID,
		EnvironmentID: e.nonProdEnvID,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if err != nil {
		t.Fatal(err)
	}
	otherProject := uuid.New()
	err = svc.UnbindForScopedActor(e.ctx, services.UnbindForScopedActorInput{
		BindingID:     b.ID,
		ProjectID:     otherProject, // mismatch
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, storage.ErrBindingNotFound) {
		t.Fatalf("want storage.ErrBindingNotFound on project mismatch, got %v", err)
	}
}

func TestUnbindForScopedActor_Gate2_OutOfScope(t *testing.T) {
	e := setupScopedBindEnv(t)
	// Create a binding via the covered actor first.
	covered := e.withCovers(t)
	b, err := covered.BindForScopedActor(e.ctx, services.BindForScopedActorInput{
		ConnectionID:  e.bindableID,
		ProjectID:     e.projectID,
		EnvironmentID: e.nonProdEnvID,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Now run unbind with an actor whose grant doesn't cover.
	svc := e.withoutCoverage(t)
	err = svc.UnbindForScopedActor(e.ctx, services.UnbindForScopedActorInput{
		BindingID:     b.ID,
		ProjectID:     e.projectID,
		ActorID:       "mallory",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, services.ErrOutOfScopeBinding) {
		t.Fatalf("want ErrOutOfScopeBinding, got %v", err)
	}
}

func TestUnbindForScopedActor_Gate3_ProdBlocked(t *testing.T) {
	// Insert a prod-env binding directly (the admin path would land
	// this — scoped users can never CREATE one). Then verify scoped
	// unbind refuses with ErrProdBindingNotAllowedForScope.
	e := setupScopedBindEnv(t)
	var bindingID uuid.UUID
	if err := e.pool.QueryRow(e.ctx,
		`INSERT INTO project_provider_connections
			(project_id, environment_id, provider_connection_id, purpose, created_by)
		 VALUES ($1, $2, $3, 'destination', 'platform-admin')
		 RETURNING id`,
		e.projectID, e.prodEnvID, e.bindableID,
	).Scan(&bindingID); err != nil {
		t.Fatal(err)
	}
	svc := e.withCovers(t)
	err := svc.UnbindForScopedActor(e.ctx, services.UnbindForScopedActorInput{
		BindingID:     bindingID,
		ProjectID:     e.projectID,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, services.ErrProdBindingNotAllowedForScope) {
		t.Fatalf("want ErrProdBindingNotAllowedForScope, got %v", err)
	}
}

func TestUnbindForScopedActor_Gate3_ProjectWideBlocked(t *testing.T) {
	// Project-wide bindings (env_id IS NULL) are admin-managed only.
	// Scoped unbind refuses with the prod gate (semantically: scoped
	// users can't reach project-wide bindings either, since they could
	// implicitly affect prod).
	e := setupScopedBindEnv(t)
	var bindingID uuid.UUID
	if err := e.pool.QueryRow(e.ctx,
		`INSERT INTO project_provider_connections
			(project_id, environment_id, provider_connection_id, purpose, created_by)
		 VALUES ($1, NULL, $2, 'destination', 'platform-admin')
		 RETURNING id`,
		e.projectID, e.bindableID,
	).Scan(&bindingID); err != nil {
		t.Fatal(err)
	}
	svc := e.withCovers(t)
	err := svc.UnbindForScopedActor(e.ctx, services.UnbindForScopedActorInput{
		BindingID:     bindingID,
		ProjectID:     e.projectID,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, services.ErrProdBindingNotAllowedForScope) {
		t.Fatalf("want ErrProdBindingNotAllowedForScope on project-wide unbind, got %v", err)
	}
}

func TestUnbindForScopedActor_HappyPath_SkipsSelfServiceBindable(t *testing.T) {
	// Q7=B: scoped unbind is allowed even after platform flips
	// self_service_bindable=false on the connection. Cleanup is
	// always allowed.
	e := setupScopedBindEnv(t)
	svc := e.withCovers(t)
	b, err := svc.BindForScopedActor(e.ctx, services.BindForScopedActorInput{
		ConnectionID:  e.bindableID,
		ProjectID:     e.projectID,
		EnvironmentID: e.nonProdEnvID,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Platform flips self_service_bindable off AFTER the bind.
	if _, err := e.pool.Exec(e.ctx,
		`UPDATE provider_connections SET self_service_bindable=false WHERE id=$1`,
		e.bindableID,
	); err != nil {
		t.Fatal(err)
	}
	// Scoped unbind should still succeed.
	err = svc.UnbindForScopedActor(e.ctx, services.UnbindForScopedActorInput{
		BindingID:     b.ID,
		ProjectID:     e.projectID,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("scoped unbind after flag flip: %v", err)
	}
	// Audit: binding.delete emitted with self_service_bindable=false
	// captured at the time of the unbind.
	var ssb bool
	if err := e.pool.QueryRow(e.ctx,
		`SELECT (metadata->>'self_service_bindable')::bool
		   FROM audit_events
		  WHERE action='binding.delete'
		  ORDER BY occurred_at DESC LIMIT 1`,
	).Scan(&ssb); err != nil {
		t.Fatal(err)
	}
	if ssb {
		t.Fatalf("delete audit should capture current self_service_bindable=false; got true")
	}
}
