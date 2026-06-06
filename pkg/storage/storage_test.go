package storage_test

// Integration tests against a live PostgreSQL. To run locally:
//
//   make compose-up      # or: docker compose up -d postgres
//   export TEST_DATABASE_URL=postgres://secrets_bridge:devpass@localhost:5432/secrets_bridge_test?sslmode=disable
//   go test -count=1 ./pkg/storage/...
//
// In CI, GitHub Actions exposes a postgres service container via the
// same env var. When TEST_DATABASE_URL is unset, the suite SKIPs every
// test rather than failing — keeps `go test ./...` ergonomic on a
// laptop without docker.

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

func testCfg(t *testing.T) storage.Config {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping storage integration tests")
	}
	return storage.Config{
		DSN:          dsn,
		MaxConns:     5,
		ConnLifetime: 5 * time.Minute,
	}
}

// freshDB opens a pool, runs migrations up to head, and truncates every
// data table so each test starts from a clean slate. Returns the pool;
// cleanup happens via t.Cleanup.
func freshDB(t *testing.T) *storage.Pool {
	t.Helper()
	cfg := testCfg(t)
	ctx := t.Context()

	if err := storage.Migrate(ctx, cfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pool, err := storage.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(pool.Close)

	// TRUNCATE every data table. audit_events has a no-delete trigger
	// but TRUNCATE doesn't fire row-level triggers, so it bypasses the
	// rule cleanly — that's the standard "test wipe" pattern.
	const truncate = `
		TRUNCATE TABLE
			audit_events,
			reveal_sessions,
			sync_runs,
			sync_jobs,
			approvals,
			access_requests,
			secret_mappings,
			agents,
			provider_connections,
			environments,
			projects,
			team_members,
			teams,
			local_users
		RESTART IDENTITY CASCADE`
	if _, err := pool.Exec(ctx, truncate); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	// EPIC R (api#108) — migration 0033 added a FK from policy_rules to
	// projects with ON DELETE CASCADE. TRUNCATE projects CASCADE walks
	// that FK and wipes the seed match-all rule from migration 0005.
	// Re-seed it so storage tests that depend on the platform default
	// (e.g. cross_team_test's snap_policy_rule_id) always see it.
	const reseedSystemPolicy = `
		INSERT INTO policy_rules
			(name, selector, workflow_id, priority, is_system)
		SELECT
			'match-all (system default)',
			'{}'::jsonb,
			(SELECT id FROM workflow_definitions WHERE name = 'standard'),
			0,
			true
		WHERE NOT EXISTS (SELECT 1 FROM policy_rules WHERE name = 'match-all (system default)');
	`
	if _, err := pool.Exec(ctx, reseedSystemPolicy); err != nil {
		t.Fatalf("reseed match-all: %v", err)
	}
	return pool
}

func TestMigrate_Idempotent(t *testing.T) {
	cfg := testCfg(t)
	ctx := t.Context()
	if err := storage.Migrate(ctx, cfg); err != nil {
		t.Fatalf("first Migrate: %v", err)
	}
	if err := storage.Migrate(ctx, cfg); err != nil {
		t.Fatalf("second Migrate (should be no-op): %v", err)
	}
	v, dirty, err := storage.Version(ctx, cfg)
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if dirty {
		t.Fatal("schema reported as dirty after a clean migrate")
	}
	if v == 0 {
		t.Fatal("schema version is 0 after migrating up")
	}
}

func TestProjects_CRUDLifecycle(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewProjects(pool)

	created := &storage.Project{Name: "secrets-bridge", OwnerTeamID: "platform"}
	if err := repo.Create(ctx, created); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID == uuid.Nil {
		t.Fatal("Create did not populate ID")
	}
	if created.Status != storage.ProjectStatusActive {
		t.Fatalf("default Status: %q", created.Status)
	}

	got, err := repo.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "secrets-bridge" || got.OwnerTeamID != "platform" {
		t.Fatalf("Get returned wrong row: %+v", got)
	}

	byName, err := repo.GetByName(ctx, "secrets-bridge")
	if err != nil || byName.ID != created.ID {
		t.Fatalf("GetByName: %+v err=%v", byName, err)
	}

	_, err = repo.Get(ctx, uuid.New())
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("Get(missing) expected ErrNotFound, got %v", err)
	}

	if err := repo.UpdateStatus(ctx, created.ID, storage.ProjectStatusArchived); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}
	got, _ = repo.Get(ctx, created.ID)
	if got.Status != storage.ProjectStatusArchived {
		t.Fatalf("status after update: %q", got.Status)
	}

	if err := repo.UpdateStatus(ctx, uuid.New(), storage.ProjectStatusActive); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("UpdateStatus(missing) expected ErrNotFound, got %v", err)
	}

	all, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 1 || all[0].ID != created.ID {
		t.Fatalf("List: %+v", all)
	}
}

func TestProjects_RejectsDuplicateName(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewProjects(pool)

	if err := repo.Create(ctx, &storage.Project{Name: "dup"}); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	err := repo.Create(ctx, &storage.Project{Name: "dup"})
	if err == nil {
		t.Fatal("duplicate name was accepted; expected a unique-constraint violation")
	}
}

func TestAuditEvents_AppendAndQuery(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewAuditEvents(pool)

	corr := uuid.New()

	for i, action := range []string{"projects.create", "agents.register", "requests.approve"} {
		evt := &storage.AuditEvent{
			Actor:         "user:alice",
			Action:        action,
			Resource:      "project:demo",
			Status:        storage.AuditStatusSuccess,
			CorrelationID: corr,
			Metadata:      map[string]any{"i": i},
		}
		if err := repo.Append(ctx, evt); err != nil {
			t.Fatalf("Append #%d: %v", i, err)
		}
		if evt.ID == uuid.Nil {
			t.Fatalf("Append #%d did not populate ID", i)
		}
	}

	byCorrelation, err := repo.Query(ctx, storage.AuditQuery{CorrelationID: corr})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(byCorrelation) != 3 {
		t.Fatalf("Query by correlation: got %d events, want 3", len(byCorrelation))
	}
	// Query returns DESC by occurred_at — the last-appended action
	// must appear first.
	if byCorrelation[0].Action != "requests.approve" {
		t.Fatalf("expected first result to be the latest event; got %+v", byCorrelation[0])
	}

	byActor, err := repo.Query(ctx, storage.AuditQuery{Actor: "user:alice", Limit: 2})
	if err != nil {
		t.Fatalf("Query by actor: %v", err)
	}
	if len(byActor) != 2 {
		t.Fatalf("Limit not honoured: got %d events, want 2", len(byActor))
	}
}

// CLAUDE.md hard rule: audit_events is append-only. Verify the schema
// trigger actually rejects UPDATE and DELETE — a CHECK or repository
// guard alone wouldn't be enough.
func TestAuditEvents_TableIsAppendOnly(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewAuditEvents(pool)

	evt := &storage.AuditEvent{Actor: "x", Action: "y", Resource: "z"}
	if err := repo.Append(ctx, evt); err != nil {
		t.Fatalf("Append: %v", err)
	}

	_, updateErr := pool.Exec(ctx, `UPDATE audit_events SET action='tampered' WHERE id=$1`, evt.ID)
	if updateErr == nil || !strings.Contains(updateErr.Error(), "append-only") {
		t.Fatalf("UPDATE on audit_events was not rejected; err=%v", updateErr)
	}

	_, deleteErr := pool.Exec(ctx, `DELETE FROM audit_events WHERE id=$1`, evt.ID)
	if deleteErr == nil || !strings.Contains(deleteErr.Error(), "append-only") {
		t.Fatalf("DELETE on audit_events was not rejected; err=%v", deleteErr)
	}
}

func TestAuditEvents_AppendValidatesRequiredFields(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewAuditEvents(pool)

	cases := []*storage.AuditEvent{
		{Action: "x", Resource: "y"},     // missing Actor
		{Actor: "x", Resource: "y"},      // missing Action
		{Actor: "x", Action: "y"},        // missing Resource
	}
	for i, evt := range cases {
		if err := repo.Append(ctx, evt); err == nil {
			t.Fatalf("case %d: expected validation error, got nil", i)
		}
	}
}

func TestEnvironments_CRUDLifecycle(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	projects := storage.NewProjects(pool)
	envs := storage.NewEnvironments(pool)

	proj := &storage.Project{Name: "archive"}
	if err := projects.Create(ctx, proj); err != nil {
		t.Fatalf("Project Create: %v", err)
	}

	created := &storage.Environment{ProjectID: proj.ID, Name: "uat", Type: storage.EnvironmentTypeUAT}
	if err := envs.Create(ctx, created); err != nil {
		t.Fatalf("Env Create: %v", err)
	}
	if created.ID == uuid.Nil {
		t.Fatal("Create did not populate ID")
	}

	got, err := envs.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "uat" || got.Type != storage.EnvironmentTypeUAT || got.ProjectID != proj.ID {
		t.Fatalf("Get returned wrong row: %+v", got)
	}

	_, err = envs.Get(ctx, uuid.New())
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("Get(missing) expected ErrNotFound, got %v", err)
	}

	// Second env under the same project.
	prod := &storage.Environment{ProjectID: proj.ID, Name: "prod", Type: storage.EnvironmentTypeProd}
	if err := envs.Create(ctx, prod); err != nil {
		t.Fatalf("prod Create: %v", err)
	}

	byProject, err := envs.ListByProject(ctx, proj.ID)
	if err != nil {
		t.Fatalf("ListByProject: %v", err)
	}
	if len(byProject) != 2 {
		t.Fatalf("ListByProject: want 2 envs, got %d", len(byProject))
	}

	all, err := envs.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("List: want 2 envs, got %d", len(all))
	}

	if err := envs.Delete(ctx, created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := envs.Delete(ctx, created.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("Delete(missing) expected ErrNotFound, got %v", err)
	}
}

func TestEnvironments_RejectsDuplicateWithinProject(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	projects := storage.NewProjects(pool)
	envs := storage.NewEnvironments(pool)

	proj := &storage.Project{Name: "archive"}
	if err := projects.Create(ctx, proj); err != nil {
		t.Fatalf("Project Create: %v", err)
	}

	if err := envs.Create(ctx, &storage.Environment{ProjectID: proj.ID, Name: "uat", Type: storage.EnvironmentTypeUAT}); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	err := envs.Create(ctx, &storage.Environment{ProjectID: proj.ID, Name: "uat", Type: storage.EnvironmentTypeUAT})
	if !errors.Is(err, storage.ErrDuplicateName) {
		t.Fatalf("duplicate Create: want ErrDuplicateName, got %v", err)
	}
}

func TestEnvironments_AllowsSameNameAcrossProjects(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	projects := storage.NewProjects(pool)
	envs := storage.NewEnvironments(pool)

	for _, name := range []string{"archive", "elite"} {
		if err := projects.Create(ctx, &storage.Project{Name: name}); err != nil {
			t.Fatalf("Project Create %q: %v", name, err)
		}
	}
	all, _ := projects.List(ctx)
	if len(all) != 2 {
		t.Fatalf("projects: %d", len(all))
	}

	// Both projects get an env named "uat" — should NOT collide.
	for _, p := range all {
		if err := envs.Create(ctx, &storage.Environment{ProjectID: p.ID, Name: "uat", Type: storage.EnvironmentTypeUAT}); err != nil {
			t.Fatalf("Create env for %s: %v", p.Name, err)
		}
	}
}
