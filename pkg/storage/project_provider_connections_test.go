package storage_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// Slice P1 — project_provider_connections repo tests. Exercises the
// bind/unbind surface + the load-bearing partial unique indexes
// (env-specific vs project-wide) + CASCADE on project/env delete +
// RESTRICT on provider_connection delete + ListForProjectEnv branch
// logic (env-specific + project-wide bindings).

func makeProvConnP1(t *testing.T, pool *storage.Pool, name string) uuid.UUID {
	t.Helper()
	pc, err := storage.NewProviderConnections(pool).Create(t.Context(), pcInput(name))
	if err != nil {
		t.Fatalf("create provider_connection: %v", err)
	}
	return pc.ID
}

func makeEnvP1(t *testing.T, pool *storage.Pool, projectID uuid.UUID, name string) uuid.UUID {
	t.Helper()
	var envID uuid.UUID
	err := pool.QueryRow(t.Context(),
		`INSERT INTO environments (project_id, name, type, kind, risk_level)
		 VALUES ($1, $2, 'uat', 'non_prod', 1) RETURNING id`,
		projectID, name,
	).Scan(&envID)
	if err != nil {
		t.Fatalf("create env: %v", err)
	}
	return envID
}

func TestProjectProviderConnections_BindAndGet(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewProjectProviderConnections(pool)

	projectID := makeProject(t, pool, "p-bind")
	connID := makeProvConnP1(t, pool, "pc-bind")

	b, err := repo.Bind(ctx, storage.ProjectProviderConnectionBindingInput{
		ProjectID:            projectID,
		ProviderConnectionID: connID,
		Purpose:              storage.ProjectProviderConnectionPurposeDestination,
		CreatedBy:            "alice",
	})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if b.ID == uuid.Nil {
		t.Fatal("Bind did not populate ID")
	}
	if b.EnvironmentID != nil {
		t.Fatalf("env_id should be NULL for project-wide bind: %v", b.EnvironmentID)
	}
	if b.CreatedBy != "alice" {
		t.Fatalf("created_by = %q want alice", b.CreatedBy)
	}

	got, err := repo.GetBinding(ctx, b.ID)
	if err != nil || got.ID != b.ID {
		t.Fatalf("GetBinding: %+v err=%v", got, err)
	}
}

func TestProjectProviderConnections_BindWithEnv(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewProjectProviderConnections(pool)

	projectID := makeProject(t, pool, "p-env")
	connID := makeProvConnP1(t, pool, "pc-env")
	envID := makeEnvP1(t, pool, projectID, "prod")

	b, err := repo.Bind(ctx, storage.ProjectProviderConnectionBindingInput{
		ProjectID:            projectID,
		EnvironmentID:        &envID,
		ProviderConnectionID: connID,
		Purpose:              storage.ProjectProviderConnectionPurposeDestination,
	})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if b.EnvironmentID == nil || *b.EnvironmentID != envID {
		t.Fatalf("env_id not set: %v", b.EnvironmentID)
	}
}

func TestProjectProviderConnections_PartialUnique_EnvSpecific(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewProjectProviderConnections(pool)

	projectID := makeProject(t, pool, "p-uniq-env")
	connID := makeProvConnP1(t, pool, "pc-uniq-env")
	envID := makeEnvP1(t, pool, projectID, "prod")

	in := storage.ProjectProviderConnectionBindingInput{
		ProjectID:            projectID,
		EnvironmentID:        &envID,
		ProviderConnectionID: connID,
		Purpose:              storage.ProjectProviderConnectionPurposeDestination,
	}
	if _, err := repo.Bind(ctx, in); err != nil {
		t.Fatalf("first Bind: %v", err)
	}
	_, err := repo.Bind(ctx, in)
	if !errors.Is(err, storage.ErrBindingExists) {
		t.Fatalf("duplicate env-specific Bind: expected ErrBindingExists, got %v", err)
	}
}

// Load-bearing: PG treats NULL ≠ NULL for uniqueness, so a single
// UNIQUE (project_id, environment_id, provider_connection_id, purpose)
// would let two NULL-env bindings co-exist. The migration creates
// TWO partial unique indexes — this test pins the project-wide branch.
func TestProjectProviderConnections_PartialUnique_ProjectWide(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewProjectProviderConnections(pool)

	projectID := makeProject(t, pool, "p-uniq-wide")
	connID := makeProvConnP1(t, pool, "pc-uniq-wide")

	in := storage.ProjectProviderConnectionBindingInput{
		ProjectID:            projectID,
		EnvironmentID:        nil,
		ProviderConnectionID: connID,
		Purpose:              storage.ProjectProviderConnectionPurposeDestination,
	}
	if _, err := repo.Bind(ctx, in); err != nil {
		t.Fatalf("first project-wide Bind: %v", err)
	}
	_, err := repo.Bind(ctx, in)
	if !errors.Is(err, storage.ErrBindingExists) {
		t.Fatalf("duplicate project-wide Bind: expected ErrBindingExists, got %v", err)
	}
}

// One env-specific + one project-wide binding for the same
// (project, connection, purpose) MUST both be allowed — they're
// distinct rows under the two partial unique indexes.
func TestProjectProviderConnections_EnvAndProjectWideCoexist(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewProjectProviderConnections(pool)

	projectID := makeProject(t, pool, "p-coexist")
	connID := makeProvConnP1(t, pool, "pc-coexist")
	envID := makeEnvP1(t, pool, projectID, "prod")

	if _, err := repo.Bind(ctx, storage.ProjectProviderConnectionBindingInput{
		ProjectID: projectID, EnvironmentID: &envID, ProviderConnectionID: connID,
		Purpose: storage.ProjectProviderConnectionPurposeDestination,
	}); err != nil {
		t.Fatalf("env-specific Bind: %v", err)
	}
	if _, err := repo.Bind(ctx, storage.ProjectProviderConnectionBindingInput{
		ProjectID: projectID, EnvironmentID: nil, ProviderConnectionID: connID,
		Purpose: storage.ProjectProviderConnectionPurposeDestination,
	}); err != nil {
		t.Fatalf("project-wide Bind alongside env-specific: %v", err)
	}
}

func TestProjectProviderConnections_Unbind(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewProjectProviderConnections(pool)

	projectID := makeProject(t, pool, "p-unbind")
	connID := makeProvConnP1(t, pool, "pc-unbind")

	b, err := repo.Bind(ctx, storage.ProjectProviderConnectionBindingInput{
		ProjectID: projectID, ProviderConnectionID: connID,
		Purpose: storage.ProjectProviderConnectionPurposeDestination,
	})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := repo.Unbind(ctx, b.ID); err != nil {
		t.Fatalf("Unbind: %v", err)
	}
	err = repo.Unbind(ctx, b.ID)
	if !errors.Is(err, storage.ErrBindingNotFound) {
		t.Fatalf("double Unbind: expected ErrBindingNotFound, got %v", err)
	}
}

func TestProjectProviderConnections_CascadeOnProjectDelete(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewProjectProviderConnections(pool)

	projectID := makeProject(t, pool, "p-cascade")
	connID := makeProvConnP1(t, pool, "pc-cascade")

	b, err := repo.Bind(ctx, storage.ProjectProviderConnectionBindingInput{
		ProjectID: projectID, ProviderConnectionID: connID,
		Purpose: storage.ProjectProviderConnectionPurposeDestination,
	})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM projects WHERE id = $1`, projectID); err != nil {
		t.Fatalf("delete project: %v", err)
	}
	_, err = repo.GetBinding(ctx, b.ID)
	if !errors.Is(err, storage.ErrBindingNotFound) {
		t.Fatalf("binding should CASCADE-disappear: got %v", err)
	}
}

func TestProjectProviderConnections_CascadeOnEnvDelete(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewProjectProviderConnections(pool)

	projectID := makeProject(t, pool, "p-cascade-env")
	connID := makeProvConnP1(t, pool, "pc-cascade-env")
	envID := makeEnvP1(t, pool, projectID, "prod")

	b, err := repo.Bind(ctx, storage.ProjectProviderConnectionBindingInput{
		ProjectID: projectID, EnvironmentID: &envID, ProviderConnectionID: connID,
		Purpose: storage.ProjectProviderConnectionPurposeDestination,
	})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM environments WHERE id = $1`, envID); err != nil {
		t.Fatalf("delete env: %v", err)
	}
	_, err = repo.GetBinding(ctx, b.ID)
	if !errors.Is(err, storage.ErrBindingNotFound) {
		t.Fatalf("binding should CASCADE-disappear: got %v", err)
	}
}

func TestProjectProviderConnections_ListForProjectEnv_EnvSpecificAndProjectWide(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewProjectProviderConnections(pool)

	projectID := makeProject(t, pool, "p-list")
	envProd := makeEnvP1(t, pool, projectID, "prod")
	envUat := makeEnvP1(t, pool, projectID, "uat")

	pcEnv := makeProvConnP1(t, pool, "pc-env-only")    // env-specific to prod
	pcWide := makeProvConnP1(t, pool, "pc-project")    // project-wide
	pcOther := makeProvConnP1(t, pool, "pc-other-env") // env-specific to uat

	_, _ = repo.Bind(ctx, storage.ProjectProviderConnectionBindingInput{
		ProjectID: projectID, EnvironmentID: &envProd, ProviderConnectionID: pcEnv,
		Purpose: storage.ProjectProviderConnectionPurposeDestination,
	})
	_, _ = repo.Bind(ctx, storage.ProjectProviderConnectionBindingInput{
		ProjectID: projectID, EnvironmentID: nil, ProviderConnectionID: pcWide,
		Purpose: storage.ProjectProviderConnectionPurposeDestination,
	})
	_, _ = repo.Bind(ctx, storage.ProjectProviderConnectionBindingInput{
		ProjectID: projectID, EnvironmentID: &envUat, ProviderConnectionID: pcOther,
		Purpose: storage.ProjectProviderConnectionPurposeDestination,
	})

	got, err := repo.ListForProjectEnv(ctx, projectID, envProd)
	if err != nil {
		t.Fatalf("ListForProjectEnv: %v", err)
	}
	names := make(map[string]bool)
	for _, s := range got {
		names[s.Name] = true
	}
	if !names["pc-env-only"] {
		t.Fatal("env-specific binding for prod missing from result")
	}
	if !names["pc-project"] {
		t.Fatal("project-wide binding missing from result")
	}
	if names["pc-other-env"] {
		t.Fatal("uat env-specific binding leaked into prod query")
	}
}

func TestProjectProviderConnections_ListForProjectEnv_ExcludesDisabled(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewProjectProviderConnections(pool)
	pcRepo := storage.NewProviderConnections(pool)

	projectID := makeProject(t, pool, "p-disabled")
	envID := makeEnvP1(t, pool, projectID, "prod")
	connID := makeProvConnP1(t, pool, "pc-will-disable")

	if _, err := repo.Bind(ctx, storage.ProjectProviderConnectionBindingInput{
		ProjectID: projectID, EnvironmentID: &envID, ProviderConnectionID: connID,
		Purpose: storage.ProjectProviderConnectionPurposeDestination,
	}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	// Disable the connection — even though binding is intact, it
	// must NOT appear in the dropdown.
	upd := pcInput("pc-will-disable")
	upd.Status = storage.ProviderConnectionStatusDisabled
	if _, err := pcRepo.Update(ctx, connID, upd); err != nil {
		t.Fatalf("Update disable: %v", err)
	}

	got, err := repo.ListForProjectEnv(ctx, projectID, envID)
	if err != nil {
		t.Fatalf("ListForProjectEnv: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("disabled connection leaked into dropdown: %+v", got)
	}
}

func TestProjectProviderConnections_ListForProjectEnv_EmptyReturnsEmptySlice(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewProjectProviderConnections(pool)

	projectID := makeProject(t, pool, "p-empty")
	envID := makeEnvP1(t, pool, projectID, "prod")
	got, err := repo.ListForProjectEnv(ctx, projectID, envID)
	if err != nil {
		t.Fatalf("ListForProjectEnv: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty slice, got %+v", got)
	}
}
