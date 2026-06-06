package storage_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// Slice P1 — provider_connections repo tests. Exercises the full
// CRUD surface + the discovery scheduling methods + the canary scan.

// pcInput returns a valid ProviderConnectionInput. Caller mutates
// per-test fields.
func pcInput(name string) storage.ProviderConnectionInput {
	return storage.ProviderConnectionInput{
		Name:       name,
		Type:       storage.ProviderConnectionTypeVault,
		AuthMethod: "token",
		Scope: map[string]string{
			"address": "https://vault.example.com",
			"mount":   "secret",
		},
		Status:                  storage.ProviderConnectionStatusActive,
		ClusterName:             "",
		Description:             "",
		DiscoverEnabled:         false,
		DiscoverIntervalSeconds: 300,
	}
}

func TestProviderConnections_CreateAndGet(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewProviderConnections(pool)

	created, err := repo.Create(ctx, pcInput("vault-prod"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID == uuid.Nil {
		t.Fatal("Create did not populate ID")
	}
	if created.Status != storage.ProviderConnectionStatusActive {
		t.Fatalf("Status = %q want active", created.Status)
	}
	if created.DiscoverIntervalSeconds != 300 {
		t.Fatalf("DiscoverIntervalSeconds = %d want 300", created.DiscoverIntervalSeconds)
	}

	got, err := repo.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "vault-prod" || got.Type != storage.ProviderConnectionTypeVault {
		t.Fatalf("Get returned wrong row: %+v", got)
	}

	byName, err := repo.GetByName(ctx, "vault-prod")
	if err != nil || byName.ID != created.ID {
		t.Fatalf("GetByName: %+v err=%v", byName, err)
	}

	_, err = repo.Get(ctx, uuid.New())
	if !errors.Is(err, storage.ErrConnectionNotFound) {
		t.Fatalf("Get(missing) expected ErrConnectionNotFound, got %v", err)
	}
}

func TestProviderConnections_UniqueName(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewProviderConnections(pool)

	if _, err := repo.Create(ctx, pcInput("dup-name")); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	_, err := repo.Create(ctx, pcInput("dup-name"))
	if !errors.Is(err, storage.ErrConnectionNameTaken) {
		t.Fatalf("dup Create: expected ErrConnectionNameTaken, got %v", err)
	}
}

func TestProviderConnections_Update(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewProviderConnections(pool)

	created, err := repo.Create(ctx, pcInput("vault-orig"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	in := pcInput("vault-renamed")
	in.Description = "rotated 2026"
	in.ClusterName = "prod-eu"
	in.DiscoverEnabled = true
	in.DiscoverIntervalSeconds = 600
	in.Status = storage.ProviderConnectionStatusDisabled

	updated, err := repo.Update(ctx, created.ID, in)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Name != "vault-renamed" {
		t.Fatalf("rename did not apply: %q", updated.Name)
	}
	if updated.Description != "rotated 2026" {
		t.Fatalf("description = %q", updated.Description)
	}
	if !updated.DiscoverEnabled || updated.DiscoverIntervalSeconds != 600 {
		t.Fatalf("discover settings not applied: enabled=%v interval=%d",
			updated.DiscoverEnabled, updated.DiscoverIntervalSeconds)
	}
	if updated.Status != storage.ProviderConnectionStatusDisabled {
		t.Fatalf("Status = %q want disabled", updated.Status)
	}
}

func TestProviderConnections_Update_RenameToTakenNameFails(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewProviderConnections(pool)

	if _, err := repo.Create(ctx, pcInput("a")); err != nil {
		t.Fatalf("Create a: %v", err)
	}
	b, err := repo.Create(ctx, pcInput("b"))
	if err != nil {
		t.Fatalf("Create b: %v", err)
	}

	rename := pcInput("a") // try to rename b → a
	_, err = repo.Update(ctx, b.ID, rename)
	if !errors.Is(err, storage.ErrConnectionNameTaken) {
		t.Fatalf("rename to taken: expected ErrConnectionNameTaken, got %v", err)
	}
}

func TestProviderConnections_DiscoverEnabledRequiresClusterCHECK(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewProviderConnections(pool)

	in := pcInput("requires-cluster")
	in.DiscoverEnabled = true
	in.ClusterName = "" // CHECK should reject
	_, err := repo.Create(ctx, in)
	if err == nil {
		t.Fatal("Create with discover_enabled + no cluster_name: expected CHECK error, got nil")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "discover_requires_cluster") {
		t.Fatalf("expected check constraint error, got: %v", err)
	}
}

func TestProviderConnections_Delete(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewProviderConnections(pool)

	created, err := repo.Create(ctx, pcInput("to-delete"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := repo.Delete(ctx, created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err = repo.Get(ctx, created.ID)
	if !errors.Is(err, storage.ErrConnectionNotFound) {
		t.Fatalf("Get(deleted): %v", err)
	}
	err = repo.Delete(ctx, created.ID)
	if !errors.Is(err, storage.ErrConnectionNotFound) {
		t.Fatalf("double-Delete: %v", err)
	}
}

func TestProviderConnections_DeleteRestrictedByBinding(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewProviderConnections(pool)
	bindings := storage.NewProjectProviderConnections(pool)

	created, err := repo.Create(ctx, pcInput("in-use"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	project := makeProject(t, pool, "p-rest")
	_, err = bindings.Bind(ctx, storage.ProjectProviderConnectionBindingInput{
		ProjectID:            project,
		ProviderConnectionID: created.ID,
		Purpose:              storage.ProjectProviderConnectionPurposeDestination,
		CreatedBy:            "admin",
	})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}

	err = repo.Delete(ctx, created.ID)
	if !errors.Is(err, storage.ErrConnectionInUse) {
		t.Fatalf("Delete with binding: expected ErrConnectionInUse, got %v", err)
	}
}

func TestProviderConnections_Exists(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewProviderConnections(pool)

	created, err := repo.Create(ctx, pcInput("does-exist"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	ok, err := repo.Exists(ctx, created.ID)
	if err != nil || !ok {
		t.Fatalf("Exists(known) = %v err=%v want true", ok, err)
	}
	ok, err = repo.Exists(ctx, uuid.New())
	if err != nil || ok {
		t.Fatalf("Exists(unknown) = %v err=%v want false", ok, err)
	}
}

func TestProviderConnections_List_FilterByTypeStatus(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewProviderConnections(pool)

	v1, _ := repo.Create(ctx, pcInput("vault-a"))
	v2, _ := repo.Create(ctx, pcInput("vault-b"))
	if v1 == nil || v2 == nil {
		t.Fatal("setup")
	}
	awsIn := pcInput("aws-x")
	awsIn.Type = storage.ProviderConnectionTypeAWSSM
	awsIn.AuthMethod = "default"
	awsIn.Scope = map[string]string{"region": "us-east-1"}
	if _, err := repo.Create(ctx, awsIn); err != nil {
		t.Fatalf("Create aws: %v", err)
	}

	got, err := repo.List(ctx, storage.ProviderConnectionListFilter{Type: "vault"})
	if err != nil || len(got) != 2 {
		t.Fatalf("List(type=vault) = %d err=%v", len(got), err)
	}
}

func TestProviderConnections_ListDueForDiscovery(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewProviderConnections(pool)
	now := time.Now()

	// (a) never-discovered, eligible — should appear, NULLS FIRST
	a := pcInput("a-due")
	a.DiscoverEnabled = true
	a.ClusterName = "c1"
	a.DiscoverIntervalSeconds = 60
	created, err := repo.Create(ctx, a)
	if err != nil {
		t.Fatalf("create a: %v", err)
	}

	// (b) discovered 200s ago + interval 60 → overdue, should appear
	b := pcInput("b-overdue")
	b.DiscoverEnabled = true
	b.ClusterName = "c1"
	b.DiscoverIntervalSeconds = 60
	bRow, _ := repo.Create(ctx, b)
	if err := repo.MarkDiscoverFinished(ctx, bRow.ID, storage.DiscoverStatusSuccess, "", now.Add(-200*time.Second)); err != nil {
		t.Fatalf("mark b: %v", err)
	}

	// (c) discovered 10s ago + interval 60 → not yet due, should skip
	c := pcInput("c-fresh")
	c.DiscoverEnabled = true
	c.ClusterName = "c1"
	c.DiscoverIntervalSeconds = 60
	cRow, _ := repo.Create(ctx, c)
	if err := repo.MarkDiscoverFinished(ctx, cRow.ID, storage.DiscoverStatusSuccess, "", now.Add(-10*time.Second)); err != nil {
		t.Fatalf("mark c: %v", err)
	}

	// (d) discover_enabled = false — excluded
	d := pcInput("d-disabled-discover")
	d.DiscoverEnabled = false
	if _, err := repo.Create(ctx, d); err != nil {
		t.Fatalf("create d: %v", err)
	}

	// (e) status = disabled — excluded even though discover_enabled = true.
	// CHECK requires cluster_name; supply one then disable.
	e := pcInput("e-conn-disabled")
	e.DiscoverEnabled = true
	e.ClusterName = "c1"
	eRow, err := repo.Create(ctx, e)
	if err != nil {
		t.Fatalf("create e: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE provider_connections SET status='disabled' WHERE id=$1`, eRow.ID); err != nil {
		t.Fatalf("disable e: %v", err)
	}

	targets, err := repo.ListDueForDiscovery(ctx, now)
	if err != nil {
		t.Fatalf("ListDueForDiscovery: %v", err)
	}
	gotNames := make(map[string]bool)
	for _, t := range targets {
		gotNames[t.Name] = true
	}
	if !gotNames["a-due"] || !gotNames["b-overdue"] {
		t.Fatalf("expected a-due + b-overdue in result: %v", gotNames)
	}
	if gotNames["c-fresh"] || gotNames["d-disabled-discover"] || gotNames["e-conn-disabled"] {
		t.Fatalf("ineligible row returned: %v", gotNames)
	}

	// NULLS FIRST ordering: a (never discovered) comes before b (200s ago)
	if targets[0].Name != "a-due" {
		t.Fatalf("NULLS FIRST: expected a-due first, got %q", targets[0].Name)
	}
	_ = created
}

func TestProviderConnections_MarkDiscoverFinished_RejectsRunning(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewProviderConnections(pool)

	in := pcInput("p-mark")
	in.DiscoverEnabled = true
	in.ClusterName = "c1"
	created, err := repo.Create(ctx, in)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	err = repo.MarkDiscoverFinished(ctx, created.ID,
		storage.DiscoverStatusRunning, "", time.Now())
	if !errors.Is(err, storage.ErrInvalidDiscoverStatus) {
		t.Fatalf("running: expected ErrInvalidDiscoverStatus, got %v", err)
	}
}

func TestProviderConnections_MarkDiscoverLifecycle(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewProviderConnections(pool)

	in := pcInput("p-life")
	in.DiscoverEnabled = true
	in.ClusterName = "c1"
	created, err := repo.Create(ctx, in)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	startedAt := time.Now()
	if err := repo.MarkDiscoverStarted(ctx, created.ID, startedAt); err != nil {
		t.Fatalf("Started: %v", err)
	}
	mid, err := repo.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get mid: %v", err)
	}
	if mid.LastDiscoverStatus != storage.DiscoverStatusRunning {
		t.Fatalf("status mid = %q want running", mid.LastDiscoverStatus)
	}

	finishedAt := startedAt.Add(time.Second)
	if err := repo.MarkDiscoverFinished(ctx, created.ID,
		storage.DiscoverStatusSuccess, "", finishedAt); err != nil {
		t.Fatalf("Finished: %v", err)
	}
	done, err := repo.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get done: %v", err)
	}
	if done.LastDiscoverStatus != storage.DiscoverStatusSuccess {
		t.Fatalf("status done = %q want success", done.LastDiscoverStatus)
	}
	if done.LastDiscoverError != "" {
		t.Fatalf("error should be cleared on success: %q", done.LastDiscoverError)
	}
}

// Canary: the scope JSONB column MUST never hold credential-shaped
// substrings. The service layer (P2) enforces this on write; this
// test scans every row across the package's test corpus on read.
// A failure means a test (or service layer regression) let a
// credential land in scope.
func TestStorage_ProviderConnections_ScopeNeverHoldsCredentialShapedValues(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewProviderConnections(pool)

	// Seed a handful of rows with legitimate metadata.
	for _, name := range []string{"canary-1", "canary-2", "canary-3"} {
		if _, err := repo.Create(ctx, pcInput(name)); err != nil {
			t.Fatalf("Create %s: %v", name, err)
		}
	}

	// Scan ALL provider_connections rows + last_discover_error for
	// credential-shaped substrings.
	canaries := []string{
		`AKIA[A-Z0-9]{16}`,    // AWS access key prefix
		`hvs\.[A-Z0-9]{20,}`,  // Vault token prefix
		`eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}`, // JWT
		`ya29\.[A-Za-z0-9_-]+`, // OAuth token
	}
	for _, pattern := range canaries {
		var hit int
		if err := pool.QueryRow(ctx, `
SELECT count(*) FROM provider_connections
WHERE scope::text ~ $1 OR coalesce(last_discover_error, '') ~ $1
`, pattern).Scan(&hit); err != nil {
			t.Fatalf("canary query %q: %v", pattern, err)
		}
		if hit > 0 {
			t.Fatalf("canary hit %d row(s) for pattern %q — a credential-shaped substring landed in scope or last_discover_error", hit, pattern)
		}
	}
}
