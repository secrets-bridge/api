package storage_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// makeProject inserts a minimal projects row so an environments FK can
// resolve. Returns the new UUID.
func makeProject(t *testing.T, pool *storage.Pool, name string) uuid.UUID {
	t.Helper()
	repo := storage.NewProjects(pool)
	p := &storage.Project{Name: name}
	if err := repo.Create(t.Context(), p); err != nil {
		t.Fatalf("makeProject %q: %v", name, err)
	}
	return p.ID
}

func TestEnvironments_CreateDerivesKindFromType(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewEnvironments(pool)
	ctx := t.Context()
	projectID := makeProject(t, pool, "kind-derive")

	cases := []struct {
		name     string
		envType  storage.EnvironmentType
		wantKind storage.EnvironmentKind
	}{
		{"dev", storage.EnvironmentTypeDev, storage.EnvironmentKindNonProd},
		{"staging", storage.EnvironmentTypeStaging, storage.EnvironmentKindNonProd},
		{"uat", storage.EnvironmentTypeUAT, storage.EnvironmentKindNonProd},
		{"prod", storage.EnvironmentTypeProd, storage.EnvironmentKindProd},
		{"other", storage.EnvironmentTypeOther, storage.EnvironmentKindNonProd},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := &storage.Environment{
				ProjectID: projectID,
				Name:      tc.name,
				Type:      tc.envType,
			}
			if err := repo.Create(ctx, e); err != nil {
				t.Fatalf("Create: %v", err)
			}
			got, err := repo.Get(ctx, e.ID)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if got.Kind != tc.wantKind {
				t.Errorf("Kind: got %q want %q", got.Kind, tc.wantKind)
			}
			if got.RiskLevel != 1 {
				t.Errorf("RiskLevel default: got %d want 1", got.RiskLevel)
			}
			if got.Description != "" {
				t.Errorf("Description: got %q want empty", got.Description)
			}
		})
	}
}

func TestEnvironments_ExplicitKindOverridesType(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewEnvironments(pool)
	ctx := t.Context()
	projectID := makeProject(t, pool, "kind-override")

	// Operator marks a `staging` lifecycle env as kind=prod because it
	// carries customer-look-alike data. The override holds — the
	// derivation only kicks in when Kind is blank.
	e := &storage.Environment{
		ProjectID:   projectID,
		Name:        "staging-but-prod",
		Type:        storage.EnvironmentTypeStaging,
		Kind:        storage.EnvironmentKindProd,
		RiskLevel:   4,
		Description: "Mirrors prod data; treat as prod.",
	}
	if err := repo.Create(ctx, e); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := repo.Get(ctx, e.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Kind != storage.EnvironmentKindProd {
		t.Errorf("Kind override lost: got %q want prod", got.Kind)
	}
	if got.Type != storage.EnvironmentTypeStaging {
		t.Errorf("Type changed: got %q want staging", got.Type)
	}
	if got.RiskLevel != 4 {
		t.Errorf("RiskLevel: got %d want 4", got.RiskLevel)
	}
	if got.Description != "Mirrors prod data; treat as prod." {
		t.Errorf("Description: got %q", got.Description)
	}
}

func TestEnvironments_Update_MutatesDescriptionAndRisk_KindImmutable(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewEnvironments(pool)
	ctx := t.Context()
	projectID := makeProject(t, pool, "kind-immutable")

	e := &storage.Environment{
		ProjectID: projectID,
		Name:      "uat-1",
		Type:      storage.EnvironmentTypeUAT,
	}
	if err := repo.Create(ctx, e); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := repo.Update(ctx, e.ID, "tier-2 customer support env", 3); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, err := repo.Get(ctx, e.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Description != "tier-2 customer support env" {
		t.Errorf("Description: got %q", got.Description)
	}
	if got.RiskLevel != 3 {
		t.Errorf("RiskLevel: got %d want 3", got.RiskLevel)
	}
	// Kind MUST NOT change — Update can't touch it. The Get also
	// confirms scanEnvironment keeps the column round-tripped.
	if got.Kind != storage.EnvironmentKindNonProd {
		t.Errorf("Kind drift: got %q want non_prod", got.Kind)
	}

	// Updated-at advances.
	if !got.UpdatedAt.After(got.CreatedAt) {
		t.Errorf("UpdatedAt did not advance: %v vs %v", got.UpdatedAt, got.CreatedAt)
	}
}

func TestEnvironments_Update_ClearDescription(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewEnvironments(pool)
	ctx := t.Context()
	projectID := makeProject(t, pool, "clear-desc")

	e := &storage.Environment{
		ProjectID:   projectID,
		Name:        "uat-with-note",
		Type:        storage.EnvironmentTypeUAT,
		Description: "initial note",
	}
	if err := repo.Create(ctx, e); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Empty description should land as SQL NULL via NULLIF; Get
	// returns "" via COALESCE.
	if err := repo.Update(ctx, e.ID, "", 2); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, _ := repo.Get(ctx, e.ID)
	if got.Description != "" {
		t.Errorf("Description not cleared: got %q", got.Description)
	}
}

func TestEnvironments_Update_NotFound(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewEnvironments(pool)
	ctx := t.Context()

	err := repo.Update(ctx, uuid.New(), "x", 1)
	if !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("got %v want ErrNotFound", err)
	}
}

func TestEnvironments_RiskLevelOutOfRangeRejected(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewEnvironments(pool)
	ctx := t.Context()
	projectID := makeProject(t, pool, "risk-range")

	e := &storage.Environment{
		ProjectID: projectID,
		Name:      "bad-risk",
		Type:      storage.EnvironmentTypeUAT,
		RiskLevel: 9, // schema CHECK 0-4
	}
	err := repo.Create(ctx, e)
	if err == nil {
		t.Fatal("Create with risk_level=9 should have failed (CHECK 0..4)")
	}
}

func TestEnvironments_DuplicateNameWithinProject(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewEnvironments(pool)
	ctx := t.Context()
	projectID := makeProject(t, pool, "dup-name")

	a := &storage.Environment{ProjectID: projectID, Name: "uat", Type: storage.EnvironmentTypeUAT}
	if err := repo.Create(ctx, a); err != nil {
		t.Fatalf("Create a: %v", err)
	}
	b := &storage.Environment{ProjectID: projectID, Name: "uat", Type: storage.EnvironmentTypeUAT}
	err := repo.Create(ctx, b)
	if !errors.Is(err, storage.ErrDuplicateName) {
		t.Errorf("got %v want ErrDuplicateName", err)
	}
}

func TestEnvironments_ListByProjectOrdered(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewEnvironments(pool)
	ctx := t.Context()
	projectID := makeProject(t, pool, "list-ordered")

	for _, name := range []string{"prod", "uat", "dev"} {
		envType := storage.EnvironmentType(name)
		if name == "uat" {
			envType = storage.EnvironmentTypeUAT
		}
		if err := repo.Create(ctx, &storage.Environment{
			ProjectID: projectID, Name: name, Type: envType,
		}); err != nil {
			t.Fatalf("Create %q: %v", name, err)
		}
	}

	got, err := repo.ListByProject(ctx, projectID)
	if err != nil {
		t.Fatalf("ListByProject: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("ListByProject: got %d want 3", len(got))
	}
	wantOrder := []string{"dev", "prod", "uat"}
	for i, name := range wantOrder {
		if got[i].Name != name {
			t.Errorf("position %d: got %q want %q", i, got[i].Name, name)
		}
	}
	// kind derivation on List path matches Get.
	for _, e := range got {
		want := storage.EnvironmentKindNonProd
		if e.Name == "prod" {
			want = storage.EnvironmentKindProd
		}
		if e.Kind != want {
			t.Errorf("%q kind: got %q want %q", e.Name, e.Kind, want)
		}
	}
}
