package storage_test

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

func bootstrapProjectSecrets(t *testing.T) (*storage.ProjectSecrets, *storage.Projects, *storage.Secrets, *storage.Pool) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required; skipping")
	}
	ctx := t.Context()
	cfg := storage.Config{DSN: dsn, MaxConns: 6, ConnLifetime: 5 * time.Minute}
	if err := storage.Migrate(ctx, cfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pool, err := storage.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(pool.Close)

	// Clear in dependency order: project_secrets references both
	// project + secret. TRUNCATE CASCADE handles the rest.
	if _, err := pool.Exec(ctx,
		"TRUNCATE TABLE project_secrets, projects, secrets RESTART IDENTITY CASCADE",
	); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if _, err := pool.Exec(ctx, "TRUNCATE audit_events"); err != nil {
		t.Fatalf("truncate audit: %v", err)
	}

	return storage.NewProjectSecrets(pool), storage.NewProjects(pool), storage.NewSecrets(pool), pool
}

// seedSecret inserts one row + returns its UUID. The cluster +
// secret_ref tuple is what makes (cluster, provider, secret_ref) unique
// in the schema, so each call gets a distinct ref.
func seedSecret(t *testing.T, secrets *storage.Secrets, ref string) uuid.UUID {
	t.Helper()
	ctx := t.Context()
	s := &storage.Secret{
		ClusterName:  "eks-egov-uat",
		ProviderType: "aws-sm",
		SecretRef:    ref,
		Status:       storage.SecretStatusPresent,
		Labels:       map[string]any{},
	}
	if err := secrets.Upsert(ctx, s); err != nil {
		t.Fatalf("seed secret %q: %v", ref, err)
	}
	return s.ID
}

func seedProject(t *testing.T, projects *storage.Projects, name string) uuid.UUID {
	t.Helper()
	p := &storage.Project{Name: name}
	if err := projects.Create(t.Context(), p); err != nil {
		t.Fatalf("seed project %q: %v", name, err)
	}
	return p.ID
}

func TestBind_HappyPath_AllKeysAllowed(t *testing.T) {
	repo, projects, secrets, _ := bootstrapProjectSecrets(t)
	projectID := seedProject(t, projects, "billing")
	secretID := seedSecret(t, secrets, "/eks/uat/billing/db")

	b := &storage.ProjectSecret{
		ProjectID:   projectID,
		SecretID:    secretID,
		AllowedKeys: nil, // = all
		AllowedOps:  []string{storage.OpRead},
		CreatedBy:   "test",
	}
	if err := repo.Bind(t.Context(), b); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if b.CreatedAt.IsZero() {
		t.Fatal("expected CreatedAt populated")
	}
}

func TestBind_RejectsEmptyAllowedKeys(t *testing.T) {
	repo, projects, secrets, _ := bootstrapProjectSecrets(t)
	projectID := seedProject(t, projects, "billing")
	secretID := seedSecret(t, secrets, "/eks/uat/billing/db")

	b := &storage.ProjectSecret{
		ProjectID:   projectID,
		SecretID:    secretID,
		AllowedKeys: []string{}, // explicit empty — the "block all" trap
		AllowedOps:  []string{storage.OpRead},
	}
	if err := repo.Bind(t.Context(), b); !errors.Is(err, storage.ErrEmptyAllowedKeys) {
		t.Fatalf("expected ErrEmptyAllowedKeys, got %v", err)
	}
}

func TestBind_RejectsEmptyAllowedOps(t *testing.T) {
	repo, projects, secrets, _ := bootstrapProjectSecrets(t)
	projectID := seedProject(t, projects, "billing")
	secretID := seedSecret(t, secrets, "/eks/uat/billing/db")

	b := &storage.ProjectSecret{
		ProjectID:  projectID,
		SecretID:   secretID,
		AllowedOps: nil,
	}
	if err := repo.Bind(t.Context(), b); !errors.Is(err, storage.ErrEmptyAllowedOps) {
		t.Fatalf("expected ErrEmptyAllowedOps, got %v", err)
	}
}

func TestBind_DuplicateReturnsErrAlreadyExists(t *testing.T) {
	repo, projects, secrets, _ := bootstrapProjectSecrets(t)
	projectID := seedProject(t, projects, "billing")
	secretID := seedSecret(t, secrets, "/eks/uat/billing/db")

	first := &storage.ProjectSecret{
		ProjectID: projectID, SecretID: secretID,
		AllowedOps: []string{storage.OpRead},
	}
	if err := repo.Bind(t.Context(), first); err != nil {
		t.Fatalf("first Bind: %v", err)
	}
	second := &storage.ProjectSecret{
		ProjectID: projectID, SecretID: secretID,
		AllowedOps: []string{storage.OpPatch},
	}
	if err := repo.Bind(t.Context(), second); !errors.Is(err, storage.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got %v", err)
	}
}

func TestBind_SameSecretMultipleProjects(t *testing.T) {
	repo, projects, secrets, _ := bootstrapProjectSecrets(t)
	billing := seedProject(t, projects, "billing")
	reporting := seedProject(t, projects, "reporting")
	shared := seedSecret(t, secrets, "/eks/uat/shared/db")

	for _, projID := range []uuid.UUID{billing, reporting} {
		b := &storage.ProjectSecret{
			ProjectID: projID, SecretID: shared,
			AllowedOps: []string{storage.OpRead},
		}
		if err := repo.Bind(t.Context(), b); err != nil {
			t.Fatalf("Bind on %s: %v", projID, err)
		}
	}

	bs, err := repo.ListByProject(t.Context(), billing)
	if err != nil || len(bs) != 1 {
		t.Fatalf("billing bindings: %d %v", len(bs), err)
	}
	bs, err = repo.ListByProject(t.Context(), reporting)
	if err != nil || len(bs) != 1 {
		t.Fatalf("reporting bindings: %d %v", len(bs), err)
	}
}

func TestUpdate_RewritesKeysAndOps(t *testing.T) {
	repo, projects, secrets, _ := bootstrapProjectSecrets(t)
	projectID := seedProject(t, projects, "billing")
	secretID := seedSecret(t, secrets, "/eks/uat/billing/db")

	if err := repo.Bind(t.Context(), &storage.ProjectSecret{
		ProjectID: projectID, SecretID: secretID,
		AllowedOps: []string{storage.OpRead},
	}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := repo.Update(t.Context(), projectID, secretID,
		[]string{"DB_HOST", "DB_PORT"},
		[]string{storage.OpRead, storage.OpPatch}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	b, err := repo.Get(t.Context(), projectID, secretID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(b.AllowedKeys) != 2 || b.AllowedKeys[0] != "DB_HOST" {
		t.Fatalf("AllowedKeys: %v", b.AllowedKeys)
	}
	if len(b.AllowedOps) != 2 {
		t.Fatalf("AllowedOps: %v", b.AllowedOps)
	}
}

func TestUpdate_AbsentBindingReturnsErrNotFound(t *testing.T) {
	repo, projects, secrets, _ := bootstrapProjectSecrets(t)
	projectID := seedProject(t, projects, "billing")
	secretID := seedSecret(t, secrets, "/eks/uat/billing/db")
	if err := repo.Update(t.Context(), projectID, secretID, nil,
		[]string{storage.OpRead}); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestUnbind_DropsRow(t *testing.T) {
	repo, projects, secrets, _ := bootstrapProjectSecrets(t)
	projectID := seedProject(t, projects, "billing")
	secretID := seedSecret(t, secrets, "/eks/uat/billing/db")
	_ = repo.Bind(t.Context(), &storage.ProjectSecret{
		ProjectID: projectID, SecretID: secretID,
		AllowedOps: []string{storage.OpRead},
	})

	if err := repo.Unbind(t.Context(), projectID, secretID); err != nil {
		t.Fatalf("Unbind: %v", err)
	}
	if _, err := repo.Get(t.Context(), projectID, secretID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound post-unbind, got %v", err)
	}
}

func TestListSecretIDsForProjects_UnionsAcrossProjects(t *testing.T) {
	repo, projects, secrets, _ := bootstrapProjectSecrets(t)
	billing := seedProject(t, projects, "billing")
	reporting := seedProject(t, projects, "reporting")

	billDB := seedSecret(t, secrets, "/eks/uat/billing/db")
	billAPI := seedSecret(t, secrets, "/eks/uat/billing/api")
	repDB := seedSecret(t, secrets, "/eks/uat/reporting/db")
	_ = seedSecret(t, secrets, "/eks/uat/orphan/db") // not bound to any project

	for _, b := range []storage.ProjectSecret{
		{ProjectID: billing, SecretID: billDB, AllowedOps: []string{storage.OpRead}},
		{ProjectID: billing, SecretID: billAPI, AllowedOps: []string{storage.OpRead}},
		{ProjectID: reporting, SecretID: repDB, AllowedOps: []string{storage.OpRead}},
	} {
		b := b
		if err := repo.Bind(t.Context(), &b); err != nil {
			t.Fatalf("Bind: %v", err)
		}
	}

	ids, err := repo.ListSecretIDsForProjects(t.Context(), []uuid.UUID{billing, reporting})
	if err != nil {
		t.Fatalf("ListSecretIDsForProjects: %v", err)
	}
	if len(ids) != 3 {
		t.Fatalf("expected 3 bound secrets across both projects, got %d", len(ids))
	}
}

func TestListSecretIDsForProjects_EmptySliceReturnsEmpty(t *testing.T) {
	repo, _, _, _ := bootstrapProjectSecrets(t)
	ids, err := repo.ListSecretIDsForProjects(t.Context(), nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected empty, got %d", len(ids))
	}
}

func TestUnbind_AbsentReturnsErrNotFound(t *testing.T) {
	repo, _, _, _ := bootstrapProjectSecrets(t)
	if err := repo.Unbind(t.Context(),
		uuid.New(), uuid.New()); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
