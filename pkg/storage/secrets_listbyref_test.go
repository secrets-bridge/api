package storage_test

import (
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

func bootstrapSecretsRepo(t *testing.T) *storage.Secrets {
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

	if _, err := pool.Exec(ctx, "TRUNCATE TABLE secrets RESTART IDENTITY CASCADE"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return storage.NewSecrets(pool)
}

func TestSecrets_ListByRef_MultipleClusters(t *testing.T) {
	repo := bootstrapSecretsRepo(t)
	ctx := t.Context()

	// Same secret_ref on two clusters — Slice C's lookup has to find
	// both rows so the binding check can hit any matching project.
	a := &storage.Secret{
		ClusterName: "eks-egov-uat", ProviderType: "aws-sm",
		SecretRef: "/eks/uat/billing/db", Status: storage.SecretStatusPresent,
		Labels: map[string]any{},
	}
	b := &storage.Secret{
		ClusterName: "eks-egov-prod", ProviderType: "aws-sm",
		SecretRef: "/eks/uat/billing/db", Status: storage.SecretStatusPresent,
		Labels: map[string]any{},
	}
	for _, s := range []*storage.Secret{a, b} {
		if err := repo.Upsert(ctx, s); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}

	rows, err := repo.ListByRef(ctx, "aws-sm", "/eks/uat/billing/db")
	if err != nil {
		t.Fatalf("ListByRef: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 matching rows across clusters, got %d", len(rows))
	}
	// Ordered by cluster_name for stable assertions.
	if rows[0].ClusterName != "eks-egov-prod" || rows[1].ClusterName != "eks-egov-uat" {
		t.Fatalf("expected ORDER BY cluster_name, got [%s, %s]",
			rows[0].ClusterName, rows[1].ClusterName)
	}
}

func TestSecrets_ListByRef_NoMatchReturnsEmpty(t *testing.T) {
	repo := bootstrapSecretsRepo(t)
	rows, err := repo.ListByRef(t.Context(), "aws-sm", "/eks/uat/nonexistent")
	if err != nil {
		t.Fatalf("ListByRef: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("expected 0 rows, got %d", len(rows))
	}
}

func TestSecrets_List_SecretIDsRestrictsToSet(t *testing.T) {
	repo := bootstrapSecretsRepo(t)
	ctx := t.Context()

	keep := &storage.Secret{
		ClusterName: "c1", ProviderType: "aws-sm",
		SecretRef: "/eks/uat/keep", Status: storage.SecretStatusPresent,
		Labels: map[string]any{},
	}
	skip := &storage.Secret{
		ClusterName: "c1", ProviderType: "aws-sm",
		SecretRef: "/eks/uat/skip", Status: storage.SecretStatusPresent,
		Labels: map[string]any{},
	}
	for _, s := range []*storage.Secret{keep, skip} {
		if err := repo.Upsert(ctx, s); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}

	rows, err := repo.List(ctx, storage.SecretsListFilter{
		SecretIDs: []uuid.UUID{keep.ID},
		Limit:     10,
	})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rows) != 1 || rows[0].SecretRef != "/eks/uat/keep" {
		t.Fatalf("expected only the kept row, got %+v", rows)
	}

	// Empty (non-nil) slice → no rows.
	rows, err = repo.List(ctx, storage.SecretsListFilter{
		SecretIDs: []uuid.UUID{},
		Limit:     10,
	})
	if err != nil {
		t.Fatalf("List(empty): %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("expected 0 rows on empty SecretIDs, got %d", len(rows))
	}
}
