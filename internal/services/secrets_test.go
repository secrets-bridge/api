package services_test

import (
	"os"
	"testing"
	"time"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

func bootstrapSecrets(t *testing.T) (*services.SecretsService, *storage.Pool, *storage.Secrets) {
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

	if _, err := pool.Exec(ctx, "TRUNCATE TABLE secrets RESTART IDENTITY"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if _, err := pool.Exec(ctx, "TRUNCATE audit_events"); err != nil {
		t.Fatalf("truncate audit: %v", err)
	}

	repo := storage.NewSecrets(pool)
	svc := services.NewSecretsService(repo, storage.NewAuditEvents(pool))
	return svc, pool, repo
}

func sampleBatch(cluster string) services.BulkInput {
	return services.BulkInput{
		ClusterName:    cluster,
		ProviderType:   "vault",
		ProviderConfig: map[string]any{"address": "http://vault.example.com:8200"},
		Items: []services.BulkItem{
			{
				SecretRef: "billing/prod/db",
				Labels:    map[string]any{"team": "billing", "env": "prod"},
				Version:   "v3",
			},
			{
				SecretRef: "billing/prod/api",
				Labels:    map[string]any{"team": "billing", "env": "prod", "pii": "true"},
				Version:   "v7",
			},
			{
				SecretRef: "platform/staging/redis",
				Labels:    map[string]any{"team": "platform", "env": "staging"},
			},
		},
	}
}

func TestUpsert_FirstInsert(t *testing.T) {
	svc, _, _ := bootstrapSecrets(t)
	ctx := t.Context()

	res, err := svc.Upsert(ctx, "agent:test", sampleBatch("prod-eu"))
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if res.Count != 3 {
		t.Fatalf("count = %d want 3", res.Count)
	}
	if len(res.UpsertedIDs) != 3 {
		t.Fatalf("upserted ids = %d want 3", len(res.UpsertedIDs))
	}
}

func TestUpsert_RerunRefreshesRows(t *testing.T) {
	svc, pool, _ := bootstrapSecrets(t)
	ctx := t.Context()

	_, _ = svc.Upsert(ctx, "agent:test", sampleBatch("prod-eu"))

	// Verify first_seen_at < last_seen_at after a second run with the
	// labels updated.
	in := sampleBatch("prod-eu")
	in.Items[0].Labels["team"] = "billing-platform"
	in.Items[0].Version = "v4"
	time.Sleep(20 * time.Millisecond)

	if _, err := svc.Upsert(ctx, "agent:test", in); err != nil {
		t.Fatalf("Upsert(rerun): %v", err)
	}

	var labelsRaw []byte
	var version string
	var firstSeen, lastSeen time.Time
	err := pool.QueryRow(ctx, `
		SELECT labels::text, version, first_seen_at, last_seen_at
		FROM secrets WHERE cluster_name=$1 AND provider_type=$2 AND secret_ref=$3
	`, "prod-eu", "vault", "billing/prod/db").Scan(&labelsRaw, &version, &firstSeen, &lastSeen)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if version != "v4" {
		t.Fatalf("version = %q want v4 (upsert didn't refresh)", version)
	}
	if !lastSeen.After(firstSeen) {
		t.Fatalf("last_seen_at (%v) not after first_seen_at (%v) — refresh failed", lastSeen, firstSeen)
	}
	if got := string(labelsRaw); got == "" || got == "{}" {
		t.Fatalf("labels not persisted: %q", got)
	}
}

func TestList_ClusterAndLabelFilters(t *testing.T) {
	svc, _, _ := bootstrapSecrets(t)
	ctx := t.Context()

	// Seed two clusters with overlapping refs to prove cluster scoping.
	_, _ = svc.Upsert(ctx, "agent:eu", sampleBatch("prod-eu"))
	_, _ = svc.Upsert(ctx, "agent:us", sampleBatch("prod-us"))

	// Filter by cluster.
	rows, err := svc.List(ctx, storage.SecretsListFilter{ClusterName: "prod-eu"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("prod-eu rows = %d want 3", len(rows))
	}
	for _, r := range rows {
		if r.ClusterName != "prod-eu" {
			t.Fatalf("got row with cluster %q in prod-eu filter", r.ClusterName)
		}
	}

	// Filter by label (team=billing) — should match 2 in each cluster
	// but we filter to one cluster so expect 2.
	rows, err = svc.List(ctx, storage.SecretsListFilter{
		ClusterName: "prod-eu",
		LabelEquals: map[string]string{"team": "billing"},
	})
	if err != nil {
		t.Fatalf("List(label): %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("billing rows = %d want 2", len(rows))
	}

	// Multi-label AND: team=billing + pii=true → exactly one.
	rows, _ = svc.List(ctx, storage.SecretsListFilter{
		LabelEquals: map[string]string{"team": "billing", "pii": "true"},
	})
	if len(rows) != 2 {
		// 2 because both clusters have the pii=true billing secret.
		t.Fatalf("billing+pii rows = %d want 2", len(rows))
	}
}

func TestList_RefPrefix(t *testing.T) {
	svc, _, _ := bootstrapSecrets(t)
	ctx := t.Context()
	_, _ = svc.Upsert(ctx, "agent:eu", sampleBatch("prod-eu"))

	rows, err := svc.List(ctx, storage.SecretsListFilter{SecretRefPrefix: "billing/"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("billing/ prefix = %d want 2", len(rows))
	}
}

func TestUpsert_NoItemsIsOK(t *testing.T) {
	svc, _, _ := bootstrapSecrets(t)
	res, err := svc.Upsert(t.Context(), "agent:test", services.BulkInput{
		ClusterName:  "prod-eu",
		ProviderType: "vault",
	})
	if err != nil {
		t.Fatalf("Upsert(empty): %v", err)
	}
	if res.Count != 0 {
		t.Fatalf("count = %d want 0", res.Count)
	}
}

func TestUpsert_ValidatesRequiredFields(t *testing.T) {
	svc, _, _ := bootstrapSecrets(t)
	ctx := t.Context()

	if _, err := svc.Upsert(ctx, "agent:test", services.BulkInput{
		ProviderType: "vault",
		Items:        []services.BulkItem{{SecretRef: "x"}},
	}); err == nil {
		t.Fatal("missing ClusterName: expected error")
	}
	if _, err := svc.Upsert(ctx, "agent:test", services.BulkInput{
		ClusterName: "prod-eu",
		Items:       []services.BulkItem{{SecretRef: "x"}},
	}); err == nil {
		t.Fatal("missing ProviderType: expected error")
	}
	if _, err := svc.Upsert(ctx, "agent:test", services.BulkInput{
		ClusterName:  "prod-eu",
		ProviderType: "vault",
		Items:        []services.BulkItem{{SecretRef: ""}},
	}); err == nil {
		t.Fatal("empty SecretRef: expected error")
	}
}

func TestMarkStaleAsMissing(t *testing.T) {
	svc, pool, repo := bootstrapSecrets(t)
	ctx := t.Context()

	_, _ = svc.Upsert(ctx, "agent:eu", sampleBatch("prod-eu"))
	// Backdate one row so the sweeper hits it.
	_, err := pool.Exec(ctx,
		`UPDATE secrets SET last_seen_at = $1 WHERE secret_ref = 'platform/staging/redis'`,
		time.Now().Add(-25*time.Hour))
	if err != nil {
		t.Fatalf("backdate: %v", err)
	}

	n, err := repo.MarkStaleAsMissing(ctx, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("MarkStaleAsMissing: %v", err)
	}
	if n != 1 {
		t.Fatalf("marked %d rows want 1", n)
	}

	// Status should be present for non-stale rows.
	rows, _ := svc.List(ctx, storage.SecretsListFilter{Status: storage.SecretStatusPresent})
	for _, r := range rows {
		if r.SecretRef == "platform/staging/redis" {
			t.Fatal("redis row should be missing, found present")
		}
	}
}
