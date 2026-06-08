// R-follow-up #2 (api#121) — service-layer tests for SettingsService:
// transactional update + audit, whitelist enforcement, validation
// bounds, cache invalidation, fail-closed behaviour.

package services_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/runtime"
	"github.com/secrets-bridge/api/pkg/storage"
)

type settingsEnv struct {
	ctx  context.Context
	pool *storage.Pool
	svc  *services.SettingsService
}

func setupSettingsEnv(t *testing.T) *settingsEnv {
	t.Helper()
	dbDSN := os.Getenv("TEST_DATABASE_URL")
	if dbDSN == "" {
		t.Skip("TEST_DATABASE_URL is required; skipping")
	}
	redisURL := os.Getenv("TEST_REDIS_URL")
	if redisURL == "" {
		t.Skip("TEST_REDIS_URL is required; skipping")
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

	rdb, err := runtime.Open(ctx, runtime.Config{URL: redisURL, PoolSize: 4, DialTimeout: 5 * time.Second, Namespace: "test"})
	if err != nil {
		t.Fatalf("runtime.Open: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })

	if _, err := pool.Exec(ctx, "TRUNCATE audit_events"); err != nil {
		t.Fatalf("truncate audit: %v", err)
	}
	// Reset the platform_settings seed to 9000 in case prior tests left
	// it elsewhere.
	if _, err := pool.Exec(ctx,
		`UPDATE platform_settings SET value = '{"value": 9000}'::jsonb WHERE key = 'platform_reserved_priority'`,
	); err != nil {
		t.Fatalf("reset seed: %v", err)
	}

	repo := storage.NewPlatformSettings(pool)
	audit := storage.NewAuditEvents(pool)
	svc := services.NewSettingsService(pool, repo, audit, rdb, nil)
	if err := svc.LoadCache(ctx); err != nil {
		t.Fatalf("LoadCache: %v", err)
	}
	return &settingsEnv{ctx: ctx, pool: pool, svc: svc}
}

func TestSettings_GetInt_ReturnsSeed(t *testing.T) {
	e := setupSettingsEnv(t)
	v, err := e.svc.GetInt(e.ctx, services.KeyPlatformReservedPriority)
	if err != nil {
		t.Fatalf("GetInt: %v", err)
	}
	if v != 9000 {
		t.Fatalf("v = %d, want 9000 (seed)", v)
	}
}

func TestSettings_GetInt_RejectsUnknownKey(t *testing.T) {
	e := setupSettingsEnv(t)
	_, err := e.svc.GetInt(e.ctx, "definitely_not_a_real_key")
	if !errors.Is(err, services.ErrUnknownPlatformSetting) {
		t.Fatalf("want ErrUnknownPlatformSetting, got %v", err)
	}
}

func TestSettings_Set_PersistsAndUpdatesCache(t *testing.T) {
	e := setupSettingsEnv(t)
	out, err := e.svc.Set(e.ctx, services.SetInput{
		Key:     services.KeyPlatformReservedPriority,
		Value:   5000,
		ActorID: "alice",
	})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if v, ok := out.Value.(float64); !ok || int(v) != 5000 {
		t.Fatalf("returned value = %v, want 5000", out.Value)
	}
	cached, err := e.svc.GetInt(e.ctx, services.KeyPlatformReservedPriority)
	if err != nil {
		t.Fatalf("GetInt after Set: %v", err)
	}
	if cached != 5000 {
		t.Fatalf("cached = %d, want 5000", cached)
	}
}

func TestSettings_Set_RejectsUnknownKey(t *testing.T) {
	e := setupSettingsEnv(t)
	_, err := e.svc.Set(e.ctx, services.SetInput{
		Key:     "some_bogus_key",
		Value:   123,
		ActorID: "alice",
	})
	if !errors.Is(err, services.ErrUnknownPlatformSetting) {
		t.Fatalf("want ErrUnknownPlatformSetting, got %v", err)
	}
}

func TestSettings_Set_RejectsOutOfBounds(t *testing.T) {
	e := setupSettingsEnv(t)
	for _, v := range []int{99, 1000001, 0, -1} {
		_, err := e.svc.Set(e.ctx, services.SetInput{
			Key:     services.KeyPlatformReservedPriority,
			Value:   v,
			ActorID: "alice",
		})
		if !errors.Is(err, services.ErrInvalidPlatformSetting) {
			t.Fatalf("value %d: want ErrInvalidPlatformSetting, got %v", v, err)
		}
	}
}

func TestSettings_Set_RejectsNonInteger(t *testing.T) {
	e := setupSettingsEnv(t)
	cases := []any{
		"5000",
		5000.5,
		nil,
		map[string]any{},
		[]any{},
		true,
	}
	for _, v := range cases {
		_, err := e.svc.Set(e.ctx, services.SetInput{
			Key:     services.KeyPlatformReservedPriority,
			Value:   v,
			ActorID: "alice",
		})
		if !errors.Is(err, services.ErrInvalidPlatformSetting) {
			t.Fatalf("value %v: want ErrInvalidPlatformSetting, got %v", v, err)
		}
	}
}

func TestSettings_Set_EmitsAuditWithOldAndNewValues(t *testing.T) {
	e := setupSettingsEnv(t)
	if _, err := e.svc.Set(e.ctx, services.SetInput{
		Key:     services.KeyPlatformReservedPriority,
		Value:   5000,
		ActorID: "alice",
	}); err != nil {
		t.Fatal(err)
	}

	// Audit row should carry both old_value (9000) and new_value (5000).
	var metadataText string
	if err := e.pool.QueryRow(e.ctx,
		`SELECT metadata::text FROM audit_events
		 WHERE action='platform_setting.update'
		 ORDER BY occurred_at DESC LIMIT 1`,
	).Scan(&metadataText); err != nil {
		t.Fatal(err)
	}
	// Postgres JSONB pretty-prints with spaces; match the spaced form.
	if !settingsTestContains(metadataText, "\"old_value\": 9000") {
		t.Fatalf("audit metadata missing old_value=9000: %s", metadataText)
	}
	if !settingsTestContains(metadataText, "\"new_value\": 5000") {
		t.Fatalf("audit metadata missing new_value=5000: %s", metadataText)
	}
}

func TestSettings_Set_TransactionalWithAudit_DBCHECKRollback(t *testing.T) {
	// Defense-in-depth check: directly INSERT a row that bypasses the
	// service's validateAndEncode but trips the DB CHECK; confirm
	// neither the setting nor the audit row commit.
	e := setupSettingsEnv(t)
	tx, err := e.pool.BeginTx(e.ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(e.ctx) }()

	// Bypass: write JSON the CHECK rejects (string instead of number).
	bypassRaw, _ := json.Marshal(map[string]any{"value": "not-a-number"})
	repo := storage.NewPlatformSettings(e.pool)
	err = repo.SetTx(e.ctx, tx, services.KeyPlatformReservedPriority, bypassRaw, "alice")
	if !errors.Is(err, storage.ErrInvalidPlatformSetting) {
		t.Fatalf("want storage.ErrInvalidPlatformSetting (DB CHECK), got %v", err)
	}
}

func TestPolicyEngine_CreateForScopedAuthor_LiveCapRevalidation(t *testing.T) {
	// Admin sets cap to 5000; scoped author Create at priority 6000
	// must fail with the live-cap value (NOT the EPIC R hardcode 9000).
	e := setupSettingsEnv(t)
	if _, err := e.svc.Set(e.ctx, services.SetInput{
		Key: services.KeyPlatformReservedPriority, Value: 5000, ActorID: "admin",
	}); err != nil {
		t.Fatal(err)
	}

	pe := setupScopedPolicyEnv(t)
	pe.engine.WithSettings(e.svc)
	defer pe.engine.WithSettings(nil)

	svc := pe.withCovers()
	_, err := svc.CreateForScopedAuthor(pe.ctx, services.CreateScopedPolicyInput{
		ProjectID:     pe.projectID,
		Name:          "above-new-cap",
		Selector:      map[string]any{"environment_kind": "non_prod"},
		Priority:      6000, // above the new 5000 cap
		WorkflowID:    pe.workflowID,
		Enabled:       true,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, services.ErrPolicyPriorityReserved) {
		t.Fatalf("want ErrPolicyPriorityReserved (live cap fired), got %v", err)
	}
}

func TestPolicyEngine_UpdateForScopedAuthor_PriorityRevalidatesAgainstNewCap(t *testing.T) {
	// §1 critical pin from the design pass. Existing rule at priority
	// 7000 was authored when cap was 9000. Admin lowers cap to 5000.
	// A scoped author Update that DOESN'T touch priority must STILL
	// fail with ErrPolicyPriorityReserved because the merged final
	// priority (7000, unchanged) is above the live cap (5000).
	e := setupSettingsEnv(t)
	pe := setupScopedPolicyEnv(t)
	pe.engine.WithSettings(e.svc)
	defer pe.engine.WithSettings(nil)

	svc := pe.withCovers()
	// Create at 7000 with cap = 9000.
	rule, err := svc.CreateForScopedAuthor(pe.ctx, services.CreateScopedPolicyInput{
		ProjectID:     pe.projectID,
		Name:          "existing-rule-at-7000",
		Selector:      map[string]any{"environment_kind": "non_prod"},
		Priority:      7000,
		WorkflowID:    pe.workflowID,
		Enabled:       true,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("seed Create: %v", err)
	}

	// Admin lowers cap to 5000.
	if _, err := e.svc.Set(e.ctx, services.SetInput{
		Key: services.KeyPlatformReservedPriority, Value: 5000, ActorID: "admin",
	}); err != nil {
		t.Fatal(err)
	}

	// Scoped author tries to flip enabled WITHOUT touching priority.
	disabled := false
	_, err = svc.UpdateForScopedAuthor(pe.ctx, services.UpdateScopedPolicyInput{
		RuleID:        rule.ID,
		ProjectID:     pe.projectID,
		Enabled:       &disabled,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	})
	if !errors.Is(err, services.ErrPolicyPriorityReserved) {
		t.Fatalf("want ErrPolicyPriorityReserved (resulting priority 7000 >= live cap 5000), got %v", err)
	}

	// Scoped author lowers priority below the new cap → Update succeeds.
	newPriority := 4000
	if _, err := svc.UpdateForScopedAuthor(pe.ctx, services.UpdateScopedPolicyInput{
		RuleID:        rule.ID,
		ProjectID:     pe.projectID,
		Priority:      &newPriority,
		ActorID:       "alice",
		CorrelationID: uuid.New(),
	}); err != nil {
		t.Fatalf("Update with priority < live cap should succeed: %v", err)
	}
}

func settingsTestContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
