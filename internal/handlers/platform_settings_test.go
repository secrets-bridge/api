// R-follow-up #2 (api#121) — handler tests for the admin endpoints:
// PUT happy + 404 unknown + 400 invalid + bounds envelope + URL-vs-body
// + GET list whitelist + GET single + live-cap envelope on scoped
// policy denial.

package handlers_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/handlers"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/runtime"
	"github.com/secrets-bridge/api/pkg/storage"
)

type settingsHarness struct {
	app  *fiber.App
	pool *storage.Pool
	svc  *services.SettingsService
}

func bootstrapSettings(t *testing.T) *settingsHarness {
	t.Helper()
	dbDSN := os.Getenv("TEST_DATABASE_URL")
	if dbDSN == "" {
		t.Skip("TEST_DATABASE_URL required; skipping")
	}
	redisURL := os.Getenv("TEST_REDIS_URL")
	if redisURL == "" {
		t.Skip("TEST_REDIS_URL required; skipping")
	}
	ctx := t.Context()
	cfg := storage.Config{DSN: dbDSN, MaxConns: 5, ConnLifetime: 5 * time.Minute}
	if err := storage.Migrate(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	pool, err := storage.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	rdb, err := runtime.Open(ctx, runtime.Config{URL: redisURL, PoolSize: 4, DialTimeout: 5 * time.Second, Namespace: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rdb.Close() })

	if _, err := pool.Exec(ctx, "TRUNCATE audit_events"); err != nil {
		t.Fatal(err)
	}
	// Reset seed.
	if _, err := pool.Exec(ctx,
		`UPDATE platform_settings SET value = '{"value": 9000}'::jsonb WHERE key = 'platform_reserved_priority'`,
	); err != nil {
		t.Fatal(err)
	}

	repo := storage.NewPlatformSettings(pool)
	audit := storage.NewAuditEvents(pool)
	svc := services.NewSettingsService(pool, repo, audit, rdb, nil)
	if err := svc.LoadCache(ctx); err != nil {
		t.Fatal(err)
	}

	resolver := &stubResolver{}
	app := fiber.New()
	app.Use(testAuthMW)

	h := handlers.NewPlatformSettings(svc)
	v1 := app.Group("/api/v1")
	v1.Get("/platform-settings",
		auth.Require(auth.PermPolicyEdit, resolver),
		h.List)
	v1.Get("/platform-settings/:key",
		auth.Require(auth.PermPolicyEdit, resolver),
		h.Get)
	v1.Put("/platform-settings/:key",
		auth.Require(auth.PermPolicyEdit, resolver),
		h.Put)

	currentResolver = resolver
	return &settingsHarness{app: app, pool: pool, svc: svc}
}

func grantPolicyEdit() {
	currentResolver.grants = []auth.Grant{{Permission: string(auth.PermPolicyEdit)}}
}

func doSettingsJSON(t *testing.T, app *fiber.App, method, path string, body any) (*http.Response, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("X-Test-User-ID", "alice")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, out
}

func TestPutPlatformSetting_HappyPath_200(t *testing.T) {
	h := bootstrapSettings(t)
	grantPolicyEdit()
	resp, body := doSettingsJSON(t, h.app, "PUT",
		"/api/v1/platform-settings/platform_reserved_priority",
		map[string]any{"value": 5000})
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, string(body))
	}
	parsed := decode(t, body)
	if v, ok := parsed["value"].(float64); !ok || int(v) != 5000 {
		t.Fatalf("returned value = %v, want 5000", parsed["value"])
	}
}

func TestPutPlatformSetting_UnknownKey_404(t *testing.T) {
	h := bootstrapSettings(t)
	grantPolicyEdit()
	resp, body := doSettingsJSON(t, h.app, "PUT",
		"/api/v1/platform-settings/some_unknown_setting",
		map[string]any{"value": 5000})
	if resp.StatusCode != 404 {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, string(body))
	}
	if decode(t, body)["error_code"] != "unknown_platform_setting" {
		t.Fatalf("error_code mismatch")
	}
}

func TestPutPlatformSetting_OutOfBounds_400_WithMinMax(t *testing.T) {
	h := bootstrapSettings(t)
	grantPolicyEdit()
	for _, v := range []int{99, 1000001, 0, -1} {
		resp, body := doSettingsJSON(t, h.app, "PUT",
			"/api/v1/platform-settings/platform_reserved_priority",
			map[string]any{"value": v})
		if resp.StatusCode != 400 {
			t.Fatalf("value %d: status = %d, body = %s", v, resp.StatusCode, string(body))
		}
		parsed := decode(t, body)
		if parsed["error_code"] != "invalid_platform_setting" {
			t.Fatalf("value %d: error_code = %v", v, parsed["error_code"])
		}
		if min, ok := parsed["min"].(float64); !ok || int(min) != 100 {
			t.Fatalf("envelope min = %v", parsed["min"])
		}
		if max, ok := parsed["max"].(float64); !ok || int(max) != 1000000 {
			t.Fatalf("envelope max = %v", parsed["max"])
		}
	}
}

func TestPutPlatformSetting_NonInteger_400(t *testing.T) {
	h := bootstrapSettings(t)
	grantPolicyEdit()
	cases := []any{"5000", 5000.5, nil, map[string]any{}, []any{}, true}
	for _, v := range cases {
		resp, body := doSettingsJSON(t, h.app, "PUT",
			"/api/v1/platform-settings/platform_reserved_priority",
			map[string]any{"value": v})
		if resp.StatusCode != 400 {
			t.Fatalf("value %v: status = %d body=%s", v, resp.StatusCode, string(body))
		}
		if decode(t, body)["error_code"] != "invalid_platform_setting" {
			t.Fatalf("value %v: error_code mismatch", v)
		}
	}
}

func TestPutPlatformSetting_RequiresPolicyEdit(t *testing.T) {
	h := bootstrapSettings(t)
	currentResolver.grants = nil
	resp, _ := doSettingsJSON(t, h.app, "PUT",
		"/api/v1/platform-settings/platform_reserved_priority",
		map[string]any{"value": 5000})
	if resp.StatusCode != 403 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestPutPlatformSetting_URLKeyWinsOverBodyKey(t *testing.T) {
	// §2 Q7 lock: body's `key` field MUST be ignored; URL is the truth.
	h := bootstrapSettings(t)
	grantPolicyEdit()
	resp, body := doSettingsJSON(t, h.app, "PUT",
		"/api/v1/platform-settings/platform_reserved_priority",
		map[string]any{"key": "different_key_in_body", "value": 5000})
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, string(body))
	}
	// Confirm the URL key (platform_reserved_priority) got the write,
	// NOT the body key.
	var v int
	if err := h.pool.QueryRow(t.Context(),
		`SELECT (value->>'value')::int FROM platform_settings WHERE key = 'platform_reserved_priority'`,
	).Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != 5000 {
		t.Fatalf("URL key not updated: got %d, want 5000", v)
	}
}

func TestGetPlatformSettings_ReturnsOnlyWhitelisted(t *testing.T) {
	h := bootstrapSettings(t)
	grantPolicyEdit()
	// Sneak a non-whitelisted row in via SQL — the GET must NOT return
	// it. The DB CHECK only applies to the known key, so we can
	// insert a different key freely.
	if _, err := h.pool.Exec(t.Context(),
		`INSERT INTO platform_settings (key, value) VALUES ('_internal_test_marker', '{"value": 1}'::jsonb)
		 ON CONFLICT (key) DO NOTHING`,
	); err != nil {
		t.Fatal(err)
	}
	resp, body := doSettingsJSON(t, h.app, "GET", "/api/v1/platform-settings", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d body=%s", resp.StatusCode, string(body))
	}
	var out []map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	for _, row := range out {
		if row["key"] == "_internal_test_marker" {
			t.Fatalf("non-whitelisted key leaked into GET response: %s", string(body))
		}
	}
	// And the whitelisted one IS present.
	found := false
	for _, row := range out {
		if row["key"] == "platform_reserved_priority" {
			found = true
		}
	}
	if !found {
		t.Fatalf("whitelisted key missing from GET response: %s", string(body))
	}
}

func TestGetPlatformSetting_UnknownKey_404_AfterAuth(t *testing.T) {
	h := bootstrapSettings(t)
	// Without auth → 403.
	currentResolver.grants = nil
	resp, _ := doSettingsJSON(t, h.app, "GET",
		"/api/v1/platform-settings/some_unknown_key", nil)
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403 without auth, got %d", resp.StatusCode)
	}
	// With auth → 404 unknown_platform_setting.
	grantPolicyEdit()
	resp, body := doSettingsJSON(t, h.app, "GET",
		"/api/v1/platform-settings/some_unknown_key", nil)
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404 with auth, got %d body=%s", resp.StatusCode, string(body))
	}
	if decode(t, body)["error_code"] != "unknown_platform_setting" {
		t.Fatalf("error_code mismatch: %s", string(body))
	}
}

func TestScopedPolicyEnvelope_CapReadsLiveValue(t *testing.T) {
	// End-to-end: admin sets cap to 7000 → scoped author submits at
	// priority 8000 → envelope must carry "cap": 7000, NOT 9000.
	settings := bootstrapSettings(t)
	grantPolicyEdit()
	if resp, body := doSettingsJSON(t, settings.app, "PUT",
		"/api/v1/platform-settings/platform_reserved_priority",
		map[string]any{"value": 7000}); resp.StatusCode != 200 {
		t.Fatalf("seed Set: status=%d body=%s", resp.StatusCode, string(body))
	}

	// Now wire a scoped-policy harness with the settings service.
	pol := bootstrapScopedPolicies(t)
	pol.engine.WithSettings(settings.svc)
	defer pol.engine.WithSettings(nil)

	// Rebuild the handler with settings wired so the envelope can
	// reflect the live cap (the bootstrap fixture's pprH was built
	// with nil settings).
	pprH := handlers.NewProjectPolicyRules(pol.engine, storage.NewPolicies(pol.pool), settings.svc)
	app := fiber.New()
	app.Use(testAuthMW)
	v1 := app.Group("/api/v1")
	v1.Post("/projects/:projectID/policy-rules", pprH.Create)

	grantPolicyAuthorForProject(pol.projectID.String())

	resp, body := doPolicyJSON(t, app, "POST",
		fmt.Sprintf("/api/v1/projects/%s/policy-rules", pol.projectID),
		map[string]any{
			"name":        "above-live-cap",
			"selector":    map[string]any{"environment_kind": "non_prod"},
			"priority":    8000,
			"workflow_id": pol.workflowID.String(),
			"enabled":     true,
		})
	if resp.StatusCode != 400 {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, string(body))
	}
	parsed := decode(t, body)
	if parsed["error_code"] != "policy_priority_reserved" {
		t.Fatalf("error_code mismatch")
	}
	if cap, ok := parsed["cap"].(float64); !ok || int(cap) != 7000 {
		t.Fatalf("envelope cap = %v, want 7000 (live value)", parsed["cap"])
	}
}
