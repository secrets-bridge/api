package middleware

import (
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/runtime"
)

func openRedisForRateLimit(t *testing.T) *runtime.Client {
	t.Helper()
	url := os.Getenv("TEST_REDIS_URL")
	if url == "" {
		t.Skip("TEST_REDIS_URL not set; skipping")
	}
	cfg := runtime.Config{
		URL:         url,
		Namespace:   "test-ratelimit",
		PoolSize:    4,
		DialTimeout: 5 * time.Second,
	}
	c, err := runtime.Open(t.Context(), cfg)
	if err != nil {
		t.Fatalf("runtime.Open: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestRateLimit_AdmitsUntilLimitThen429s(t *testing.T) {
	rdb := openRedisForRateLimit(t)

	app := fiber.New()
	app.Get("/limited",
		RateLimit(rdb, nil, RateLimitConfig{
			Name:   "test:admit-then-429",
			Bucket: func(c fiber.Ctx) (string, bool) { return "alice", true },
			Limit:  3,
			Window: 60 * time.Second,
		}),
		func(c fiber.Ctx) error { return c.SendStatus(200) },
	)

	for i := 1; i <= 3; i++ {
		resp, err := app.Test(httptest.NewRequest("GET", "/limited", nil))
		if err != nil {
			t.Fatalf("attempt %d: Test: %v", i, err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("attempt %d: status %d, want 200", i, resp.StatusCode)
		}
	}

	resp, err := app.Test(httptest.NewRequest("GET", "/limited", nil))
	if err != nil {
		t.Fatalf("over-limit Test: %v", err)
	}
	if resp.StatusCode != 429 {
		t.Fatalf("status %d, want 429 over the limit", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header on 429")
	}
}

func TestRateLimit_NilRedisFailsOpen(t *testing.T) {
	app := fiber.New()
	app.Get("/limited",
		RateLimit(nil, nil, RateLimitConfig{
			Name:   "test:nil-redis",
			Bucket: func(c fiber.Ctx) (string, bool) { return "alice", true },
			Limit:  1,
			Window: 60 * time.Second,
		}),
		func(c fiber.Ctx) error { return c.SendStatus(200) },
	)

	for i := 1; i <= 5; i++ {
		resp, err := app.Test(httptest.NewRequest("GET", "/limited", nil))
		if err != nil {
			t.Fatalf("attempt %d: Test: %v", i, err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("attempt %d: status %d, want 200 (nil rdb should fail open)", i, resp.StatusCode)
		}
	}
}

func TestRateLimit_SkipsWhenBucketUnresolved(t *testing.T) {
	app := fiber.New()
	app.Get("/limited",
		RateLimit(nil, nil, RateLimitConfig{
			Name:   "test:bucket-skip",
			Bucket: func(c fiber.Ctx) (string, bool) { return "", false },
			Limit:  1,
			Window: 60 * time.Second,
		}),
		func(c fiber.Ctx) error { return c.SendStatus(200) },
	)
	resp, err := app.Test(httptest.NewRequest("GET", "/limited", nil))
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status %d, want 200 (bucket func returned !ok)", resp.StatusCode)
	}
}

func TestRateLimit_BucketsAreIndependent(t *testing.T) {
	rdb := openRedisForRateLimit(t)

	app := fiber.New()
	app.Get("/limited/:who",
		RateLimit(rdb, nil, RateLimitConfig{
			Name:   "test:independent-buckets",
			Bucket: func(c fiber.Ctx) (string, bool) { return c.Params("who"), true },
			Limit:  2,
			Window: 60 * time.Second,
		}),
		func(c fiber.Ctx) error { return c.SendStatus(200) },
	)

	// Two requests under "alice" — both admitted.
	for i := 1; i <= 2; i++ {
		resp, _ := app.Test(httptest.NewRequest("GET", "/limited/alice", nil))
		if resp.StatusCode != 200 {
			t.Fatalf("alice attempt %d: status %d, want 200", i, resp.StatusCode)
		}
	}
	// Third "alice" → 429.
	resp, _ := app.Test(httptest.NewRequest("GET", "/limited/alice", nil))
	if resp.StatusCode != 429 {
		t.Fatalf("alice over-limit: status %d, want 429", resp.StatusCode)
	}
	// "bob" still has full budget — independent bucket.
	resp, _ = app.Test(httptest.NewRequest("GET", "/limited/bob", nil))
	if resp.StatusCode != 200 {
		t.Fatalf("bob first: status %d, want 200 (separate bucket)", resp.StatusCode)
	}
}

// The reveal-session open + wrap-retrieve routes place requireMFA BEFORE
// the rate limiter so a step-up retry (401 step_up_required, while the
// user gets fresh MFA) never consumes the reveal open budget — otherwise
// the natural MFA retry flow trips 429 before a single reveal completes
// (QA P2, 2026-08-11). This pins that ordering with a stand-in gate:
// requests the gate rejects must not decrement the limiter's window.
func TestRateLimit_AfterGate_RejectedRequestsDoNotConsumeBudget(t *testing.T) {
	rdb := openRedisForRateLimit(t)

	bucket := "after-gate-" + uuid.NewString()
	gate := func(c fiber.Ctx) error {
		if c.Get("X-Reject") == "1" {
			return fiber.NewError(fiber.StatusUnauthorized, "step_up_required")
		}
		return c.Next()
	}
	limiter := RateLimit(rdb, nil, RateLimitConfig{
		Name:   "test:after-gate",
		Bucket: func(c fiber.Ctx) (string, bool) { return bucket, true },
		Limit:  2,
		Window: 60 * time.Second,
	})

	app := fiber.New()
	// Ordering under test: gate BEFORE limiter (mirrors requireMFA → RateLimit).
	app.Post("/x", gate, limiter, func(c fiber.Ctx) error { return c.SendStatus(200) })

	// Five gate-rejected requests (the MFA-stale retry flow): each 401,
	// and NONE consumes the limiter budget.
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("POST", "/x", nil)
		req.Header.Set("X-Reject", "1")
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("reject %d: %v", i, err)
		}
		if resp.StatusCode != 401 {
			t.Fatalf("reject %d: status %d, want 401 (limiter must run AFTER the gate)", i, resp.StatusCode)
		}
	}

	// Budget intact: two accepted opens admitted, the third 429s.
	for i := 0; i < 2; i++ {
		resp, _ := app.Test(httptest.NewRequest("POST", "/x", nil))
		if resp.StatusCode != 200 {
			t.Fatalf("accepted %d: status %d, want 200 (gate-rejected requests must not consume budget)", i, resp.StatusCode)
		}
	}
	resp, _ := app.Test(httptest.NewRequest("POST", "/x", nil))
	if resp.StatusCode != 429 {
		t.Fatalf("over-limit: status %d, want 429", resp.StatusCode)
	}
}

func TestRateLimit_ZeroLimitIsPassThrough(t *testing.T) {
	// A zero-limit RateLimitConfig is a misconfig; the middleware
	// degrades to pass-through rather than wedging the route.
	app := fiber.New()
	app.Get("/limited",
		RateLimit(nil, nil, RateLimitConfig{
			Name:   "test:zero-limit",
			Bucket: func(c fiber.Ctx) (string, bool) { return "alice", true },
			Limit:  0,
			Window: 60 * time.Second,
		}),
		func(c fiber.Ctx) error { return c.SendStatus(200) },
	)
	resp, err := app.Test(httptest.NewRequest("GET", "/limited", nil))
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status %d, want 200 (zero-limit should pass through)", resp.StatusCode)
	}
}
