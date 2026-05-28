package runtime_test

// Integration tests against a live Redis. To run locally:
//
//   docker compose up -d redis
//   export TEST_REDIS_URL=redis://localhost:6379/1
//   go test -count=1 ./pkg/runtime/...
//
// In CI, GitHub Actions exposes a redis service container via the same
// env var. When TEST_REDIS_URL is unset, every test SKIPs cleanly — the
// same pattern pkg/storage uses.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/secrets-bridge/api/pkg/runtime"
)

func testCfg(t *testing.T) runtime.Config {
	t.Helper()
	url := os.Getenv("TEST_REDIS_URL")
	if url == "" {
		t.Skip("TEST_REDIS_URL not set; skipping runtime integration tests")
	}
	// Each test gets a per-test namespace so a leftover key from the
	// previous run can't leak into the next.
	return runtime.Config{
		URL:       url,
		PoolSize:  4,
		Namespace: fmt.Sprintf("sb-test-%d", time.Now().UnixNano()),
	}
}

func openClient(t *testing.T) *runtime.Client {
	t.Helper()
	c, err := runtime.Open(t.Context(), testCfg(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestPing(t *testing.T) {
	c := openClient(t)
	if err := c.Ping(t.Context()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestIdempotency_FirstCallRunsCachesReplays(t *testing.T) {
	c := openClient(t)
	calls := 0
	key := "create-job-42"

	// First call: fn runs, result cached.
	r1, err := runtime.WithIdempotencyKey(t.Context(), c, key, 30*time.Second,
		func(context.Context) (string, error) {
			calls++
			return "job-id-X", nil
		})
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if r1.ResultFromCache || r1.Value != "job-id-X" || calls != 1 {
		t.Fatalf("first call result: %+v calls=%d", r1, calls)
	}

	// Second call: same key, fn must NOT run; cached result returned.
	r2, err := runtime.WithIdempotencyKey(t.Context(), c, key, 30*time.Second,
		func(context.Context) (string, error) {
			calls++
			return "different-id", nil
		})
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if !r2.ResultFromCache || r2.Value != "job-id-X" || calls != 1 {
		t.Fatalf("second call result: %+v calls=%d", r2, calls)
	}
}

func TestIdempotency_FailedExecutionReleasesSlot(t *testing.T) {
	c := openClient(t)
	key := "release-on-fail"
	boom := errors.New("boom")

	_, err := runtime.WithIdempotencyKey(t.Context(), c, key, time.Minute,
		func(context.Context) (string, error) { return "", boom })
	if !errors.Is(err, boom) {
		t.Fatalf("expected wrapped boom, got %v", err)
	}

	// Slot should be free again — second attempt acquires it.
	r, err := runtime.WithIdempotencyKey(t.Context(), c, key, time.Minute,
		func(context.Context) (string, error) { return "ok", nil })
	if err != nil {
		t.Fatalf("second attempt after failure: %v", err)
	}
	if r.ResultFromCache || r.Value != "ok" {
		t.Fatalf("post-failure result: %+v", r)
	}
}

func TestLock_AcquireAndRelease(t *testing.T) {
	c := openClient(t)
	lock, err := c.AcquireLock(t.Context(), "mylock", 5*time.Second)
	if err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}
	if err := lock.Release(t.Context()); err != nil {
		t.Fatalf("Release: %v", err)
	}
	// Re-acquire after release.
	lock2, err := c.AcquireLock(t.Context(), "mylock", 5*time.Second)
	if err != nil {
		t.Fatalf("re-acquire: %v", err)
	}
	_ = lock2.Release(t.Context())
}

func TestLock_ContendedSecondAttemptGetsErrLockHeld(t *testing.T) {
	c := openClient(t)
	lock, err := c.AcquireLock(t.Context(), "contended", 10*time.Second)
	if err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}
	defer func() { _ = lock.Release(t.Context()) }()

	if _, err := c.AcquireLock(t.Context(), "contended", 10*time.Second); !errors.Is(err, runtime.ErrLockHeld) {
		t.Fatalf("expected ErrLockHeld, got %v", err)
	}
}

func TestLock_ReleaseReturnsLostWhenLeaseFlipped(t *testing.T) {
	c := openClient(t)
	// 200ms lease — short enough to expire during the test.
	lock, err := c.AcquireLock(t.Context(), "leasy", 200*time.Millisecond)
	if err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	// A second caller now owns it (or the key is gone — either way our
	// release token mismatches the live value).
	other, _ := c.AcquireLock(t.Context(), "leasy", 5*time.Second)
	if other == nil {
		t.Fatal("expected the second acquire after expiry to succeed")
	}
	defer func() { _ = other.Release(t.Context()) }()

	if err := lock.Release(t.Context()); !errors.Is(err, runtime.ErrLockLost) {
		t.Fatalf("expected ErrLockLost, got %v", err)
	}
}

func TestLock_RenewExtendsLease(t *testing.T) {
	c := openClient(t)
	lock, err := c.AcquireLock(t.Context(), "renewable", 300*time.Millisecond)
	if err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}
	defer func() { _ = lock.Release(context.Background()) }()

	// Renew, then sleep past the original lease — the lock should
	// still be ours.
	time.Sleep(100 * time.Millisecond)
	if err := lock.Renew(t.Context()); err != nil {
		t.Fatalf("Renew: %v", err)
	}
	time.Sleep(250 * time.Millisecond)

	// Confirm we still own it: a fresh AcquireLock from another
	// "caller" must fail with ErrLockHeld.
	if _, err := c.AcquireLock(t.Context(), "renewable", time.Second); !errors.Is(err, runtime.ErrLockHeld) {
		t.Fatalf("lease was not extended; second acquire returned %v", err)
	}
}

func TestLock_ConcurrentContenders_ExactlyOneWins(t *testing.T) {
	c := openClient(t)
	const N = 8
	const name = "race"

	winners := make(chan *runtime.Lock, N)
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lock, err := c.AcquireLock(t.Context(), name, 5*time.Second)
			if err == nil {
				winners <- lock
			}
		}()
	}
	wg.Wait()
	close(winners)

	count := 0
	for lock := range winners {
		count++
		_ = lock.Release(context.Background())
	}
	if count != 1 {
		t.Fatalf("expected exactly one winner, got %d", count)
	}
}

func TestRateLimit_AdmitsThenBlocks(t *testing.T) {
	c := openClient(t)
	const limit = 3
	bucket := "tester:test"
	window := time.Second

	for i := 0; i < limit; i++ {
		r, err := c.AllowN(t.Context(), bucket, limit, window)
		if err != nil {
			t.Fatalf("AllowN #%d: %v", i, err)
		}
		if !r.Ok {
			t.Fatalf("AllowN #%d: blocked too early, remaining=%d", i, r.Remaining)
		}
	}
	r, err := c.AllowN(t.Context(), bucket, limit, window)
	if err != nil {
		t.Fatalf("AllowN limit+1: %v", err)
	}
	if r.Ok {
		t.Fatal("rate limiter did not block the (limit+1)th request")
	}
	if r.Retry <= 0 {
		t.Fatalf("retry hint missing: %v", r.Retry)
	}
}

func TestPubSub_PublishReceives(t *testing.T) {
	c := openClient(t)
	sub, err := c.Subscribe(t.Context(), "notifications")
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer func() { _ = sub.Close() }()

	// Publish in a goroutine after a tiny delay so the Receive call
	// is already waiting when the message lands.
	go func() {
		time.Sleep(50 * time.Millisecond)
		_, _ = c.Publish(context.Background(), "notifications", []byte(`{"type":"hello"}`))
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	payload, err := sub.Receive(ctx)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if string(payload) != `{"type":"hello"}` {
		t.Fatalf("unexpected payload: %q", payload)
	}
}
