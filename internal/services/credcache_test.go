package services_test

// skills#104: revoking an agent or a Gateway wins against its credential
// cache. A fill that raced the revoke can't serve the revoked credential,
// a failed cache delete can't leave a window, and unknown ids are cached
// briefly so they don't reach Postgres on every request.
//
// Requires TEST_DATABASE_URL and TEST_REDIS_URL; skips otherwise.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/internal/testutil/redisproxy"
	"github.com/secrets-bridge/api/pkg/runtime"
	"github.com/secrets-bridge/api/pkg/storage"
)

var errRedisDown = errors.New("redis: connection refused")

// raceThroughFill runs auth as request A with the fill held until revoke
// has finished, then runs a second request B in the window between the
// cache write and the fill's re-read (or right after A when the fill
// writes nothing). It returns B's result.
func raceThroughFill(t *testing.T, install func(services.CredCacheSeams), auth func() error, revoke func()) error {
	t.Helper()
	arrived, revoked := make(chan struct{}), make(chan struct{})
	var bErr error
	var bRan atomic.Bool
	install(services.CredCacheSeams{
		BeforeFill: func() { close(arrived); <-revoked },
		AfterWrite: func() { bErr = auth(); bRan.Store(true) },
	})
	aDone := make(chan struct{})
	go func() { _ = auth(); close(aDone) }()
	select {
	case <-arrived:
	case <-time.After(10 * time.Second):
		t.Fatal("request A never reached the cache fill")
	}
	revoke()
	close(revoked)
	<-aDone
	install(services.CredCacheSeams{})
	if !bRan.Load() {
		bErr = auth()
	}
	return bErr
}

// ---- agents ---------------------------------------------------------------

type countingAgents struct {
	storage.AgentRepository
	gets atomic.Int32
}

func (c *countingAgents) Get(ctx context.Context, id uuid.UUID) (*storage.Agent, error) {
	c.gets.Add(1)
	return c.AgentRepository.Get(ctx, id)
}

func TestAgentAuth_RevokeWinsAFillRace(t *testing.T) {
	svc, _, _ := bootstrap(t)
	ctx := t.Context()
	minted, err := svc.Mint(ctx, services.MintInput{Name: "race"})
	if err != nil {
		t.Fatal(err)
	}
	b := raceThroughFill(t,
		func(s services.CredCacheSeams) { services.SetAgentCacheSeams(svc, s) },
		func() error { return svc.Authenticate(ctx, minted.ID, minted.AgentSecret) },
		func() {
			if err := svc.Revoke(ctx, minted.ID, "test-admin", "race"); err != nil {
				t.Errorf("Revoke: %v", err)
			}
		})
	if !errors.Is(b, storage.ErrUnauthorized) {
		t.Fatalf("a request after the revoke = %v, want ErrUnauthorized", b)
	}
}

func TestAgentAuth_RevokeSurvivesAFailedCacheDelete(t *testing.T) {
	svc, _, _ := bootstrap(t)
	ctx := t.Context()
	minted, err := svc.Mint(ctx, services.MintInput{Name: "del"})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Authenticate(ctx, minted.ID, minted.AgentSecret); err != nil {
		t.Fatalf("prime the cache: %v", err)
	}
	services.SetAgentCacheSeams(svc, services.CredCacheSeams{Del: func(context.Context, string) error { return errRedisDown }})
	if err := svc.Revoke(ctx, minted.ID, "test-admin", "del"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := svc.Authenticate(ctx, minted.ID, minted.AgentSecret); !errors.Is(err, storage.ErrUnauthorized) {
		t.Fatalf("after a revoke whose cache delete failed = %v, want ErrUnauthorized", err)
	}
}

func TestAgentAuth_UnknownIDIsCachedBriefly(t *testing.T) {
	_, pool, rdb := bootstrap(t)
	ctx := t.Context()
	repo := &countingAgents{AgentRepository: storage.NewAgents(pool)}
	svc := services.NewAgentService(repo, storage.NewAuditEvents(pool), rdb)
	id := uuid.New()
	for i := range 3 {
		if err := svc.Authenticate(ctx, id, "x"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("call %d = %v, want ErrNotFound", i, err)
		}
	}
	if n := repo.gets.Load(); n != 1 {
		t.Fatalf("Postgres lookups for one unknown id = %d, want 1", n)
	}
	// A real agent is unaffected.
	minted, err := svc.Mint(ctx, services.MintInput{Name: "known"})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Authenticate(ctx, minted.ID, minted.AgentSecret); err != nil {
		t.Fatalf("known agent: %v", err)
	}
}

// ---- Gateways -------------------------------------------------------------

type countingGateways struct {
	services.GatewayStore
	gets atomic.Int32
}

func (c *countingGateways) GetAuth(ctx context.Context, id uuid.UUID) (storage.GatewayStatus, []byte, error) {
	c.gets.Add(1)
	return c.GatewayStore.GetAuth(ctx, id)
}

// enrolledGateway creates a Gateway and enrolls it, returning its id and secret.
func enrolledGateway(t *testing.T, svc *services.GatewayService) (uuid.UUID, string) {
	t.Helper()
	ctx := t.Context()
	g, err := svc.CreateGateway(ctx, services.CreateGatewayInput{Name: fmt.Sprintf("gw-%d", time.Now().UnixNano()), Boundary: "test", CreatedBy: "test-admin"})
	if err != nil {
		t.Fatalf("CreateGateway: %v", err)
	}
	tok, err := svc.MintEnrollmentToken(ctx, services.MintGatewayTokenInput{GatewayID: g.ID, CreatedBy: "test-admin"})
	if err != nil {
		t.Fatalf("MintEnrollmentToken: %v", err)
	}
	en, err := svc.Enroll(ctx, services.GatewayEnrollInput{Token: tok.Token})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	return en.GatewayID, en.Secret
}

func gatewayService(t *testing.T) (*services.GatewayService, *countingGateways) {
	t.Helper()
	_, pool, rdb := bootstrap(t)
	store := &countingGateways{GatewayStore: storage.NewGateways(pool)}
	return services.NewGatewayService(store, storage.NewAuditEvents(pool), rdb), store
}

func TestGatewayAuth_RevokeWinsAFillRace(t *testing.T) {
	svc, _ := gatewayService(t)
	ctx := t.Context()
	id, secret := enrolledGateway(t, svc)
	b := raceThroughFill(t,
		func(s services.CredCacheSeams) { services.SetGatewayCacheSeams(svc, s) },
		func() error { return svc.Authenticate(ctx, id, secret) },
		func() {
			if _, err := svc.Revoke(ctx, id, "test-admin", "race"); err != nil {
				t.Errorf("Revoke: %v", err)
			}
		})
	if !errors.Is(b, storage.ErrUnauthorized) {
		t.Fatalf("a request after the revoke = %v, want ErrUnauthorized", b)
	}
}

func TestGatewayAuth_RevokeSurvivesAFailedCacheDelete(t *testing.T) {
	svc, _ := gatewayService(t)
	ctx := t.Context()
	id, secret := enrolledGateway(t, svc)
	if err := svc.Authenticate(ctx, id, secret); err != nil {
		t.Fatalf("prime the cache: %v", err)
	}
	services.SetGatewayCacheSeams(svc, services.CredCacheSeams{Del: func(context.Context, string) error { return errRedisDown }})
	if _, err := svc.Revoke(ctx, id, "test-admin", "del"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := svc.Authenticate(ctx, id, secret); !errors.Is(err, storage.ErrUnauthorized) {
		t.Fatalf("after a revoke whose cache delete failed = %v, want ErrUnauthorized", err)
	}
}

func TestGatewayAuth_DisableBlocksAndEnableRestores(t *testing.T) {
	svc, _ := gatewayService(t)
	ctx := t.Context()
	id, secret := enrolledGateway(t, svc)
	if err := svc.Authenticate(ctx, id, secret); err != nil {
		t.Fatalf("prime the cache: %v", err)
	}
	services.SetGatewayCacheSeams(svc, services.CredCacheSeams{Del: func(context.Context, string) error { return errRedisDown }})
	if _, err := svc.SetEnabled(ctx, id, false, "test-admin"); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if err := svc.Authenticate(ctx, id, secret); !errors.Is(err, storage.ErrUnauthorized) {
		t.Fatalf("disabled (cache delete failed) = %v, want ErrUnauthorized", err)
	}
	services.SetGatewayCacheSeams(svc, services.CredCacheSeams{})
	if _, err := svc.SetEnabled(ctx, id, true, "test-admin"); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if err := svc.Authenticate(ctx, id, secret); err != nil {
		t.Fatalf("enabled again: %v, want nil", err)
	}
}

func TestGatewayAuth_UnknownIDIsCachedBriefly(t *testing.T) {
	svc, store := gatewayService(t)
	ctx := t.Context()
	id := uuid.New()
	for i := range 3 {
		if err := svc.Authenticate(ctx, id, "x"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("call %d = %v, want ErrNotFound", i, err)
		}
	}
	if n := store.gets.Load(); n != 1 {
		t.Fatalf("Postgres lookups for one unknown id = %d, want 1", n)
	}
}

// ---- Redis outages (review of api#303) ------------------------------------

// proxiedServices builds an agent and a Gateway service whose Redis goes
// through a redisproxy, so a test can take Redis down or blackhole it.
func proxiedServices(t *testing.T) (*services.AgentService, *services.GatewayService, *redisproxy.Proxy, *storage.Pool) {
	t.Helper()
	_, pool, _ := bootstrap(t)
	p, proxied := redisproxy.Start(t, os.Getenv("TEST_REDIS_URL"))
	rdb, err := runtime.Open(t.Context(), runtime.Config{URL: proxied, PoolSize: 4, Namespace: fmt.Sprintf("sb-test-%d", time.Now().UnixNano())})
	if err != nil {
		t.Fatalf("Open runtime through the proxy: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	agents := services.NewAgentService(storage.NewAgents(pool), storage.NewAuditEvents(pool), rdb)
	gws := services.NewGatewayService(storage.NewGateways(pool), storage.NewAuditEvents(pool), rdb)
	services.SetAgentCacheRetry(agents, 50*time.Millisecond)
	services.SetGatewayCacheRetry(gws, 50*time.Millisecond)
	return agents, gws, p, pool
}

func countAudit(t *testing.T, pool *storage.Pool, action, resource string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE action = $1 AND resource = $2`, action, resource).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// eventually polls cond for up to 5s.
func eventually(cond func() bool) bool {
	for range 100 {
		if cond() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func TestAgentAuth_RevokeDuringARedisOutage(t *testing.T) {
	svc, _, proxy, pool := proxiedServices(t)
	ctx := t.Context()
	minted, err := svc.Mint(ctx, services.MintInput{Name: "outage"})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Authenticate(ctx, minted.ID, minted.AgentSecret); err != nil {
		t.Fatalf("prime the cache: %v", err)
	}
	proxy.Set(redisproxy.Down)
	if err := svc.Revoke(ctx, minted.ID, "test-admin", "outage"); !errors.Is(err, services.ErrCredentialCacheUnconfirmed) {
		t.Fatalf("Revoke during the outage = %v, want ErrCredentialCacheUnconfirmed", err)
	}
	if n := countAudit(t, pool, "agent.revoke.cache_unconfirmed", "agent:"+minted.ID.String()); n != 1 {
		t.Fatalf("cache_unconfirmed audit rows = %d, want 1", n)
	}
	// While Redis is down, the database decides.
	if err := svc.Authenticate(ctx, minted.ID, minted.AgentSecret); !errors.Is(err, storage.ErrUnauthorized) {
		t.Fatalf("during the outage = %v, want ErrUnauthorized", err)
	}
	// Redis comes back with the old entry still inside its TTL: the
	// background retry lands the tombstone and the credential stays out.
	proxy.Set(redisproxy.Up)
	if !eventually(func() bool { return services.AgentTombstone(ctx, svc, minted.ID) == "revoked" }) {
		t.Fatal("the tombstone never landed after Redis came back")
	}
	if err := svc.Authenticate(ctx, minted.ID, minted.AgentSecret); !errors.Is(err, storage.ErrUnauthorized) {
		t.Fatalf("after Redis came back = %v, want ErrUnauthorized", err)
	}
}

func TestGatewayAuth_RevokeDuringARedisOutage(t *testing.T) {
	_, svc, proxy, pool := proxiedServices(t)
	ctx := t.Context()
	id, secret := enrolledGateway(t, svc)
	if err := svc.Authenticate(ctx, id, secret); err != nil {
		t.Fatalf("prime the cache: %v", err)
	}
	proxy.Set(redisproxy.Down)
	if _, err := svc.Revoke(ctx, id, "test-admin", "outage"); !errors.Is(err, services.ErrCredentialCacheUnconfirmed) {
		t.Fatalf("Revoke during the outage = %v, want ErrCredentialCacheUnconfirmed", err)
	}
	if n := countAudit(t, pool, "gateway.revoke.cache_unconfirmed", "gateway:"+id.String()); n != 1 {
		t.Fatalf("cache_unconfirmed audit rows = %d, want 1", n)
	}
	proxy.Set(redisproxy.Up)
	if !eventually(func() bool { return services.GatewayTombstone(ctx, svc, id) == "revoked" }) {
		t.Fatal("the tombstone never landed after Redis came back")
	}
	if err := svc.Authenticate(ctx, id, secret); !errors.Is(err, storage.ErrUnauthorized) {
		t.Fatalf("after Redis came back = %v, want ErrUnauthorized", err)
	}
	// Retrying the revoke now confirms the tombstone and answers as before.
	if _, err := svc.Revoke(ctx, id, "test-admin", "retry"); !errors.Is(err, storage.ErrGatewayAlreadyRevoked) {
		t.Fatalf("retried revoke = %v, want ErrGatewayAlreadyRevoked", err)
	}
}

// With Redis down for good, authentication is decided by Postgres alone.
func TestAuth_RedisDownFailsSafeToPostgres(t *testing.T) {
	agents, gws, proxy, _ := proxiedServices(t)
	ctx := t.Context()
	live, err := agents.Mint(ctx, services.MintInput{Name: "live"})
	if err != nil {
		t.Fatal(err)
	}
	gone, err := agents.Mint(ctx, services.MintInput{Name: "gone"})
	if err != nil {
		t.Fatal(err)
	}
	gwID, gwSecret := enrolledGateway(t, gws)
	proxy.Set(redisproxy.Down)
	if err := agents.Authenticate(ctx, live.ID, live.AgentSecret); err != nil {
		t.Fatalf("active agent with Redis down = %v, want nil", err)
	}
	_ = agents.Revoke(ctx, gone.ID, "test-admin", "down")
	if err := agents.Authenticate(ctx, gone.ID, gone.AgentSecret); !errors.Is(err, storage.ErrUnauthorized) {
		t.Fatalf("revoked agent with Redis down = %v, want ErrUnauthorized", err)
	}
	if err := agents.Authenticate(ctx, uuid.New(), "x"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("unknown agent with Redis down = %v, want ErrNotFound", err)
	}
	if err := gws.Authenticate(ctx, gwID, gwSecret); err != nil {
		t.Fatalf("active Gateway with Redis down = %v, want nil", err)
	}
}

func TestGatewayAuth_EnableNeverLiftsARevokeTombstone(t *testing.T) {
	svc, _ := gatewayService(t)
	ctx := t.Context()
	id, secret := enrolledGateway(t, svc)
	if _, err := svc.SetEnabled(ctx, id, false, "test-admin"); err != nil {
		t.Fatalf("disable: %v", err)
	}
	// A revoke racing the enable has written its tombstone, not yet
	// committed.
	if err := services.WriteGatewayTombstone(ctx, svc, id, "revoked"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetEnabled(ctx, id, true, "test-admin"); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if v := services.GatewayTombstone(ctx, svc, id); v != "revoked" {
		t.Fatalf("tombstone after enable = %q, want revoked", v)
	}
	if err := svc.Authenticate(ctx, id, secret); !errors.Is(err, storage.ErrUnauthorized) {
		t.Fatalf("after enable over a revoke tombstone = %v, want ErrUnauthorized", err)
	}
}

func TestGatewayAuth_DisableKeepsARevokedReason(t *testing.T) {
	svc, _ := gatewayService(t)
	ctx := t.Context()
	id, _ := enrolledGateway(t, svc)
	if _, err := svc.Revoke(ctx, id, "test-admin", "gone"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := svc.SetEnabled(ctx, id, false, "test-admin"); !errors.Is(err, storage.ErrGatewayStatusConflict) {
		t.Fatalf("disable after revoke = %v, want ErrGatewayStatusConflict", err)
	}
	if v := services.GatewayTombstone(ctx, svc, id); v != "revoked" {
		t.Fatalf("tombstone = %q, want revoked", v)
	}
}

// Only the fill-side check stops this one: the fill must not write at all
// once the revoke's tombstone is there.
func TestAgentAuth_FillNeverWritesPastATombstone(t *testing.T) {
	svc, _, _ := bootstrap(t)
	ctx := t.Context()
	minted, err := svc.Mint(ctx, services.MintInput{Name: "fill"})
	if err != nil {
		t.Fatal(err)
	}
	var wrote atomic.Bool
	arrived, revoked := make(chan struct{}), make(chan struct{})
	services.SetAgentCacheSeams(svc, services.CredCacheSeams{
		BeforeFill: func() { close(arrived); <-revoked },
		AfterWrite: func() { wrote.Store(true) },
	})
	done := make(chan struct{})
	go func() { _ = svc.Authenticate(ctx, minted.ID, minted.AgentSecret); close(done) }()
	<-arrived
	if err := svc.Revoke(ctx, minted.ID, "test-admin", "fill"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	close(revoked)
	<-done
	if wrote.Load() {
		t.Fatal("the fill wrote an entry past the revoke's tombstone")
	}
}

// ---- api#304 ----------------------------------------------------------------

// A disable's background retry must not shut out a Gateway that was
// enabled again before Redis came back.
func TestGatewayAuth_DisableRetryStopsAfterAnEnable(t *testing.T) {
	_, svc, proxy, _ := proxiedServices(t)
	services.SetGatewayCacheRetry(svc, time.Second)
	ctx := t.Context()
	id, secret := enrolledGateway(t, svc)
	proxy.Set(redisproxy.Down)
	if _, err := svc.SetEnabled(ctx, id, false, "test-admin"); !errors.Is(err, services.ErrCredentialCacheUnconfirmed) {
		t.Fatalf("disable during the outage = %v, want ErrCredentialCacheUnconfirmed", err)
	}
	proxy.Set(redisproxy.Up)
	if _, err := svc.SetEnabled(ctx, id, true, "test-admin"); err != nil {
		t.Fatalf("enable: %v", err)
	}
	var retried atomic.Int32
	services.SetGatewayCacheSeams(svc, services.CredCacheSeams{BeforeConfirm: func() { retried.Add(1) }})
	time.Sleep(2500 * time.Millisecond) // two ticks of the disable's retry
	if n := retried.Load(); n != 0 {
		t.Fatalf("the disable's retry tried to write a tombstone %d time(s) after the enable", n)
	}
	if v := services.GatewayTombstone(ctx, svc, id); v != "" {
		t.Fatalf("tombstone = %q after the enable, want none", v)
	}
	if err := svc.Authenticate(ctx, id, secret); err != nil {
		t.Fatalf("enabled Gateway = %v, want nil", err)
	}
}

// An enable that commits and clears between a disable's commit and its
// tombstone write must win: the write sees the row live and lifts it.
func TestGatewayAuth_DisableConfirmLosesToAConcurrentEnable(t *testing.T) {
	svc, _ := gatewayService(t)
	ctx := t.Context()
	id, secret := enrolledGateway(t, svc)
	var once sync.Once
	services.SetGatewayCacheSeams(svc, services.CredCacheSeams{BeforeConfirm: func() {
		once.Do(func() {
			if _, err := svc.SetEnabled(ctx, id, true, "test-admin"); err != nil {
				t.Errorf("concurrent enable: %v", err)
			}
		})
	}})
	if _, err := svc.SetEnabled(ctx, id, false, "test-admin"); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if v := services.GatewayTombstone(ctx, svc, id); v != "" {
		t.Fatalf("tombstone = %q on a Gateway the database has enabled, want none", v)
	}
	if err := svc.Authenticate(ctx, id, secret); err != nil {
		t.Fatalf("enabled Gateway = %v, want nil", err)
	}
}

// An enable that can't clear the cache says so, and the clear lands once
// Redis is back.
func TestGatewayAuth_EnableDuringARedisOutage(t *testing.T) {
	_, svc, proxy, pool := proxiedServices(t)
	ctx := t.Context()
	id, secret := enrolledGateway(t, svc)
	if _, err := svc.SetEnabled(ctx, id, false, "test-admin"); err != nil {
		t.Fatalf("disable: %v", err)
	}
	proxy.Set(redisproxy.Down)
	if _, err := svc.SetEnabled(ctx, id, true, "test-admin"); !errors.Is(err, services.ErrCredentialCacheUnconfirmed) {
		t.Fatalf("enable during the outage = %v, want ErrCredentialCacheUnconfirmed", err)
	}
	if n := countAudit(t, pool, "gateway.enable.cache_unconfirmed", "gateway:"+id.String()); n != 1 {
		t.Fatalf("cache_unconfirmed audit rows = %d, want 1", n)
	}
	proxy.Set(redisproxy.Up)
	if !eventually(func() bool { return svc.Authenticate(ctx, id, secret) == nil }) {
		t.Fatalf("enabled Gateway still refused after Redis came back (tombstone %q)", services.GatewayTombstone(ctx, svc, id))
	}
}

// A retried Gateway revoke whose tombstone is gone (the replica that held
// the retry died, or the key was lost) re-confirms it instead of only
// answering "already revoked".
func TestGatewayAuth_RetriedRevokeReconfirmsTheTombstone(t *testing.T) {
	_, svc, proxy, _ := proxiedServices(t)
	ctx := t.Context()
	id, secret := enrolledGateway(t, svc)
	if _, err := svc.Revoke(ctx, id, "test-admin", "first"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := services.DeleteGatewayTombstone(ctx, svc, id); err != nil {
		t.Fatal(err)
	}
	proxy.Set(redisproxy.Down)
	if _, err := svc.Revoke(ctx, id, "test-admin", "retry"); !errors.Is(err, services.ErrCredentialCacheUnconfirmed) {
		t.Fatalf("retried revoke without a tombstone = %v, want ErrCredentialCacheUnconfirmed", err)
	}
	proxy.Set(redisproxy.Up)
	if !eventually(func() bool { return services.GatewayTombstone(ctx, svc, id) == "revoked" }) {
		t.Fatal("the tombstone never came back")
	}
	if err := svc.Authenticate(ctx, id, secret); !errors.Is(err, storage.ErrUnauthorized) {
		t.Fatalf("revoked Gateway = %v, want ErrUnauthorized", err)
	}
}

// A Redis that drops packets costs each call a few hundred milliseconds,
// not the client's read timeout times its retries.
func TestAuth_BlackholedRedisIsBounded(t *testing.T) {
	agents, gws, proxy, _ := proxiedServices(t)
	ctx := t.Context()
	a, err := agents.Mint(ctx, services.MintInput{Name: "blackhole"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := agents.Mint(ctx, services.MintInput{Name: "blackhole-revoke"})
	if err != nil {
		t.Fatal(err)
	}
	gwID, gwSecret := enrolledGateway(t, gws)
	for _, err := range []error{agents.Authenticate(ctx, a.ID, a.AgentSecret), agents.Authenticate(ctx, b.ID, b.AgentSecret), gws.Authenticate(ctx, gwID, gwSecret)} {
		if err != nil {
			t.Fatalf("prime the cache: %v", err)
		}
	}
	proxy.Set(redisproxy.Blackhole)
	timed := func(name string, limit time.Duration, call func() error, check func(error) bool) {
		t.Helper()
		start := time.Now()
		err := call()
		took := time.Since(start)
		t.Logf("%s: %s with Redis blackholed", name, took.Round(time.Millisecond))
		if took > limit {
			t.Errorf("%s took %s with Redis blackholed, want under %s", name, took.Round(time.Millisecond), limit)
		}
		if !check(err) {
			t.Errorf("%s = %v", name, err)
		}
	}
	isNil := func(err error) bool { return err == nil }
	timed("agent auth", 2*time.Second, func() error { return agents.Authenticate(ctx, a.ID, a.AgentSecret) }, isNil)
	timed("agent auth, wrong secret", 2*time.Second, func() error { return agents.Authenticate(ctx, a.ID, "wrong") },
		func(err error) bool { return errors.Is(err, storage.ErrUnauthorized) })
	timed("agent heartbeat", 2*time.Second, func() error { return agents.Heartbeat(ctx, a.ID, a.AgentSecret) }, isNil)
	timed("gateway auth", 2*time.Second, func() error { return gws.Authenticate(ctx, gwID, gwSecret) }, isNil)
	unconfirmed := func(err error) bool { return errors.Is(err, services.ErrCredentialCacheUnconfirmed) }
	timed("agent revoke", 3*time.Second, func() error { return agents.Revoke(ctx, b.ID, "test-admin", "blackhole") }, unconfirmed)
	timed("gateway disable", 3*time.Second, func() error { _, err := gws.SetEnabled(ctx, gwID, false, "test-admin"); return err }, unconfirmed)
}

// A disable that commits between an enable's commit and its clear keeps
// its tombstone: the clear sees the row blocked and puts it back.
func TestGatewayAuth_EnableClearLosesToAConcurrentDisable(t *testing.T) {
	svc, _ := gatewayService(t)
	ctx := t.Context()
	id, secret := enrolledGateway(t, svc)
	if _, err := svc.SetEnabled(ctx, id, false, "test-admin"); err != nil {
		t.Fatalf("disable: %v", err)
	}
	var once sync.Once
	services.SetGatewayCacheSeams(svc, services.CredCacheSeams{BeforeClear: func() {
		once.Do(func() {
			if _, err := svc.SetEnabled(ctx, id, false, "test-admin"); err != nil {
				t.Errorf("concurrent disable: %v", err)
			}
		})
	}})
	if _, err := svc.SetEnabled(ctx, id, true, "test-admin"); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if v := services.GatewayTombstone(ctx, svc, id); v != "disabled" {
		t.Fatalf("tombstone = %q on a Gateway the database has disabled, want disabled", v)
	}
	if err := svc.Authenticate(ctx, id, secret); !errors.Is(err, storage.ErrUnauthorized) {
		t.Fatalf("disabled Gateway = %v, want ErrUnauthorized", err)
	}
}
