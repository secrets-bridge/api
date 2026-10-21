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
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
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
