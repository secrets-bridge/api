package main

// Route-level regression tests for the MFA hardening in api#191 (H3,
// M4) and API-S-17. Every test drives the REAL route wiring
// (registerMFARoutes, the same function main.go calls) behind the real
// group middleware, with real services against Postgres + Redis. They
// skip when TEST_DATABASE_URL / TEST_REDIS_URL are unset.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 mandates HMAC-SHA1 for TOTP
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth/authtest"
	"github.com/secrets-bridge/api/internal/handlers"
	"github.com/secrets-bridge/api/internal/middleware"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/keymgmt"
	"github.com/secrets-bridge/api/pkg/runtime"
	"github.com/secrets-bridge/api/pkg/storage"
)

const (
	mfaTestRPID   = "sb.example.com"
	mfaTestOrigin = "https://sb.example.com"
)

// frozenClock is the TOTP service clock. It only moves when a test
// advances it, so codes, steps and the lockout window are exact.
type frozenClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *frozenClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *frozenClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type mfaStack struct {
	app      *fiber.App
	pool     *storage.Pool
	rdb      *runtime.Client
	users    storage.LocalUserRepository
	factors  storage.UserMFAFactorRepository
	audit    storage.AuditEventRepository
	sessions *services.SessionService
	signer   *authtest.Signer
	clk      *frozenClock
}

type mfaStackOpts struct {
	// loginGate mounts RequireMFAStamped on the group, the same as
	// SB_REQUIRE_MFA_AT_LOGIN=true does in main.go.
	loginGate bool
}

func newMFAStack(t *testing.T, opts mfaStackOpts) *mfaStack {
	t.Helper()
	dbDSN := os.Getenv("TEST_DATABASE_URL")
	redisURL := os.Getenv("TEST_REDIS_URL")
	if dbDSN == "" || redisURL == "" {
		t.Skip("TEST_DATABASE_URL and TEST_REDIS_URL are required; skipping")
	}
	ctx := t.Context()
	cfg := storage.Config{DSN: dbDSN, MaxConns: 8, ConnLifetime: 5 * time.Minute}
	if err := storage.Migrate(ctx, cfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pool, err := storage.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(pool.Close)
	const truncate = `
		TRUNCATE TABLE
			audit_events, sync_runs, sync_jobs, approvals,
			access_requests, secret_mappings, agents,
			provider_connections, environments, projects,
			team_members, teams, local_users
		RESTART IDENTITY CASCADE`
	if _, err := pool.Exec(ctx, truncate); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	ns := fmt.Sprintf("sb-test-mfaroutes-%d", time.Now().UnixNano())
	rdb, err := runtime.Open(ctx, runtime.Config{URL: redisURL, PoolSize: 8, Namespace: ns})
	if err != nil {
		t.Fatalf("runtime.Open: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	// Drop every key this test wrote (limiter buckets, challenges,
	// lockout state). CI runs all packages against one Redis DB, and
	// later packages scan it. A fresh client because some tests close
	// rdb on purpose.
	t.Cleanup(func() { deleteRedisNamespace(t, redisURL, ns) })

	masterKey := make([]byte, 32)
	_, _ = rand.Read(masterKey)
	km, err := keymgmt.NewLocalKMS(masterKey)
	if err != nil {
		t.Fatalf("NewLocalKMS: %v", err)
	}
	users := storage.NewLocalUsers(pool)
	factors := storage.NewUserMFAFactors(pool)
	audit := storage.NewAuditEvents(pool)
	clk := &frozenClock{now: time.Now().UTC()}

	totpSvc := services.NewTOTPService(factors, km, audit, rdb, services.TOTPConfig{
		Issuer: "Secrets Bridge (test)",
		Clock:  clk.Now,
	})
	webauthnSvc, err := services.NewWebAuthnService(factors, users, km, audit, rdb, services.WebAuthnConfig{
		RPID:          mfaTestRPID,
		RPDisplayName: "Secrets Bridge (test)",
		RPOrigins:     []string{mfaTestOrigin},
	})
	if err != nil {
		t.Fatalf("NewWebAuthnService: %v", err)
	}
	sessionSvc := services.NewSessionService(storage.NewSessions(pool), audit)
	// The verify service stamps last_mfa_at with REAL time, the same
	// clock HasFreshMFA compares against.
	verifySvc := services.NewMFAVerifyService(factors, totpSvc, webauthnSvc, sessionSvc, audit, rdb, services.MFAVerifyConfig{})
	signer := authtest.NewSigner([]byte("test-only-jwt-secret-0123456789abcdef"))

	// Same handler wiring as main.go.
	mfaH := handlers.NewMFA(factors, users, totpSvc).WithWebAuthn(webauthnSvc)
	authMFAH := handlers.NewAuthMFA(verifySvc)
	mfaH = mfaH.WithFactorDeleter(verifySvc)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	app := fiber.New(fiber.Config{ErrorHandler: jsonErrorHandler(logger)})
	app.Use(middleware.RequestID())
	groupMW := []any{
		middleware.AuthWith(sessionSvc),
		middleware.RequireAuthedExcept(publicV1Paths, "/api/v1/agents/"),
		middleware.RBAC(),
		middleware.Audit(logger),
	}
	if opts.loginGate {
		groupMW = append(groupMW, middleware.RequireMFAStamped(sessionSvc, verifySvc))
	}
	v1 := app.Group("/api/v1", groupMW...)
	registerMFARoutes(v1, mfaRouteDeps{
		factors:    mfaH,
		verify:     authMFAH,
		stepUp:     sessionSvc,
		enrollment: verifySvc,
		rdb:        rdb,
		logger:     logger,
	})

	return &mfaStack{
		app: app, pool: pool, rdb: rdb, users: users, factors: factors,
		audit: audit, sessions: sessionSvc, signer: signer, clk: clk,
	}
}

func deleteRedisNamespace(t *testing.T, redisURL, ns string) {
	ctx := context.Background()
	c, err := runtime.Open(ctx, runtime.Config{URL: redisURL, PoolSize: 1, Namespace: ns})
	if err != nil {
		t.Logf("redis cleanup: %v", err)
		return
	}
	defer func() { _ = c.Close() }()
	iter := c.Raw().Scan(ctx, 0, ns+":*", 200).Iterator()
	var keys []string
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}
	if len(keys) > 0 {
		_ = c.Raw().Del(ctx, keys...).Err()
	}
}

// mfaCaller is one authenticated client: a cookie session, or a bearer
// JWT (no session row) for the M1 interaction cases.
type mfaCaller struct {
	userID    uuid.UUID
	sessionID uuid.UUID
	cookie    string
	bearer    string
}

func (s *mfaStack) seedUser(t *testing.T, email string) uuid.UUID {
	t.Helper()
	u := &storage.LocalUser{
		Email:        email,
		PasswordHash: []byte("$2a$10$dummybcryptdummybcryptdummybcryptdummybcryptdummybcryp"),
		DisplayName:  email,
	}
	if err := s.users.Create(t.Context(), u); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return u.ID
}

// loginSession issues a password-only cookie session (no MFA stamp),
// exactly what /auth/login or an OIDC sign-in without trusted amr
// produces.
func (s *mfaStack) loginSession(t *testing.T, uid uuid.UUID) mfaCaller {
	t.Helper()
	out, err := s.sessions.Issue(t.Context(), uid, "127.0.0.1", "test")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return mfaCaller{userID: uid, sessionID: out.Session.ID, cookie: out.CookieValue}
}

func (s *mfaStack) bearerFor(t *testing.T, uid uuid.UUID) mfaCaller {
	t.Helper()
	tok, _, err := s.signer.SignToken(authtest.Claims{Subject: uid.String()}, time.Hour)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}
	return mfaCaller{userID: uid, bearer: tok}
}

type mfaResp struct {
	status int
	header http.Header
	body   []byte
}

func (r mfaResp) decode(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal(r.body, v); err != nil {
		t.Fatalf("decode %q: %v", r.body, err)
	}
}

func (s *mfaStack) call(t *testing.T, who mfaCaller, method, path string, body any) mfaResp {
	t.Helper()
	r, err := s.send(who, method, path, body)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return r
}

// send is call without the testing.T, safe to use from goroutines.
func (s *mfaStack) send(who mfaCaller, method, path string, body any) (mfaResp, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return mfaResp{}, err
		}
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, "/api/v1"+path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if who.cookie != "" {
		req.AddCookie(&http.Cookie{Name: middleware.SessionCookieName, Value: who.cookie})
	}
	if who.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+who.bearer)
	}
	resp, err := s.app.Test(req, fiber.TestConfig{Timeout: 10 * time.Second})
	if err != nil {
		return mfaResp{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return mfaResp{status: resp.StatusCode, header: resp.Header, body: b}, nil
}

// sendParallel fires the verify bodies at once and returns the status
// of each (0 when the request itself errored).
func (s *mfaStack) sendParallel(who mfaCaller, path string, bodies []any) []int {
	statuses := make([]int, len(bodies))
	var wg sync.WaitGroup
	for i := range bodies {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if r, err := s.send(who, http.MethodPost, path, bodies[i]); err == nil {
				statuses[i] = r.status
			}
		}(i)
	}
	wg.Wait()
	return statuses
}

func (s *mfaStack) lastMFAAt(t *testing.T, sid uuid.UUID) *time.Time {
	t.Helper()
	var at *time.Time
	if err := s.pool.QueryRow(t.Context(), `SELECT last_mfa_at FROM sessions WHERE id = $1`, sid).Scan(&at); err != nil {
		t.Fatalf("last_mfa_at: %v", err)
	}
	return at
}

func (s *mfaStack) countFactors(t *testing.T, uid uuid.UUID) int {
	t.Helper()
	n, err := s.factors.CountForUser(t.Context(), uid)
	if err != nil {
		t.Fatalf("CountForUser: %v", err)
	}
	return n
}

// --- TOTP helpers -----------------------------------------------------

func totpCodeAt(secret []byte, at time.Time) string {
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], uint64(at.Unix())/30) //nolint:gosec // unix time is positive
	mac := hmac.New(sha1.New, secret)
	mac.Write(ctr[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1_000_000)
}

// wrongTOTPCode returns a 6-digit code that does not match any step
// in the ±1 window around `at`.
func wrongTOTPCode(secret []byte, at time.Time) string {
	valid := map[string]bool{
		totpCodeAt(secret, at.Add(-30*time.Second)): true,
		totpCodeAt(secret, at):                      true,
		totpCodeAt(secret, at.Add(30*time.Second)):  true,
	}
	for i := 0; ; i++ {
		c := fmt.Sprintf("%06d", i)
		if !valid[c] {
			return c
		}
	}
}

type enrolledTOTP struct {
	factorID string
	secret   []byte
}

func decodeB32Secret(t *testing.T, s string) []byte {
	t.Helper()
	if pad := len(s) % 8; pad != 0 {
		s += strings.Repeat("=", 8-pad)
	}
	b, err := base32.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	return b
}

// startTOTPEnroll runs POST /users/me/mfa/totp/enroll and returns the
// challenge id + decoded secret.
func (s *mfaStack) startTOTPEnroll(t *testing.T, who mfaCaller, label string) (string, []byte) {
	t.Helper()
	r := s.call(t, who, http.MethodPost, "/users/me/mfa/totp/enroll", map[string]string{"label": label})
	if r.status != http.StatusOK {
		t.Fatalf("totp enroll = %d %s; want 200", r.status, r.body)
	}
	var out struct {
		ChallengeID  string `json:"challenge_id"`
		SecretBase32 string `json:"secret_base32"`
	}
	r.decode(t, &out)
	return out.ChallengeID, decodeB32Secret(t, out.SecretBase32)
}

func (s *mfaStack) enrollTOTP(t *testing.T, who mfaCaller, label string) enrolledTOTP {
	t.Helper()
	chal, secret := s.startTOTPEnroll(t, who, label)
	r := s.call(t, who, http.MethodPost, "/users/me/mfa/totp/confirm", map[string]string{
		"challenge_id": chal,
		"code":         totpCodeAt(secret, s.clk.Now()),
	})
	if r.status != http.StatusCreated {
		t.Fatalf("totp confirm = %d %s; want 201", r.status, r.body)
	}
	var out struct {
		ID string `json:"id"`
	}
	r.decode(t, &out)
	return enrolledTOTP{factorID: out.ID, secret: secret}
}

func (s *mfaStack) totpChallenge(t *testing.T, who mfaCaller) mfaResp {
	t.Helper()
	return s.call(t, who, http.MethodPost, "/auth/mfa/challenge", map[string]string{"kind": "totp"})
}

// totpStepUp runs challenge + verify with `code` and returns the
// verify response (or the challenge response when that one failed).
func (s *mfaStack) totpStepUp(t *testing.T, who mfaCaller, f enrolledTOTP, code string) mfaResp {
	t.Helper()
	cr := s.totpChallenge(t, who)
	if cr.status != http.StatusOK {
		return cr
	}
	var chal struct {
		ChallengeID string `json:"challenge_id"`
	}
	cr.decode(t, &chal)
	return s.call(t, who, http.MethodPost, "/auth/mfa/verify", map[string]string{
		"challenge_id": chal.ChallengeID,
		"factor_id":    f.factorID,
		"code":         code,
	})
}

// --- H3: factor changes are step-up gated ----------------------------

// First-factor enrollment must keep working without any MFA stamp:
// that is how MFA gets bootstrapped. Covered for a cookie session and
// with the login-time gate switched on. A bearer JWT is not a
// credential any more (M1, api#191): even one signed with the server's
// key for a live user is unauthenticated and enrolls nothing.
func TestMFARoutes_FirstFactorEnrollment_NoStampNeeded(t *testing.T) {
	for _, tc := range []struct {
		name      string
		loginGate bool
		bearer    bool
	}{
		{name: "cookie session", loginGate: false},
		{name: "cookie session with SB_REQUIRE_MFA_AT_LOGIN", loginGate: true},
		{name: "bearer jwt", bearer: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newMFAStack(t, mfaStackOpts{loginGate: tc.loginGate})
			uid := s.seedUser(t, "first@example.com")
			who := s.loginSession(t, uid)
			if tc.bearer {
				who = s.bearerFor(t, uid)
			}
			if tc.bearer {
				r := s.call(t, who, http.MethodPost, "/users/me/mfa/totp/enroll", map[string]string{"label": "phone"})
				if r.status != http.StatusUnauthorized {
					t.Fatalf("bearer totp enroll = %d %s; want 401", r.status, r.body)
				}
				if got := s.countFactors(t, uid); got != 0 {
					t.Fatalf("bearer added %d factors", got)
				}
				return
			}
			if at := who.sessionID; at != uuid.Nil {
				if s.lastMFAAt(t, at) != nil {
					t.Fatal("precondition: session must be unstamped")
				}
			}
			s.enrollTOTP(t, who, "phone")
			if got := s.countFactors(t, uid); got != 1 {
				t.Fatalf("factors after first enrollment = %d; want 1", got)
			}
		})
	}
}

// H3 / api#191: once a user has a confirmed factor, enrolling another
// one, confirming a pending one, or deleting one needs fresh MFA. The
// audit reproduced the bypass with a password-only session: enroll a
// new TOTP, confirm it, then use it to mint a fresh MFA stamp.
func TestMFARoutes_FactorChanges_RequireFreshMFAOnceEnrolled(t *testing.T) {
	s := newMFAStack(t, mfaStackOpts{})
	uid := s.seedUser(t, "victim@example.com")
	owner := s.loginSession(t, uid)

	// A pending enrollment started while the user had no factor yet.
	// Confirming it later must not slip past the gate.
	stalePending, staleSecret := s.startTOTPEnroll(t, owner, "pending-before-first")
	first := s.enrollTOTP(t, owner, "phone")

	// The attacker holds the password only: a fresh session that never
	// passed MFA.
	attacker := s.loginSession(t, uid)
	bearer := s.bearerFor(t, uid)

	for _, who := range []struct {
		name string
		c    mfaCaller
	}{{"password-only session", attacker}, {"bearer jwt", bearer}} {
		r := s.call(t, who.c, http.MethodPost, "/users/me/mfa/totp/enroll", map[string]string{"label": "attacker"})
		if r.status != http.StatusUnauthorized {
			t.Errorf("%s: totp enroll = %d %s; want 401", who.name, r.status, r.body)
		}
		r = s.call(t, who.c, http.MethodPost, "/users/me/mfa/totp/confirm", map[string]string{
			"challenge_id": stalePending, "code": totpCodeAt(staleSecret, s.clk.Now()),
		})
		if r.status != http.StatusUnauthorized {
			t.Errorf("%s: totp confirm = %d %s; want 401", who.name, r.status, r.body)
		}
		r = s.call(t, who.c, http.MethodPost, "/users/me/mfa/webauthn/register/start", map[string]string{"label": "attacker-key"})
		if r.status != http.StatusUnauthorized {
			t.Errorf("%s: webauthn register/start = %d %s; want 401", who.name, r.status, r.body)
		}
		r = s.call(t, who.c, http.MethodPost, "/users/me/mfa/webauthn/register/finish", map[string]any{
			"challenge_id": "00000000-0000-4000-8000-000000000000", "response": map[string]string{},
		})
		if r.status != http.StatusUnauthorized {
			t.Errorf("%s: webauthn register/finish = %d %s; want 401", who.name, r.status, r.body)
		}
		r = s.call(t, who.c, http.MethodDelete, "/users/me/mfa/factors/"+first.factorID, nil)
		if r.status != http.StatusUnauthorized {
			t.Errorf("%s: delete factor = %d %s; want 401", who.name, r.status, r.body)
		}
	}
	if got := s.countFactors(t, uid); got != 1 {
		t.Fatalf("factor count after refused changes = %d; want 1 (nothing added or removed)", got)
	}
	if s.lastMFAAt(t, attacker.sessionID) != nil {
		t.Fatal("attacker session must still be unstamped")
	}

	// The real user steps up with the existing factor, then the same
	// changes go through.
	s.clk.Advance(60 * time.Second)
	if r := s.totpStepUp(t, owner, first, totpCodeAt(first.secret, s.clk.Now())); r.status != http.StatusNoContent {
		t.Fatalf("step-up verify = %d %s; want 204", r.status, r.body)
	}
	second := s.enrollTOTP(t, owner, "backup")
	if got := s.countFactors(t, uid); got != 2 {
		t.Fatalf("factor count after fresh-MFA enroll = %d; want 2", got)
	}
	r := s.call(t, owner, http.MethodPost, "/users/me/mfa/webauthn/register/start", map[string]string{"label": "key"})
	if r.status != http.StatusOK {
		t.Fatalf("webauthn register/start with fresh MFA = %d %s; want 200", r.status, r.body)
	}
	if r := s.call(t, owner, http.MethodDelete, "/users/me/mfa/factors/"+second.factorID, nil); r.status != http.StatusNoContent {
		t.Fatalf("delete with fresh MFA = %d %s; want 204", r.status, r.body)
	}
	if got := s.countFactors(t, uid); got != 1 {
		t.Fatalf("factor count after fresh-MFA delete = %d; want 1", got)
	}
	// Every factor change is audited: two enrolls and the delete.
	for _, want := range []struct{ action, resource string }{
		{"mfa.totp.enroll", "user_mfa_factor:" + first.factorID},
		{"mfa.totp.enroll", "user_mfa_factor:" + second.factorID},
		{"mfa.factor.delete", "user_mfa_factor:" + second.factorID},
	} {
		var n int
		if err := s.pool.QueryRow(t.Context(),
			`SELECT count(*) FROM audit_events WHERE action = $1 AND resource = $2 AND status = 'success'`,
			want.action, want.resource).Scan(&n); err != nil {
			t.Fatalf("audit lookup: %v", err)
		}
		if n != 1 {
			t.Errorf("audit %s on %s: %d rows; want 1", want.action, want.resource, n)
		}
	}
}

// --- M4: brute force, lockout, replay --------------------------------

// M4 / API-S-11: the audit sent 300 wrong codes through challenge +
// verify and the right code was still accepted afterwards. After the
// lockout threshold the factor refuses even the correct code until the
// lockout window passes.
func TestMFARoutes_TOTPLockout_RefusesCorrectCodeUntilWindowEnds(t *testing.T) {
	s := newMFAStack(t, mfaStackOpts{})
	uid := s.seedUser(t, "brute@example.com")
	owner := s.loginSession(t, uid)
	f := s.enrollTOTP(t, owner, "phone")
	s.clk.Advance(60 * time.Second)

	for i := 0; i < 5; i++ {
		r := s.totpStepUp(t, owner, f, wrongTOTPCode(f.secret, s.clk.Now()))
		if r.status != http.StatusBadRequest {
			t.Fatalf("wrong code #%d = %d %s; want 400", i+1, r.status, r.body)
		}
	}
	for i := 0; i < 2; i++ {
		r := s.totpStepUp(t, owner, f, totpCodeAt(f.secret, s.clk.Now()))
		if r.status != http.StatusTooManyRequests {
			t.Fatalf("correct code while locked (try %d) = %d %s; want 429", i+1, r.status, r.body)
		}
	}
	if s.lastMFAAt(t, owner.sessionID) != nil {
		t.Fatal("a locked factor must not stamp the session")
	}

	// Lockout is 15 minutes. One minute short: still locked.
	s.clk.Advance(14 * time.Minute)
	if r := s.totpStepUp(t, owner, f, totpCodeAt(f.secret, s.clk.Now())); r.status != http.StatusTooManyRequests {
		t.Fatalf("correct code before the lockout ends = %d %s; want 429", r.status, r.body)
	}
	s.clk.Advance(2 * time.Minute)
	if r := s.totpStepUp(t, owner, f, totpCodeAt(f.secret, s.clk.Now())); r.status != http.StatusNoContent {
		t.Fatalf("correct code after the lockout = %d %s; want 204", r.status, r.body)
	}
	if s.lastMFAAt(t, owner.sessionID) == nil {
		t.Fatal("successful verify after the lockout must stamp the session")
	}
}

// M4: guesses sent in parallel cannot exceed the lockout budget. Each
// attempt is reserved before its code is checked, so of 8 concurrent
// wrong guesses exactly 5 are evaluated and the rest are refused.
func TestMFARoutes_TOTPLockout_ParallelGuessesCapped(t *testing.T) {
	s := newMFAStack(t, mfaStackOpts{})
	uid := s.seedUser(t, "parallel@example.com")
	owner := s.loginSession(t, uid)
	f := s.enrollTOTP(t, owner, "phone")
	s.clk.Advance(60 * time.Second)
	wrong := wrongTOTPCode(f.secret, s.clk.Now())

	const n = 8
	chals := make([]string, n)
	for i := range chals {
		cr := s.totpChallenge(t, owner)
		if cr.status != http.StatusOK {
			t.Fatalf("challenge %d = %d %s", i+1, cr.status, cr.body)
		}
		var c struct {
			ChallengeID string `json:"challenge_id"`
		}
		cr.decode(t, &c)
		chals[i] = c.ChallengeID
	}
	bodies := make([]any, n)
	for i := range chals {
		bodies[i] = map[string]string{"challenge_id": chals[i], "factor_id": f.factorID, "code": wrong}
	}
	statuses := s.sendParallel(owner, "/auth/mfa/verify", bodies)
	counts := map[int]int{}
	for _, st := range statuses {
		counts[st]++
	}
	if counts[http.StatusBadRequest] != 5 || counts[http.StatusTooManyRequests] != n-5 {
		t.Fatalf("parallel wrong guesses: statuses %v; want 5x400 and %dx429", statuses, n-5)
	}
}

// M4: per-user limiter on challenge, verify and confirm. The 11th call
// inside the window is refused with 429 + Retry-After, and the budget
// is per user, not shared.
func TestMFARoutes_PerUserRateLimit(t *testing.T) {
	s := newMFAStack(t, mfaStackOpts{})
	uid := s.seedUser(t, "noisy@example.com")
	noisy := s.loginSession(t, uid)
	s.enrollTOTP(t, noisy, "phone")
	otherUID := s.seedUser(t, "quiet@example.com")
	quiet := s.loginSession(t, otherUID)

	type route struct {
		name, path string
		body       any
		okStatus   int
	}
	bogus := "00000000-0000-4000-8000-00000000dead"
	for _, rt := range []route{
		{"challenge", "/auth/mfa/challenge", map[string]string{"kind": "totp"}, http.StatusOK},
		{"verify", "/auth/mfa/verify", map[string]string{"challenge_id": bogus, "code": "123456"}, http.StatusGone},
	} {
		for i := 0; i < 10; i++ {
			if r := s.call(t, noisy, http.MethodPost, rt.path, rt.body); r.status != rt.okStatus {
				t.Fatalf("%s call %d = %d %s; want %d", rt.name, i+1, r.status, r.body, rt.okStatus)
			}
		}
		r := s.call(t, noisy, http.MethodPost, rt.path, rt.body)
		if r.status != http.StatusTooManyRequests {
			t.Fatalf("%s call 11 = %d %s; want 429", rt.name, r.status, r.body)
		}
		if r.header.Get("Retry-After") == "" {
			t.Errorf("%s 429 is missing Retry-After", rt.name)
		}
	}
	// A different user keeps their own budget.
	if r := s.call(t, quiet, http.MethodPost, "/auth/mfa/verify", map[string]string{"challenge_id": bogus, "code": "1"}); r.status != http.StatusGone {
		t.Fatalf("other user's verify = %d %s; want 410 (own budget)", r.status, r.body)
	}

	// Confirm (TOTP confirm + WebAuthn finish share one bucket).
	// `quiet` has no factor so the step-up gate lets them through.
	for i := 0; i < 10; i++ {
		r := s.call(t, quiet, http.MethodPost, "/users/me/mfa/totp/confirm", map[string]string{"challenge_id": bogus, "code": "123456"})
		if r.status != http.StatusGone {
			t.Fatalf("confirm call %d = %d %s; want 410", i+1, r.status, r.body)
		}
	}
	r := s.call(t, quiet, http.MethodPost, "/users/me/mfa/webauthn/register/finish", map[string]any{
		"challenge_id": bogus, "response": map[string]string{"id": "x"},
	})
	if r.status != http.StatusTooManyRequests {
		t.Fatalf("11th confirm (webauthn finish) = %d %s; want 429", r.status, r.body)
	}
}

// M4: a TOTP code is accepted once. Replaying it on a new challenge,
// or sending an older step's code after a newer one was used, fails.
// The code typed at enrollment confirm is also spent.
func TestMFARoutes_TOTPReplayRejected(t *testing.T) {
	s := newMFAStack(t, mfaStackOpts{})
	uid := s.seedUser(t, "replay@example.com")
	owner := s.loginSession(t, uid)
	f := s.enrollTOTP(t, owner, "phone")

	// Same step as the confirm code: already spent at enrollment.
	if r := s.totpStepUp(t, owner, f, totpCodeAt(f.secret, s.clk.Now())); r.status != http.StatusBadRequest {
		t.Fatalf("confirm code replayed at verify = %d %s; want 400", r.status, r.body)
	}

	s.clk.Advance(60 * time.Second)
	code := totpCodeAt(f.secret, s.clk.Now())
	if r := s.totpStepUp(t, owner, f, code); r.status != http.StatusNoContent {
		t.Fatalf("first use = %d %s; want 204", r.status, r.body)
	}
	if r := s.totpStepUp(t, owner, f, code); r.status != http.StatusBadRequest {
		t.Fatalf("replay = %d %s; want 400", r.status, r.body)
	}
	// Previous step is inside the ±1 skew window but older than the
	// step just used.
	if r := s.totpStepUp(t, owner, f, totpCodeAt(f.secret, s.clk.Now().Add(-30*time.Second))); r.status != http.StatusBadRequest {
		t.Fatalf("older step after newer one = %d %s; want 400", r.status, r.body)
	}

	// Concurrent replay: two challenges, the same fresh code sent at
	// once. Exactly one may win.
	s.clk.Advance(60 * time.Second)
	code = totpCodeAt(f.secret, s.clk.Now())
	var chals [2]string
	for i := range chals {
		cr := s.totpChallenge(t, owner)
		if cr.status != http.StatusOK {
			t.Fatalf("challenge = %d %s", cr.status, cr.body)
		}
		var c struct {
			ChallengeID string `json:"challenge_id"`
		}
		cr.decode(t, &c)
		chals[i] = c.ChallengeID
	}
	statuses := s.sendParallel(owner, "/auth/mfa/verify", []any{
		map[string]string{"challenge_id": chals[0], "factor_id": f.factorID, "code": code},
		map[string]string{"challenge_id": chals[1], "factor_id": f.factorID, "code": code},
	})
	ok := 0
	for _, st := range statuses {
		if st == http.StatusNoContent {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("concurrent replay statuses = %v; want exactly one 204", statuses)
	}
}

// M4: these are per-user auth controls, so a Redis outage refuses the
// request instead of waving it through (unlike the per-IP limiters,
// which fail open by the M5 decision).
func TestMFARoutes_RedisOutage_FailsClosed(t *testing.T) {
	s := newMFAStack(t, mfaStackOpts{})
	uid := s.seedUser(t, "outage@example.com")
	owner := s.loginSession(t, uid)
	s.enrollTOTP(t, owner, "phone")
	if err := s.rdb.Close(); err != nil {
		t.Fatalf("close redis: %v", err)
	}
	for _, c := range []struct {
		path string
		body any
	}{
		{"/auth/mfa/challenge", map[string]string{"kind": "totp"}},
		{"/auth/mfa/verify", map[string]string{"challenge_id": "00000000-0000-4000-8000-000000000001", "code": "123456"}},
	} {
		r := s.call(t, owner, http.MethodPost, c.path, c.body)
		if r.status != http.StatusServiceUnavailable {
			t.Errorf("%s with redis down = %d %s; want 503", c.path, r.status, r.body)
		}
	}
	if s.lastMFAAt(t, owner.sessionID) != nil {
		t.Fatal("session must stay unstamped during the outage")
	}
}

// --- API-S-17: WebAuthn step-up --------------------------------------

// softAuthenticator is a minimal software FIDO2 authenticator: P-256
// key, "none" attestation, and a sign counter the test controls.
type softAuthenticator struct {
	priv   *ecdsa.PrivateKey
	credID []byte
	count  uint32
}

func newSoftAuthenticator(t *testing.T) *softAuthenticator {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	return &softAuthenticator{priv: priv, credID: id}
}

func (a *softAuthenticator) coseKey(t *testing.T) []byte {
	t.Helper()
	pt, err := a.priv.PublicKey.Bytes() // 0x04 || X || Y
	if err != nil {
		t.Fatalf("public key bytes: %v", err)
	}
	key := webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.EllipticKey),
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  1, // P-256
		XCoord: pt[1:33],
		YCoord: pt[33:65],
	}
	b, err := webauthncbor.Marshal(key)
	if err != nil {
		t.Fatalf("cbor cose key: %v", err)
	}
	return b
}

const (
	flagUP = 0x01
	flagAT = 0x40
)

func (a *softAuthenticator) authData(t *testing.T, flags byte, attested bool) []byte {
	t.Helper()
	rp := sha256.Sum256([]byte(mfaTestRPID))
	out := append([]byte{}, rp[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, a.count)
	if attested {
		out = append(out, make([]byte, 16)...)                          // zero AAGUID
		out = binary.BigEndian.AppendUint16(out, uint16(len(a.credID))) //nolint:gosec // 32
		out = append(out, a.credID...)
		out = append(out, a.coseKey(t)...)
	}
	return out
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func clientData(t *testing.T, typ, challenge string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"type": typ, "challenge": challenge, "origin": mfaTestOrigin, "crossOrigin": false,
	})
	if err != nil {
		t.Fatalf("client data: %v", err)
	}
	return b
}

// register answers a PublicKeyCredentialCreationOptions challenge.
func (a *softAuthenticator) register(t *testing.T, challenge string) json.RawMessage {
	t.Helper()
	attObj, err := webauthncbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": a.authData(t, flagUP|flagAT, true),
	})
	if err != nil {
		t.Fatalf("cbor attestation: %v", err)
	}
	b, _ := json.Marshal(map[string]any{
		"id": b64u(a.credID), "rawId": b64u(a.credID), "type": "public-key",
		"response": map[string]string{
			"clientDataJSON":    b64u(clientData(t, "webauthn.create", challenge)),
			"attestationObject": b64u(attObj),
		},
	})
	return b
}

// assert answers a PublicKeyCredentialRequestOptions challenge.
func (a *softAuthenticator) assert(t *testing.T, challenge string) json.RawMessage {
	t.Helper()
	ad := a.authData(t, flagUP, false)
	cd := clientData(t, "webauthn.get", challenge)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	b, _ := json.Marshal(map[string]any{
		"id": b64u(a.credID), "rawId": b64u(a.credID), "type": "public-key",
		"response": map[string]string{
			"clientDataJSON":    b64u(cd),
			"authenticatorData": b64u(ad),
			"signature":         b64u(sig),
		},
	})
	return b
}

type webauthnOptions struct {
	ChallengeID string `json:"challenge_id"`
	Options     struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	} `json:"options"`
}

func (s *mfaStack) webauthnStepUp(t *testing.T, who mfaCaller, a *softAuthenticator) mfaResp {
	t.Helper()
	cr := s.call(t, who, http.MethodPost, "/auth/mfa/challenge", map[string]string{"kind": "webauthn"})
	if cr.status != http.StatusOK {
		return cr
	}
	var opts webauthnOptions
	cr.decode(t, &opts)
	return s.call(t, who, http.MethodPost, "/auth/mfa/verify", map[string]any{
		"challenge_id": opts.ChallengeID,
		"response":     a.assert(t, opts.Options.PublicKey.Challenge),
	})
}

// API-S-17: the assertion is checked against the stored public key,
// and an authenticator that always reports sign counter 0 is not a
// clone (WebAuthn §6.1.1). A real counter regression still trips
// clone detection and revokes the user's sessions.
func TestMFARoutes_WebAuthnStepUp_VerifiesStoredCredential(t *testing.T) {
	s := newMFAStack(t, mfaStackOpts{})
	uid := s.seedUser(t, "key@example.com")
	owner := s.loginSession(t, uid)
	key := newSoftAuthenticator(t)

	// First factor: no stamp needed.
	r := s.call(t, owner, http.MethodPost, "/users/me/mfa/webauthn/register/start", map[string]string{"label": "yubikey"})
	if r.status != http.StatusOK {
		t.Fatalf("register/start = %d %s", r.status, r.body)
	}
	var reg webauthnOptions
	r.decode(t, &reg)
	r = s.call(t, owner, http.MethodPost, "/users/me/mfa/webauthn/register/finish", map[string]any{
		"challenge_id": reg.ChallengeID,
		"response":     key.register(t, reg.Options.PublicKey.Challenge),
	})
	if r.status != http.StatusCreated {
		t.Fatalf("register/finish = %d %s", r.status, r.body)
	}

	// Counter stays 0 on every assertion (many platform authenticators).
	for i := 0; i < 2; i++ {
		if r := s.webauthnStepUp(t, owner, key); r.status != http.StatusNoContent {
			t.Fatalf("assertion %d with counter 0 = %d %s; want 204", i+1, r.status, r.body)
		}
	}
	if s.lastMFAAt(t, owner.sessionID) == nil {
		t.Fatal("webauthn verify must stamp the session")
	}

	// Counter moves forward: accepted and persisted.
	key.count = 5
	if r := s.webauthnStepUp(t, owner, key); r.status != http.StatusNoContent {
		t.Fatalf("assertion with counter 5 = %d %s; want 204", r.status, r.body)
	}
	// Counter goes backwards: clone signal, refused, sessions revoked.
	key.count = 3
	if r := s.webauthnStepUp(t, owner, key); r.status == http.StatusNoContent {
		t.Fatal("counter regression must be refused")
	}
	if r := s.call(t, owner, http.MethodGet, "/users/me/mfa/factors", nil); r.status != http.StatusUnauthorized {
		t.Fatalf("session after clone detection = %d; want 401 (revoked)", r.status)
	}

	// A different key signing for the stored credential id fails: the
	// stored public key is what verifies the signature.
	owner2 := s.loginSession(t, uid)
	forged := newSoftAuthenticator(t)
	forged.credID = key.credID
	forged.count = 9
	if r := s.webauthnStepUp(t, owner2, forged); r.status != http.StatusBadRequest {
		t.Fatalf("assertion signed by a different key = %d %s; want 400", r.status, r.body)
	}
}
