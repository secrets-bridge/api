package main

// Regression tests for the login + OIDC hardening:
//
//   - API-S-05 / API-N-09: a disabled user can't sign in through OIDC
//     and their live session / bearer JWT stops working.
//   - api#191 M2: OIDC only links to (or JIT-creates) a local user when
//     the IdP says the email is verified.
//   - API-S-12 / API-N-08: return_to is same-origin only, and the
//     callback must come from the browser that called /start.
//   - API-S-25: concurrent wrong passwords can't get past the lockout
//     threshold.
//
// They boot the REAL router (newApp) on a real listener against
// Postgres + Redis and a small in-process OIDC provider, and drive it
// over HTTP the way a browser would. Requires TEST_DATABASE_URL and
// TEST_REDIS_URL; skips otherwise.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/keymgmt"
	"github.com/secrets-bridge/api/pkg/runtime"
	"github.com/secrets-bridge/api/pkg/storage"
)

const (
	loginTestClientID   = "sb-test-client"
	loginTestStateName  = "sb_oidc_state"
	loginTestSessionKey = "sb_session"
)

// --- fake OIDC provider ----------------------------------------------

var (
	fakeIdPKeyOnce sync.Once
	fakeIdPKey     *rsa.PrivateKey
)

type fakeIdPCode struct {
	challenge string
	claims    map[string]any
}

// fakeIdP serves discovery, JWKS and the token endpoint. The test
// mints a code for a given nonce + PKCE challenge + claim set; the
// token endpoint checks the PKCE verifier and returns an RS256 ID
// token carrying those claims.
type fakeIdP struct {
	srv   *httptest.Server
	url   string
	mu    sync.Mutex
	codes map[string]fakeIdPCode
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	fakeIdPKeyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		fakeIdPKey = k
	})
	p := &fakeIdP{codes: map[string]fakeIdPCode{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                p.url,
			"authorization_endpoint":                p.url + "/authorize",
			"token_endpoint":                        p.url + "/token",
			"jwks_uri":                              p.url + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		pub := fakeIdPKey.PublicKey
		writeJSON(w, map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "test-key",
			"n": b64url(pub.N.Bytes()),
			"e": b64url(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		p.mu.Lock()
		entry, ok := p.codes[r.PostForm.Get("code")]
		delete(p.codes, r.PostForm.Get("code"))
		p.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || b64url(sum[:]) != entry.challenge {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		now := time.Now()
		claims := map[string]any{
			"iss": p.url,
			"aud": loginTestClientID,
			"iat": now.Unix(),
			"exp": now.Add(5 * time.Minute).Unix(),
		}
		for k, v := range entry.claims {
			claims[k] = v
		}
		writeJSON(w, map[string]any{
			"access_token": "fake-access-token",
			"token_type":   "Bearer",
			"expires_in":   300,
			"id_token":     signRS256(claims),
		})
	})
	p.srv = httptest.NewServer(mux)
	p.url = p.srv.URL
	t.Cleanup(p.srv.Close)
	return p
}

// issueCode registers a single-use authorization code.
func (p *fakeIdP) issueCode(nonce, challenge string, claims map[string]any) string {
	code := uuid.NewString()
	c := map[string]any{"nonce": nonce}
	for k, v := range claims {
		c[k] = v
	}
	p.mu.Lock()
	p.codes[code] = fakeIdPCode{challenge: challenge, claims: c}
	p.mu.Unlock()
	return code
}

func signRS256(claims map[string]any) string {
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "test-key", "typ": "JWT"})
	body, _ := json.Marshal(claims)
	input := b64url(hdr) + "." + b64url(body)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, fakeIdPKey, crypto.SHA256, sum[:])
	if err != nil {
		panic(err)
	}
	return input + "." + b64url(sig)
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// --- harness ---------------------------------------------------------

type loginHarness struct {
	t      *testing.T
	pool   *storage.Pool
	rdb    *runtime.Client
	users  *storage.LocalUsers
	idp    *fakeIdP
	apiURL string
	client *http.Client
	km     keymgmt.KeyManager
	// jwtKey is the key login tokens were signed with before M1; tests
	// forge correctly signed JWTs with it to show they are no credential.
	jwtKey []byte
}

func newLoginHarness(t *testing.T, opts ...func(*Config)) *loginHarness {
	t.Helper()
	dbDSN := os.Getenv("TEST_DATABASE_URL")
	redisURL := os.Getenv("TEST_REDIS_URL")
	if dbDSN == "" || redisURL == "" {
		t.Skip("TEST_DATABASE_URL and TEST_REDIS_URL are required; skipping")
	}
	ctx := t.Context()

	storageCfg := storage.Config{DSN: dbDSN, MaxConns: 30, ConnLifetime: 5 * time.Minute}
	if err := storage.Migrate(ctx, storageCfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pool, err := storage.Open(ctx, storageCfg)
	if err != nil {
		t.Fatalf("Open storage: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `
		TRUNCATE TABLE audit_events, sessions, user_roles, user_identities, sso_providers, local_users
		RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE sso_settings SET public_url = NULL, pending_cap = 50`); err != nil {
		t.Fatalf("reset sso settings: %v", err)
	}

	// Fresh namespace per test: no rate-limit buckets or OIDC states
	// carried over from another test.
	rdb, err := runtime.Open(ctx, runtime.Config{
		URL: redisURL, PoolSize: 8,
		Namespace: fmt.Sprintf("sb-test-login-%d", time.Now().UnixNano()),
	})
	if err != nil {
		t.Fatalf("Open runtime: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })

	idp := newFakeIdP(t)

	kmsKey := make([]byte, 32)
	jwtKey := make([]byte, 32)
	if _, err := rand.Read(kmsKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if _, err := rand.Read(jwtKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	km, err := keymgmt.NewLocalKMS(kmsKey)
	if err != nil {
		t.Fatalf("NewLocalKMS: %v", err)
	}
	users := storage.NewLocalUsers(pool)
	authSvc := services.NewAuthService(
		users, storage.NewRoles(pool), storage.NewUserRoles(pool),
		storage.NewAuditEvents(pool),
	)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	apiURL := "http://" + ln.Addr().String()
	cfg := Config{
		Env:              ModeProduction,
		OIDCIssuer:       idp.url,
		OIDCClientID:     loginTestClientID,
		OIDCClientSecret: "test-client-secret",
		OIDCRedirectURL:  apiURL + "/api/v1/auth/oidc/callback",
		OIDCScopes:       "openid profile email",
	}
	for _, o := range opts {
		o(&cfg)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	app := newApp(cfg, logger, pool, rdb, km, authSvc)
	go func() { _ = app.Listener(ln, fiber.ListenConfig{DisableStartupMessage: true}) }()
	t.Cleanup(func() { _ = app.ShutdownWithTimeout(5 * time.Second) })

	return &loginHarness{
		t: t, pool: pool, rdb: rdb, users: users, idp: idp, apiURL: apiURL, km: km,
		jwtKey: jwtKey,
		client: &http.Client{
			Timeout: 60 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (h *loginHarness) createUser(email, password string, cost int) *storage.LocalUser {
	h.t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		h.t.Fatalf("bcrypt: %v", err)
	}
	u := &storage.LocalUser{Email: email, PasswordHash: hash, DisplayName: "Test"}
	if err := h.users.Create(h.t.Context(), u); err != nil {
		h.t.Fatalf("create user: %v", err)
	}
	return u
}

func (h *loginHarness) grantAdmin(userID uuid.UUID) {
	h.t.Helper()
	role, err := storage.NewRoles(h.pool).GetByName(h.t.Context(), "admin")
	if err != nil {
		h.t.Fatalf("admin role: %v", err)
	}
	if err := storage.NewUserRoles(h.pool).Grant(h.t.Context(), &storage.UserRole{
		UserID: userID.String(), RoleID: role.ID, Scope: map[string]any{},
	}); err != nil {
		h.t.Fatalf("grant admin: %v", err)
	}
}

func (h *loginHarness) do(req *http.Request) *http.Response {
	h.t.Helper()
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	h.t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func findCookie(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// oidcStart is one browser hit on /auth/oidc/start.
type oidcStart struct {
	state, nonce, challenge string
	cookie                  *http.Cookie // nil when the server set none
	resp                    *http.Response
}

func (h *loginHarness) start(returnTo string) oidcStart {
	h.t.Helper()
	u := h.apiURL + "/api/v1/auth/oidc/start"
	if returnTo != "" {
		u += "?return_to=" + url.QueryEscape(returnTo)
	}
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	resp := h.do(req)
	if resp.StatusCode != http.StatusFound {
		h.t.Fatalf("start: status %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		h.t.Fatalf("start: bad Location: %v", err)
	}
	q := loc.Query()
	return oidcStart{
		state:     q.Get("state"),
		nonce:     q.Get("nonce"),
		challenge: q.Get("code_challenge"),
		cookie:    findCookie(resp, loginTestStateName),
		resp:      resp,
	}
}

func (h *loginHarness) callback(state, code string, cookies ...*http.Cookie) *http.Response {
	h.t.Helper()
	q := url.Values{"state": {state}, "code": {code}}
	req, _ := http.NewRequest(http.MethodGet, h.apiURL+"/api/v1/auth/oidc/callback?"+q.Encode(), nil)
	for _, c := range cookies {
		if c != nil {
			req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
		}
	}
	return h.do(req)
}

// oidcLogin runs start -> IdP -> callback with the browser's own
// state cookie, the way a real browser would.
func (h *loginHarness) oidcLogin(returnTo string, claims map[string]any) *http.Response {
	h.t.Helper()
	s := h.start(returnTo)
	code := h.idp.issueCode(s.nonce, s.challenge, claims)
	return h.callback(s.state, code, s.cookie)
}

// passwordLogin posts to /auth/login and returns the response plus
// any `token` field in the body. Since M1 (api#191) there is none, and
// tests assert it stays empty.
func (h *loginHarness) passwordLogin(email, password string) (*http.Response, string) {
	h.t.Helper()
	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	req, _ := http.NewRequest(http.MethodPost, h.apiURL+"/api/v1/auth/login", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	resp := h.do(req)
	var out struct {
		Token string `json:"token"`
	}
	if resp.StatusCode == http.StatusOK {
		_ = json.NewDecoder(resp.Body).Decode(&out)
	}
	return resp, out.Token
}

// me calls GET /users/me with a session cookie and/or bearer token
// and returns the status plus the resolved user id on 200.
func (h *loginHarness) me(session *http.Cookie, bearer string) (int, string) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, h.apiURL+"/api/v1/users/me", nil)
	if session != nil {
		req.AddCookie(&http.Cookie{Name: session.Name, Value: session.Value})
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp := h.do(req)
	var out struct {
		ID string `json:"id"`
	}
	if resp.StatusCode == http.StatusOK {
		_ = json.NewDecoder(resp.Body).Decode(&out)
	}
	return resp.StatusCode, out.ID
}

// signedToken is a JWT for uid signed with the key the api used to
// sign login tokens: before M1 it was a working credential.
func (h *loginHarness) signedToken(uid uuid.UUID) string {
	h.t.Helper()
	return forgedLoginJWT(h.t, h.jwtKey, uid.String())
}

func (h *loginHarness) count(q string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.pool.QueryRow(h.t.Context(), q, args...).Scan(&n); err != nil {
		h.t.Fatalf("count %q: %v", q, err)
	}
	return n
}

func (h *loginHarness) deniedCallbacks(kind string) int {
	return h.count(`SELECT count(*) FROM audit_events
		WHERE action = 'auth.oidc.callback' AND status = 'denied'
		  AND metadata->>'error_kind' = $1`, kind)
}

func (h *loginHarness) sessionsFor(userID uuid.UUID) int {
	return h.count(`SELECT count(*) FROM sessions WHERE user_id = $1`, userID)
}

func verifiedClaims(sub, email string) map[string]any {
	return map[string]any{"sub": sub, "email": email, "email_verified": true, "name": "SSO User"}
}

// --- M2: email_verified ----------------------------------------------

// The audit proof: a different `sub` presenting the admin's address
// without a verified email must not become the admin.
func TestLoginSecurity_OIDCUnverifiedEmailCannotLinkExistingUser(t *testing.T) {
	h := newLoginHarness(t)
	admin := h.createUser("admin@example.com", "admin-pw-not-used", bcrypt.MinCost)
	h.grantAdmin(admin.ID)

	unverified := []map[string]any{
		{"sub": "attacker-1", "email": "admin@example.com", "email_verified": false},
		{"sub": "attacker-2", "email": "admin@example.com"}, // claim absent
		{"sub": "attacker-3", "email": "Admin@Example.com", "email_verified": "false"},
		{"sub": "attacker-4", "email": "admin@example.com", "email_verified": "yes"},
	}
	for i, claims := range unverified {
		resp := h.oidcLogin("/requests/1", claims)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("case %d: status %d, want 401 (unverified email must not link)", i, resp.StatusCode)
		}
		if c := findCookie(resp, loginTestSessionKey); c != nil && c.Value != "" {
			t.Fatalf("case %d: session cookie issued for an unverified email", i)
		}
	}
	if n := h.sessionsFor(admin.ID); n != 0 {
		t.Fatalf("admin has %d sessions after unverified logins, want 0", n)
	}
	if n := h.count(`SELECT count(*) FROM local_users`); n != 1 {
		t.Fatalf("local_users = %d, want 1 (no JIT row for unverified email)", n)
	}
	if n := h.deniedCallbacks("email_unverified"); n != len(unverified) {
		t.Fatalf("email_unverified audit events = %d, want %d", n, len(unverified))
	}

	// A verified email still links to the existing account.
	resp := h.oidcLogin("/requests/1", verifiedClaims("idp-admin-sub", "admin@example.com"))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("verified login: status %d, want 302", resp.StatusCode)
	}
	session := findCookie(resp, loginTestSessionKey)
	if session == nil || session.Value == "" {
		t.Fatal("verified login: no session cookie")
	}
	status, id := h.me(session, "")
	if status != http.StatusOK || id != admin.ID.String() {
		t.Fatalf("verified login: /users/me = %d id=%q, want 200 id=%s", status, id, admin.ID)
	}
}

func TestLoginSecurity_OIDCJITRequiresVerifiedEmail(t *testing.T) {
	h := newLoginHarness(t)

	resp := h.oidcLogin("/", map[string]any{"sub": "new-1", "email": "new.user@example.com", "email_verified": false})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unverified JIT: status %d, want 401", resp.StatusCode)
	}
	// No email claim at all: the old code fell back to `sub` as the
	// lookup key, which can collide with a real address the same way.
	resp = h.oidcLogin("/", map[string]any{"sub": "admin@example.com"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("email-less JIT: status %d, want 401", resp.StatusCode)
	}
	if n := h.count(`SELECT count(*) FROM local_users`); n != 0 {
		t.Fatalf("local_users = %d, want 0 after refused JIT", n)
	}
	if h.deniedCallbacks("email_unverified") != 1 || h.deniedCallbacks("email_missing") != 1 {
		t.Fatalf("expected one email_unverified and one email_missing audit event")
	}

	// Verified (string "true" form some IdPs emit) creates the user.
	resp = h.oidcLogin("/", map[string]any{"sub": "new-2", "email": "new.user@example.com", "email_verified": "true"})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("verified JIT: status %d, want 302", resp.StatusCode)
	}
	row, err := h.users.GetByEmail(t.Context(), "new.user@example.com")
	if err != nil {
		t.Fatalf("JIT row missing: %v", err)
	}
	// The JIT hash must cost the same as the dummy hash /auth/login
	// compares unknown emails against, or timing tells them apart.
	if cost, err := bcrypt.Cost(row.PasswordHash); err != nil || cost != 12 {
		t.Fatalf("JIT bcrypt cost = %d (%v), want 12", cost, err)
	}
}

// --- API-S-05 / API-N-09: disabled users -----------------------------

func TestLoginSecurity_DisabledUserLosesSessionsAndOIDC(t *testing.T) {
	h := newLoginHarness(t)
	ctx := t.Context()
	user := h.createUser("dana@example.com", "dana-correct-pw", bcrypt.MinCost)

	resp, token := h.passwordLogin("dana@example.com", "dana-correct-pw")
	if resp.StatusCode != http.StatusOK || token != "" {
		t.Fatalf("password login: status %d, token in body=%v", resp.StatusCode, token != "")
	}
	bearer := h.signedToken(user.ID)
	pwSession := findCookie(resp, loginTestSessionKey)
	resp = h.oidcLogin("/", verifiedClaims("dana-sub", "dana@example.com"))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("oidc login: status %d, want 302", resp.StatusCode)
	}
	ssoSession := findCookie(resp, loginTestSessionKey)
	for name, st := range map[string]int{
		"password session": first(h.me(pwSession, "")),
		"sso session":      first(h.me(ssoSession, "")),
	} {
		if st != http.StatusOK {
			t.Fatalf("%s before disable: /users/me = %d, want 200", name, st)
		}
	}
	if st, _ := h.me(nil, bearer); st != http.StatusUnauthorized {
		t.Fatalf("signed bearer JWT before disable: /users/me = %d, want 401 (not a credential)", st)
	}

	if err := h.users.SetDisabled(ctx, user.ID, true); err != nil {
		t.Fatalf("SetDisabled: %v", err)
	}

	for name, st := range map[string]int{
		"password session": first(h.me(pwSession, "")),
		"sso session":      first(h.me(ssoSession, "")),
		"bearer":           first(h.me(nil, bearer)),
	} {
		if st != http.StatusUnauthorized {
			t.Fatalf("%s after disable: /users/me = %d, want 401", name, st)
		}
	}
	if n := h.count(`SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL`, user.ID); n != 0 {
		t.Fatalf("%d live sessions left for the disabled user, want 0", n)
	}

	before := h.sessionsFor(user.ID)
	resp = h.oidcLogin("/", verifiedClaims("dana-sub", "dana@example.com"))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("oidc login while disabled: status %d, want 401", resp.StatusCode)
	}
	if h.sessionsFor(user.ID) != before {
		t.Fatal("oidc login while disabled created a session")
	}
	if h.deniedCallbacks("user_disabled") != 1 {
		t.Fatal("expected one user_disabled audit event on the OIDC callback")
	}
	if resp, _ := h.passwordLogin("dana@example.com", "dana-correct-pw"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("password login while disabled: status %d, want 401", resp.StatusCode)
	}

	// Re-enabling must not bring the old cookies back.
	if err := h.users.SetDisabled(ctx, user.ID, false); err != nil {
		t.Fatalf("SetDisabled(false): %v", err)
	}
	if st, _ := h.me(pwSession, ""); st != http.StatusUnauthorized {
		t.Fatalf("old session after re-enable: /users/me = %d, want 401", st)
	}
}

func first(a int, _ string) int { return a }

// --- API-S-12: open redirect -----------------------------------------

func TestLoginSecurity_ReturnToIsSameOriginOnly(t *testing.T) {
	h := newLoginHarness(t)
	h.createUser("rita@example.com", "unused", bcrypt.MinCost)

	cases := []struct{ in, want string }{
		{"https://evil.example", "/"},
		{"//evil.example", "/"},
		{`/\evil.example`, "/"},
		{"/\t/evil.example", "/"},
		{"javascript:alert(1)", "/"},
		{"/requests/123", "/requests/123"},
		{"/requests/123?tab=audit#top", "/requests/123?tab=audit#top"},
		{"", "/"},
	}
	for _, tc := range cases {
		resp := h.oidcLogin(tc.in, verifiedClaims("rita-sub", "rita@example.com"))
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("return_to %q: status %d, want 302", tc.in, resp.StatusCode)
		}
		if got := resp.Header.Get("Location"); got != tc.want {
			t.Fatalf("return_to %q: Location %q, want %q", tc.in, got, tc.want)
		}
	}

	// A state written to Redis before this fix (unvalidated return_to)
	// is cleaned on the way out too.
	verifier := "legacy-verifier-0123456789-0123456789-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	state, nonce := "legacy-state-"+uuid.NewString(), "legacy-nonce"
	payload, _ := json.Marshal(map[string]string{"v": verifier, "n": nonce, "r": "https://evil.example/phish"})
	if err := h.rdb.Raw().Set(t.Context(), h.rdb.Key("oidc:state", state), payload, time.Minute).Err(); err != nil {
		t.Fatalf("seed legacy state: %v", err)
	}
	code := h.idp.issueCode(nonce, b64url(sum[:]), verifiedClaims("rita-sub", "rita@example.com"))
	resp := h.callback(state, code, &http.Cookie{Name: loginTestStateName, Value: state})
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Fatalf("legacy state: status %d Location %q, want 302 to /", resp.StatusCode, resp.Header.Get("Location"))
	}
}

// --- API-N-08: login CSRF --------------------------------------------

func TestLoginSecurity_CallbackRequiresStateCookie(t *testing.T) {
	h := newLoginHarness(t)
	victim := h.createUser("vic@example.com", "unused", bcrypt.MinCost)

	s := h.start("/requests/7")
	c := s.cookie
	if c == nil || c.Value != s.state {
		t.Fatalf("start did not bind the state to a cookie: %+v", c)
	}
	if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || !c.Secure {
		t.Fatalf("state cookie attrs: HttpOnly=%v SameSite=%v Secure=%v, want true/Lax/true", c.HttpOnly, c.SameSite, c.Secure)
	}
	if c.Path != "/api/v1/auth/oidc/callback" || c.MaxAge <= 0 || c.MaxAge > 300 {
		t.Fatalf("state cookie Path=%q MaxAge=%d, want callback path and <=300s", c.Path, c.MaxAge)
	}
	code := h.idp.issueCode(s.nonce, s.challenge, verifiedClaims("vic-sub", "vic@example.com"))

	// Attacker sends the victim a callback URL from a flow the
	// victim's browser never started: no cookie, or someone else's.
	resp := h.callback(s.state, code)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("callback without state cookie: status %d, want 401", resp.StatusCode)
	}
	resp = h.callback(s.state, code, &http.Cookie{Name: loginTestStateName, Value: "some-other-flow"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("callback with mismatched state cookie: status %d, want 401", resp.StatusCode)
	}
	if cleared := findCookie(resp, loginTestStateName); cleared == nil || cleared.Value != "" {
		t.Fatalf("refused callback did not clear the state cookie: %+v", cleared)
	}
	if n := h.sessionsFor(victim.ID); n != 0 {
		t.Fatalf("refused callbacks created %d sessions", n)
	}
	if h.deniedCallbacks("state_cookie_missing") != 1 || h.deniedCallbacks("state_cookie_mismatch") != 1 {
		t.Fatal("expected state_cookie_missing and state_cookie_mismatch audit events")
	}

	// The refusals ran before the stored state was consumed, so the
	// real browser can still finish its own flow.
	resp = h.callback(s.state, code, s.cookie)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/requests/7" {
		t.Fatalf("own callback: status %d Location %q, want 302 /requests/7", resp.StatusCode, resp.Header.Get("Location"))
	}
	if cleared := findCookie(resp, loginTestStateName); cleared == nil || cleared.Value != "" {
		t.Fatal("successful callback did not clear the state cookie")
	}
	if st, id := h.me(findCookie(resp, loginTestSessionKey), ""); st != http.StatusOK || id != victim.ID.String() {
		t.Fatalf("own callback session: /users/me = %d id=%q", st, id)
	}
	// State is single use: replaying it, even with the cookie, fails.
	if resp := h.callback(s.state, code, s.cookie); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed callback: status %d, want 401", resp.StatusCode)
	}
}

// --- API-S-25: atomic lockout ----------------------------------------

func TestLoginSecurity_ConcurrentWrongPasswordsStopAtThreshold(t *testing.T) {
	h := newLoginHarness(t)
	// Default bcrypt cost keeps each compare long enough that every
	// request is in flight before the first ones finish.
	user := h.createUser("erin@example.com", "erin-correct-pw", bcrypt.DefaultCost)
	const attempts, threshold = 20, 5 // threshold = services.DefaultLockoutPolicy()

	var wg sync.WaitGroup
	gate := make(chan struct{})
	statuses := make([]int, attempts)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := fmt.Sprintf(`{"email":"erin@example.com","password":"wrong-guess-%d"}`, i)
			req, _ := http.NewRequest(http.MethodPost, h.apiURL+"/api/v1/auth/login", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			<-gate
			resp, err := h.client.Do(req)
			if err != nil {
				statuses[i] = -1
				return
			}
			statuses[i] = resp.StatusCode
			_ = resp.Body.Close()
		}(i)
	}
	close(gate)
	wg.Wait()
	for i, st := range statuses {
		if st != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d, want 401", i, st)
		}
	}

	guesses := h.count(`SELECT count(*) FROM audit_events
		WHERE action = 'auth.login' AND resource = $1
		  AND metadata->>'error_kind' = 'wrong_password'`, "user:"+user.ID.String())
	if guesses != threshold {
		t.Fatalf("%d concurrent guesses reached the password compare, want exactly %d", guesses, threshold)
	}
	got, err := h.users.Get(t.Context(), user.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.FailedLoginCount != threshold || got.LockedUntil == nil || !got.LockedUntil.After(time.Now()) {
		t.Fatalf("failed_login_count=%d locked_until=%v, want %d and a future lock", got.FailedLoginCount, got.LockedUntil, threshold)
	}
	if n := h.count(`SELECT count(*) FROM audit_events WHERE action = 'auth.lockout.applied'`); n != 1 {
		t.Fatalf("auth.lockout.applied events = %d, want 1", n)
	}
	if resp, _ := h.passwordLogin("erin@example.com", "erin-correct-pw"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("correct password while locked: status %d, want 401", resp.StatusCode)
	}
}

// --- happy paths still work ------------------------------------------

func TestLoginSecurity_NormalPasswordAndOIDCLoginStillWork(t *testing.T) {
	h := newLoginHarness(t)
	user := h.createUser("pat@example.com", "pat-correct-pw", bcrypt.MinCost)

	for i := 0; i < 2; i++ {
		if resp, _ := h.passwordLogin("pat@example.com", "typo"); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("wrong password: status %d, want 401", resp.StatusCode)
		}
	}
	resp, token := h.passwordLogin("pat@example.com", "pat-correct-pw")
	if resp.StatusCode != http.StatusOK || token != "" {
		t.Fatalf("password login: status %d, token in body=%v", resp.StatusCode, token != "")
	}
	session := findCookie(resp, loginTestSessionKey)
	if session == nil || !session.HttpOnly || session.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie attrs: %+v", session)
	}
	if st, id := h.me(session, ""); st != http.StatusOK || id != user.ID.String() {
		t.Fatalf("cookie /users/me = %d id=%q", st, id)
	}
	if st, _ := h.me(nil, h.signedToken(user.ID)); st != http.StatusUnauthorized {
		t.Fatalf("signed bearer JWT /users/me = %d, want 401 (M1: not a credential)", st)
	}
	got, err := h.users.Get(t.Context(), user.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.FailedLoginCount != 0 || got.LockedUntil != nil {
		t.Fatalf("after success: failed_login_count=%d locked_until=%v, want 0/nil", got.FailedLoginCount, got.LockedUntil)
	}

	resp = h.oidcLogin("/requests/123", verifiedClaims("pat-sub", "pat@example.com"))
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/requests/123" {
		t.Fatalf("oidc login: status %d Location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if st, id := h.me(findCookie(resp, loginTestSessionKey), ""); st != http.StatusOK || id != user.ID.String() {
		t.Fatalf("oidc session /users/me = %d id=%q", st, id)
	}
}

// M1 (api#191): before, logout revoked only the cookie session and the
// login JWT from the response body kept working for its full lifetime.
// Now login returns no token and a signed one is not a credential, so
// logout leaves nothing that still works.
func TestLoginSecurity_LogoutLeavesNoWorkingCredential(t *testing.T) {
	h := newLoginHarness(t)
	user := h.createUser("m1@example.com", "m1-correct-pw", bcrypt.MinCost)
	resp, token := h.passwordLogin("m1@example.com", "m1-correct-pw")
	if resp.StatusCode != http.StatusOK || token != "" {
		t.Fatalf("login = %d, token in body=%v; want 200 and no token", resp.StatusCode, token != "")
	}
	session := findCookie(resp, loginTestSessionKey)
	if st, _ := h.me(session, ""); st != http.StatusOK {
		t.Fatalf("cookie before logout = %d, want 200", st)
	}
	req, _ := http.NewRequest(http.MethodPost, h.apiURL+"/api/v1/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: session.Name, Value: session.Value})
	if out := h.do(req); out.StatusCode != http.StatusNoContent && out.StatusCode != http.StatusOK {
		t.Fatalf("logout = %d", out.StatusCode)
	}
	if st, _ := h.me(session, ""); st != http.StatusUnauthorized {
		t.Fatalf("cookie after logout = %d, want 401", st)
	}
	if st, _ := h.me(nil, h.signedToken(user.ID)); st != http.StatusUnauthorized {
		t.Fatalf("signed bearer after logout = %d, want 401", st)
	}
}
