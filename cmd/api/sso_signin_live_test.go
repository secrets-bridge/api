package main

// api#267 part 2: signing in with Google configured from the console,
// against the fake IdP. Each check named in the #265 review is here and
// fails without its change.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

const ssoClientSecret = "GOCSPX-live-test-secret-0000"

type ssoHarness struct {
	*loginHarness
	svc      *services.SSOService
	provider *storage.SSOProvider
}

// newSSOHarness boots the app with a Google provider pointing at the
// fake IdP, enabled, with example.com allowed and approval on (unless
// mutate says otherwise).
func newSSOHarness(t *testing.T, mutate func(*loginHarness, *services.SSOProviderInput)) *ssoHarness {
	h := newLoginHarness(t)
	prev := services.GoogleIssuer
	services.GoogleIssuer = h.idp.url
	t.Cleanup(func() { services.GoogleIssuer = prev })
	// Leave no provider behind: one with a default role holds that role
	// (ON DELETE RESTRICT), and other packages' tests wipe roles in the
	// same database.
	t.Cleanup(func() { _, _ = h.pool.Exec(context.Background(), `DELETE FROM sso_providers`) })

	svc, err := services.NewSSOService(storage.NewSSOStore(h.pool), storage.NewRoles(h.pool), h.km, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	in := services.SSOProviderInput{Type: "google", ClientID: loginTestClientID, ClientSecret: ssoClientSecret,
		AllowedDomains: []string{"example.com"}, RequireApproval: true}
	if mutate != nil {
		mutate(h, &in)
	}
	p, err := svc.CreateProvider(t.Context(), in, "test")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	if _, err := h.pool.Exec(t.Context(), `UPDATE sso_settings SET public_url = $1`, h.apiURL); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetEnabled(t.Context(), p.ID, true, "test"); err != nil {
		t.Fatalf("enable: %v", err)
	}
	return &ssoHarness{loginHarness: h, svc: svc, provider: p}
}

func googleClaims(sub, email, hd string) map[string]any {
	c := map[string]any{"sub": sub, "email": email, "email_verified": true, "name": "Google User"}
	if hd != "" {
		c["hd"] = hd
	}
	return c
}

type ssoRoundTrip struct {
	state, nonce, challenge, redirectURI, clientID string
	cookie                                         *http.Cookie
}

func parseAuthorize(t *testing.T, location string, cookies []*http.Cookie) ssoRoundTrip {
	t.Helper()
	loc, err := url.Parse(location)
	if err != nil {
		t.Fatalf("bad authorize URL %q: %v", location, err)
	}
	q := loc.Query()
	rt := ssoRoundTrip{state: q.Get("state"), nonce: q.Get("nonce"), challenge: q.Get("code_challenge"),
		redirectURI: q.Get("redirect_uri"), clientID: q.Get("client_id")}
	for _, c := range cookies {
		if c.Name == "sb_sso_state" {
			rt.cookie = c
		}
	}
	return rt
}

// startSignIn begins a Google sign-in, optionally with a forged Host.
func (h *ssoHarness) startSignIn(host string) (*http.Response, ssoRoundTrip) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, h.apiURL+"/api/v1/auth/sso/google/start?return_to=/requests", nil)
	if host != "" {
		req.Host = host
		req.Header.Set("X-Forwarded-Host", host)
		req.Header.Set("X-Forwarded-Proto", "https")
	}
	resp := h.do(req)
	if resp.StatusCode != http.StatusFound {
		h.t.Fatalf("start = %d", resp.StatusCode)
	}
	return resp, parseAuthorize(h.t, resp.Header.Get("Location"), resp.Cookies())
}

func (h *ssoHarness) callbackWith(rt ssoRoundTrip, code string) *http.Response {
	h.t.Helper()
	q := url.Values{"state": {rt.state}, "code": {code}}
	req, _ := http.NewRequest(http.MethodGet, h.apiURL+"/api/v1/auth/sso/google/callback?"+q.Encode(), nil)
	if rt.cookie != nil {
		req.AddCookie(&http.Cookie{Name: rt.cookie.Name, Value: rt.cookie.Value})
	}
	return h.do(req)
}

// signIn runs start -> fake Google -> callback with the browser's own
// state cookie.
func (h *ssoHarness) signIn(claims map[string]any) *http.Response {
	h.t.Helper()
	_, rt := h.startSignIn("")
	return h.callbackWith(rt, h.idp.issueCode(rt.nonce, rt.challenge, claims))
}

func (h *ssoHarness) authed(method, path string, session *http.Cookie, body any) (int, []byte, *http.Response) {
	h.t.Helper()
	var rdr io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rdr = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, h.apiURL+path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if session != nil {
		req.AddCookie(&http.Cookie{Name: session.Name, Value: session.Value})
	}
	resp := h.do(req)
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out, resp
}

// freshSession signs a local user in with a password and marks the
// session as having passed a second factor just now.
func (h *ssoHarness) freshSession(email string) (*storage.LocalUser, *http.Cookie) {
	h.t.Helper()
	u := h.createUser(email, "correct-horse-"+email, bcrypt.MinCost)
	resp, _ := h.passwordLogin(email, "correct-horse-"+email)
	session := findCookie(resp, loginTestSessionKey)
	if session == nil {
		h.t.Fatalf("password login for %s gave no session", email)
	}
	if _, err := h.pool.Exec(h.t.Context(), `UPDATE sessions SET last_mfa_at = now() WHERE user_id = $1`, u.ID); err != nil {
		h.t.Fatal(err)
	}
	return u, session
}

// connect runs Connect Google for a session up to the ticket the console
// would redeem.
func (h *ssoHarness) connect(session *http.Cookie, claims map[string]any) string {
	h.t.Helper()
	code, body, resp := h.authed(http.MethodPost, "/api/v1/auth/sso/google/connect", session, nil)
	if code != http.StatusOK {
		h.t.Fatalf("connect = %d %s", code, body)
	}
	var out struct {
		RedirectURL string `json:"redirect_url"`
	}
	_ = json.Unmarshal(body, &out)
	rt := parseAuthorize(h.t, out.RedirectURL, resp.Cookies())
	cb := h.callbackWith(rt, h.idp.issueCode(rt.nonce, rt.challenge, claims))
	loc := cb.Header.Get("Location")
	if cb.StatusCode != http.StatusFound || !strings.HasPrefix(loc, "/me#sso_ticket=") {
		h.t.Fatalf("connect callback = %d %q; want a ticket for the profile page", cb.StatusCode, loc)
	}
	return strings.TrimPrefix(loc, "/me#sso_ticket=")
}

func (h *ssoHarness) finish(session *http.Cookie, ticket string) (int, []byte) {
	h.t.Helper()
	code, body, _ := h.authed(http.MethodPost, "/api/v1/auth/sso/google/finish", session, map[string]any{"ticket": ticket})
	return code, body
}

func (h *ssoHarness) auditReasons(kind string) int {
	return h.count(`SELECT count(*) FROM audit_events WHERE metadata->>'error_kind' = $1`, kind)
}

func TestSSO_SignInCreatesAWaitingAccountBoundBySubject(t *testing.T) {
	h := newSSOHarness(t, nil)

	resp := h.signIn(googleClaims("g-sub-1", "Nia@Example.com", "example.com"))
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/requests" {
		t.Fatalf("sign-in = %d %q; want 302 to the return_to", resp.StatusCode, resp.Header.Get("Location"))
	}
	session := findCookie(resp, loginTestSessionKey)
	if session == nil {
		t.Fatal("no session issued")
	}
	if st, _ := h.me(session, ""); st != http.StatusOK {
		t.Fatalf("/users/me = %d", st)
	}
	if code, _, _ := h.authed(http.MethodGet, "/api/v1/users/me/projects", session, nil); code != http.StatusForbidden {
		t.Fatalf("a new Google account reached /users/me/projects (%d); want 403 while waiting", code)
	}
	if n := h.count(`SELECT count(*) FROM local_users WHERE email = 'nia@example.com' AND pending_approval`); n != 1 {
		t.Fatalf("waiting accounts for nia = %d, want 1", n)
	}
	if n := h.count(`SELECT count(*) FROM user_identities WHERE issuer = $1 AND subject = 'g-sub-1'`, h.idp.url); n != 1 {
		t.Fatalf("identities for g-sub-1 = %d, want 1", n)
	}
	// The same identity signs in to the same account.
	if resp := h.signIn(googleClaims("g-sub-1", "nia@example.com", "example.com")); findCookie(resp, loginTestSessionKey) == nil {
		t.Fatal("second sign-in got no session")
	}
	if n := h.count(`SELECT count(*) FROM local_users WHERE email = 'nia@example.com'`); n != 1 {
		t.Fatalf("accounts for nia after a second sign-in = %d, want 1", n)
	}
}

// Review: an existing account's email doesn't reach that account (or its
// roles) without linking, and the refusal is identical to any other.
func TestSSO_ExistingEmailIsRefusedLikeAnyOtherRefusal(t *testing.T) {
	h := newSSOHarness(t, nil)
	dana := h.createUser("dana@example.com", "dana-correct-pw", bcrypt.MinCost)
	h.grantAdmin(dana.ID)

	existing := h.signIn(googleClaims("attacker-sub", "dana@example.com", "example.com"))
	wrongDomain := h.signIn(googleClaims("other-sub", "sam@other.org", "other.org"))
	for name, r := range map[string]*http.Response{"existing email": existing, "wrong domain": wrongDomain} {
		if r.StatusCode != http.StatusFound || r.Header.Get("Location") != "/login?error=sso" || findCookie(r, loginTestSessionKey) != nil {
			t.Errorf("%s = %d %q (session %v); want the generic refusal and no session", name, r.StatusCode,
				r.Header.Get("Location"), findCookie(r, loginTestSessionKey) != nil)
		}
	}
	a, _ := io.ReadAll(existing.Body)
	b, _ := io.ReadAll(wrongDomain.Body)
	if !bytes.Equal(a, b) {
		t.Errorf("refusal bodies differ: %q vs %q", a, b)
	}
	if n := h.sessionsFor(dana.ID); n != 0 {
		t.Fatalf("a Google sign-in with dana's email opened %d sessions on her account", n)
	}
	if n := h.count(`SELECT count(*) FROM user_identities`); n != 0 {
		t.Fatalf("identities after refused sign-ins = %d, want 0", n)
	}
	if h.auditReasons("email_has_account") != 1 || h.auditReasons("hd_not_allowed") != 1 {
		t.Error("the audit log should carry the real reasons")
	}
}

// Review: hd must be present and allowed, even when the email's domain is.
func TestSSO_HDIsRequired(t *testing.T) {
	h := newSSOHarness(t, nil)
	for name, claims := range map[string]map[string]any{
		"no hd":        googleClaims("p1", "pat@example.com", ""),
		"different hd": googleClaims("p2", "pat2@example.com", "personal.example.net"),
	} {
		if r := h.signIn(claims); r.Header.Get("Location") != "/login?error=sso" || findCookie(r, loginTestSessionKey) != nil {
			t.Errorf("%s: sign-in = %d %q; want refused", name, r.StatusCode, r.Header.Get("Location"))
		}
	}
	if n := h.count(`SELECT count(*) FROM local_users`); n != 0 {
		t.Fatalf("accounts created without an allowed hd = %d", n)
	}
	unverified := googleClaims("p3", "pat3@example.com", "example.com")
	unverified["email_verified"] = false
	if r := h.signIn(unverified); findCookie(r, loginTestSessionKey) != nil {
		t.Error("an unverified email signed in")
	}
}

// Review: a forged Host or X-Forwarded-Host doesn't change the redirect URI.
func TestSSO_RedirectURIComesFromThePublicAddress(t *testing.T) {
	h := newSSOHarness(t, nil)
	_, rt := h.startSignIn("evil.example")
	if want := h.apiURL + "/api/v1/auth/sso/google/callback"; rt.redirectURI != want {
		t.Fatalf("redirect_uri = %q with forged headers; want %q", rt.redirectURI, want)
	}
}

// Review: the cap on waiting accounts refuses the next one, and refusals
// are aggregated in the audit log.
func TestSSO_WaitingCap(t *testing.T) {
	h := newSSOHarness(t, nil)
	if _, err := h.pool.Exec(h.t.Context(), `UPDATE sso_settings SET pending_cap = 2`); err != nil {
		t.Fatal(err)
	}
	for i, who := range []string{"a", "b"} {
		if r := h.signIn(googleClaims("cap-"+who, who+"@example.com", "example.com")); findCookie(r, loginTestSessionKey) == nil {
			t.Fatalf("sign-in %d under the cap was refused", i+1)
		}
	}
	for _, who := range []string{"c", "d", "e"} {
		if r := h.signIn(googleClaims("cap-"+who, who+"@example.com", "example.com")); findCookie(r, loginTestSessionKey) != nil {
			t.Fatalf("sign-in over the cap (%s) got a session", who)
		}
	}
	if n := h.count(`SELECT count(*) FROM local_users`); n != 2 {
		t.Fatalf("accounts = %d, want 2", n)
	}
	if n := h.count(`SELECT count(*) FROM audit_events WHERE action = 'user.pending_refused'`); n != 1 {
		t.Fatalf("user.pending_refused events for 3 refusals in one window = %d, want 1", n)
	}
	// Review S1: and no row per attempt next to the aggregate.
	if n := h.auditReasons("pending_cap"); n != 0 {
		t.Fatalf("per-attempt pending_cap rows = %d, want 0", n)
	}
}

// With approval off, a new account is active with the default role.
func TestSSO_ApprovalOffGrantsTheDefaultRole(t *testing.T) {
	role := uuid.New()
	h := newSSOHarness(t, func(lh *loginHarness, in *services.SSOProviderInput) {
		if _, err := lh.pool.Exec(t.Context(),
			`INSERT INTO roles (id, name, permissions) VALUES ($1, $2, '["secret.request"]')`, role, "sso-basic-"+role.String()[:8]); err != nil {
			t.Fatal(err)
		}
		in.RequireApproval = false
		in.DefaultRoleID = &role
	})
	r := h.signIn(googleClaims("open-1", "omar@example.com", "example.com"))
	session := findCookie(r, loginTestSessionKey)
	if session == nil {
		t.Fatal("no session")
	}
	if code, body, _ := h.authed(http.MethodGet, "/api/v1/users/me/projects", session, nil); code != http.StatusOK {
		t.Fatalf("an account created with approval off can't act: %d %s", code, body)
	}
	if n := h.count(`SELECT count(*) FROM user_roles ur JOIN local_users u ON u.id::text = ur.user_id
		WHERE u.email = 'omar@example.com' AND ur.role_id = $1 AND ur.granted_by = 'system:sso'`, role); n != 1 {
		t.Fatalf("default role grants = %d, want 1", n)
	}
	if n := h.count(`SELECT count(*) FROM audit_events WHERE action = 'user.sso_provision'`); n != 1 {
		t.Fatalf("user.sso_provision events = %d, want 1", n)
	}
}

// An admin's Test round trip reports the result to that admin only and
// creates nothing.
func TestSSO_AdminTest(t *testing.T) {
	h := newSSOHarness(t, nil)
	admin, session := h.freshSession("ada@example.com")
	h.grantAdmin(admin.ID)
	run := func(claims map[string]any) []byte {
		t.Helper()
		code, body, resp := h.authed(http.MethodPost, "/api/v1/sso/providers/"+h.provider.ID.String()+"/test", session, nil)
		if code != http.StatusOK {
			t.Fatalf("test start = %d %s", code, body)
		}
		var out struct {
			RedirectURL string `json:"redirect_url"`
		}
		_ = json.Unmarshal(body, &out)
		rt := parseAuthorize(t, out.RedirectURL, resp.Cookies())
		cb := h.callbackWith(rt, h.idp.issueCode(rt.nonce, rt.challenge, claims))
		loc := cb.Header.Get("Location")
		if findCookie(cb, loginTestSessionKey) != nil || !strings.HasPrefix(loc, "/admin/sign-in#sso_ticket=") {
			t.Fatalf("test callback = %q (session %v)", loc, findCookie(cb, loginTestSessionKey) != nil)
		}
		_, res := h.finish(session, strings.TrimPrefix(loc, "/admin/sign-in#sso_ticket="))
		return res
	}
	if res := run(googleClaims("t1", "ada@example.com", "example.com")); !strings.Contains(string(res), `"result":"ok"`) {
		t.Fatalf("a passing test = %s", res)
	}
	if res := run(googleClaims("t2", "ada@example.com", "other.org")); !strings.Contains(string(res), `"reason":"hd_not_allowed"`) {
		t.Fatalf("a failing test = %s", res)
	}
	if n := h.count(`SELECT count(*) FROM user_identities`); n != 0 {
		t.Fatalf("a test created %d identities", n)
	}
	// Review S2: both results are audited as the admin, not anonymous.
	if n := h.count(`SELECT count(*) FROM audit_events WHERE action = 'sso_provider.test' AND actor = $1`, "user:"+admin.ID.String()); n != 2 {
		t.Fatalf("sso_provider.test events by the admin = %d, want 2 (one ok, one failed)", n)
	}
}

// Review: Connect Google is bound to the session that started it, and an
// identity linked elsewhere is refused.
func TestSSO_ConnectGoogle(t *testing.T) {
	h := newSSOHarness(t, nil)
	alice, aliceSession := h.freshSession("alice@example.com")
	bob, bobSession := h.freshSession("bob@example.com")
	aliceGoogle := googleClaims("alice-google", "alice@example.com", "example.com")

	t.Run("a ticket redeemed on another session is refused", func(t *testing.T) {
		ticket := h.connect(aliceSession, aliceGoogle)
		if code, body := h.finish(bobSession, ticket); code != http.StatusForbidden {
			t.Fatalf("bob redeeming alice's ticket = %d %s; want 403", code, body)
		}
		if n := h.count(`SELECT count(*) FROM user_identities`); n != 0 {
			t.Fatalf("identities after the refused redeem = %d, want 0", n)
		}
	})

	t.Run("the starting session links its own account", func(t *testing.T) {
		ticket := h.connect(aliceSession, aliceGoogle)
		if code, body := h.finish(aliceSession, ticket); code != http.StatusOK || !strings.Contains(string(body), `"linked"`) {
			t.Fatalf("alice redeeming her ticket = %d %s", code, body)
		}
		if code, _ := h.finish(aliceSession, ticket); code != http.StatusForbidden {
			t.Fatalf("a ticket redeemed twice = %d; want 403", code)
		}
		r := h.signIn(aliceGoogle)
		session := findCookie(r, loginTestSessionKey)
		if session == nil {
			t.Fatal("the linked Google identity didn't sign in")
		}
		if n := h.sessionsFor(alice.ID); n < 2 {
			t.Fatalf("Google sign-in didn't land on alice's account (sessions %d)", n)
		}
	})

	t.Run("an identity linked elsewhere is refused", func(t *testing.T) {
		ticket := h.connect(bobSession, aliceGoogle)
		code, body := h.finish(bobSession, ticket)
		if code != http.StatusConflict || !strings.Contains(string(body), "identity_taken") {
			t.Fatalf("bob linking alice's Google = %d %s; want 409 identity_taken", code, body)
		}
		// Review S2: the refused link is audited as bob.
		if n := h.count(`SELECT count(*) FROM audit_events WHERE metadata->>'error_kind' = 'identity_taken' AND actor = $1`, "user:"+bob.ID.String()); n != 1 {
			t.Fatalf("identity_taken refusals audited as bob = %d, want 1", n)
		}
	})

	t.Run("connecting needs a fresh second factor", func(t *testing.T) {
		if _, err := h.pool.Exec(h.t.Context(), `UPDATE sessions SET last_mfa_at = NULL`); err != nil {
			t.Fatal(err)
		}
		if code, body, _ := h.authed(http.MethodPost, "/api/v1/auth/sso/google/connect", bobSession, nil); code == http.StatusOK {
			t.Fatalf("connect without a fresh second factor = %d %s", code, body)
		}
	})

	t.Run("disconnect, then the identity can't sign in", func(t *testing.T) {
		if _, err := h.pool.Exec(h.t.Context(), `UPDATE sessions SET last_mfa_at = now()`); err != nil {
			t.Fatal(err)
		}
		if code, body, _ := h.authed(http.MethodDelete, "/api/v1/users/me/identities/google", aliceSession, nil); code != http.StatusNoContent {
			t.Fatalf("disconnect = %d %s", code, body)
		}
		if r := h.signIn(aliceGoogle); findCookie(r, loginTestSessionKey) != nil {
			t.Fatal("a disconnected identity still signed in")
		}
		if n := h.count(`SELECT count(*) FROM audit_events WHERE action IN ('user.identity_link','user.identity_unlink')`); n != 2 {
			t.Fatalf("link and unlink audit events = %d, want 2", n)
		}
	})
}

// A provider change takes effect on the next round trip, no restart.
func TestSSO_ChangesTakeEffectWithoutRestart(t *testing.T) {
	h := newSSOHarness(t, nil)
	if _, err := h.pool.Exec(h.t.Context(), `UPDATE sso_providers SET client_id = 'changed-client'`); err != nil {
		t.Fatal(err)
	}
	if _, rt := h.startSignIn(""); rt.clientID != "changed-client" {
		t.Fatalf("client_id after a change = %q; want the new one", rt.clientID)
	}
	code, body, _ := h.authed(http.MethodGet, "/api/v1/auth/providers", nil, nil)
	if code != http.StatusOK || !strings.Contains(string(body), `"google"`) || strings.Contains(string(body), ssoClientSecret) {
		t.Fatalf("provider list = %d %s", code, body)
	}
	if _, err := h.pool.Exec(h.t.Context(), `UPDATE sso_providers SET enabled = FALSE`); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, h.apiURL+"/api/v1/auth/sso/google/start", nil)
	if r := h.do(req); r.Header.Get("Location") != "/login?error=sso" {
		t.Fatalf("start on a disabled provider = %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	if _, body, _ := h.authed(http.MethodGet, "/api/v1/auth/providers", nil, nil); strings.Contains(string(body), `"google"`) {
		t.Fatalf("a disabled provider is still listed: %s", body)
	}
	if n := h.count(`SELECT count(*) FROM audit_events WHERE metadata::text LIKE '%' || $1 || '%'`, ssoClientSecret); n != 0 {
		t.Fatalf("the client secret appears in %d audit rows", n)
	}
}

// staleSecondFactor gives the account an enrolled second factor and makes its
// sessions stale, so a step-up route answers the challenge (401) rather
// than "enroll a factor first" (412).
func (h *ssoHarness) staleSecondFactor(userID uuid.UUID) {
	h.t.Helper()
	if _, err := h.pool.Exec(h.t.Context(), `
		INSERT INTO user_mfa_factors (user_id, kind, label, secret_ciphertext, secret_nonce, data_key_ciphertext, kms_key_id)
		VALUES ($1, 'totp', 'test', '\x00', '\x00', '\x00', 'test')`, userID); err != nil {
		h.t.Fatal(err)
	}
	if _, err := h.pool.Exec(h.t.Context(), `UPDATE sessions SET last_mfa_at = NULL WHERE user_id = $1`, userID); err != nil {
		h.t.Fatal(err)
	}
}

func (h *ssoHarness) accounts() int { return h.count(`SELECT count(*) FROM local_users`) }

// Review B1: the default role is checked again at every sign-in. Widened
// after the provider was saved, it isn't granted: the account waits for
// approval instead, and the refusal is audited.
func TestSSO_WidenedDefaultRoleIsNotGranted(t *testing.T) {
	role := uuid.New()
	h := newSSOHarness(t, func(lh *loginHarness, in *services.SSOProviderInput) {
		if _, err := lh.pool.Exec(t.Context(),
			`INSERT INTO roles (id, name, permissions) VALUES ($1, $2, '["secret.request"]')`, role, "sso-widen-"+role.String()[:8]); err != nil {
			t.Fatal(err)
		}
		in.RequireApproval = false
		in.DefaultRoleID = &role
	})
	// The api now refuses this edit (TestSSO_DefaultRoleCantBeWidenedOrDeleted),
	// so widen it in the database, as an older api, a migration or psql
	// could have: sign-in must still not grant it.
	if _, err := h.pool.Exec(t.Context(),
		`UPDATE roles SET permissions = '["secret.request", "secret.reveal.direct", "user_role.edit"]' WHERE id = $1`, role); err != nil {
		t.Fatal(err)
	}

	r := h.signIn(googleClaims("wide-1", "wes@example.com", "example.com"))
	session := findCookie(r, loginTestSessionKey)
	if session == nil {
		t.Fatal("no session")
	}
	if n := h.count(`SELECT count(*) FROM user_roles ur JOIN local_users u ON u.id::text = ur.user_id WHERE u.email = 'wes@example.com'`); n != 0 {
		t.Fatalf("the widened default role was granted (%d grants)", n)
	}
	if code, body, _ := h.authed(http.MethodGet, "/api/v1/users/me/projects", session, nil); code != http.StatusForbidden || !strings.Contains(string(body), "account_pending_approval") {
		t.Fatalf("the account isn't waiting for approval: %d %s", code, body)
	}
	if n := h.count(`SELECT count(*) FROM audit_events WHERE action = 'sso_provider.default_role_refused' AND metadata->>'reason' = 'default_role_privileged'`); n != 1 {
		t.Fatalf("default_role_refused audit events = %d, want 1", n)
	}
}

// Review B2: an account that a Google sign-in created has no password
// anyone knows. /users/me says so, and its Google identity can't be
// disconnected, so it can't lock itself out.
func TestSSO_AccountCreatedByGoogleKeepsItsIdentity(t *testing.T) {
	h := newSSOHarness(t, func(_ *loginHarness, in *services.SSOProviderInput) { in.RequireApproval = false })
	pat := googleClaims("pat-1", "pat@example.com", "example.com")
	session := findCookie(h.signIn(pat), loginTestSessionKey)
	if session == nil {
		t.Fatal("no session")
	}
	if _, body, _ := h.authed(http.MethodGet, "/api/v1/users/me", session, nil); !strings.Contains(string(body), `"has_password":false`) {
		t.Fatalf("/users/me for a Google-created account = %s; want has_password false", body)
	}
	if _, err := h.pool.Exec(h.t.Context(), `UPDATE sessions SET last_mfa_at = now()`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(h.t.Context(), `
		INSERT INTO user_mfa_factors (user_id, kind, label, secret_ciphertext, secret_nonce, data_key_ciphertext, kms_key_id)
		SELECT id, 'totp', 'test', '\x00', '\x00', '\x00', 'test' FROM local_users WHERE email = 'pat@example.com'`); err != nil {
		t.Fatal(err)
	}
	code, body, _ := h.authed(http.MethodDelete, "/api/v1/users/me/identities/google", session, nil)
	if code != http.StatusConflict || !strings.Contains(string(body), "identity_required") {
		t.Fatalf("disconnecting the only way in = %d %s; want 409 identity_required", code, body)
	}
	if findCookie(h.signIn(pat), loginTestSessionKey) == nil {
		t.Fatal("the account can't sign in with Google any more")
	}

	_, local := h.freshSession("lee@example.com")
	if _, body, _ := h.authed(http.MethodGet, "/api/v1/users/me", local, nil); !strings.Contains(string(body), `"has_password":true`) {
		t.Fatalf("/users/me for a password account = %s; want has_password true", body)
	}
}

// Review S3: the state cookie must be this browser's. A callback with no
// cookie, or another browser's, is refused even though the state itself
// is valid.
func TestSSO_StateCookieMustMatch(t *testing.T) {
	h := newSSOHarness(t, nil)
	claims := googleClaims("sc-1", "sam@example.com", "example.com")

	_, rt := h.startSignIn("")
	rt.cookie = nil
	if r := h.callbackWith(rt, h.idp.issueCode(rt.nonce, rt.challenge, claims)); findCookie(r, loginTestSessionKey) != nil {
		t.Fatal("a callback without the state cookie signed in")
	}
	_, rt = h.startSignIn("")
	_, other := h.startSignIn("")
	rt.cookie = other.cookie
	if r := h.callbackWith(rt, h.idp.issueCode(rt.nonce, rt.challenge, claims)); findCookie(r, loginTestSessionKey) != nil {
		t.Fatal("a callback with another browser's state cookie signed in")
	}
	if n := h.accounts(); n != 0 || h.auditReasons("state_cookie") != 2 {
		t.Fatalf("accounts %d, state_cookie refusals %d; want 0 and 2", n, h.auditReasons("state_cookie"))
	}
}

// Review S3: an ID token issued for another round trip's nonce is refused.
func TestSSO_NonceMustMatch(t *testing.T) {
	h := newSSOHarness(t, nil)
	_, rt := h.startSignIn("")
	claims := googleClaims("n-1", "nia@example.com", "example.com")
	claims["nonce"] = "another-round-trip"
	if r := h.callbackWith(rt, h.idp.issueCode(rt.nonce, rt.challenge, claims)); findCookie(r, loginTestSessionKey) != nil {
		t.Fatal("an ID token with the wrong nonce signed in")
	}
	if h.accounts() != 0 || h.auditReasons("nonce_mismatch") != 1 {
		t.Fatalf("accounts %d, nonce_mismatch refusals %d", h.accounts(), h.auditReasons("nonce_mismatch"))
	}
}

// Review S3: with hd allowed, the email's own domain must be allowed too.
func TestSSO_EmailDomainMustBeAllowedToo(t *testing.T) {
	h := newSSOHarness(t, nil)
	if r := h.signIn(googleClaims("ed-1", "pat@other.org", "example.com")); findCookie(r, loginTestSessionKey) != nil {
		t.Fatal("an email outside the allowed domains signed in")
	}
	if h.accounts() != 0 || h.auditReasons("email_domain_not_allowed") != 1 {
		t.Fatalf("accounts %d, email_domain_not_allowed refusals %d", h.accounts(), h.auditReasons("email_domain_not_allowed"))
	}
}

// Review S3: disconnecting Google and starting an admin test both need a
// fresh second factor.
func TestSSO_StepUpOnDisconnectAndTest(t *testing.T) {
	h := newSSOHarness(t, nil)
	alice, session := h.freshSession("alice@example.com")
	h.grantAdmin(alice.ID)
	if code, body := h.finish(session, h.connect(session, googleClaims("alice-g", "alice@example.com", "example.com"))); code != http.StatusOK {
		t.Fatalf("connect = %d %s", code, body)
	}
	h.staleSecondFactor(alice.ID)

	if code, body, _ := h.authed(http.MethodDelete, "/api/v1/users/me/identities/google", session, nil); code != http.StatusUnauthorized || !strings.Contains(string(body), "step_up_required") {
		t.Fatalf("disconnect without a fresh second factor = %d %s; want 401", code, body)
	}
	if n := h.count(`SELECT count(*) FROM user_identities`); n != 1 {
		t.Fatalf("identities = %d after a refused disconnect", n)
	}
	if code, body, _ := h.authed(http.MethodPost, "/api/v1/sso/providers/"+h.provider.ID.String()+"/test", session, nil); code != http.StatusUnauthorized || !strings.Contains(string(body), "step_up_required") {
		t.Fatalf("test without a fresh second factor = %d %s; want 401", code, body)
	}
}

// Review S3: a provider turned off while someone is at Google refuses the
// callback.
func TestSSO_ProviderTurnedOffMidRoundTrip(t *testing.T) {
	h := newSSOHarness(t, nil)
	_, rt := h.startSignIn("")
	if _, err := h.pool.Exec(h.t.Context(), `UPDATE sso_providers SET enabled = FALSE`); err != nil {
		t.Fatal(err)
	}
	if r := h.callbackWith(rt, h.idp.issueCode(rt.nonce, rt.challenge, googleClaims("off-1", "oz@example.com", "example.com"))); findCookie(r, loginTestSessionKey) != nil {
		t.Fatal("a callback after the provider was turned off signed in")
	}
	if h.accounts() != 0 || h.auditReasons("provider_disabled") != 1 {
		t.Fatalf("accounts %d, provider_disabled refusals %d", h.accounts(), h.auditReasons("provider_disabled"))
	}
}

// Review nit: go-oidc checks exp but not iat. An ID token issued long ago,
// or in the future, is refused.
func TestSSO_IssuedAtMustBeRecent(t *testing.T) {
	h := newSSOHarness(t, nil)
	for i, iat := range []int64{time.Now().Add(-time.Hour).Unix(), time.Now().Add(time.Hour).Unix()} {
		claims := googleClaims(fmt.Sprintf("iat-%d", i), fmt.Sprintf("iat%d@example.com", i), "example.com")
		claims["iat"] = iat
		if r := h.signIn(claims); findCookie(r, loginTestSessionKey) != nil {
			t.Fatalf("an ID token with iat %d signed in", iat)
		}
	}
	if h.accounts() != 0 || h.auditReasons("iat_invalid") != 2 {
		t.Fatalf("accounts %d, iat_invalid refusals %d", h.accounts(), h.auditReasons("iat_invalid"))
	}
}

// Review (ui#155): a Connect cancelled at Google comes back to the profile
// with a ticket that explains it, not to the login page.
func TestSSO_CancelledConnectComesBackToTheProfile(t *testing.T) {
	h := newSSOHarness(t, nil)
	_, session := h.freshSession("cy@example.com")
	code, body, resp := h.authed(http.MethodPost, "/api/v1/auth/sso/google/connect", session, nil)
	if code != http.StatusOK {
		t.Fatalf("connect = %d %s", code, body)
	}
	var out struct {
		RedirectURL string `json:"redirect_url"`
	}
	_ = json.Unmarshal(body, &out)
	rt := parseAuthorize(t, out.RedirectURL, resp.Cookies())
	q := url.Values{"state": {rt.state}, "error": {"access_denied"}}
	req, _ := http.NewRequest(http.MethodGet, h.apiURL+"/api/v1/auth/sso/google/callback?"+q.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: rt.cookie.Name, Value: rt.cookie.Value})
	cb := h.do(req)
	loc := cb.Header.Get("Location")
	if !strings.HasPrefix(loc, "/me#sso_ticket=") {
		t.Fatalf("a cancelled connect went to %q; want the profile page", loc)
	}
	if code, body := h.finish(session, strings.TrimPrefix(loc, "/me#sso_ticket=")); code != http.StatusConflict || !strings.Contains(string(body), `"reason":"no_code"`) {
		t.Fatalf("finish = %d %s; want 409 with reason no_code", code, body)
	}
}

// Review (ui#155): a Connect whose provider is removed while the user is
// at Google also comes back to the profile with a ticket. It used to end
// on the login page before any ticket existed.
func TestSSO_ConnectWithTheProviderGoneComesBackToTheProfile(t *testing.T) {
	h := newSSOHarness(t, nil)
	_, session := h.freshSession("di@example.com")
	code, body, resp := h.authed(http.MethodPost, "/api/v1/auth/sso/google/connect", session, nil)
	if code != http.StatusOK {
		t.Fatalf("connect = %d %s", code, body)
	}
	var out struct {
		RedirectURL string `json:"redirect_url"`
	}
	_ = json.Unmarshal(body, &out)
	rt := parseAuthorize(t, out.RedirectURL, resp.Cookies())
	if _, err := h.pool.Exec(h.t.Context(), `DELETE FROM sso_providers`); err != nil {
		t.Fatal(err)
	}
	cb := h.callbackWith(rt, h.idp.issueCode(rt.nonce, rt.challenge, googleClaims("di-g", "di@example.com", "example.com")))
	loc := cb.Header.Get("Location")
	if !strings.HasPrefix(loc, "/me#sso_ticket=") {
		t.Fatalf("connect with the provider gone went to %q; want the profile page", loc)
	}
	if code, body := h.finish(session, strings.TrimPrefix(loc, "/me#sso_ticket=")); code != http.StatusConflict || !strings.Contains(string(body), `"reason":"no_provider"`) {
		t.Fatalf("finish = %d %s; want 409 with reason no_provider", code, body)
	}
}

// hatmast2r's pass: a role that a provider gives to new accounts can't be
// widened through the API, and can't be deleted while it's the default
// (409, not 500).
func TestSSO_DefaultRoleCantBeWidenedOrDeleted(t *testing.T) {
	role, other := uuid.New(), uuid.New()
	h := newSSOHarness(t, func(lh *loginHarness, in *services.SSOProviderInput) {
		for _, id := range []uuid.UUID{role, other} {
			if _, err := lh.pool.Exec(t.Context(), `INSERT INTO roles (id, name, permissions) VALUES ($1, $2, '["secret.request"]')`,
				id, "sso-guard-"+id.String()[:8]); err != nil {
				t.Fatal(err)
			}
		}
		in.RequireApproval = false
		in.DefaultRoleID = &role
	})
	admin, session := h.freshSession("ada@example.com")
	h.grantAdmin(admin.ID)
	put := func(id uuid.UUID, perms ...string) (int, []byte) {
		code, body, _ := h.authed(http.MethodPut, "/api/v1/roles/"+id.String()+"/permissions", session, map[string]any{"permissions": perms})
		return code, body
	}
	if code, body := put(role, "secret.request", "secret.reveal.direct"); code != http.StatusConflict || !strings.Contains(string(body), "role_is_sso_default") {
		t.Fatalf("widening the default role = %d %s; want 409 role_is_sso_default", code, body)
	}
	if n := h.count(`SELECT count(*) FROM roles WHERE id = $1 AND permissions ? 'secret.reveal.direct'`, role); n != 0 {
		t.Fatal("the refused edit changed the role")
	}
	if code, body := put(role, "secret.request", "secret.list", "audit.read"); code != http.StatusNoContent {
		t.Fatalf("a non-privileged edit of the default role = %d %s; want 204", code, body)
	}
	if code, body := put(other, "secret.request", "secret.reveal.direct"); code != http.StatusNoContent {
		t.Fatalf("widening a role no provider uses = %d %s; want 204", code, body)
	}
	code, body, _ := h.authed(http.MethodDelete, "/api/v1/roles/"+role.String(), session, nil)
	if code != http.StatusConflict {
		t.Fatalf("deleting the default role = %d %s; want 409", code, body)
	}
	if n := h.count(`SELECT count(*) FROM roles WHERE id = $1`, role); n != 1 {
		t.Fatal("the default role was deleted")
	}
}

// hatmast2r's pass: with no public address (cleared in the console, or
// SB_PUBLIC_URL removed later) sign-in fails closed. Google isn't
// offered, start refuses, and a forged Host never becomes the redirect.
func TestSSO_NoPublicAddressFailsClosed(t *testing.T) {
	h := newSSOHarness(t, nil)
	if _, err := h.pool.Exec(h.t.Context(), `UPDATE sso_settings SET public_url = NULL`); err != nil {
		t.Fatal(err)
	}
	if _, body, _ := h.authed(http.MethodGet, "/api/v1/auth/providers", nil, nil); strings.Contains(string(body), `"google"`) {
		t.Fatalf("Google is offered without a public address: %s", body)
	}
	for _, host := range []string{"", "evil.example"} {
		req, _ := http.NewRequest(http.MethodGet, h.apiURL+"/api/v1/auth/sso/google/start", nil)
		if host != "" {
			req.Host = host
			req.Header.Set("X-Forwarded-Host", host)
			req.Header.Set("X-Forwarded-Proto", "https")
		}
		r := h.do(req)
		if loc := r.Header.Get("Location"); r.StatusCode != http.StatusFound || loc != "/login?error=sso" {
			t.Fatalf("start without a public address (host %q) = %d %q; want the refusal page", host, r.StatusCode, loc)
		}
	}
	if n := h.auditReasons("no_public_url"); n != 2 {
		t.Fatalf("no_public_url refusals = %d, want 2", n)
	}
}

// hatmast2r's pass: the hd and domain checks run on every sign-in, not
// only when the identity is first bound. An identity whose domain is
// later removed (or a provider deleted and added again with other
// domains) is refused.
func TestSSO_DomainsAreCheckedOnEverySignIn(t *testing.T) {
	h := newSSOHarness(t, func(_ *loginHarness, in *services.SSOProviderInput) { in.RequireApproval = false })
	pat := googleClaims("dom-1", "pat@example.com", "example.com")
	if findCookie(h.signIn(pat), loginTestSessionKey) == nil {
		t.Fatal("first sign-in refused")
	}
	if _, err := h.pool.Exec(h.t.Context(), `UPDATE sso_providers SET allowed_domains = '{other.org}'`); err != nil {
		t.Fatal(err)
	}
	if findCookie(h.signIn(pat), loginTestSessionKey) != nil {
		t.Fatal("an identity outside the allowed domains signed in again")
	}
	if n := h.auditReasons("hd_not_allowed"); n != 1 {
		t.Fatalf("hd_not_allowed refusals = %d, want 1", n)
	}
}

// hatmast2r's pass: a client secret sent with a normal edit is refused,
// not silently ignored. It changes only through PUT .../secret, which
// audits the rotation.
func TestSSO_EditDoesNotTakeASecret(t *testing.T) {
	h := newSSOHarness(t, nil)
	admin, session := h.freshSession("ada@example.com")
	h.grantAdmin(admin.ID)
	var before []byte
	if err := h.pool.QueryRow(h.t.Context(), `SELECT client_secret_ciphertext FROM sso_providers`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	code, body, _ := h.authed(http.MethodPut, "/api/v1/sso/providers/"+h.provider.ID.String(), session, map[string]any{
		"client_id": loginTestClientID, "client_secret": "GOCSPX-sent-with-an-edit", "allowed_domains": []string{"example.com"}, "require_approval": true,
	})
	if code != http.StatusBadRequest || !strings.Contains(string(body), "client_secret") {
		t.Fatalf("an edit with a client secret = %d %s; want 400 naming client_secret", code, body)
	}
	var after []byte
	if err := h.pool.QueryRow(h.t.Context(), `SELECT client_secret_ciphertext FROM sso_providers`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("the refused edit changed the stored secret")
	}
}

// Review follow-up: default_role_refused is audited only when an account
// was created waiting because of it, not for a sign-in the waiting cap
// turned away.
func TestSSO_DefaultRoleRefusedAuditedOnlyForACreatedAccount(t *testing.T) {
	role := uuid.New()
	h := newSSOHarness(t, func(lh *loginHarness, in *services.SSOProviderInput) {
		if _, err := lh.pool.Exec(t.Context(), `INSERT INTO roles (id, name, permissions) VALUES ($1, $2, '["secret.request"]')`,
			role, "sso-audit-"+role.String()[:8]); err != nil {
			t.Fatal(err)
		}
		in.RequireApproval = false
		in.DefaultRoleID = &role
	})
	if _, err := h.pool.Exec(t.Context(), `UPDATE roles SET permissions = '["secret.request", "secret.reveal.direct"]' WHERE id = $1`, role); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(t.Context(), `UPDATE sso_settings SET pending_cap = 1`); err != nil {
		t.Fatal(err)
	}
	refused := func() int {
		return h.count(`SELECT count(*) FROM audit_events WHERE action = 'sso_provider.default_role_refused'`)
	}
	if findCookie(h.signIn(googleClaims("ar-1", "first@example.com", "example.com")), loginTestSessionKey) == nil || refused() != 1 {
		t.Fatalf("first sign-in: refused events = %d, want 1", refused())
	}
	if findCookie(h.signIn(googleClaims("ar-2", "second@example.com", "example.com")), loginTestSessionKey) != nil {
		t.Fatal("a sign-in over the waiting cap got a session")
	}
	if n := refused(); n != 1 {
		t.Fatalf("refused events after a cap refusal = %d, want still 1", n)
	}
}
