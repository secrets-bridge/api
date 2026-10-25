package main

// skills#116 against the real route table: two-step enrollment, the key
// fingerprint check, no key substitution route, the admin rotation token
// behind agent.mint and a fresh second factor, rotation end to end,
// revoke killing an open rotation, rate limits and redaction.

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// resetAgentEnrollLimits clears the per-IP enroll bucket and the agent
// audit rollup slots, which every test in this package shares.
func resetAgentEnrollLimits(t *testing.T) {
	t.Helper()
	opt, err := redis.ParseURL(os.Getenv("TEST_REDIS_URL"))
	if err != nil {
		t.Fatalf("redis url: %v", err)
	}
	rc := redis.NewClient(opt)
	defer func() { _ = rc.Close() }()
	ctx := t.Context()
	for _, pat := range []string{"*agent:enroll*", "*agent:key-rotation*", "*agent-*-audit*"} {
		iter := rc.Scan(ctx, 0, pat, 100).Iterator()
		for iter.Next(ctx) {
			_ = rc.Del(ctx, iter.Val()).Err()
		}
	}
}

type v2Fixture struct {
	l      *liveApp
	op     string // header user with agent.mint and integration.edit
	connID uuid.UUID
}

func newV2Fixture(t *testing.T) *v2Fixture {
	t.Helper()
	l := newLiveApp(t)
	resetAgentEnrollLimits(t)
	t.Cleanup(func() { resetAgentEnrollLimits(t) })
	op := l.grantUser(t, []string{"agent.mint", "agent.list", "agent.revoke", "integration.edit"}, `{}`)
	code, body := l.call(t, http.MethodPost, "/api/v1/provider-connections", op, map[string]any{
		"name": "v2-conn", "type": "aws-sm", "auth_method": "default",
		"scope": map[string]string{"region": "eu-central-1"}, "cluster_name": "tenant-a-uat", "discover_interval_seconds": 300,
	})
	if code != http.StatusCreated {
		t.Fatalf("create connection = %d %s", code, body)
	}
	var c struct{ ID uuid.UUID }
	mustJSON(t, body, &c)
	return &v2Fixture{l: l, op: op, connID: c.ID}
}

func (f *v2Fixture) token(t *testing.T) string {
	t.Helper()
	code, body := f.l.call(t, http.MethodPost, "/api/v1/provider-connections/"+f.connID.String()+"/agent-enrollment-token", f.op, map[string]any{})
	if code != http.StatusCreated {
		t.Fatalf("enrollment token = %d %s", code, body)
	}
	var res struct {
		EnrollmentToken string `json:"enrollment_token"`
	}
	mustJSON(t, body, &res)
	return res.EnrollmentToken
}

type v2Agent struct {
	id     string
	secret string
	c      *enrollClient
}

func (f *v2Fixture) enroll(t *testing.T, token, name string) v2Agent {
	t.Helper()
	c := newEnrollClient(t)
	code, body := f.l.call(t, http.MethodPost, "/api/v1/agents/enroll/challenge", "", c.challengeBody(token))
	if code != http.StatusOK {
		t.Fatalf("challenge = %d %s", code, body)
	}
	chID, resp, err := c.open(body)
	if err != nil {
		t.Fatal(err)
	}
	code, body = f.l.call(t, http.MethodPost, "/api/v1/agents/enroll", "", map[string]any{
		"schema_version": "2", "enrollment_token": token, "challenge_id": chID, "challenge_response": resp,
		"name": name, "cluster_name": "tenant-a-uat", "provider_type": "aws-sm", "region": "eu-central-1",
	})
	if code != http.StatusCreated {
		t.Fatalf("enroll = %d %s", code, body)
	}
	var res map[string]any
	mustJSON(t, body, &res)
	for _, k := range []string{"agent_id", "agent_secret", "public_key_fingerprint", "public_key_version", "heartbeat_interval_seconds", "claim_interval_seconds"} {
		if _, ok := res[k]; !ok {
			t.Fatalf("enroll response lacks %s: %s", k, body)
		}
	}
	if res["public_key_fingerprint"] != c.fingerprint() || res["public_key_version"] != float64(1) {
		t.Fatalf("enroll response %s", body)
	}
	return v2Agent{id: res["agent_id"].(string), secret: res["agent_secret"].(string), c: c}
}

func (f *v2Fixture) heartbeat(t *testing.T, a v2Agent, fingerprint string) (int, string) {
	t.Helper()
	hdr := map[string]string{"X-Agent-Secret": a.secret}
	if fingerprint != "" {
		hdr["X-Agent-Key-Fingerprint"] = fingerprint
	}
	code, body := f.l.callAs(t, http.MethodPost, "/api/v1/agents/"+a.id+"/heartbeat", hdr, nil)
	return code, string(body)
}

func TestLive_EnrollV2_HappyPathAndErrors(t *testing.T) {
	f := newV2Fixture(t)
	tok := f.token(t)
	a := f.enroll(t, tok, "v2-agent")

	if code, body := f.heartbeat(t, a, a.c.fingerprint()); code != http.StatusNoContent {
		t.Fatalf("heartbeat with the bound key = %d %s", code, body)
	}
	if code, body := f.heartbeat(t, a, ""); code != http.StatusConflict || !strings.Contains(body, `"agent_key_mismatch"`) {
		t.Fatalf("heartbeat without a fingerprint = %d %s; want 409", code, body)
	}
	other := newEnrollClient(t)
	if code, body := f.heartbeat(t, a, other.fingerprint()); code != http.StatusConflict {
		t.Fatalf("heartbeat with another key = %d %s; want 409", code, body)
	}

	// The admin projection carries the key's fingerprint, version and
	// algorithm, never the key.
	code, body := f.l.call(t, http.MethodGet, "/api/v1/admin/agents/"+a.id, f.op, nil)
	if code != http.StatusOK {
		t.Fatalf("admin get = %d %s", code, body)
	}
	var item map[string]any
	mustJSON(t, body, &item)
	if item["public_key_fingerprint"] != a.c.fingerprint() || item["public_key_version"] != float64(1) || item["public_key_algorithm"] != "x25519" {
		t.Fatalf("admin projection %s", body)
	}
	if strings.Contains(string(body), base64.StdEncoding.EncodeToString(a.c.pub)) {
		t.Fatal("admin projection carries the public key")
	}

	// Generic error bodies.
	for name, c := range map[string]struct {
		path string
		body map[string]any
		code int
		want string
	}{
		"used token":      {"/api/v1/agents/enroll/challenge", newEnrollClient(t).challengeBody(tok), 401, "enrollment_rejected"},
		"unknown token":   {"/api/v1/agents/enroll/challenge", newEnrollClient(t).challengeBody("nope"), 401, "enrollment_rejected"},
		"zero key":        {"/api/v1/agents/enroll/challenge", map[string]any{"schema_version": "2", "enrollment_token": tok, "public_key": base64.StdEncoding.EncodeToString(make([]byte, 32)), "public_key_algorithm": "x25519"}, 400, "invalid_public_key"},
		"no schema":       {"/api/v1/agents/enroll/challenge", map[string]any{"enrollment_token": tok, "public_key": base64.StdEncoding.EncodeToString(other.pub), "public_key_algorithm": "x25519"}, 400, "unsupported_schema_version"},
		"v1 enroll shape": {"/api/v1/agents/enroll", map[string]any{"enrollment_token": tok, "agent_name": "legacy"}, 400, "unsupported_schema_version"},
	} {
		code, body := f.l.call(t, http.MethodPost, c.path, "", c.body)
		if code != c.code || string(body) != `{"error":"`+c.want+`"}` {
			t.Errorf("%s: %d %s; want %d %s", name, code, body, c.code, c.want)
		}
	}

	// Nothing secret in the logs or audit rows.
	var audit string
	_ = f.l.pool.QueryRow(t.Context(), `SELECT coalesce(string_agg(metadata::text, ' '), '') FROM audit_events`).Scan(&audit)
	for _, s := range []string{tok, a.secret} {
		if strings.Contains(f.l.logs.String(), s) || strings.Contains(audit, s) {
			t.Fatal("token or agent secret in the logs or audit")
		}
	}
}

// The enroll routes are rate limited per client IP.
func TestLive_EnrollV2_RateLimited(t *testing.T) {
	f := newV2Fixture(t)
	got429 := false
	for i := 0; i < 40; i++ {
		code, body := f.l.call(t, http.MethodPost, "/api/v1/agents/enroll/challenge", "", newEnrollClient(t).challengeBody("nope"))
		if code == http.StatusTooManyRequests {
			got429 = true
			break
		}
		if code != http.StatusUnauthorized {
			t.Fatalf("challenge %d = %d %s", i, code, body)
		}
	}
	if !got429 {
		t.Fatal("40 enroll attempts from one address were never rate limited")
	}
}

// No public-key substitution: the PUT route is gone, and no agent-side
// route other than the rotation pair is a write that could touch the key.
func TestLive_EnrollV2_NoKeySubstitutionRoute(t *testing.T) {
	f := newV2Fixture(t)
	a := f.enroll(t, f.token(t), "v2-nosub")
	hdr := map[string]string{"X-Agent-Secret": a.secret, "X-Agent-Key-Fingerprint": a.c.fingerprint()}
	for _, m := range []string{http.MethodPut, http.MethodPost, http.MethodPatch} {
		code, _ := f.l.callAs(t, m, "/api/v1/agents/"+a.id+"/public-key", hdr, map[string]any{
			"public_key": base64.StdEncoding.EncodeToString(newEnrollClient(t).pub), "public_key_algorithm": "x25519",
		})
		if code != http.StatusNotFound && code != http.StatusMethodNotAllowed {
			t.Errorf("%s /public-key = %d; want 404/405", m, code)
		}
	}
	var fp string
	_ = f.l.pool.QueryRow(t.Context(), `SELECT public_key_fingerprint FROM agents WHERE id = $1`, a.id).Scan(&fp)
	if fp != a.c.fingerprint() {
		t.Fatal("the key changed")
	}

	reviewed := map[string]bool{
		"POST /api/v1/agents/:id/heartbeat":              true,
		"POST /api/v1/agents/:id/jobs/claim":             true,
		"POST /api/v1/agents/:id/jobs/:job/complete":     true,
		"GET /api/v1/agents/:id/wraps/:wrap_id":          true,
		"POST /api/v1/agents/:id/wraps":                  true,
		"POST /api/v1/agents/:id/dek":                    true,
		"POST /api/v1/agents/:id/secrets/bulk":           true,
		"POST /api/v1/agents/:id/revoke":                 true,
		"POST /api/v1/agents/:id/key-rotation/challenge": true,
		"POST /api/v1/agents/:id/key-rotation":           true,
		"POST /api/v1/agents/enroll/challenge":           true,
		"POST /api/v1/agents/enroll":                     true,
	}
	for _, r := range f.l.app.GetRoutes(true) {
		if !strings.HasPrefix(r.Path, "/api/v1/agents/") || r.Method == http.MethodHead {
			continue
		}
		if strings.Contains(r.Path, "public-key") || !reviewed[r.Method+" "+r.Path] {
			t.Errorf("unreviewed route under /api/v1/agents/: %s %s", r.Method, r.Path)
		}
	}
}

// Rotation end to end over the real routes, behind agent.mint and a
// fresh second factor, and a revoke that kills an open rotation.
func TestLive_EnrollV2_RotationAndRevoke(t *testing.T) {
	f := newV2Fixture(t)
	ctx := t.Context()
	a := f.enroll(t, f.token(t), "v2-rot")
	path := "/api/v1/admin/agents/" + a.id + "/key-rotation"

	// No session: 401. Session without agent.mint: 403. agent.mint with
	// a stale second factor: 401 step-up.
	if code, _ := f.l.callAs(t, http.MethodPost, path, nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("anonymous rotation = %d", code)
	}
	noPerm := uuid.New()
	noPermHdr := map[string]string{"Cookie": f.l.sessionFor(t, noPerm, "v2-noperm@example.com")}
	f.l.addGrant(t, noPerm.String(), []string{"agent.list"}, `{}`)
	if code, _ := f.l.callAs(t, http.MethodPost, path, noPermHdr, nil); code != http.StatusForbidden {
		t.Fatalf("rotation without agent.mint = %d", code)
	}
	stale := uuid.New()
	staleHdr := map[string]string{"Cookie": f.l.sessionFor(t, stale, "v2-stale@example.com")}
	f.l.addGrant(t, stale.String(), []string{"agent.mint"}, `{}`)
	if _, err := f.l.pool.Exec(ctx, `
		INSERT INTO user_mfa_factors (user_id, kind, label, secret_ciphertext, secret_nonce, data_key_ciphertext, kms_key_id)
		VALUES ($1, 'totp', 'test', '\x00', '\x00', '\x00', 'test')`, stale); err != nil {
		t.Fatal(err)
	}
	if _, err := f.l.pool.Exec(ctx, `UPDATE sessions SET last_mfa_at = now() - interval '2 hours' WHERE user_id = $1`, stale); err != nil {
		t.Fatal(err)
	}
	if code, body := f.l.callAs(t, http.MethodPost, path, staleHdr, nil); code != http.StatusUnauthorized || !strings.Contains(string(body), "step_up_required") {
		t.Fatalf("rotation with a stale second factor = %d %s", code, body)
	}

	admin := uuid.New()
	adminHdr := map[string]string{"Cookie": f.l.sessionFor(t, admin, "v2-admin@example.com")}
	f.l.addGrant(t, admin.String(), []string{"agent.mint"}, `{}`)
	issue := func() string {
		t.Helper()
		code, raw, body := f.l.callRaw(t, http.MethodPost, path, adminHdr, nil)
		if code != http.StatusCreated {
			t.Fatalf("rotation token = %d %s", code, body)
		}
		var res map[string]any
		mustJSON(t, body, &res)
		if len(res) != 2 || res["rotation_token"] == "" || res["expires_at"] == "" {
			t.Fatalf("rotation token response %s; want exactly rotation_token and expires_at", body)
		}
		if cc := raw.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
			t.Errorf("rotation token Cache-Control = %q", cc)
		}
		return res["rotation_token"].(string)
	}
	rt := issue()

	base := "/api/v1/agents/" + a.id
	secretOnly := map[string]string{"X-Agent-Secret": a.secret}
	newKey := newEnrollClient(t)
	chBody := newKey.challengeBody("")
	delete(chBody, "enrollment_token")
	chBody["rotation_token"] = rt
	code, body := f.l.callAs(t, http.MethodPost, base+"/key-rotation/challenge", secretOnly, chBody)
	if code != http.StatusOK {
		t.Fatalf("rotation challenge = %d %s", code, body)
	}
	chID, resp, err := newKey.open(body)
	if err != nil {
		t.Fatal(err)
	}
	code, body = f.l.callAs(t, http.MethodPost, base+"/key-rotation", secretOnly, map[string]any{
		"schema_version": "2", "rotation_token": rt, "challenge_id": chID, "challenge_response": resp,
	})
	if code != http.StatusOK {
		t.Fatalf("rotation confirm = %d %s", code, body)
	}
	var rot map[string]any
	_ = json.Unmarshal(body, &rot)
	if rot["public_key_fingerprint"] != newKey.fingerprint() || rot["public_key_version"] != float64(2) {
		t.Fatalf("rotation response %s", body)
	}
	if code, _ := f.heartbeat(t, a, a.c.fingerprint()); code != http.StatusConflict {
		t.Fatalf("old key after rotation = %d; want 409", code)
	}
	if code, _ := f.heartbeat(t, a, newKey.fingerprint()); code != http.StatusNoContent {
		t.Fatalf("new key, same secret = %d; want 204", code)
	}
	for _, action := range []string{"agent.key_rotation.requested", "agent.key_rotation.challenge", "agent.key.rotated"} {
		if n := len(f.l.auditRows(t, action)); n != 1 {
			t.Errorf("%s audit rows = %d; want 1", action, n)
		}
	}

	// Revoke kills an open rotation.
	rt2 := issue()
	k3 := newEnrollClient(t)
	ch3 := k3.challengeBody("")
	delete(ch3, "enrollment_token")
	ch3["rotation_token"] = rt2
	code, body = f.l.callAs(t, http.MethodPost, base+"/key-rotation/challenge", secretOnly, ch3)
	if code != http.StatusOK {
		t.Fatalf("second rotation challenge = %d %s", code, body)
	}
	chID3, resp3, _ := k3.open(body)
	if code, body := f.l.call(t, http.MethodPost, "/api/v1/admin/agents/"+a.id+"/revoke", f.op, map[string]any{"reason": "test"}); code != http.StatusNoContent {
		t.Fatalf("revoke = %d %s", code, body)
	}
	code, _ = f.l.callAs(t, http.MethodPost, base+"/key-rotation", secretOnly, map[string]any{
		"schema_version": "2", "rotation_token": rt2, "challenge_id": chID3, "challenge_response": resp3,
	})
	if code != http.StatusUnauthorized {
		t.Fatalf("confirm after revoke = %d; want 401", code)
	}
	var open int
	_ = f.l.pool.QueryRow(ctx, `SELECT count(*) FROM agent_key_rotation_tokens WHERE agent_id = $1 AND consumed_at IS NULL AND revoked_at IS NULL`, a.id).Scan(&open)
	if open != 0 {
		t.Fatalf("%d open rotation tokens after revoke", open)
	}
	var fp string
	_ = f.l.pool.QueryRow(ctx, `SELECT public_key_fingerprint FROM agents WHERE id = $1`, a.id).Scan(&fp)
	if fp != newKey.fingerprint() {
		t.Fatal("the key changed after revoke")
	}

	// Nothing secret in the logs or audit rows.
	var audit string
	_ = f.l.pool.QueryRow(ctx, `SELECT coalesce(string_agg(metadata::text, ' '), '') FROM audit_events`).Scan(&audit)
	for _, s := range []string{rt, rt2, resp, resp3, a.secret} {
		if strings.Contains(f.l.logs.String(), s) || strings.Contains(audit, s) {
			t.Fatal("rotation token, nonce or secret in the logs or audit")
		}
	}
}
