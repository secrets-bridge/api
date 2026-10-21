package main

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/testutil/redisproxy"
)

// TestLive_CredentialCacheUnconfirmedAnswers503: with Redis down, an
// agent revoke and a Gateway disable, enable and revoke are saved but
// answer 503 with a code that says which way the cache may still be
// wrong. Once Redis is back, the revoked credentials are refused and a
// repeated revoke settles to 409 (api#304).
func TestLive_CredentialCacheUnconfirmedAnswers503(t *testing.T) {
	if os.Getenv("TEST_DATABASE_URL") == "" || os.Getenv("TEST_REDIS_URL") == "" {
		t.Skip("TEST_DATABASE_URL and TEST_REDIS_URL required; skipping")
	}
	proxy, proxied := redisproxy.Start(t, os.Getenv("TEST_REDIS_URL"))
	t.Setenv("TEST_REDIS_URL", proxied)
	f := newGatewayFixture(t)
	gw := f.enrolled(t, "cache-503")
	op := f.l.grantUser(t, []string{"agent.mint", "agent.revoke"}, `{}`)
	code, body := f.l.call(t, http.MethodPost, "/api/v1/agents", op, map[string]any{"name": "cache-503-agent"})
	if code != http.StatusCreated {
		t.Fatalf("mint = %d %s", code, body)
	}
	var minted struct {
		ID          uuid.UUID `json:"id"`
		AgentSecret string    `json:"agent_secret"`
	}
	mustJSON(t, body, &minted)
	agentHdr := map[string]string{"X-Agent-Secret": minted.AgentSecret}
	if code, body := f.l.callAs(t, http.MethodPost, "/api/v1/agents/"+minted.ID.String()+"/heartbeat", agentHdr, nil); code != http.StatusNoContent && code != http.StatusOK {
		t.Fatalf("agent heartbeat = %d %s", code, body)
	}
	replica := uuid.NewString()
	if code, body := f.heartbeat(t, gw.GatewayID, gw.GatewaySecret, replica); code != http.StatusOK {
		t.Fatalf("gateway heartbeat = %d %s", code, body)
	}

	proxy.Set(redisproxy.Down)
	enabled := "/api/v1/admin/gateways/" + gw.GatewayID + "/enabled"
	revoke := "/api/v1/admin/gateways/" + gw.GatewayID + "/revoke"
	for _, c := range []struct {
		name, method, path string
		body               any
		want               string
	}{
		{"disable", http.MethodPut, enabled, map[string]any{"enabled": false}, "revoked_cache_unconfirmed"},
		{"enable", http.MethodPut, enabled, map[string]any{"enabled": true}, "enabled_cache_unconfirmed"},
		{"revoke", http.MethodPost, revoke, map[string]any{"reason": "outage"}, "revoked_cache_unconfirmed"},
	} {
		code, body := f.l.callAs(t, c.method, c.path, f.admin, c.body)
		checkUnconfirmed(t, "gateway "+c.name, code, body, c.want)
	}
	code, body = f.l.call(t, http.MethodPost, "/api/v1/admin/agents/"+minted.ID.String()+"/revoke", op, map[string]any{"reason": "outage"})
	checkUnconfirmed(t, "agent revoke", code, body, "revoked_cache_unconfirmed")

	// Back up: the cache still holds both credentials until the background
	// retry lands the tombstones, one retry tick later.
	proxy.Set(redisproxy.Up)
	back := time.Now()
	refused := func(name string, call func() (int, []byte)) {
		t.Helper()
		for time.Since(back) < 2*time.Second {
			if code, _ := call(); code == http.StatusUnauthorized {
				t.Logf("revoked %s refused %s after Redis came back", name, time.Since(back).Round(time.Millisecond))
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Errorf("revoked %s still not refused 2s after Redis came back", name)
	}
	refused("agent", func() (int, []byte) {
		return f.l.callAs(t, http.MethodPost, "/api/v1/agents/"+minted.ID.String()+"/heartbeat", agentHdr, nil)
	})
	refused("gateway", func() (int, []byte) { return f.heartbeat(t, gw.GatewayID, gw.GatewaySecret, replica) })
	if code, body := f.l.callAs(t, http.MethodPost, revoke, f.admin, nil); code != http.StatusConflict || errCode(t, body) != "gateway_already_revoked" {
		t.Errorf("repeated gateway revoke = %d %s, want 409 gateway_already_revoked", code, body)
	}
	for _, action := range []string{"agent.revoke.cache_unconfirmed", "gateway.disable.cache_unconfirmed", "gateway.enable.cache_unconfirmed", "gateway.revoke.cache_unconfirmed"} {
		var n int
		if err := f.l.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE action = $1`, action).Scan(&n); err != nil || n != 1 {
			t.Errorf("%s audit rows = %d (%v), want 1", action, n, err)
		}
	}
}

// checkUnconfirmed: a 503 in the stableErr shape (error_code, message)
// with the request's correlation id, like every other error body.
func checkUnconfirmed(t *testing.T, name string, code int, body []byte, want string) {
	t.Helper()
	var e struct {
		ErrorCode     string `json:"error_code"`
		Message       string `json:"message"`
		CorrelationID string `json:"correlation_id"`
	}
	_ = json.Unmarshal(body, &e)
	if code != http.StatusServiceUnavailable || e.ErrorCode != want || e.Message == "" || e.CorrelationID == "" {
		t.Errorf("%s with Redis down = %d %s, want 503 %s with a message and a correlation_id", name, code, body, want)
	}
}
