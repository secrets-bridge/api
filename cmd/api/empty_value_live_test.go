package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// api#286: a read of a secret bundle with one empty key and two
// non-empty keys, through the real router with a keyed agent posting
// wire envelopes. Before the fix the empty key's POST /agents/:id/wraps
// answered 500 "wraps: plaintext is empty" and the agent failed the
// whole job. Now the request reaches executed and the reveal returns
// every key, the empty one as "value": "".
func TestLive_ReadFlow_EmptyValueRevealed(t *testing.T) {
	l := newLiveApp(t)
	ctx := t.Context()

	proj, env := uuid.New(), uuid.New()
	if _, err := l.pool.Exec(ctx, `INSERT INTO projects (id, name) VALUES ($1, 'tenant-a')`, proj); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if _, err := l.pool.Exec(ctx, `INSERT INTO environments (id, project_id, name, type, kind) VALUES ($1, $2, 'uat', 'uat', 'non_prod')`, env, proj); err != nil {
		t.Fatalf("seed env: %v", err)
	}
	sec := &storage.Secret{ClusterName: "tenant-a-uat", ProviderType: "vault", SecretRef: "team-alpha/uat/app-env", Status: "present"}
	if err := storage.NewSecrets(l.pool).Upsert(ctx, sec); err != nil {
		t.Fatalf("seed secret: %v", err)
	}
	keys := []string{"DB_USER", "OPTIONAL_WEBHOOK_URL", "DB_PASSWORD"}
	values := map[string]string{"DB_USER": "fake-db-user-286", "OPTIONAL_WEBHOOK_URL": "", "DB_PASSWORD": "fake-db-password-286"}
	if err := storage.NewProjectSecrets(l.pool).Bind(ctx, &storage.ProjectSecret{
		ProjectID: proj, SecretID: sec.ID, EnvironmentID: &env,
		AllowedKeys: keys, AllowedOps: []string{storage.OpRead}, CreatedBy: "seed",
	}); err != nil {
		t.Fatalf("seed binding: %v", err)
	}

	requester, approver := uuid.New(), uuid.New()
	l.addGrant(t, requester.String(), []string{"secret.request", "secret.list"}, `{"project_id":"`+proj.String()+`"}`)
	l.addGrant(t, approver.String(), []string{"secret.approve"}, `{}`)
	reqCookie := l.sessionFor(t, requester, "requester@example.com")
	apprCookie := l.sessionFor(t, approver, "approver@example.com")
	op := l.grantUser(t, []string{"agent.mint"}, `{}`)

	code, body := l.callAs(t, http.MethodPost, "/api/v1/requests/read", map[string]string{"Cookie": reqCookie}, map[string]any{
		"requester_id": requester.String(), "project_id": proj.String(), "environment": "uat",
		"target_provider_type": "vault", "target_secret_ref": "team-alpha/uat/app-env",
		"target_keys": keys, "justification": "read tenant-a uat app env",
	})
	if code != http.StatusCreated {
		t.Fatalf("submit = %d %s", code, body)
	}
	var req struct{ ID uuid.UUID }
	mustJSON(t, body, &req)
	if code, body := l.callAs(t, http.MethodPost, "/api/v1/requests/"+req.ID.String()+"/approve",
		map[string]string{"Cookie": apprCookie}, map[string]any{"comment": "ok"}); code != http.StatusOK {
		t.Fatalf("approve = %d %s", code, body)
	}

	// A keyed agent, the production shape: it registers an X25519 key.
	code, body = l.call(t, http.MethodPost, "/api/v1/agents", op, map[string]any{"name": "tenant-a-uat-agent"})
	if code != http.StatusCreated {
		t.Fatalf("mint = %d %s", code, body)
	}
	var agent struct {
		ID          uuid.UUID `json:"id"`
		AgentSecret string    `json:"agent_secret"`
	}
	mustJSON(t, body, &agent)
	agentHdr := map[string]string{"X-Agent-Secret": agent.AgentSecret}
	agentBase := "/api/v1/agents/" + agent.ID.String()
	agentKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("x25519: %v", err)
	}
	if code, body := l.callAs(t, http.MethodPut, agentBase+"/public-key", agentHdr, map[string]any{
		"public_key":           base64.StdEncoding.EncodeToString(agentKey.PublicKey().Bytes()),
		"public_key_algorithm": "x25519",
	}); code != http.StatusNoContent && code != http.StatusOK {
		t.Fatalf("register public key = %d %s", code, body)
	}
	code, body = l.callAs(t, http.MethodPost, agentBase+"/jobs/claim", agentHdr, nil)
	if code != http.StatusOK {
		t.Fatalf("claim = %d %s", code, body)
	}
	var job struct{ ID uuid.UUID }
	mustJSON(t, body, &job)

	// The agent posts one wire envelope per key, the empty one included.
	for _, k := range keys {
		code, body := l.callAs(t, http.MethodPost, agentBase+"/wraps", agentHdr, map[string]any{
			"request_id": req.ID.String(), "key_name": k,
			"envelope": l.agentEnvelope(t, agentBase, agentHdr, []byte(values[k])),
		})
		if code != http.StatusCreated {
			t.Fatalf("agent wrap %s = %d %s", k, code, body)
		}
		var cr struct {
			ByteLength int `json:"byte_length"`
		}
		mustJSON(t, body, &cr)
		if cr.ByteLength != len(values[k]) {
			t.Fatalf("wrap %s byte_length = %d; want %d", k, cr.ByteLength, len(values[k]))
		}
	}
	if code, body := l.callAs(t, http.MethodPost, agentBase+"/jobs/"+job.ID.String()+"/complete", agentHdr,
		map[string]any{"status": "succeeded"}); code != http.StatusNoContent {
		t.Fatalf("complete = %d %s", code, body)
	}
	var status string
	if err := l.pool.QueryRow(ctx, `SELECT status FROM access_requests WHERE id = $1`, req.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != string(storage.AccessRequestStatusExecuted) {
		t.Fatalf("request status = %s; want executed", status)
	}

	// Reveal: every key comes back, the empty one as "value": "".
	code, body = l.callAs(t, http.MethodPost, "/api/v1/reveal-sessions", map[string]string{"Cookie": reqCookie},
		map[string]any{"access_request_id": req.ID.String()})
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("open reveal session = %d %s", code, body)
	}
	var rs struct {
		Wraps []struct {
			WrapID  string `json:"wrap_id"`
			KeyName string `json:"key_name"`
		} `json:"wraps"`
	}
	mustJSON(t, body, &rs)
	if len(rs.Wraps) != len(keys) {
		t.Fatalf("reveal session wraps = %+v; want %d", rs.Wraps, len(keys))
	}
	revealed := map[string]string{}
	for _, w := range rs.Wraps {
		code, body := l.callAs(t, http.MethodGet, "/api/v1/requests/"+req.ID.String()+"/wraps/"+w.WrapID,
			map[string]string{"Cookie": reqCookie}, nil)
		if code != http.StatusOK {
			t.Fatalf("retrieve %s = %d %s", w.KeyName, code, body)
		}
		var raw map[string]any
		if err := json.Unmarshal(body, &raw); err != nil {
			t.Fatal(err)
		}
		v, ok := raw["value"].(string)
		if !ok {
			t.Fatalf("retrieve %s: value = %v; want a string, never omitted or null", w.KeyName, raw["value"])
		}
		plain, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			t.Fatalf("retrieve %s: value is not base64", w.KeyName)
		}
		revealed[raw["key_name"].(string)] = string(plain)
		if bl, _ := raw["byte_length"].(float64); int(bl) != len(plain) {
			t.Errorf("retrieve %s: byte_length %v for %d bytes", w.KeyName, raw["byte_length"], len(plain))
		}
	}
	for _, k := range keys {
		got, ok := revealed[k]
		if !ok {
			t.Errorf("reveal is missing %s", k)
			continue
		}
		if got != values[k] {
			t.Errorf("revealed %s does not match what the agent posted", k)
		}
	}

	// The empty value's wrap.create audit row keeps byte_length 0 and
	// the SHA-256 of the empty input; the allowlist dropped nothing.
	var n int
	if err := l.pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'wrap.create'
		AND correlation_id = $1 AND metadata->>'byte_length' = '0'
		AND metadata->>'content_hash' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'`, req.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("wrap.create rows for the empty value = %d; want 1", n)
	}
}
