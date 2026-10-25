package handlers_test

// api#286: a key whose value is "" is sealed like any other value, and
// every bad-input refusal on POST /agents/:id/wraps is a 4xx with a
// stable code in the `error` field, never a 500.

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/handlers"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/sealing"
	"github.com/secrets-bridge/api/pkg/storage"
)

// A read of a bundle with one empty key: every post is a 201, the job
// completes, the request reaches executed and the requester reveals each
// key, the empty one as an empty value.
func TestAgentSurface_ReadFlow_EmptyValueSealed(t *testing.T) {
	fx := bootstrapAgentSurface(t)
	ctx := t.Context()
	a := fx.mint(t, "agent-a", true)
	values := map[string]string{"DB_USER": "svc-team-alpha", "OPTIONAL_TOKEN": "", "DB_PASSWORD": "canary-read-pw-286"}
	req := fx.approvedRead(t, []string{"DB_USER", "OPTIONAL_TOKEN", "DB_PASSWORD"})
	job := fx.claim(t, a)

	for _, k := range []string{"DB_USER", "OPTIONAL_TOKEN", "DB_PASSWORD"} {
		code, body := fx.postWrap(t, a, req.ID, k, fx.envelope(t, a, []byte(values[k]), nil))
		if code != http.StatusCreated {
			t.Fatalf("post wrap %s = %d (%s); want 201", k, code, body)
		}
		var cr handlers.CreateResponse
		if err := json.Unmarshal(body, &cr); err != nil {
			t.Fatal(err)
		}
		if cr.ByteLength != len(values[k]) {
			t.Fatalf("%s byte_length = %d; want %d", k, cr.ByteLength, len(values[k]))
		}
	}
	if code := fx.complete(t, a, job.ID, "succeeded", ""); code != http.StatusNoContent {
		t.Fatalf("complete = %d; want 204", code)
	}
	got, _ := fx.reqSvc.Get(ctx, req.ID)
	if got.Status != storage.AccessRequestStatusExecuted {
		t.Fatalf("request status = %s; want executed", got.Status)
	}
	summaries, err := fx.reqSvc.WrapSummariesForRequest(ctx, req.ID)
	if err != nil || len(summaries) != 3 {
		t.Fatalf("summaries = %d (err=%v); want 3", len(summaries), err)
	}
	for _, s := range summaries {
		pt, _, err := fx.reqSvc.RetrieveWrapForUser(ctx, req.ID, s.ID, "alice")
		if err != nil {
			t.Fatalf("RetrieveWrapForUser %s: %v", s.KeyName, err)
		}
		if string(pt) != values[s.KeyName] {
			t.Fatalf("revealed %s does not match what the agent posted", s.KeyName)
		}
	}
}

// Patch flow with an empty value: the agent fetches a sealed envelope
// that opens to "".
func TestAgentSurface_PatchFlow_EmptyValueSealed(t *testing.T) {
	fx := bootstrapAgentSurface(t)
	a := fx.mint(t, "agent-a", true)
	req := fx.approvedPatch(t, map[string][]byte{"OPTIONAL_TOKEN": {}})
	job := fx.claim(t, a)
	if job.ID != *req.JobID {
		t.Fatalf("claimed %s; want %s", job.ID, req.JobID)
	}
	wid := wrapIDsFromPayload(t, job)[0]
	code, body := fx.getWrap(t, a, wid)
	if code != http.StatusOK {
		t.Fatalf("get wrap = %d (%s); want 200", code, body)
	}
	var p handlers.WrapPayload
	if err := json.Unmarshal(body, &p); err != nil || p.Sealed == nil || p.Value != nil {
		t.Fatalf("expected only a sealed payload (err=%v)", err)
	}
	if p.ByteLength != 0 {
		t.Fatalf("byte_length = %d; want 0", p.ByteLength)
	}
	ct, _ := base64.StdEncoding.DecodeString(p.Sealed.Ciphertext)
	nonce, _ := base64.StdEncoding.DecodeString(p.Sealed.Nonce)
	eph, _ := base64.StdEncoding.DecodeString(p.Sealed.EphemeralPublicKey)
	pt, err := sealing.Open(&sealing.Envelope{Ciphertext: ct, Nonce: nonce, EphemeralPublicKey: eph, Algorithm: p.Sealed.Algorithm}, a.priv, a.pub)
	if err != nil || len(pt) != 0 {
		t.Fatalf("sealed empty value opened to %d bytes (err=%v); want 0", len(pt), err)
	}
}

// With SB_ALLOW_UNSEALED_WRAPS, a legacy `"value": ""` on create is
// accepted. Retrieval is sealed whatever the switch (skills#116), so the
// empty value comes back as a sealed empty plaintext.
func TestAgentSurface_UnsealedBreakGlassEmptyValue(t *testing.T) {
	fx := bootstrapAgentSurfaceOpts(t, nil, true)

	a := fx.mint(t, "agent-legacy", false)
	fx.approvedPatch(t, map[string][]byte{"OPTIONAL_TOKEN": {}})
	job := fx.claim(t, a)
	code, body := fx.getWrap(t, a, wrapIDsFromPayload(t, job)[0])
	if code != http.StatusOK {
		t.Fatalf("legacy fetch = %d (%s); want 200", code, body)
	}
	var p handlers.WrapPayload
	if err := json.Unmarshal(body, &p); err != nil || p.Sealed == nil || p.Value != nil {
		t.Fatalf("fetch with the switch was not sealed (err=%v): %s", err, body)
	}
	dec := func(s string) []byte { b, _ := base64.StdEncoding.DecodeString(s); return b }
	if pt, err := sealing.Open(&sealing.Envelope{Ciphertext: dec(p.Sealed.Ciphertext), Nonce: dec(p.Sealed.Nonce),
		EphemeralPublicKey: dec(p.Sealed.EphemeralPublicKey), Algorithm: p.Sealed.Algorithm}, a.priv, a.pub); err != nil || len(pt) != 0 {
		t.Fatalf("sealed empty value opened to %d bytes (err=%v)", len(pt), err)
	}

	b := fx.mint(t, "agent-legacy-read", false)
	req := fx.approvedRead(t, []string{"OPTIONAL_TOKEN"})
	fx.claim(t, b)
	code, body = fx.call(t, http.MethodPost, "/api/v1/agents/"+b.id.String()+"/wraps", b.secret, map[string]any{
		"request_id": req.ID.String(), "key_name": "OPTIONAL_TOKEN", "value": "",
	})
	if code != http.StatusCreated {
		t.Fatalf("legacy empty value post = %d (%s); want 201", code, body)
	}
}

// Every refusal of the agent's input on POST /agents/:id/wraps is a 4xx
// with a stable code, and none of them stores a wrap.
func TestAgentSurface_WrapCreateRefusalCodes(t *testing.T) {
	fx := bootstrapAgentSurface(t)
	ctx := t.Context()
	a := fx.mint(t, "agent-a", true)
	other := fx.mint(t, "agent-b", true)

	// The read job is claimed by a. A second, unapproved read and an
	// approved patch give the state and type refusals.
	read := fx.approvedRead(t, []string{"DB_PASSWORD", "DB_USER"})
	fx.claim(t, a)
	if code, body := fx.postWrap(t, a, read.ID, "DB_USER", fx.envelope(t, a, []byte("first"), nil)); code != http.StatusCreated {
		t.Fatalf("seed wrap = %d (%s)", code, body)
	}
	pending, err := fx.reqSvc.SubmitRead(ctx, services.ReadInput{
		RequesterID: "alice", ProjectID: "team-alpha", Environment: "uat",
		TargetProviderType: "vault", TargetSecretRef: "secret/data/team-alpha/uat/db",
		TargetKeys: []string{"DB_PASSWORD"}, Justification: "pending read",
	})
	if err != nil {
		t.Fatalf("SubmitRead: %v", err)
	}
	patch := fx.approvedPatch(t, map[string][]byte{"DB_PASSWORD": []byte("canary-patch")})

	env := func(mut func(map[string]any)) map[string]any {
		e := fx.envelope(t, a, []byte("v"), nil)
		if mut != nil {
			mut(e)
		}
		return e
	}
	body := func(reqID uuid.UUID, key string, e map[string]any) map[string]any {
		return map[string]any{"request_id": reqID.String(), "key_name": key, "envelope": e}
	}

	cases := []struct {
		name   string
		agent  surfaceAgent
		body   any
		raw    string
		status int
		code   string
	}{
		{name: "invalid json", agent: a, raw: "{not json", status: http.StatusBadRequest, code: handlers.WrapCreateCodeInvalidJSON},
		{name: "missing key_name", agent: a, body: map[string]any{"request_id": read.ID.String(), "envelope": env(nil)},
			status: http.StatusBadRequest, code: handlers.WrapCreateCodeMissingField},
		{name: "neither value nor envelope", agent: a, body: map[string]any{"request_id": read.ID.String(), "key_name": "DB_PASSWORD"},
			status: http.StatusBadRequest, code: handlers.WrapCreateCodeValueOrEnvelope},
		{name: "both value and envelope", agent: a, body: map[string]any{"request_id": read.ID.String(), "key_name": "DB_PASSWORD", "value": "", "envelope": env(nil)},
			status: http.StatusBadRequest, code: handlers.WrapCreateCodeValueOrEnvelope},
		{name: "plaintext value without the switch", agent: a, body: map[string]any{"request_id": read.ID.String(), "key_name": "DB_PASSWORD", "value": ""},
			status: http.StatusBadRequest, code: handlers.WrapCreateCodeEnvelopeRequired},
		{name: "bad request_id", agent: a, body: map[string]any{"request_id": "not-a-uuid", "key_name": "DB_PASSWORD", "envelope": env(nil)},
			status: http.StatusBadRequest, code: handlers.WrapCreateCodeInvalidRequestID},
		{name: "unsupported algorithm", agent: a, body: body(read.ID, "DB_PASSWORD", env(func(e map[string]any) { e["algorithm"] = "chacha20" })),
			status: http.StatusBadRequest, code: handlers.WrapCreateCodeUnsupportedAlg},
		{name: "missing ciphertext", agent: a, body: body(read.ID, "DB_PASSWORD", env(func(e map[string]any) { e["ciphertext"] = "" })),
			status: http.StatusBadRequest, code: handlers.WrapCreateCodeInvalidEnvelope},
		{name: "ciphertext not base64", agent: a, body: body(read.ID, "DB_PASSWORD", env(func(e map[string]any) { e["ciphertext"] = "%%%" })),
			status: http.StatusBadRequest, code: handlers.WrapCreateCodeInvalidEnvelope},
		{name: "nonce not base64", agent: a, body: body(read.ID, "DB_PASSWORD", env(func(e map[string]any) { e["nonce"] = "%%%" })),
			status: http.StatusBadRequest, code: handlers.WrapCreateCodeInvalidEnvelope},
		{name: "dek not base64", agent: a, body: body(read.ID, "DB_PASSWORD", env(func(e map[string]any) { e["dek_ciphertext"] = "%%%" })),
			status: http.StatusBadRequest, code: handlers.WrapCreateCodeInvalidEnvelope},
		{name: "short nonce", agent: a, body: body(read.ID, "DB_PASSWORD", env(func(e map[string]any) {
			e["nonce"] = base64.StdEncoding.EncodeToString([]byte{1, 2, 3})
		})), status: http.StatusBadRequest, code: handlers.WrapCreateCodeInvalidEnvelope},
		{name: "ciphertext shorter than the tag", agent: a, body: body(read.ID, "DB_PASSWORD", env(func(e map[string]any) {
			e["ciphertext"] = base64.StdEncoding.EncodeToString(make([]byte, 15))
		})), status: http.StatusBadRequest, code: handlers.WrapCreateCodeInvalidEnvelope},
		{name: "dek not decryptable", agent: a, body: body(read.ID, "DB_PASSWORD", env(func(e map[string]any) {
			e["dek_ciphertext"] = base64.StdEncoding.EncodeToString([]byte("not-a-wrapped-data-key-at-all-xxxxxxxxxxxxxxxx"))
		})), status: http.StatusBadRequest, code: handlers.WrapCreateCodeDataKeyUndecrypted},
		{name: "tampered ciphertext", agent: a, body: body(read.ID, "DB_PASSWORD", env(func(e map[string]any) {
			ct, _ := base64.StdEncoding.DecodeString(e["ciphertext"].(string))
			ct[0] ^= 0xff
			e["ciphertext"] = base64.StdEncoding.EncodeToString(ct)
		})), status: http.StatusBadRequest, code: handlers.WrapCreateCodeUnauthenticated},
		{name: "unknown request", agent: a, body: body(uuid.New(), "DB_PASSWORD", env(nil)),
			status: http.StatusNotFound, code: handlers.WrapCreateCodeRequestNotFound},
		{name: "patch request", agent: a, body: body(patch.ID, "DB_PASSWORD", env(nil)),
			status: http.StatusBadRequest, code: handlers.WrapCreateCodeNotReadRequest},
		{name: "unapproved request", agent: a, body: body(pending.ID, "DB_PASSWORD", env(nil)),
			status: http.StatusConflict, code: handlers.WrapCreateCodeNotApproved},
		{name: "job claimed by another agent", agent: other, body: map[string]any{
			"request_id": read.ID.String(), "key_name": "DB_PASSWORD", "envelope": fx.envelope(t, other, []byte("v"), nil)},
			status: http.StatusForbidden, code: handlers.WrapCreateCodeJobNotClaimed},
		{name: "undeclared key", agent: a, body: body(read.ID, "ADMIN_TOKEN", env(nil)),
			status: http.StatusForbidden, code: handlers.WrapCreateCodeKeyNotRequested},
		{name: "duplicate key", agent: a, body: body(read.ID, "DB_USER", env(nil)),
			status: http.StatusConflict, code: handlers.WrapCreateCodeDuplicateKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var code int
			var out []byte
			if tc.raw != "" {
				code, out = fx.callRaw(t, http.MethodPost, "/api/v1/agents/"+tc.agent.id.String()+"/wraps", tc.agent.secret, tc.raw)
			} else {
				code, out = fx.call(t, http.MethodPost, "/api/v1/agents/"+tc.agent.id.String()+"/wraps", tc.agent.secret, tc.body)
			}
			if code != tc.status {
				t.Fatalf("status = %d (%s); want %d", code, out, tc.status)
			}
			var got struct {
				Error   string `json:"error"`
				Message string `json:"message"`
			}
			if err := json.Unmarshal(out, &got); err != nil {
				t.Fatalf("body is not JSON: %s", out)
			}
			if got.Error != tc.code || got.Message == "" {
				t.Fatalf("body = %s; want error %q and a message", out, tc.code)
			}
		})
	}
	if n := fx.countRows(t, `SELECT count(*) FROM secret_wraps WHERE request_id = $1 AND key_name <> 'DB_USER'`, read.ID); n != 0 {
		t.Fatalf("refused posts stored %d wraps", n)
	}
}

// The legacy value path's own refusal: a value that is not base64.
func TestAgentSurface_WrapCreateRefusalCodes_LegacyValue(t *testing.T) {
	fx := bootstrapAgentSurfaceOpts(t, nil, true)
	a := fx.mint(t, "agent-legacy", false)
	req := fx.approvedRead(t, []string{"DB_PASSWORD"})
	fx.claim(t, a)
	code, out := fx.call(t, http.MethodPost, "/api/v1/agents/"+a.id.String()+"/wraps", a.secret, map[string]any{
		"request_id": req.ID.String(), "key_name": "DB_PASSWORD", "value": "%%%",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d (%s); want 400", code, out)
	}
	var got struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(out, &got)
	if got.Error != handlers.WrapCreateCodeInvalidValue {
		t.Fatalf("body = %s; want error %q", out, handlers.WrapCreateCodeInvalidValue)
	}
}

// callRaw posts a raw (possibly malformed) JSON body.
func (fx *agentSurface) callRaw(t *testing.T, method, path, secret, raw string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Secret", secret)
	if fp, ok := fx.fps.Load(secret); ok {
		req.Header.Set("X-Agent-Key-Fingerprint", fp.(string))
	}
	resp, err := fx.app.Test(req, fiber.TestConfig{Timeout: 20 * time.Second})
	if err != nil {
		t.Fatalf("app.Test %s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}
