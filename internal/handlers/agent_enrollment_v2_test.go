package handlers_test

// skills#116 over the agent HTTP surface: an agent enrolled through the
// two-step challenge runs read and patch jobs, the key fingerprint
// header is enforced, and a rotation in flight behaves as specified.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/secrets-bridge/api/internal/handlers"
	"github.com/secrets-bridge/api/pkg/sealing"
	"github.com/secrets-bridge/api/pkg/storage"
)

// openWrap decodes a wrap payload and opens it with the agent's key.
func openWrap(t *testing.T, body []byte, a surfaceAgent) ([]byte, handlers.WrapPayload, error) {
	t.Helper()
	var p handlers.WrapPayload
	if err := json.Unmarshal(body, &p); err != nil || p.Sealed == nil {
		t.Fatalf("not a sealed payload (err=%v): %s", err, body)
	}
	dec := func(s string) []byte { b, _ := base64.StdEncoding.DecodeString(s); return b }
	pt, err := sealing.Open(&sealing.Envelope{Ciphertext: dec(p.Sealed.Ciphertext), Nonce: dec(p.Sealed.Nonce),
		EphemeralPublicKey: dec(p.Sealed.EphemeralPublicKey), Algorithm: p.Sealed.Algorithm}, a.priv, a.pub)
	return pt, p, err
}

// An agent enrolled through the challenge flow runs a read job and a
// patch job end to end, with wraps sealed to its own key.
func TestAgentSurface_EnrolledAgent_ReadAndPatch(t *testing.T) {
	fx := bootstrapAgentSurface(t)
	ctx := t.Context()
	a := fx.httpEnroll(t, "enrolled-rw")

	// read
	req := fx.approvedRead(t, []string{"DB_PASSWORD"})
	job := fx.claim(t, a)
	if job.JobType != "read" {
		t.Fatalf("claimed %s; want read", job.JobType)
	}
	if code, body := fx.postWrap(t, a, req.ID, "DB_PASSWORD", fx.envelope(t, a, []byte("canary-enrolled-read"), nil)); code != http.StatusCreated {
		t.Fatalf("post wrap = %d %s", code, body)
	}
	if code := fx.complete(t, a, job.ID, "succeeded", ""); code != http.StatusNoContent {
		t.Fatalf("complete read = %d", code)
	}
	if got, _ := fx.reqSvc.Get(ctx, req.ID); got.Status != storage.AccessRequestStatusExecuted {
		t.Fatalf("read status %s", got.Status)
	}

	// patch
	preq := fx.approvedPatch(t, map[string][]byte{"API_KEY": []byte("canary-enrolled-patch")})
	pjob := fx.claim(t, a)
	if pjob.JobType != "patch" {
		t.Fatalf("claimed %s; want patch", pjob.JobType)
	}
	code, body := fx.getWrap(t, a, wrapIDsFromPayload(t, pjob)[0])
	if code != http.StatusOK {
		t.Fatalf("get wrap = %d %s", code, body)
	}
	pt, p, err := openWrap(t, body, a)
	if err != nil || string(pt) != "canary-enrolled-patch" {
		t.Fatalf("patch wrap did not open (err=%v)", err)
	}
	if p.RecipientKeyFingerprint != sealing.Fingerprint(a.pub) {
		t.Fatalf("recipient_key_fingerprint %q", p.RecipientKeyFingerprint)
	}
	if code := fx.complete(t, a, pjob.ID, "succeeded", ""); code != http.StatusNoContent {
		t.Fatalf("complete patch = %d", code)
	}
	if got, _ := fx.reqSvc.Get(ctx, preq.ID); got.Status != storage.AccessRequestStatusExecuted {
		t.Fatalf("patch status %s", got.Status)
	}
}

// A request with the right secret and no or another fingerprint is 409
// agent_key_mismatch on every agent route, after the secret check: a
// wrong secret is still 401.
func TestAgentSurface_FingerprintRequired(t *testing.T) {
	fx := bootstrapAgentSurface(t)
	a := fx.httpEnroll(t, "fp-agent")
	other, _, _ := sealing.GenerateRecipientKey()
	for _, path := range []string{"/jobs/claim", "/dek"} {
		for _, fp := range []string{"", sealing.Fingerprint(other), "sha256:nothex", sealing.Fingerprint(other)[:40]} {
			req := httptestReq(http.MethodPost, "/api/v1/agents/"+a.id.String()+path, a.secret, fp)
			code, body := fx.do(t, req)
			if code != http.StatusConflict || !bytes.Contains(body, []byte(`"agent_key_mismatch"`)) {
				t.Fatalf("%s with fingerprint %q = %d %s; want 409 agent_key_mismatch", path, fp, code, body)
			}
		}
		req := httptestReq(http.MethodPost, "/api/v1/agents/"+a.id.String()+path, "wrong", sealing.Fingerprint(a.pub))
		if code, _ := fx.do(t, req); code != http.StatusUnauthorized {
			t.Fatalf("%s with a wrong secret = %d; want 401", path, code)
		}
	}
}

// Rotation over HTTP while a patch wrap is queued: the old-key agent is
// refused with 409 and the wrap is not burned; the agent restarted with
// the new key (same secret) fetches it sealed to the new key only.
func TestAgentSurface_RotationInFlight(t *testing.T) {
	fx := bootstrapAgentSurface(t)
	old := fx.httpEnroll(t, "rot-agent")
	fx.approvedPatch(t, map[string][]byte{"API_KEY": []byte("canary-after-rotation")})
	job := fx.claim(t, old)
	wid := wrapIDsFromPayload(t, job)[0]

	rt, err := fx.agentSvc.RequestKeyRotation(t.Context(), old.id, "admin-user-1")
	if err != nil {
		t.Fatal(err)
	}
	base := "/api/v1/agents/" + old.id.String()
	// The rotation routes take the secret only: the old key may be lost.
	fx.fps.Delete(old.secret)
	chID, resp, newPub, newPriv := fx.httpChallengeKey(t, base+"/key-rotation/challenge", old.secret, map[string]any{
		"schema_version": "2", "rotation_token": rt.Token,
	})
	code, body := fx.call(t, http.MethodPost, base+"/key-rotation", old.secret, map[string]any{
		"schema_version": "2", "rotation_token": rt.Token, "challenge_id": chID, "challenge_response": resp,
	})
	if code != http.StatusOK {
		t.Fatalf("confirm rotation = %d %s", code, body)
	}
	var rot handlers.KeyRotationResponse
	_ = json.Unmarshal(body, &rot)
	if rot.PublicKeyVersion != 2 || rot.PublicKeyFingerprint != sealing.Fingerprint(newPub) {
		t.Fatalf("rotation response %s", body)
	}

	// Old key: 409, wrap untouched.
	fx.fps.Store(old.secret, sealing.Fingerprint(old.pub))
	if code, body := fx.getWrap(t, old, wid); code != http.StatusConflict || !bytes.Contains(body, []byte("agent_key_mismatch")) {
		t.Fatalf("old-key fetch = %d %s; want 409 agent_key_mismatch", code, body)
	}
	if n := fx.countRows(t, `SELECT count(*) FROM secret_wraps WHERE id = $1 AND consumed_at IS NULL`, wid); n != 1 {
		t.Fatal("the old-key refusal burned the wrap")
	}

	// New key, same secret: sealed to the new key, not the old one.
	restarted := surfaceAgent{id: old.id, secret: old.secret, pub: newPub, priv: newPriv}
	fx.fps.Store(old.secret, sealing.Fingerprint(newPub))
	code, body = fx.getWrap(t, restarted, wid)
	if code != http.StatusOK {
		t.Fatalf("new-key fetch = %d %s", code, body)
	}
	pt, p, err := openWrap(t, body, restarted)
	if err != nil || string(pt) != "canary-after-rotation" || p.RecipientKeyFingerprint != sealing.Fingerprint(newPub) {
		t.Fatalf("new key fetch did not open (err=%v, fp=%s)", err, p.RecipientKeyFingerprint)
	}
	if _, _, err := openWrap(t, body, old); err == nil {
		t.Fatal("a wrap sealed after rotation opened with the old key")
	}

	// Rotation needs the agent secret: another secret is 401.
	if code, _ := fx.call(t, http.MethodPost, base+"/key-rotation/challenge", "wrong", map[string]any{
		"schema_version": "2", "rotation_token": rt.Token, "public_key": base64.StdEncoding.EncodeToString(newPub), "public_key_algorithm": "x25519",
	}); code != http.StatusUnauthorized {
		t.Fatalf("rotation challenge with a wrong secret = %d; want 401", code)
	}
	// And schema_version "2".
	if code, body := fx.call(t, http.MethodPost, base+"/key-rotation/challenge", old.secret, map[string]any{
		"rotation_token": rt.Token, "public_key": base64.StdEncoding.EncodeToString(newPub), "public_key_algorithm": "x25519",
	}); code != http.StatusBadRequest || !bytes.Contains(body, []byte("unsupported_schema_version")) {
		t.Fatalf("rotation challenge without schema_version = %d %s", code, body)
	}
}

// httptestReq builds an agent request with an explicit fingerprint
// header ("" sends none).
func httptestReq(method, path, secret, fingerprint string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("X-Agent-Secret", secret)
	if fingerprint != "" {
		req.Header.Set("X-Agent-Key-Fingerprint", fingerprint)
	}
	return req
}

func (fx *agentSurface) do(t *testing.T, req *http.Request) (int, []byte) {
	t.Helper()
	resp, err := fx.app.Test(req, fiber.TestConfig{Timeout: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

// If AgentAuth passed on a stale view of the key (a cached entry from
// before a rotation), retrieval still refuses before the consume: the
// wrap is never sealed to a key the caller does not hold.
func TestAgentSurface_RetrieveRechecksBoundKey(t *testing.T) {
	fx := bootstrapAgentSurface(t)
	ctx := t.Context()
	a := fx.httpEnroll(t, "stale-view")
	fx.approvedPatch(t, map[string][]byte{"API_KEY": []byte("canary-stale-view")})
	job := fx.claim(t, a)
	wid := wrapIDsFromPayload(t, job)[0]

	// Warm the credential cache with the current (old) key, then rotate
	// in the database only, as if the rotation committed between
	// AgentAuth's read and the handler's.
	if code, _ := fx.call(t, http.MethodPost, "/api/v1/agents/"+a.id.String()+"/dek", a.secret, nil); code != http.StatusCreated {
		t.Fatalf("warm = %d", code)
	}
	newPub, _, _ := sealing.GenerateRecipientKey()
	if _, err := fx.pool.Exec(ctx, `UPDATE agents SET public_key = $2, public_key_fingerprint = 'sha256:' || encode(sha256($2), 'hex'),
		public_key_version = public_key_version + 1 WHERE id = $1`, a.id, newPub); err != nil {
		t.Fatal(err)
	}
	code, body := fx.getWrap(t, a, wid)
	if code != http.StatusConflict || !bytes.Contains(body, []byte("agent_key_mismatch")) {
		t.Fatalf("fetch on a stale key view = %d %s; want 409 agent_key_mismatch", code, body)
	}
	if n := fx.countRows(t, `SELECT count(*) FROM secret_wraps WHERE id = $1 AND consumed_at IS NULL`, wid); n != 1 {
		t.Fatal("the refusal burned the wrap")
	}
}
