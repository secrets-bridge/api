package storage_test

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// canary is plain text with no credential shape, so nothing but the
// allowlist itself can keep it out (api#263).
func canary(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "plain canary " + hex.EncodeToString(b)
}

func TestSanitizeAuditMetadata_Shapes(t *testing.T) {
	id := uuid.New().String()
	in := map[string]any{
		"request_id":   id,
		"reason":       "no_governing_binding",
		"key_count":    3,
		"transitioned": true,
		"expires_at":   "2026-10-19T08:00:00Z",
		"key_names":    []string{"DB_USER", "DB_PASSWORD"},
		"permissions":  []string{"secret.read", "audit.read"},
		"new":          map[string]any{"display_name": "Corp IdP", "enabled": true},
		"workflow_id":  nil,
	}
	out := storage.SanitizeAuditMetadata("test.shapes", in)
	for k, want := range map[string]any{
		"request_id": id, "reason": "no_governing_binding", "key_count": float64(3),
		"transitioned": true, "expires_at": "2026-10-19T08:00:00Z",
	} {
		if out[k] != want {
			t.Errorf("%s = %#v, want %#v", k, out[k], want)
		}
	}
	if kn, _ := out["key_names"].([]any); len(kn) != 2 {
		t.Errorf("key_names = %#v", out["key_names"])
	}
	if nested, _ := out["new"].(map[string]any); nested["display_name"] != "Corp IdP" || nested["enabled"] != true {
		t.Errorf("new = %#v", out["new"])
	}
	if _, ok := out["workflow_id"]; !ok || out["workflow_id"] != nil {
		t.Errorf("a null id should be kept as null, got %#v", out["workflow_id"])
	}
	if _, ok := out["_dropped_keys"]; ok {
		t.Errorf("legit metadata dropped something: %#v", out)
	}
	if _, ok := out["_rejected_keys"]; ok {
		t.Errorf("legit metadata rejected something: %#v", out)
	}

	bad := storage.SanitizeAuditMetadata("test.bad", map[string]any{
		"request_id": "not an id; DROP TABLE",
		"phase":      "free text with spaces",
		"key_count":  "3",
		"name":       "line one\nline two",
		"email":      "AKIAIOSFODNN7EXAMPLE",
		"key_names":  []any{"ok", 42},
	})
	for _, k := range []string{"request_id", "phase", "key_count", "name", "email", "key_names"} {
		if _, ok := bad[k]; ok {
			t.Errorf("%s kept with a bad value: %#v", k, bad[k])
		}
	}
	if rk, _ := bad["_rejected_keys"].([]string); len(rk) != 6 {
		t.Errorf("_rejected_keys = %#v, want the six keys", bad["_rejected_keys"])
	}
}

// Every way an arbitrary value could ride into the audit table: an
// unknown key, a key built from the value, nested JSON, a free-text
// error, a provider error body, a name field with a credential or a
// control character, an unknown key inside an allowed object. None of
// it may be in the stored row, on Append or on AppendTx.
func TestAuditEvents_MetadataCanariesNeverPersist(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	repo := storage.NewAuditEvents(pool)
	c := canary(t)
	reqID := uuid.New().String()
	meta := func() map[string]any {
		return map[string]any{
			"request_id":     reqID,
			"reason":         "binding_rejected",
			"value":          c,
			"plaintext":      []byte(c),
			"debug":          map[string]any{"body": c, "nested": []any{c}},
			"keys_" + c:      true,
			"error":          "provider said: " + c,
			"response_body":  `{"data":{"password":"` + c + `"}}`,
			"name":           "team-" + c + "\x00",
			"email":          "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJlc2lnbmF0dXJl",
			"label":          "hvs.CAESIJ8x7nY2Z3h0b2tlbi1mb3ItdGVzdGluZy1vbmx5",
			"new":            map[string]any{"display_name": "IdP", "client_secret": c},
			"target_keys":    []string{c},
			"allowed_keys":   []any{"DB_USER", map[string]any{"v": c}},
			"key_count":      1,
			"has_error":      true,
			"provider_type":  "vault",
			"content_hash":   strings.Repeat("ab", 32),
			"environment_id": nil,
		}
	}

	check := func(t *testing.T, id uuid.UUID) {
		t.Helper()
		var raw string
		if err := pool.QueryRow(ctx, `SELECT metadata::text FROM audit_events WHERE id = $1`, id).Scan(&raw); err != nil {
			t.Fatalf("read row: %v", err)
		}
		hexCanary := strings.TrimPrefix(c, "plain canary ")
		// A dropped key is named in _dropped_keys; its value never is.
		for _, bad := range []string{c, hexCanary, "eyJhbGciOiJIUzI1NiJ9", "hvs.CAES"} {
			if strings.Contains(raw, bad) {
				t.Errorf("stored metadata carries %q", bad)
			}
		}
		for _, want := range []string{reqID, `"reason": "binding_rejected"`, `"key_count": 1`, `"error": "omitted"`,
			`"provider_type": "vault"`, `"display_name": "IdP"`, `"_dropped_keys"`, `"_rejected_keys"`} {
			if !strings.Contains(raw, want) {
				t.Errorf("stored metadata lacks %s: %s", want, raw)
			}
		}
	}

	t.Run("Append", func(t *testing.T) {
		evt := &storage.AuditEvent{Actor: "agent:test", Action: "wrap.create", Resource: "request:" + reqID,
			Status: storage.AuditStatusDenied, Metadata: meta()}
		if err := repo.Append(ctx, evt); err != nil {
			t.Fatalf("Append: %v", err)
		}
		check(t, evt.ID)
	})
	t.Run("AppendTx", func(t *testing.T) {
		evt := &storage.AuditEvent{Actor: "agent:test", Action: "wrap.create", Resource: "request:" + reqID,
			Status: storage.AuditStatusDenied, Metadata: meta()}
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("Begin: %v", err)
		}
		if err := repo.AppendTx(ctx, tx, evt); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("AppendTx: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("Commit: %v", err)
		}
		check(t, evt.ID)
	})
}
