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

// Placeholder credentials for each pattern, written without spaces so
// they have the shape of an id, a token, a digest and a scalar string:
// only the credential check can keep them out (api#279).
var auditCredentialCanaries = map[string]string{
	"aws":           "AKIA" + strings.Repeat("Q7", 8),
	"github":        "ghp_" + strings.Repeat("A1b2", 9),
	"github_pat":    "github_pat_" + strings.Repeat("Ab12", 6),
	"gitlab":        "glpat-" + strings.Repeat("x1Y2", 5),
	"slack":         "xoxb-123456789012-abcdefABCDEF",
	"sk":            "sk-" + strings.Repeat("aB3d", 6),
	"pem":           "pem-----BEGIN-PRIVATE-KEY-----MIIEvQ",
	"vault_in_list": "hvs." + strings.Repeat("C1", 12),
}

func TestSanitizeAuditMetadata_CredentialInEveryKind(t *testing.T) {
	kinds := map[string]string{
		"id": "filled_by", "token": "phase", "digest": "sha256", "scalar": "succeeded",
		"name": "key", "email": "email",
	}
	lists := map[string]string{"id_list": "deleted_policy_rule_ids", "token_list": "permissions", "name_list": "key_names"}
	for pname, c := range auditCredentialCanaries {
		for kname, key := range kinds {
			val := c
			if kname == "email" {
				val = c + "@example.com"
			}
			if kname == "digest" && strings.Contains(c, ".") {
				continue // a dot is not a digest character, the shape check already refuses it
			}
			action := "test.cred." + pname + "." + kname
			out := storage.SanitizeAuditMetadata(action, map[string]any{key: val, "request_id": uuid.New().String()})
			if _, kept := out[key]; kept {
				t.Errorf("%s in %s (%s) kept: %#v", pname, kname, key, out)
				continue
			}
			if rk, _ := out["_rejected_keys"].([]string); len(rk) != 1 || rk[0] != key {
				t.Errorf("%s in %s: _rejected_keys = %#v", pname, kname, out["_rejected_keys"])
			}
			if n := storage.AuditMetadataDrops()[storage.AuditMetadataDrop{Action: action, Key: key, Reason: storage.AuditDropCredential}]; n != 1 {
				t.Errorf("%s in %s: credential drop counted %d times, want 1", pname, kname, n)
			}
		}
		for lname, key := range lists {
			out := storage.SanitizeAuditMetadata("test.cred."+pname+"."+lname, map[string]any{key: []any{"DB_USER", c}})
			if _, kept := out[key]; kept {
				t.Errorf("%s in %s (%s) kept: %#v", pname, lname, key, out)
			}
		}
	}
}

// The values from the #275 review probe, each of which was stored
// unchanged before api#279.
func TestSanitizeAuditMetadata_ReviewProbe(t *testing.T) {
	out := storage.SanitizeAuditMetadata("test.probe", map[string]any{
		"reason":    "-----BEGIN PRIVATE KEY----- MIIEvQIBADANBgkqhkiG9w0BAQEFAASC",
		"key":       "xoxb-123456789012-abcdefABCDEF",
		"filled_by": "hvs.CAESIJ8x7nY2Z3h0b2tlbi1mb3ItdGVzdGluZw",
		"old_value": "plaintextSecretValue123",
		"base_url":  "https://admin:pw@host.example.com/?token=abc",
	})
	for _, k := range []string{"reason", "key", "filled_by", "old_value"} {
		if v, kept := out[k]; kept {
			t.Errorf("%s kept: %#v", k, v)
		}
	}
	if out["base_url"] != "https://host.example.com/" {
		t.Errorf("base_url = %#v, want user info and query stripped", out["base_url"])
	}
}

func TestSanitizeAuditMetadata_URLsLoseUserInfoAndQuery(t *testing.T) {
	cases := map[string]any{
		"https://admin:pw@argocd.example.com/api?token=abc#frag": "https://argocd.example.com/api",
		"https://user@secrets.example.com":                       "https://secrets.example.com",
		"https://argocd.example.com:8443/base/":                  "https://argocd.example.com:8443/base/",
		"http://argocd-server.argocd.svc":                        "http://argocd-server.argocd.svc",
		"":                                                       "",
	}
	for in, want := range cases {
		out := storage.SanitizeAuditMetadata("test.url", map[string]any{
			"base_url": in,
			"new":      map[string]any{"public_url": in},
		})
		if out["base_url"] != want {
			t.Errorf("base_url %q = %#v, want %#v", in, out["base_url"], want)
		}
		if nested, _ := out["new"].(map[string]any); nested["public_url"] != want {
			t.Errorf("new.public_url %q = %#v, want %#v", in, out["new"], want)
		}
	}
	for _, bad := range []any{"not a url", "argocd.example.com/api", "mailto:a@example.com", 42,
		"https://argocd.example.com/" + "ghp_" + strings.Repeat("A1b2", 9)} {
		out := storage.SanitizeAuditMetadata("test.url_bad", map[string]any{"base_url": bad})
		if v, kept := out["base_url"]; kept {
			t.Errorf("base_url %#v kept as %#v", bad, v)
		}
	}
	if out := storage.SanitizeAuditMetadata("test.url_null", map[string]any{"public_url": nil}); out["public_url"] != nil {
		t.Errorf("null public_url = %#v", out["public_url"])
	}
}

// A nested key is named by its path, so "new.display_name" and
// "old.display_name" can be told apart.
func TestSanitizeAuditMetadata_NestedKeysNamedByPath(t *testing.T) {
	out := storage.SanitizeAuditMetadata("test.paths", map[string]any{
		"new":     map[string]any{"display_name": "line\nbreak", "client_secret": "x", "enabled": true},
		"old":     map[string]any{"display_name": "ok", "new": map[string]any{"old": map[string]any{"name": "deep"}}},
		"label":   "AKIA" + strings.Repeat("Q7", 8),
		"unknown": 1,
	})
	rk, _ := out["_rejected_keys"].([]string)
	dk, _ := out["_dropped_keys"].([]string)
	if strings.Join(rk, ",") != "label,new.display_name,old.new.old" {
		t.Errorf("_rejected_keys = %#v", rk)
	}
	if strings.Join(dk, ",") != "new.client_secret,unknown" {
		t.Errorf("_dropped_keys = %#v", dk)
	}
	drops := storage.AuditMetadataDrops()
	for d, want := range map[storage.AuditMetadataDrop]int{
		{Action: "test.paths", Key: "new.display_name", Reason: storage.AuditDropBadValue}:    1,
		{Action: "test.paths", Key: "new.client_secret", Reason: storage.AuditDropUnknownKey}: 1,
		{Action: "test.paths", Key: "label", Reason: storage.AuditDropCredential}:             1,
		{Action: "test.paths", Key: "old.new.old", Reason: storage.AuditDropBadValue}:         1,
	} {
		if drops[d] != want {
			t.Errorf("drops[%+v] = %d, want %d", d, drops[d], want)
		}
	}
}

func TestAuditMetadataDrops_Reset(t *testing.T) {
	storage.SanitizeAuditMetadata("test.reset", map[string]any{"nope": 1})
	if storage.AuditMetadataDrops()[storage.AuditMetadataDrop{Action: "test.reset", Key: "nope", Reason: storage.AuditDropUnknownKey}] == 0 {
		t.Fatal("drop not counted")
	}
	storage.ResetAuditMetadataDrops()
	if n := len(storage.AuditMetadataDrops()); n != 0 {
		t.Fatalf("after reset: %d entries", n)
	}
}
