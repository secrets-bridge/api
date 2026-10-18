package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

const ssoTestSecret = "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3456789"

// TestLive_SSOProviders drives the sign-in configuration routes through
// the real router (api#267): who may use them, the step-up on every
// write, the client secret never leaving in plain, the default-role
// rules, the public address and enabling.
func TestLive_SSOProviders(t *testing.T) {
	l := newLiveApp(t)
	ctx := t.Context()

	// The seeded admin role carries the new permission (migration 0043).
	var adminHas bool
	if err := l.pool.QueryRow(ctx,
		`SELECT permissions ? 'auth.sso.edit' FROM roles WHERE name = 'admin' AND is_system`).Scan(&adminHas); err != nil || !adminHas {
		t.Fatalf("seeded admin role holds auth.sso.edit = %v, %v", adminHas, err)
	}

	admin := uuid.New()
	as := map[string]string{"Cookie": l.sessionFor(t, admin, "sso-admin@example.com")}
	l.addGrant(t, admin.String(), []string{"auth.sso.edit"}, `{}`)

	google := map[string]any{
		"type": "google", "client_id": "123-abc.apps.googleusercontent.com", "client_secret": ssoTestSecret,
		"allowed_domains": []string{"Example.com", " example.com ", "corp.example.org"},
	}

	t.Run("only a global auth.sso.edit gets in", func(t *testing.T) {
		scoped := uuid.New()
		sas := map[string]string{"Cookie": l.sessionFor(t, scoped, "sso-scoped@example.com")}
		l.addGrant(t, scoped.String(), []string{"auth.sso.edit"}, `{"team_id":"`+uuid.NewString()+`"}`)
		for _, path := range []string{"/api/v1/sso/providers", "/api/v1/sso/settings"} {
			if code, body := l.callAs(t, http.MethodGet, path, sas, nil); code != http.StatusForbidden {
				t.Errorf("GET %s as team-scoped = %d %s; want 403", path, code, body)
			}
		}
		if code, body := l.callAs(t, http.MethodPost, "/api/v1/sso/providers", sas, google); code != http.StatusForbidden {
			t.Errorf("create as team-scoped = %d %s; want 403", code, body)
		}
	})

	t.Run("a write without a fresh second factor gets 401", func(t *testing.T) {
		stale := uuid.New()
		stas := map[string]string{"Cookie": l.sessionFor(t, stale, "sso-stale@example.com")}
		l.addGrant(t, stale.String(), []string{"auth.sso.edit"}, `{}`)
		// An enrolled factor, so the refusal is the step-up challenge (401)
		// and not "enroll a factor first" (412); then a stale session.
		if _, err := l.pool.Exec(ctx, `
			INSERT INTO user_mfa_factors (user_id, kind, label, secret_ciphertext, secret_nonce, data_key_ciphertext, kms_key_id)
			VALUES ($1, 'totp', 'test', '\x00', '\x00', '\x00', 'test')`, stale); err != nil {
			t.Fatal(err)
		}
		if _, err := l.pool.Exec(ctx, `UPDATE sessions SET last_mfa_at = NULL WHERE user_id = $1`, stale); err != nil {
			t.Fatal(err)
		}
		for _, w := range []struct{ method, path string }{
			{http.MethodPost, "/api/v1/sso/providers"},
			{http.MethodPut, "/api/v1/sso/settings"},
			{http.MethodPut, "/api/v1/sso/providers/" + uuid.NewString()},
			{http.MethodPut, "/api/v1/sso/providers/" + uuid.NewString() + "/secret"},
			{http.MethodPost, "/api/v1/sso/providers/" + uuid.NewString() + "/enable"},
			{http.MethodDelete, "/api/v1/sso/providers/" + uuid.NewString()},
		} {
			code, body := l.callAs(t, w.method, w.path, stas, google)
			if code != http.StatusUnauthorized || !strings.Contains(string(body), "step_up_required") {
				t.Errorf("%s %s without fresh MFA = %d %s; want 401 step_up_required", w.method, w.path, code, body)
			}
		}
		if code, _ := l.callAs(t, http.MethodGet, "/api/v1/sso/providers", stas, nil); code != http.StatusOK {
			t.Errorf("reading without fresh MFA = %d; want 200", code)
		}
	})

	var provider struct {
		ID              string   `json:"id"`
		ClientSecretSet bool     `json:"client_secret_set"`
		AllowedDomains  []string `json:"allowed_domains"`
		RequireApproval bool     `json:"require_approval"`
		Enabled         bool     `json:"enabled"`
		RedirectURL     string   `json:"redirect_url"`
	}

	t.Run("create stores the secret sealed and never returns it", func(t *testing.T) {
		code, body := l.callAs(t, http.MethodPost, "/api/v1/sso/providers", as, google)
		if code != http.StatusCreated {
			t.Fatalf("create = %d %s", code, body)
		}
		mustJSON(t, body, &provider)
		if strings.Contains(string(body), ssoTestSecret) || !provider.ClientSecretSet || provider.Enabled || !provider.RequireApproval {
			t.Fatalf("create body = %s; want the secret absent, client_secret_set, disabled, approval on", body)
		}
		if strings.Join(provider.AllowedDomains, ",") != "example.com,corp.example.org" {
			t.Errorf("allowed_domains = %v; want lowercased and de-duplicated", provider.AllowedDomains)
		}
		if provider.RedirectURL != "" {
			t.Errorf("redirect_url = %q before a public address is set; want empty", provider.RedirectURL)
		}
		if code, body := l.callAs(t, http.MethodPost, "/api/v1/sso/providers", as, google); code != http.StatusConflict ||
			!strings.Contains(string(body), "provider_exists") {
			t.Errorf("second google provider = %d %s; want 409 provider_exists", code, body)
		}
	})

	t.Run("a default role needs approval off and must be non-privileged", func(t *testing.T) {
		var adminRole string
		if err := l.pool.QueryRow(ctx, `SELECT id FROM roles WHERE name = 'admin' AND is_system`).Scan(&adminRole); err != nil {
			t.Fatal(err)
		}
		basic := uuid.New()
		if _, err := l.pool.Exec(ctx, `INSERT INTO roles (id, name, permissions) VALUES ($1, 'sso-basic', '["secret.request","secret.list"]')`, basic); err != nil {
			t.Fatal(err)
		}
		edit := func(requireApproval bool, role string) (int, []byte) {
			return l.callAs(t, http.MethodPut, "/api/v1/sso/providers/"+provider.ID, as, map[string]any{
				"client_id": "123-abc.apps.googleusercontent.com", "allowed_domains": []string{"example.com"},
				"require_approval": requireApproval, "default_role_id": role,
			})
		}
		if code, body := edit(true, basic.String()); code != http.StatusBadRequest || !strings.Contains(string(body), "default_role_needs_approval_off") {
			t.Errorf("default role with approval on = %d %s", code, body)
		}
		if code, body := edit(false, adminRole); code != http.StatusBadRequest || !strings.Contains(string(body), "default_role_privileged") {
			t.Errorf("approval off with the admin role = %d %s; want 400 default_role_privileged", code, body)
		}
		if code, body := edit(false, basic.String()); code != http.StatusOK {
			t.Errorf("approval off with a non-privileged role = %d %s; want 200", code, body)
		}
		ev := l.requireOneAudit(t, "sso_provider.update", admin.String())
		oldV, _ := ev.Metadata["old"].(map[string]any)
		newV, _ := ev.Metadata["new"].(map[string]any)
		if oldV["require_approval"] != true || newV["require_approval"] != false || newV["default_role_id"] != basic.String() {
			t.Errorf("sso_provider.update old/new = %v / %v", oldV, newV)
		}
	})

	t.Run("bad input is refused with the field", func(t *testing.T) {
		bad := map[string]any{"client_id": "x", "allowed_domains": []string{"not a domain"}}
		if code, body := l.callAs(t, http.MethodPut, "/api/v1/sso/providers/"+provider.ID, as, bad); code != http.StatusBadRequest ||
			!strings.Contains(string(body), "allowed_domains") {
			t.Errorf("bad domain = %d %s", code, body)
		}
	})

	t.Run("enabling needs a public address", func(t *testing.T) {
		code, body := l.callAs(t, http.MethodPost, "/api/v1/sso/providers/"+provider.ID+"/enable", as, nil)
		if code != http.StatusConflict || !strings.Contains(string(body), "public_url") {
			t.Fatalf("enable without a public address = %d %s; want 409 naming public_url", code, body)
		}
	})

	t.Run("the public address is validated and builds the redirect URI", func(t *testing.T) {
		for _, bad := range []string{"http://secrets.example.com", "secrets.example.com", "https://x.example.com/?a=b", "https://user@x.example.com"} {
			if code, body := l.callAs(t, http.MethodPut, "/api/v1/sso/settings", as, map[string]any{"public_url": bad}); code != http.StatusBadRequest {
				t.Errorf("public_url %q = %d %s; want 400", bad, code, body)
			}
		}
		code, body := l.callAs(t, http.MethodPut, "/api/v1/sso/settings", as, map[string]any{"public_url": "https://secrets.example.com/", "pending_cap": 25})
		if code != http.StatusOK || !strings.Contains(string(body), `"public_url":"https://secrets.example.com"`) ||
			!strings.Contains(string(body), `"public_url_source":"console"`) || !strings.Contains(string(body), `"pending_cap":25`) {
			t.Fatalf("set settings = %d %s", code, body)
		}
		// A forged Host or X-Forwarded-Host doesn't change the redirect URI.
		forged := map[string]string{"Cookie": as["Cookie"], "Host": "evil.example", "X-Forwarded-Host": "evil.example", "X-Forwarded-Proto": "http"}
		code, body = l.callAs(t, http.MethodGet, "/api/v1/sso/providers/"+provider.ID, forged, nil)
		mustJSON(t, body, &provider)
		if code != http.StatusOK || provider.RedirectURL != "https://secrets.example.com/api/v1/auth/sso/google/callback" {
			t.Fatalf("redirect_url with forged headers = %d %q", code, provider.RedirectURL)
		}
		ev := l.requireOneAudit(t, "sso_settings.update", admin.String())
		if newV, _ := ev.Metadata["new"].(map[string]any); newV["public_url"] != "https://secrets.example.com" {
			t.Errorf("sso_settings.update new = %v", ev.Metadata["new"])
		}
	})

	t.Run("enable, rotate the secret, disable", func(t *testing.T) {
		if code, body := l.callAs(t, http.MethodPost, "/api/v1/sso/providers/"+provider.ID+"/enable", as, nil); code != http.StatusNoContent {
			t.Fatalf("enable = %d %s", code, body)
		}
		var before []byte
		if err := l.pool.QueryRow(ctx, `SELECT client_secret_ciphertext FROM sso_providers WHERE id = $1`, provider.ID).Scan(&before); err != nil {
			t.Fatal(err)
		}
		if code, body := l.callAs(t, http.MethodPut, "/api/v1/sso/providers/"+provider.ID+"/secret", as,
			map[string]any{"client_secret": ssoTestSecret + "-rotated"}); code != http.StatusNoContent {
			t.Fatalf("rotate = %d %s", code, body)
		}
		var after []byte
		if err := l.pool.QueryRow(ctx, `SELECT client_secret_ciphertext FROM sso_providers WHERE id = $1`, provider.ID).Scan(&after); err != nil {
			t.Fatal(err)
		}
		if string(before) == string(after) {
			t.Error("rotating didn't change the stored ciphertext")
		}
		if code, body := l.callAs(t, http.MethodPost, "/api/v1/sso/providers/"+provider.ID+"/disable", as, nil); code != http.StatusNoContent {
			t.Fatalf("disable = %d %s", code, body)
		}
		l.requireOneAudit(t, "sso_provider.enable", admin.String())
		l.requireOneAudit(t, "sso_provider.secret_rotate", admin.String())
		l.requireOneAudit(t, "sso_provider.disable", admin.String())
	})

	t.Run("the secret is nowhere in plain", func(t *testing.T) {
		var leaks int
		if err := l.pool.QueryRow(ctx, `
			SELECT (SELECT count(*) FROM sso_providers
			        WHERE position($1::bytea IN client_secret_ciphertext) > 0
			           OR client_id LIKE '%' || $2 || '%' OR display_name LIKE '%' || $2 || '%')
			     + (SELECT count(*) FROM audit_events WHERE metadata::text LIKE '%' || $2 || '%')`,
			[]byte("not-a-real-client-secret"), "not-a-real-client-secret").Scan(&leaks); err != nil {
			t.Fatal(err)
		}
		if leaks != 0 {
			t.Fatalf("the client secret appears in plain in %d rows", leaks)
		}
		_, body := l.callAs(t, http.MethodGet, "/api/v1/sso/providers", as, nil)
		if strings.Contains(string(body), "not-a-real-client-secret") {
			t.Fatal("GET /sso/providers returned the secret")
		}
	})

	t.Run("delete is audited with the old values", func(t *testing.T) {
		if code, body := l.callAs(t, http.MethodDelete, "/api/v1/sso/providers/"+provider.ID, as, nil); code != http.StatusNoContent {
			t.Fatalf("delete = %d %s", code, body)
		}
		ev := l.requireOneAudit(t, "sso_provider.delete", admin.String())
		raw, _ := json.Marshal(ev.Metadata)
		if !strings.Contains(string(raw), "example.com") || strings.Contains(string(raw), "not-a-real-client-secret") {
			t.Errorf("sso_provider.delete metadata = %s", raw)
		}
	})
}

// With SB_PUBLIC_URL set, the address comes from the install and the
// console can't change it.
func TestLive_SSOPublicURLFromEnv(t *testing.T) {
	l := newLiveApp(t, func(c *Config) { c.PublicURL = "https://secrets.example.com/" })
	admin := uuid.New()
	as := map[string]string{"Cookie": l.sessionFor(t, admin, "sso-env@example.com")}
	l.addGrant(t, admin.String(), []string{"auth.sso.edit"}, `{}`)

	code, body := l.callAs(t, http.MethodGet, "/api/v1/sso/settings", as, nil)
	if code != http.StatusOK || !strings.Contains(string(body), `"public_url":"https://secrets.example.com"`) ||
		!strings.Contains(string(body), `"public_url_source":"env"`) {
		t.Fatalf("settings with SB_PUBLIC_URL = %d %s", code, body)
	}
	code, body = l.callAs(t, http.MethodPut, "/api/v1/sso/settings", as, map[string]any{"public_url": "https://other.example.com"})
	if code != http.StatusConflict || !strings.Contains(string(body), "public_url_from_env") {
		t.Fatalf("changing an env public address = %d %s; want 409 public_url_from_env", code, body)
	}
	if code, body := l.callAs(t, http.MethodPut, "/api/v1/sso/settings", as, map[string]any{"pending_cap": 10}); code != http.StatusOK {
		t.Fatalf("changing only the cap = %d %s; want 200", code, body)
	}
}
