package services

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/keymgmt"
	"github.com/secrets-bridge/api/pkg/storage"
)

func TestNormalizePublicURL(t *testing.T) {
	good := map[string]string{
		"https://secrets.example.com":       "https://secrets.example.com",
		"https://secrets.example.com/":      "https://secrets.example.com",
		" https://secrets.example.com/sb/ ": "https://secrets.example.com/sb",
		"https://secrets.example.com:8443":  "https://secrets.example.com:8443",
	}
	for in, want := range good {
		for _, dev := range []bool{false, true} {
			if got, err := NormalizePublicURL(in, dev); err != nil || got != want {
				t.Errorf("NormalizePublicURL(%q, dev=%v) = %q, %v; want %q", in, dev, got, err, want)
			}
		}
	}
	for _, in := range []string{"", "secrets.example.com", "http://secrets.example.com", "ftp://x.example.com",
		"https://u:p@x.example.com", "https://x.example.com/?a=b", "https://x.example.com/#f"} {
		for _, dev := range []bool{false, true} {
			if got, err := NormalizePublicURL(in, dev); err == nil {
				t.Errorf("NormalizePublicURL(%q, dev=%v) = %q; want an error", in, dev, got)
			}
		}
	}
	// Plain http for localhost and loopback only with SB_ENV=dev.
	loopback := map[string]string{
		"http://localhost:18080":  "http://localhost:18080",
		"http://127.0.0.1:18080/": "http://127.0.0.1:18080",
		"http://[::1]:18080":      "http://[::1]:18080",
	}
	for in, want := range loopback {
		if got, err := NormalizePublicURL(in, true); err != nil || got != want {
			t.Errorf("NormalizePublicURL(%q, dev) = %q, %v; want %q", in, got, err, want)
		}
		if got, err := NormalizePublicURL(in, false); err == nil {
			t.Errorf("NormalizePublicURL(%q) outside dev = %q; want an error", in, got)
		}
	}
}

// fakeSSOStore keeps one provider in memory; only what these tests use.
type fakeSSOStore struct {
	ssoStore
	created  *storage.SSOProvider
	settings storage.SSOSettings
}

func (f *fakeSSOStore) GetSettings(context.Context) (*storage.SSOSettings, error) {
	st := f.settings
	return &st, nil
}

func (f *fakeSSOStore) CreateProvider(_ context.Context, p *storage.SSOProvider, _ []string) error {
	p.ID = uuid.New()
	f.created = p
	return nil
}

func (f *fakeSSOStore) GetProvider(_ context.Context, id uuid.UUID) (*storage.SSOProvider, error) {
	if f.created == nil || f.created.ID != id {
		return nil, storage.ErrNotFound
	}
	return f.created, nil
}

type fakeRoles map[uuid.UUID]*storage.Role

func (f fakeRoles) Get(_ context.Context, id uuid.UUID) (*storage.Role, error) {
	if r, ok := f[id]; ok {
		return r, nil
	}
	return nil, storage.ErrNotFound
}

func newTestSSO(t *testing.T, envIssuer string, roles fakeRoles) (*SSOService, *fakeSSOStore) {
	t.Helper()
	km, err := keymgmt.NewLocalKMS(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeSSOStore{}
	s, err := NewSSOService(store, roles, km, "", envIssuer, false)
	if err != nil {
		t.Fatal(err)
	}
	return s, store
}

// The console won't add Google when SB_OIDC_ISSUER is already Google.
func TestSSO_RefusesGoogleWhenEnvProviderIsGoogle(t *testing.T) {
	s, _ := newTestSSO(t, "https://accounts.google.com", nil)
	_, err := s.CreateProvider(t.Context(), SSOProviderInput{
		Type: "google", ClientID: "x", ClientSecret: "y", AllowedDomains: []string{"example.com"}, RequireApproval: true,
	}, "user:a")
	if !errors.Is(err, ErrSSOEnvProviderIsGoogle) {
		t.Fatalf("create with a Google env provider = %v; want ErrSSOEnvProviderIsGoogle", err)
	}
	s, _ = newTestSSO(t, "https://idp.example.com", nil)
	if _, err := s.CreateProvider(t.Context(), SSOProviderInput{
		Type: "google", ClientID: "x", ClientSecret: "y", AllowedDomains: []string{"example.com"}, RequireApproval: true,
	}, "user:a"); err != nil {
		t.Fatalf("create with another env provider = %v; want ok", err)
	}
}

// api#274: a saved address is checked again when it's read. One saved
// under an older rule (plain http for localhost before that needed
// SB_ENV=dev) counts as unset outside dev, so sign-in fails closed.
func TestSSO_SavedPublicURLIsCheckedOnRead(t *testing.T) {
	km, err := keymgmt.NewLocalKMS(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeSSOStore{settings: storage.SSOSettings{PublicURL: "http://localhost:5173", PendingCap: 50}}
	for _, tc := range []struct {
		dev         bool
		url, source string
	}{{false, "", ""}, {true, "http://localhost:5173", "console"}} {
		s, err := NewSSOService(store, nil, km, "", "", tc.dev)
		if err != nil {
			t.Fatal(err)
		}
		url, source, err := s.PublicURL(t.Context())
		if err != nil || url != tc.url || source != tc.source {
			t.Errorf("PublicURL with dev=%v = %q, %q, %v; want %q, %q", tc.dev, url, source, err, tc.url, tc.source)
		}
		if redirect, _ := s.RedirectURL(t.Context(), "google"); (redirect == "") != (tc.url == "") {
			t.Errorf("RedirectURL with dev=%v = %q", tc.dev, redirect)
		}
	}
	store.settings.PublicURL = "https://secrets.example.com"
	s, _ := NewSSOService(store, nil, km, "", "", false)
	if url, _, _ := s.PublicURL(t.Context()); url != "https://secrets.example.com" {
		t.Errorf("a valid saved address = %q", url)
	}
}

// A provider saved before SB_OIDC_ISSUER was pointed at Google can't be
// turned on, and isn't offered on the login page.
func TestSSO_EnvGoogleBlocksEnableAndListing(t *testing.T) {
	s, store := newTestSSO(t, "https://idp.example.com", nil)
	p, err := s.CreateProvider(t.Context(), SSOProviderInput{
		Type: "google", ClientID: "x", ClientSecret: "y", AllowedDomains: []string{"example.com"}, RequireApproval: true,
	}, "user:a")
	if err != nil {
		t.Fatal(err)
	}
	km, err := keymgmt.NewLocalKMS(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	google, err := NewSSOService(store, nil, km, "", "https://accounts.google.com", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := google.SetEnabled(t.Context(), p.ID, true, "user:a"); !errors.Is(err, ErrSSOEnvProviderIsGoogle) {
		t.Fatalf("enable with a Google env provider = %v; want ErrSSOEnvProviderIsGoogle", err)
	}
	listed, err := (&SSOSignIn{cfg: google}).Enabled(t.Context())
	if err != nil || len(listed) != 0 {
		t.Fatalf("Enabled with a Google env provider = %v, %v; want none", listed, err)
	}
}

// The secret is sealed with a fresh data key and opens back to itself;
// the stored form never contains it.
func TestSSO_SecretSealsAndOpens(t *testing.T) {
	s, store := newTestSSO(t, "", nil)
	const secret = "GOCSPX-sealed-secret-value"
	if _, err := s.CreateProvider(t.Context(), SSOProviderInput{
		Type: "google", ClientID: "x", ClientSecret: secret, AllowedDomains: []string{"example.com"}, RequireApproval: true,
	}, "user:a"); err != nil {
		t.Fatal(err)
	}
	sealed := store.created.Secret
	if sealed == nil || bytes.Contains(sealed.Ciphertext, []byte(secret)) || len(sealed.DataKeyCiphertext) == 0 || sealed.KMSKeyID == "" {
		t.Fatalf("stored secret = %+v", sealed)
	}
	got, err := s.ClientSecret(t.Context(), store.created)
	if err != nil || string(got) != secret {
		t.Fatalf("ClientSecret = %q, %v", got, err)
	}
}

func TestSSO_DefaultRoleRules(t *testing.T) {
	basic, priv := uuid.New(), uuid.New()
	roles := fakeRoles{
		basic: {ID: basic, Permissions: []string{"secret.request", "audit.read"}},
		priv:  {ID: priv, Permissions: []string{"secret.request", "secret.approve"}},
	}
	s, _ := newTestSSO(t, "", roles)
	in := func(requireApproval bool, role uuid.UUID) SSOProviderInput {
		return SSOProviderInput{Type: "google", ClientID: "x", ClientSecret: "y", AllowedDomains: []string{"example.com"},
			RequireApproval: requireApproval, DefaultRoleID: &role}
	}
	if _, err := s.CreateProvider(t.Context(), in(true, basic), "u"); !errors.Is(err, ErrSSODefaultRoleNeedsOff) {
		t.Errorf("default role with approval on = %v", err)
	}
	if _, err := s.CreateProvider(t.Context(), in(false, priv), "u"); !errors.Is(err, ErrSSOPrivilegedDefaultRole) {
		t.Errorf("privileged default role = %v", err)
	}
	if _, err := s.CreateProvider(t.Context(), in(false, uuid.New()), "u"); !errors.Is(err, ErrSSOInvalid) {
		t.Errorf("unknown default role = %v", err)
	}
	if _, err := s.CreateProvider(t.Context(), in(false, basic), "u"); err != nil {
		t.Errorf("non-privileged default role = %v", err)
	}
}
