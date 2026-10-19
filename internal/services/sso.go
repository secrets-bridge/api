// Package services, sso.go: sign-in providers configured from the
// console and the sign-in settings (api#265, api#267).
//
// This part stores and validates the configuration; signing in with it
// is the second half of api#267. Rules the review asked for:
//
//   - The client secret is sealed with the KMS (a fresh data key per
//     secret, AES-256-GCM), never stored, logged or returned in plain.
//   - A default role is only allowed when approval is off, and only a
//     non-privileged one: every permission it holds is in
//     NonPrivilegedPermissions.
//   - The public address comes from SB_PUBLIC_URL when the install sets
//     it, otherwise from the console. Redirect URIs are built from it,
//     never from request headers.
//   - The console won't add a Google provider when the env-var provider
//     is already Google.
package services

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/pkg/keymgmt"
	"github.com/secrets-bridge/api/pkg/storage"
)

// NonPrivilegedPermissions are the only permissions a provider's default
// role may hold. audit.read is safe since #259 limits it to the reader's
// own events.
var NonPrivilegedPermissions = []string{
	string(auth.PermSecretList), string(auth.PermSecretRequest), string(auth.PermAuditRead),
}

// SSOCallbackPath is where a provider of each type sends the browser
// back. The redirect URI registered at the provider is the public
// address plus this path.
func SSOCallbackPath(providerType string) string {
	return "/api/v1/auth/sso/" + providerType + "/callback"
}

// Sign-in configuration errors. Handlers map them to stable codes.
var (
	ErrSSOInvalid               = errors.New("services: invalid sign-in provider input")
	ErrSSOPrivilegedDefaultRole = errors.New("services: default role holds privileged permissions")
	ErrSSODefaultRoleNeedsOff   = errors.New("services: a default role needs approval off")
	ErrSSOEnvProviderIsGoogle   = errors.New("services: the env-var provider is already Google")
	ErrSSONotReady              = errors.New("services: provider is not ready to enable")
	ErrSSOPublicURLFromEnv      = errors.New("services: the public address is set by SB_PUBLIC_URL")
)

// SSOInputError carries the field and reason for ErrSSOInvalid.
type SSOInputError struct {
	Field  string
	Reason string
}

func (e *SSOInputError) Error() string { return e.Field + ": " + e.Reason }
func (e *SSOInputError) Unwrap() error { return ErrSSOInvalid }

// SSONotReadyError lists what's missing before a provider can be enabled.
type SSONotReadyError struct{ Missing []string }

func (e *SSONotReadyError) Error() string { return "missing: " + strings.Join(e.Missing, ", ") }
func (e *SSONotReadyError) Unwrap() error { return ErrSSONotReady }

// SSOProviderInput is what an admin sets on a provider. ClientSecret is
// only read on create; replacing it is SetSecret.
type SSOProviderInput struct {
	Type            string
	DisplayName     string
	ClientID        string
	ClientSecret    string
	AllowedDomains  []string
	RequireApproval bool
	DefaultRoleID   *uuid.UUID
}

type ssoStore interface {
	CreateProvider(ctx context.Context, p *storage.SSOProvider, allowedDefaultPerms []string) error
	GetProvider(ctx context.Context, id uuid.UUID) (*storage.SSOProvider, error)
	ListProviders(ctx context.Context) ([]*storage.SSOProvider, error)
	UpdateProvider(ctx context.Context, p *storage.SSOProvider, allowedDefaultPerms []string) (*storage.SSOProvider, error)
	SetProviderSecret(ctx context.Context, id uuid.UUID, secret storage.SSOSecret, by string) error
	SetProviderEnabled(ctx context.Context, id uuid.UUID, enabled bool, by string) error
	DeleteProvider(ctx context.Context, id uuid.UUID) (*storage.SSOProvider, error)
	GetSettings(ctx context.Context) (*storage.SSOSettings, error)
	UpdateSettings(ctx context.Context, publicURL *string, pendingCap *int, by string) (before, after *storage.SSOSettings, err error)
}

type roleGetter interface {
	Get(ctx context.Context, id uuid.UUID) (*storage.Role, error)
}

// SSOService validates and stores the sign-in configuration.
type SSOService struct {
	store     ssoStore
	roles     roleGetter
	km        keymgmt.KeyManager
	envPublic string // SB_PUBLIC_URL, normalised; empty when unset
	envIssuer string // SB_OIDC_ISSUER
	dev       bool   // SB_ENV=dev: a plain-http loopback address is allowed
}

// NewSSOService wires the service. envPublicURL is SB_PUBLIC_URL and
// envOIDCIssuer is SB_OIDC_ISSUER; either may be empty. dev is
// SB_ENV=dev, the only mode that accepts a plain-http public address
// (localhost or loopback).
func NewSSOService(store ssoStore, roles roleGetter, km keymgmt.KeyManager, envPublicURL, envOIDCIssuer string, dev bool) (*SSOService, error) {
	s := &SSOService{store: store, roles: roles, km: km, envIssuer: envOIDCIssuer, dev: dev}
	if envPublicURL != "" {
		u, err := NormalizePublicURL(envPublicURL, dev)
		if err != nil {
			return nil, fmt.Errorf("SB_PUBLIC_URL: %w", err)
		}
		s.envPublic = u
	}
	return s, nil
}

// ListProviders returns every provider.
func (s *SSOService) ListProviders(ctx context.Context) ([]*storage.SSOProvider, error) {
	return s.store.ListProviders(ctx)
}

// GetProvider returns one provider.
func (s *SSOService) GetProvider(ctx context.Context, id uuid.UUID) (*storage.SSOProvider, error) {
	return s.store.GetProvider(ctx, id)
}

// CreateProvider validates in, seals the secret and stores the provider,
// disabled.
func (s *SSOService) CreateProvider(ctx context.Context, in SSOProviderInput, by string) (*storage.SSOProvider, error) {
	if in.Type != storage.SSOProviderTypeGoogle {
		return nil, &SSOInputError{"type", "only google is supported"}
	}
	if s.envIsGoogle() {
		return nil, ErrSSOEnvProviderIsGoogle
	}
	p := &storage.SSOProvider{Type: in.Type, CreatedBy: by}
	if err := s.apply(ctx, p, in); err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.ClientSecret) == "" {
		return nil, &SSOInputError{"client_secret", "is required"}
	}
	sealed, err := s.seal(ctx, in.ClientSecret)
	if err != nil {
		return nil, err
	}
	p.Secret = sealed
	// apply checked the default role for a clear error; the store checks
	// it again under a lock on the role, against a concurrent role edit.
	if err := s.store.CreateProvider(ctx, p, NonPrivilegedPermissions); err != nil {
		return nil, mapDefaultRoleErr(err)
	}
	return p, nil
}

// UpdateProvider replaces the editable fields and returns the provider
// before and after.
func (s *SSOService) UpdateProvider(ctx context.Context, id uuid.UUID, in SSOProviderInput, by string) (before, after *storage.SSOProvider, err error) {
	// The secret only changes through SetSecret, which audits the
	// rotation. One sent here used to be ignored with a 200.
	if in.ClientSecret != "" {
		return nil, nil, &SSOInputError{"client_secret", "can't be changed here; replace it with PUT /sso/providers/:id/secret"}
	}
	current, err := s.store.GetProvider(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	p := &storage.SSOProvider{ID: id, Type: current.Type, UpdatedBy: by}
	if err := s.apply(ctx, p, in); err != nil {
		return nil, nil, err
	}
	before, err = s.store.UpdateProvider(ctx, p, NonPrivilegedPermissions)
	if err != nil {
		return nil, nil, mapDefaultRoleErr(err)
	}
	after, err = s.store.GetProvider(ctx, id)
	return before, after, err
}

// SetSecret seals and stores a new client secret.
func (s *SSOService) SetSecret(ctx context.Context, id uuid.UUID, secret, by string) error {
	if strings.TrimSpace(secret) == "" {
		return &SSOInputError{"client_secret", "is required"}
	}
	sealed, err := s.seal(ctx, secret)
	if err != nil {
		return err
	}
	return s.store.SetProviderSecret(ctx, id, *sealed, by)
}

// SetEnabled turns a provider on or off. Turning it on needs a public
// address, a client secret and at least one allowed domain.
func (s *SSOService) SetEnabled(ctx context.Context, id uuid.UUID, enabled bool, by string) error {
	p, err := s.store.GetProvider(ctx, id)
	if err != nil {
		return err
	}
	if enabled {
		// Also checked on create; this covers a provider saved before
		// SB_OIDC_ISSUER was pointed at Google.
		if s.envIsGoogle() {
			return ErrSSOEnvProviderIsGoogle
		}
		var missing []string
		if url, _, err := s.PublicURL(ctx); err != nil {
			return err
		} else if url == "" {
			missing = append(missing, "public_url")
		}
		if p.Secret == nil {
			missing = append(missing, "client_secret")
		}
		if len(p.AllowedDomains) == 0 {
			missing = append(missing, "allowed_domains")
		}
		if len(missing) > 0 {
			return &SSONotReadyError{Missing: missing}
		}
	}
	return s.store.SetProviderEnabled(ctx, id, enabled, by)
}

// DeleteProvider removes a provider and returns it as it was.
func (s *SSOService) DeleteProvider(ctx context.Context, id uuid.UUID) (*storage.SSOProvider, error) {
	return s.store.DeleteProvider(ctx, id)
}

// ClientSecret opens a provider's sealed client secret. The caller must
// zero the result when done with it.
func (s *SSOService) ClientSecret(ctx context.Context, p *storage.SSOProvider) ([]byte, error) {
	if p.Secret == nil {
		return nil, fmt.Errorf("services: provider %s has no client secret", p.ID)
	}
	dek, err := s.km.DecryptDataKey(ctx, p.Secret.DataKeyCiphertext, p.Secret.KMSKeyID)
	if err != nil {
		return nil, fmt.Errorf("services: open client secret data key: %w", err)
	}
	defer zero(dek)
	return aeadDecrypt(dek, p.Secret.Nonce, p.Secret.Ciphertext)
}

// PublicURL returns the install's public address and where it came from
// ("env", "console", or "" when unset).
func (s *SSOService) PublicURL(ctx context.Context) (string, string, error) {
	if s.envPublic != "" {
		return s.envPublic, "env", nil
	}
	st, err := s.store.GetSettings(ctx)
	if err != nil {
		return "", "", err
	}
	if st.PublicURL == "" {
		return "", "", nil
	}
	return st.PublicURL, "console", nil
}

// Settings returns the stored settings with the effective public
// address.
func (s *SSOService) Settings(ctx context.Context) (*storage.SSOSettings, string, error) {
	st, err := s.store.GetSettings(ctx)
	if err != nil {
		return nil, "", err
	}
	url, source, err := s.PublicURL(ctx)
	if err != nil {
		return nil, "", err
	}
	st.PublicURL = url
	return st, source, nil
}

// UpdateSettings sets the public address (unless SB_PUBLIC_URL does) and
// the waiting-account cap. Returns the settings before and after.
// publicURL nil leaves it as it is; "" clears it. The store merges the
// fields under the row lock, so two saves of different fields can't
// undo each other.
func (s *SSOService) UpdateSettings(ctx context.Context, publicURL *string, pendingCap *int, by string) (before, after *storage.SSOSettings, err error) {
	if publicURL != nil {
		if s.envPublic != "" {
			return nil, nil, ErrSSOPublicURLFromEnv
		}
		normalized := ""
		if strings.TrimSpace(*publicURL) != "" {
			u, err := NormalizePublicURL(*publicURL, s.dev)
			if err != nil {
				return nil, nil, &SSOInputError{"public_url", err.Error()}
			}
			normalized = u
		}
		publicURL = &normalized
	}
	if pendingCap != nil && (*pendingCap < 1 || *pendingCap > 10000) {
		return nil, nil, &SSOInputError{"pending_cap", "must be between 1 and 10000"}
	}
	return s.store.UpdateSettings(ctx, publicURL, pendingCap, by)
}

// RedirectURL is the redirect URI for a provider type, from the public
// address, or "" when no address is set.
func (s *SSOService) RedirectURL(ctx context.Context, providerType string) (string, error) {
	base, _, err := s.PublicURL(ctx)
	if err != nil || base == "" {
		return "", err
	}
	return base + SSOCallbackPath(providerType), nil
}

// apply validates in onto p.
func (s *SSOService) apply(ctx context.Context, p *storage.SSOProvider, in SSOProviderInput) error {
	p.DisplayName = strings.TrimSpace(in.DisplayName)
	if p.DisplayName == "" {
		p.DisplayName = "Google"
	}
	if len(p.DisplayName) > 64 {
		return &SSOInputError{"display_name", "is longer than 64 characters"}
	}
	p.ClientID = strings.TrimSpace(in.ClientID)
	if p.ClientID == "" || len(p.ClientID) > 255 || strings.ContainsAny(p.ClientID, " \t\r\n") {
		return &SSOInputError{"client_id", "is required, at most 255 characters, without spaces"}
	}
	domains, err := normalizeDomains(in.AllowedDomains)
	if err != nil {
		return err
	}
	p.AllowedDomains = domains
	p.RequireApproval = in.RequireApproval
	p.DefaultRoleID = nil
	if in.DefaultRoleID != nil && *in.DefaultRoleID != uuid.Nil {
		if in.RequireApproval {
			return ErrSSODefaultRoleNeedsOff
		}
		role, err := s.roles.Get(ctx, *in.DefaultRoleID)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return &SSOInputError{"default_role_id", "no such role"}
			}
			return err
		}
		if HoldsPrivileged(role.Permissions) {
			return ErrSSOPrivilegedDefaultRole
		}
		id := *in.DefaultRoleID
		p.DefaultRoleID = &id
	}
	return nil
}

// HoldsPrivileged reports whether any permission is outside
// NonPrivilegedPermissions, the only ones a sign-in provider's default
// role may hold.
func HoldsPrivileged(perms []string) bool {
	for _, perm := range perms {
		if !slices.Contains(NonPrivilegedPermissions, perm) {
			return true
		}
	}
	return false
}

// mapDefaultRoleErr turns the store's default-role refusals into the
// service's errors. A role that's gone by the time of the write is a
// missing role on default_role_id.
func mapDefaultRoleErr(err error) error {
	switch {
	case errors.Is(err, storage.ErrDefaultRolePrivileged):
		return ErrSSOPrivilegedDefaultRole
	case errors.Is(err, storage.ErrDefaultRoleMissing):
		return &SSOInputError{"default_role_id", "no such role"}
	}
	return err
}

// defaultRoleUsable reports whether a provider's default role may be
// granted now: it still exists and holds only non-privileged
// permissions. The check at save time isn't enough, because the role's
// permissions can change afterwards (PUT /roles/:id/permissions).
func (s *SSOService) defaultRoleUsable(ctx context.Context, id uuid.UUID) (bool, error) {
	role, err := s.roles.Get(ctx, id)
	if errors.Is(err, storage.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return !HoldsPrivileged(role.Permissions), nil
}

func (s *SSOService) envIsGoogle() bool {
	u, err := url.Parse(strings.TrimSpace(s.envIssuer))
	return err == nil && strings.EqualFold(u.Hostname(), "accounts.google.com")
}

func (s *SSOService) seal(ctx context.Context, secret string) (*storage.SSOSecret, error) {
	dk, err := s.km.GenerateDataKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("services: data key for client secret: %w", err)
	}
	defer zero(dk.Plaintext)
	plain := []byte(secret)
	defer zero(plain)
	ct, nonce, err := aeadEncrypt(dk.Plaintext, plain)
	if err != nil {
		return nil, fmt.Errorf("services: seal client secret: %w", err)
	}
	return &storage.SSOSecret{Ciphertext: ct, Nonce: nonce, DataKeyCiphertext: dk.Ciphertext, KMSKeyID: dk.KeyID}, nil
}

var domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

func normalizeDomains(in []string) ([]string, error) {
	out := []string{}
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if len(d) > 253 || !domainRe.MatchString(d) {
			return nil, &SSOInputError{"allowed_domains", fmt.Sprintf("%q is not a domain such as example.com", d)}
		}
		if !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		return nil, &SSOInputError{"allowed_domains", "needs at least one domain"}
	}
	if len(out) > 20 {
		return nil, &SSOInputError{"allowed_domains", "at most 20 domains"}
	}
	return out, nil
}

// NormalizePublicURL checks an install's public address: an absolute
// https URL, no query, fragment or user info, and returns it without a
// trailing slash. Plain http is accepted only with dev (SB_ENV=dev), and
// then only for localhost or a loopback address.
func NormalizePublicURL(raw string, dev bool) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", errors.New("must be an absolute address such as https://secrets.example.com")
	}
	host := u.Hostname()
	loopback := host == "localhost" || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback())
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && loopback && dev:
	default:
		return "", errors.New("must use https (http is allowed for localhost with SB_ENV=dev only)")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("must not carry user info, a query or a fragment")
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.EscapedPath(), "/"), nil
}
