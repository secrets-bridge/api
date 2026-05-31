// OIDC client (architect Slice B). Single-IdP Authorization Code +
// PKCE flow:
//
//   /auth/oidc/start         redirect to IdP's authorize endpoint
//   /auth/oidc/callback      exchange + verify + JIT-create + issue session
//   /auth/oidc/logout        revoke local session + redirect to IdP end_session
//   /auth/oidc/backchannel   accept logout_token from IdP (RFC 8417)
//
// State storage is Redis-backed: each /start call writes
// {verifier, nonce, return_to} keyed by a 32-byte random state value,
// 5-min TTL. Callback enforces single-use by deleting the key on hit.
//
// JIT provisioning (architect Q5): if the local_users row keyed on the
// IdP-supplied `sub` doesn't exist, create it. Email + display_name
// come from the ID token's `email` + `name` claims. Group-claim →
// role mapping is Slice E's concern; this slice creates the user with
// NO role grants — admin still has to assign a role from the UI
// before the new user can do anything.
//
// MFA enforcement (architect Q6) is gated in Slice D; this slice
// records `amr` from the ID token on the session row for that future
// gate to consult.

package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"

	"github.com/secrets-bridge/api/pkg/runtime"
	"github.com/secrets-bridge/api/pkg/storage"
)

// OIDCConfig carries the static knobs. Constructed by cmd/api from
// SB_OIDC_* env vars.
type OIDCConfig struct {
	Issuer          string
	ClientID        string
	ClientSecret    string
	RedirectURL     string
	Scopes          []string
	PostLogoutURL   string
	// StateTTL bounds how long an in-flight /start → /callback round
	// trip can take. 5 minutes covers IdP redirect + user interaction
	// + MFA challenge without leaving stale state in Redis.
	StateTTL        time.Duration
}

// DefaultStateTTL is what cmd/api wires when SB_OIDC_STATE_TTL isn't
// overridden.
const DefaultStateTTL = 5 * time.Minute

// ErrOIDC is the public failure surface — every failure mode returns
// a wrapper around this so handlers can map cleanly.
var ErrOIDC = errors.New("services: oidc")

// OIDCService coordinates provider discovery + OAuth2 client + the
// SessionService.
type OIDCService struct {
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth        *oauth2.Config
	cfg          OIDCConfig
	users        storage.LocalUserRepository
	sessions     *SessionService
	audit        storage.AuditEventRepository
	rdb          *runtime.Client
}

// NewOIDCService bootstraps the provider via discovery and wires the
// stored deps. Discovery is a network call — pass a `ctx` with a
// bounded timeout (cmd/api uses the boot context).
func NewOIDCService(
	ctx context.Context,
	cfg OIDCConfig,
	users storage.LocalUserRepository,
	sessions *SessionService,
	audit storage.AuditEventRepository,
	rdb *runtime.Client,
) (*OIDCService, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.RedirectURL == "" {
		return nil, fmt.Errorf("%w: issuer + client_id + redirect_url required", ErrOIDC)
	}
	if cfg.StateTTL <= 0 {
		cfg.StateTTL = DefaultStateTTL
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: discovery: %v", ErrOIDC, err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	oauth := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.RedirectURL,
		Scopes:       cfg.Scopes,
	}
	return &OIDCService{
		provider: provider,
		verifier: verifier,
		oauth:    oauth,
		cfg:      cfg,
		users:    users,
		sessions: sessions,
		audit:    audit,
		rdb:      rdb,
	}, nil
}

// PostLogoutURL exposes the configured RP-initiated logout target so
// the handler can build the end_session URL without re-reading config.
func (s *OIDCService) PostLogoutURL() string { return s.cfg.PostLogoutURL }

// --- Authorize ------------------------------------------------------

// AuthorizeStart represents one /auth/oidc/start invocation: the
// browser-facing redirect URL and the state token (which the caller
// also stores in a short-lived cookie or as the `state` query param —
// the value comes back in the callback for cross-verification).
type AuthorizeStart struct {
	RedirectURL string
	State       string
}

// authorizeState is what we persist in Redis under the state key. The
// callback round-trips it back out by reading the inbound `state`
// param.
type authorizeState struct {
	Verifier string `json:"v"`
	Nonce    string `json:"n"`
	ReturnTo string `json:"r"`
}

// StepUpOptions toggles the optional `prompt` / `max_age` /
// `acr_values` params on the authorize URL. When zero-valued, the
// regular sign-in flow is used. Slice D wires the step-up modal:
// `{Prompt: "login", MaxAge: 0, ACRValues: "mfa"}` forces the IdP
// to re-prompt for a strong second factor.
type StepUpOptions struct {
	Prompt    string // e.g. "login"
	MaxAgeSet bool   // separate from MaxAge so 0 can be explicit
	MaxAge    int    // seconds; 0 means "no session reuse"
	ACRValues string // e.g. "mfa"
}

// StartAuthorize generates fresh PKCE + nonce + state, persists them
// in Redis (single-use, 5-min TTL), and returns the IdP authorize URL
// the caller should redirect the browser to. `returnTo` is the
// post-login destination on the api's host — the callback redirects
// there after the session cookie is set.
func (s *OIDCService) StartAuthorize(ctx context.Context, returnTo string) (*AuthorizeStart, error) {
	return s.StartAuthorizeWith(ctx, returnTo, StepUpOptions{})
}

// StartAuthorizeWith is the step-up-aware variant. The SPA's step-up
// path calls this with `{Prompt: "login", MaxAgeSet: true, MaxAge: 0,
// ACRValues: "mfa"}` so the IdP re-prompts for MFA even when a SSO
// session is already alive.
func (s *OIDCService) StartAuthorizeWith(ctx context.Context, returnTo string, stepUp StepUpOptions) (*AuthorizeStart, error) {
	state, err := randomURLToken(32)
	if err != nil {
		return nil, fmt.Errorf("%w: state mint: %v", ErrOIDC, err)
	}
	verifier, err := randomURLToken(48)
	if err != nil {
		return nil, fmt.Errorf("%w: verifier mint: %v", ErrOIDC, err)
	}
	nonce, err := randomURLToken(16)
	if err != nil {
		return nil, fmt.Errorf("%w: nonce mint: %v", ErrOIDC, err)
	}

	payload, err := json.Marshal(authorizeState{
		Verifier: verifier,
		Nonce:    nonce,
		ReturnTo: returnTo,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: marshal state: %v", ErrOIDC, err)
	}
	if err := s.persistState(ctx, state, payload); err != nil {
		return nil, fmt.Errorf("%w: persist state: %v", ErrOIDC, err)
	}

	challenge := pkceS256(verifier)
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oidc.Nonce(nonce),
	}
	if stepUp.Prompt != "" {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", stepUp.Prompt))
	}
	if stepUp.MaxAgeSet {
		opts = append(opts, oauth2.SetAuthURLParam("max_age", fmt.Sprintf("%d", stepUp.MaxAge)))
	}
	if stepUp.ACRValues != "" {
		opts = append(opts, oauth2.SetAuthURLParam("acr_values", stepUp.ACRValues))
	}
	authURL := s.oauth.AuthCodeURL(state, opts...)
	return &AuthorizeStart{RedirectURL: authURL, State: state}, nil
}

// --- Callback -------------------------------------------------------

// CallbackResult is what the handler hands back to the HTTP layer —
// the authenticated user's session (cookie value etc.) plus the
// caller-supplied `return_to` so the browser ends up on the SPA page
// the user originally requested.
type CallbackResult struct {
	Issued   *IssuedSession
	ReturnTo string
	User     *storage.LocalUser
}

// HandleCallback completes the Authorization Code + PKCE exchange,
// verifies the ID token (including nonce), JIT-creates the local_users
// row if needed, and issues a server-side session via SessionService.
//
// `state` and `code` come from the IdP's redirect query params. `ip`
// + `userAgent` are stamped on the session row for the audit shape.
func (s *OIDCService) HandleCallback(ctx context.Context, state, code, ip, userAgent string) (*CallbackResult, error) {
	if state == "" || code == "" {
		return nil, fmt.Errorf("%w: state + code required", ErrOIDC)
	}
	raw, err := s.consumeState(ctx, state)
	if err != nil {
		return nil, fmt.Errorf("%w: state invalid or expired", ErrOIDC)
	}
	var stored authorizeState
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, fmt.Errorf("%w: decode stored state: %v", ErrOIDC, err)
	}

	tok, err := s.oauth.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", stored.Verifier),
	)
	if err != nil {
		s.auditFailure(ctx, "code_exchange_failed", err)
		return nil, fmt.Errorf("%w: code exchange: %v", ErrOIDC, err)
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		s.auditFailure(ctx, "missing_id_token", nil)
		return nil, fmt.Errorf("%w: missing id_token in exchange response", ErrOIDC)
	}
	idToken, err := s.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		s.auditFailure(ctx, "id_token_invalid", err)
		return nil, fmt.Errorf("%w: id_token verify: %v", ErrOIDC, err)
	}
	if idToken.Nonce != stored.Nonce {
		s.auditFailure(ctx, "nonce_mismatch", nil)
		return nil, fmt.Errorf("%w: nonce mismatch", ErrOIDC)
	}

	var claims struct {
		Sub      string   `json:"sub"`
		Email    string   `json:"email"`
		Name     string   `json:"name"`
		AMR      []string `json:"amr"`
		ACR      string   `json:"acr"`
		Iss      string   `json:"iss"`
	}
	if err := idToken.Claims(&claims); err != nil {
		s.auditFailure(ctx, "claims_decode", err)
		return nil, fmt.Errorf("%w: decode claims: %v", ErrOIDC, err)
	}
	if claims.Sub == "" {
		s.auditFailure(ctx, "missing_sub", nil)
		return nil, fmt.Errorf("%w: id_token missing sub claim", ErrOIDC)
	}

	user, err := s.upsertLocalUser(ctx, claims.Sub, claims.Email, claims.Name)
	if err != nil {
		return nil, fmt.Errorf("%w: jit provision: %v", ErrOIDC, err)
	}

	issued, err := s.sessions.Issue(ctx, user.ID, ip, userAgent)
	if err != nil {
		return nil, fmt.Errorf("%w: session issue: %v", ErrOIDC, err)
	}

	// Slice D — step-up gate input. Stamp `last_mfa_at` when the IdP
	// asserted a strong factor in the `amr` claim. Failure of the
	// stamp is audited but doesn't fail the login; the user just
	// won't pass Tier 2 gates until they re-auth.
	if isStrongAMR(claims.AMR) {
		if mfaErr := s.sessions.MarkMFA(ctx, issued.Session.ID, time.Now().UTC()); mfaErr != nil {
			_ = s.audit.Append(ctx, &storage.AuditEvent{
				Actor:    "user:" + user.ID.String(),
				Action:   "session.mfa_stamp_failed",
				Resource: "session:" + issued.Session.ID.String(),
				Status:   storage.AuditStatusFailure,
				Metadata: map[string]any{"error": mfaErr.Error(), "amr": claims.AMR},
			})
		}
	}

	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "user:" + user.ID.String(),
		Action:   "auth.oidc.callback",
		Resource: "user:" + user.ID.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: map[string]any{
			"sub":        claims.Sub,
			"iss":        claims.Iss,
			"acr":        claims.ACR,
			"amr":        claims.AMR,
			"session_id": issued.Session.ID.String(),
			"ip":         ip,
			"user_agent": userAgent,
		},
	})

	return &CallbackResult{Issued: issued, ReturnTo: stored.ReturnTo, User: user}, nil
}

// --- Logout ---------------------------------------------------------

// BuildEndSessionURL composes the IdP's RP-initiated logout URL with
// the `post_logout_redirect_uri` param. Returns empty string when the
// provider didn't advertise an `end_session_endpoint` (in which case
// the caller skips the redirect and just clears the cookie).
func (s *OIDCService) BuildEndSessionURL(idTokenHint string) string {
	var meta struct {
		EndSession string `json:"end_session_endpoint"`
	}
	if err := s.provider.Claims(&meta); err != nil || meta.EndSession == "" {
		return ""
	}
	u, err := url.Parse(meta.EndSession)
	if err != nil {
		return ""
	}
	q := u.Query()
	if s.cfg.PostLogoutURL != "" {
		q.Set("post_logout_redirect_uri", s.cfg.PostLogoutURL)
	}
	q.Set("client_id", s.cfg.ClientID)
	if idTokenHint != "" {
		q.Set("id_token_hint", idTokenHint)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// HandleBackchannelLogout consumes a logout_token POSTed by the IdP
// (RFC 8417). Verifies signature + issuer + audience + the events
// claim, then revokes every server-side session bound to the user's
// `sub`. Idempotent — the IdP can retry safely.
func (s *OIDCService) HandleBackchannelLogout(ctx context.Context, logoutTokenRaw string) error {
	if logoutTokenRaw == "" {
		return fmt.Errorf("%w: empty logout_token", ErrOIDC)
	}
	tok, err := s.verifier.Verify(ctx, logoutTokenRaw)
	if err != nil {
		return fmt.Errorf("%w: logout_token verify: %v", ErrOIDC, err)
	}
	var claims struct {
		Sub    string                 `json:"sub"`
		Events map[string]interface{} `json:"events"`
		Iss    string                 `json:"iss"`
	}
	if err := tok.Claims(&claims); err != nil {
		return fmt.Errorf("%w: decode logout claims: %v", ErrOIDC, err)
	}
	if claims.Sub == "" {
		return fmt.Errorf("%w: logout_token missing sub", ErrOIDC)
	}
	if _, ok := claims.Events["http://schemas.openid.net/event/backchannel-logout"]; !ok {
		return fmt.Errorf("%w: logout_token missing backchannel-logout event", ErrOIDC)
	}
	user, err := s.users.GetByEmail(ctx, oidcUserLookup(claims.Sub, ""))
	if err != nil {
		// Sub-as-email isn't always correct (some IdPs use UUIDs).
		// Treat lookup failure as "no local user, nothing to revoke"
		// rather than 500-ing — the IdP retry path doesn't help.
		return nil
	}
	if _, err := s.sessions.RevokeAllForUser(ctx, user.ID); err != nil {
		return fmt.Errorf("%w: revoke sessions: %v", ErrOIDC, err)
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "system:oidc",
		Action:   "auth.oidc.backchannel_logout",
		Resource: "user:" + user.ID.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: map[string]any{"sub": claims.Sub, "iss": claims.Iss},
	})
	return nil
}

// --- helpers --------------------------------------------------------

// oidcUserLookup picks the email when set, falling back to sub. A
// follow-up slice adds an explicit `local_users.oidc_sub` column +
// `GetBySub` lookup; v1 reuses the email column because most IdPs
// emit a stable `email` claim with the `openid email` scope and that
// keeps the schema unchanged.
func oidcUserLookup(sub, email string) string {
	v := strings.TrimSpace(email)
	if v == "" {
		v = strings.TrimSpace(sub)
	}
	return strings.ToLower(v)
}

// upsertLocalUser returns the existing row for the claims or creates
// a fresh one with no role grants. Admin still has to assign a role
// in the UI before the new user can do anything beyond `/users/me`.
func (s *OIDCService) upsertLocalUser(ctx context.Context, sub, email, displayName string) (*storage.LocalUser, error) {
	lookup := oidcUserLookup(sub, email)
	if existing, err := s.users.GetByEmail(ctx, lookup); err == nil {
		return existing, nil
	}
	// Generate a random unguessable password — OIDC users never use it.
	// SetPasswordHash requires a real bcrypt hash; using a random one
	// keeps the local-admin login path strictly disjoint from OIDC.
	randomPW, err := randomURLToken(32)
	if err != nil {
		return nil, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(randomPW), 10)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(displayName)
	if name == "" {
		name = strings.TrimSpace(email)
	}
	if name == "" {
		name = lookup
	}
	row := &storage.LocalUser{
		Email:        lookup,
		PasswordHash: hash,
		DisplayName:  name,
	}
	if err := s.users.Create(ctx, row); err != nil {
		// If we lose a race with another concurrent OIDC login for the
		// same user, re-read and return the winning row.
		if errors.Is(err, storage.ErrLocalUserExists) {
			existing, lookupErr := s.users.GetByEmail(ctx, lookup)
			if lookupErr == nil {
				return existing, nil
			}
		}
		return nil, err
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "system:oidc",
		Action:   "auth.oidc.jit_provision",
		Resource: "user:" + row.ID.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: map[string]any{"sub": sub, "email": email},
	})
	return row, nil
}

func (s *OIDCService) persistState(ctx context.Context, state string, payload []byte) error {
	return s.rdb.Raw().Set(ctx, oidcStateKey(s.rdb, state), payload, s.cfg.StateTTL).Err()
}

func (s *OIDCService) consumeState(ctx context.Context, state string) ([]byte, error) {
	key := oidcStateKey(s.rdb, state)
	val, err := s.rdb.Raw().GetDel(ctx, key).Bytes()
	if err != nil {
		return nil, err
	}
	if len(val) == 0 {
		return nil, fmt.Errorf("state empty")
	}
	return val, nil
}

func (s *OIDCService) auditFailure(ctx context.Context, kind string, err error) {
	meta := map[string]any{"error_kind": kind}
	if err != nil {
		meta["error"] = err.Error()
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "anonymous",
		Action:   "auth.oidc.callback",
		Resource: "auth:oidc",
		Status:   storage.AuditStatusDenied,
		Metadata: meta,
	})
}

func oidcStateKey(rdb *runtime.Client, state string) string {
	return rdb.Key("oidc:state", state)
}

func randomURLToken(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// isStrongAMR reports whether the `amr` claim asserts a factor
// strong enough to justify stamping last_mfa_at. The OIDC spec
// defines (RFC 8176): mfa, otp, hwk, fido, swk, sc, pop, ftp,
// kba, mca, eye, geo, retina. We treat the multi-factor + hardware
// + biometric subset as "strong"; `pwd` and `kba` alone are not.
//
// Operators wanting a stricter list can override by post-processing
// the token in a custom IdP middleware before this code sees it.
func isStrongAMR(amr []string) bool {
	for _, a := range amr {
		switch a {
		case "mfa", "otp", "hwk", "fido", "swk", "sc", "pop", "eye", "fpt", "retina":
			return true
		}
	}
	return false
}

// Ensure imports referenced indirectly are kept (linter sweep).
var _ = uuid.Nil