// Package services, sso_signin.go: signing in with a provider configured
// from the console (api#267 part 2). Google for now.
//
// Three round trips share one start and one callback, told apart by the
// purpose stored with the state:
//
//   - signin: someone signs in. The account is found by (issuer,
//     subject) only, never by email. A new identity creates a new
//     account (waiting for approval, or active with the provider's
//     non-privileged default role when approval is off). An identity
//     whose email already belongs to an account is refused.
//   - link:   a signed-in user connects Google to their own account
//     (Account → Connect Google, after a fresh second factor).
//   - test:   an admin checks a provider's settings with a real round
//     trip. Nothing is created and no session is issued.
//
// Link and test are bound to the session that started them. The browser
// comes back from Google on a cross-site redirect, which doesn't carry
// the SameSite=Strict session cookie, so the callback can't check the
// session itself. It parks the verified result in a one-time ticket, and
// the console redeems it with a same-site request (Finish), which only
// succeeds on the session that started the round trip.
//
// Every refused sign-in gets the same answer, whatever the reason, so the
// answer can't tell an outsider which emails have accounts; the reason
// goes to the audit log. Checks on top of #197's: Google's `hd` claim
// must be present and allowed, and so must the email's domain.
package services

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"

	"github.com/secrets-bridge/api/pkg/runtime"
	"github.com/secrets-bridge/api/pkg/storage"
)

// GoogleIssuer is Google's OIDC issuer. Tests point it at a fake IdP.
var GoogleIssuer = "https://accounts.google.com"

// Round-trip purposes.
const (
	SSOPurposeSignIn = "signin"
	SSOPurposeLink   = "link"
	SSOPurposeTest   = "test"
)

// ssoStateTTL bounds a round trip: account chooser, password, Google's
// own second factor.
const ssoStateTTL = 5 * time.Minute

// ssoRefusalWindow is the window over which refusals at the waiting
// cap are counted into one audit event.
const ssoRefusalWindow = 10 * time.Minute

// An ID token is used right after the code exchange, so its iat must be
// recent: no older than ssoMaxTokenAge, and no further in the future
// than ssoClockSkew.
const (
	ssoMaxTokenAge = 10 * time.Minute
	ssoClockSkew   = 5 * time.Minute
)

// ErrSSORefused is a refused sign-in, link or test. SSORefusal carries
// the reason, which goes to the audit log (and, for a test, back to the
// admin who ran it), never to an anonymous browser.
var ErrSSORefused = errors.New("services: sign-in refused")

// SSORefusal is ErrSSORefused with its reason.
type SSORefusal struct{ Reason string }

func (e *SSORefusal) Error() string { return "sign-in refused: " + e.Reason }
func (e *SSORefusal) Unwrap() error { return ErrSSORefused }

func refuse(reason string) error { return &SSORefusal{Reason: reason} }

type ssoProviderStore interface {
	GetProviderByType(ctx context.Context, providerType string) (*storage.SSOProvider, error)
	ListProviders(ctx context.Context) ([]*storage.SSOProvider, error)
	GetSettings(ctx context.Context) (*storage.SSOSettings, error)
}

type identityStore interface {
	GetBySubject(ctx context.Context, issuer, subject string) (*storage.UserIdentity, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]*storage.UserIdentity, error)
	Link(ctx context.Context, id *storage.UserIdentity) error
	Unlink(ctx context.Context, userID uuid.UUID, providerType string) (*storage.UserIdentity, error)
	CreateAccount(ctx context.Context, u *storage.LocalUser, id *storage.UserIdentity, defaultRole *uuid.UUID, grantedBy string, pendingCap int) error
	HasPassword(ctx context.Context, userID uuid.UUID) (bool, error)
}

type ssoUserStore interface {
	Get(ctx context.Context, id uuid.UUID) (*storage.LocalUser, error)
	GetByEmail(ctx context.Context, email string) (*storage.LocalUser, error)
}

// SSOSignIn runs the round trips.
type SSOSignIn struct {
	cfg        *SSOService
	providers  ssoProviderStore
	identities identityStore
	users      ssoUserStore
	sessions   *SessionService
	audit      storage.AuditEventRepository
	rdb        *runtime.Client

	mu        sync.Mutex
	discovery map[string]*oidc.Provider // by issuer, discovered on first use
}

// NewSSOSignIn wires the sign-in service.
func NewSSOSignIn(cfg *SSOService, providers ssoProviderStore, identities identityStore, users ssoUserStore,
	sessions *SessionService, audit storage.AuditEventRepository, rdb *runtime.Client) *SSOSignIn {
	return &SSOSignIn{cfg: cfg, providers: providers, identities: identities, users: users,
		sessions: sessions, audit: audit, rdb: rdb, discovery: map[string]*oidc.Provider{}}
}

// SSOListedProvider is a provider on the login page.
type SSOListedProvider struct {
	Type        string `json:"type"`
	DisplayName string `json:"display_name"`
	StartURL    string `json:"start_url"`
}

// Enabled lists the console providers people can sign in with: enabled,
// and an install address is set. None while SB_OIDC_ISSUER is Google:
// the env-var provider is the Google sign-in then, and the two would
// match the same people differently.
func (s *SSOSignIn) Enabled(ctx context.Context) ([]SSOListedProvider, error) {
	if s.cfg.envIsGoogle() {
		return []SSOListedProvider{}, nil
	}
	base, _, err := s.cfg.PublicURL(ctx)
	if err != nil || base == "" {
		return []SSOListedProvider{}, err
	}
	ps, err := s.providers.ListProviders(ctx)
	if err != nil {
		return nil, err
	}
	out := []SSOListedProvider{}
	for _, p := range ps {
		if p.Enabled {
			out = append(out, SSOListedProvider{
				Type: p.Type, DisplayName: p.DisplayName, StartURL: "/api/v1/auth/sso/" + p.Type + "/start",
			})
		}
	}
	return out, nil
}

type ssoState struct {
	Purpose   string `json:"p"`
	Type      string `json:"t"`
	Verifier  string `json:"v"`
	Nonce     string `json:"n"`
	ReturnTo  string `json:"r,omitempty"`
	SessionID string `json:"s,omitempty"` // link, test: the session that started it
}

// SSOStart is where to send the browser, and the state to bind to it in
// a cookie.
type SSOStart struct {
	RedirectURL string
	State       string
}

// Start begins a round trip. sessionID is the caller's session for link
// and test (empty for signin).
func (s *SSOSignIn) Start(ctx context.Context, providerType, purpose, returnTo, sessionID string) (*SSOStart, error) {
	p, err := s.providers.GetProviderByType(ctx, providerType)
	if err != nil {
		return nil, refuse("no_provider")
	}
	if purpose != SSOPurposeTest && (!p.Enabled || s.cfg.envIsGoogle()) {
		return nil, refuse("provider_disabled")
	}
	if (purpose == SSOPurposeLink || purpose == SSOPurposeTest) && sessionID == "" {
		return nil, refuse("no_session")
	}
	oauth, _, err := s.oauthConfig(ctx, p, nil)
	if err != nil {
		return nil, err
	}
	state, err := randomURLToken(32)
	if err != nil {
		return nil, err
	}
	verifier, err := randomURLToken(48)
	if err != nil {
		return nil, err
	}
	nonce, err := randomURLToken(16)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(ssoState{Purpose: purpose, Type: providerType, Verifier: verifier, Nonce: nonce,
		ReturnTo: SafeReturnTo(returnTo), SessionID: sessionID})
	if err != nil {
		return nil, err
	}
	if err := s.rdb.Raw().Set(ctx, s.rdb.Key("sso:state", state), payload, ssoStateTTL).Err(); err != nil {
		return nil, fmt.Errorf("services: store sign-in state: %w", err)
	}
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge", pkceS256(verifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("prompt", "select_account"),
	}
	if len(p.AllowedDomains) == 1 {
		// A hint for Google's account chooser only; the callback checks hd.
		opts = append(opts, oauth2.SetAuthURLParam("hd", p.AllowedDomains[0]))
	}
	return &SSOStart{RedirectURL: oauth.AuthCodeURL(state, opts...), State: state}, nil
}

// SSOCallbackResult is what a callback did.
type SSOCallbackResult struct {
	Purpose  string
	Issued   *IssuedSession // signin
	ReturnTo string         // signin
	User     *storage.LocalUser
	Ticket   string // link and test: for the console to redeem with Finish
}

// ssoTicket is a link or test result waiting for the session that
// started it. Refusal is set when the checks failed; the reason is only
// shown to that session.
type ssoTicket struct {
	Purpose   string `json:"p"`
	Type      string `json:"t"`
	SessionID string `json:"s"`
	Iss       string `json:"i,omitempty"`
	Sub       string `json:"u,omitempty"`
	Email     string `json:"e,omitempty"`
	Refusal   string `json:"r,omitempty"`
}

const ssoTicketTTL = 2 * time.Minute

// Callback finishes the Google side of a round trip. A signin issues a
// session; a link or test returns a ticket for Finish.
func (s *SSOSignIn) Callback(ctx context.Context, providerType, state, boundState, code, ip, userAgent string) (res *SSOCallbackResult, purpose string, err error) {
	if state == "" || boundState == "" || subtle.ConstantTimeCompare([]byte(state), []byte(boundState)) != 1 {
		return nil, "", refuse("state_cookie")
	}
	raw, err := s.rdb.Raw().GetDel(ctx, s.rdb.Key("sso:state", state)).Bytes()
	if err != nil || len(raw) == 0 {
		return nil, "", refuse("state_unknown")
	}
	var st ssoState
	if err := json.Unmarshal(raw, &st); err != nil || st.Type != providerType {
		return nil, "", refuse("state_mismatch")
	}
	purpose = st.Purpose

	var claims *googleClaims
	p, err := s.providers.GetProviderByType(ctx, providerType)
	switch {
	case err != nil:
		err = refuse("no_provider")
	case purpose != SSOPurposeTest && (!p.Enabled || s.cfg.envIsGoogle()):
		err = refuse("provider_disabled")
	default:
		if claims, err = s.exchange(ctx, p, code, st); err == nil {
			err = checkGoogleClaims(p, claims)
		}
	}

	// From here on the purpose is known, so a link or test always comes
	// back to the console with a ticket, refused or not, instead of
	// landing a signed-in user on the login page.
	if purpose == SSOPurposeLink || purpose == SSOPurposeTest {
		t := ssoTicket{Purpose: purpose, Type: providerType, SessionID: st.SessionID}
		if err != nil {
			t.Refusal = "error"
			var r *SSORefusal
			if errors.As(err, &r) {
				t.Refusal = r.Reason
			}
		} else {
			t.Iss, t.Sub, t.Email = claims.Iss, claims.Sub, strings.ToLower(strings.TrimSpace(claims.Email))
		}
		id, terr := s.parkTicket(ctx, t)
		if terr != nil {
			return nil, purpose, terr
		}
		return &SSOCallbackResult{Purpose: purpose, Ticket: id}, purpose, nil
	}
	if err != nil {
		return nil, purpose, err
	}

	u, err := s.signIn(ctx, p, claims)
	if err != nil {
		return nil, purpose, err
	}
	issued, err := s.sessions.Issue(ctx, u.ID, ip, userAgent)
	if err != nil {
		return nil, purpose, fmt.Errorf("services: issue session: %w", err)
	}
	return &SSOCallbackResult{Purpose: purpose, Issued: issued, ReturnTo: SafeReturnTo(st.ReturnTo), User: u}, purpose, nil
}

func (s *SSOSignIn) parkTicket(ctx context.Context, t ssoTicket) (string, error) {
	id, err := randomURLToken(32)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	if err := s.rdb.Raw().Set(ctx, s.rdb.Key("sso:ticket", id), payload, ssoTicketTTL).Err(); err != nil {
		return "", fmt.Errorf("services: store sign-in ticket: %w", err)
	}
	return id, nil
}

// SSOFinishResult is a redeemed link or test ticket.
type SSOFinishResult struct {
	Purpose string
	Type    string
	User    *storage.LocalUser // link
}

// Finish redeems a link or test ticket on the session that started the
// round trip. A ticket is single-use; another session, or a ticket of
// another provider type, is refused.
func (s *SSOSignIn) Finish(ctx context.Context, providerType, ticketID, currentSessionID, currentUserID string) (*SSOFinishResult, error) {
	raw, err := s.rdb.Raw().GetDel(ctx, s.rdb.Key("sso:ticket", ticketID)).Bytes()
	if ticketID == "" || err != nil || len(raw) == 0 {
		return nil, refuse("ticket_unknown")
	}
	var t ssoTicket
	if err := json.Unmarshal(raw, &t); err != nil || t.Type != providerType {
		return nil, refuse("ticket_unknown")
	}
	res := &SSOFinishResult{Purpose: t.Purpose, Type: t.Type}
	if currentSessionID == "" || subtle.ConstantTimeCompare([]byte(currentSessionID), []byte(t.SessionID)) != 1 {
		return res, refuse("other_session")
	}
	if t.Refusal != "" {
		return res, refuse(t.Refusal)
	}
	if t.Purpose == SSOPurposeTest {
		return res, nil
	}
	p, err := s.providers.GetProviderByType(ctx, providerType)
	if err != nil || !p.Enabled {
		return res, refuse("provider_disabled")
	}
	u, err := s.link(ctx, p, &googleClaims{Iss: t.Iss, Sub: t.Sub, Email: t.Email}, currentUserID)
	if err != nil {
		return res, err
	}
	res.User = u
	return res, nil
}

type googleClaims struct {
	Iss           string `json:"iss"`
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified any    `json:"email_verified"`
	Name          string `json:"name"`
	HD            string `json:"hd"`
	Nonce         string `json:"nonce"`
}

func (s *SSOSignIn) exchange(ctx context.Context, p *storage.SSOProvider, code string, st ssoState) (*googleClaims, error) {
	if code == "" {
		return nil, refuse("no_code")
	}
	secret, err := s.cfg.ClientSecret(ctx, p)
	if err != nil {
		return nil, err
	}
	defer zero(secret)
	oauth, provider, err := s.oauthConfig(ctx, p, secret)
	if err != nil {
		return nil, err
	}
	tok, err := oauth.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", st.Verifier))
	if err != nil {
		return nil, refuse("exchange_failed")
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		return nil, refuse("no_id_token")
	}
	idTok, err := provider.Verifier(&oidc.Config{ClientID: p.ClientID}).Verify(ctx, rawID)
	if err != nil {
		return nil, refuse("id_token_invalid")
	}
	// go-oidc checks exp but not iat.
	if age := time.Since(idTok.IssuedAt); idTok.IssuedAt.IsZero() || age > ssoMaxTokenAge || age < -ssoClockSkew {
		return nil, refuse("iat_invalid")
	}
	var c googleClaims
	if err := idTok.Claims(&c); err != nil {
		return nil, refuse("claims_invalid")
	}
	if subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(st.Nonce)) != 1 {
		return nil, refuse("nonce_mismatch")
	}
	c.Iss = idTok.Issuer
	if c.Sub == "" {
		return nil, refuse("missing_sub")
	}
	return &c, nil
}

// checkGoogleClaims: a verified email, and both Google's `hd` (the
// Workspace the account belongs to) and the email's domain in the
// allowed list. A personal account can carry an address in an allowed
// domain without belonging to the Workspace; `hd` tells them apart.
func checkGoogleClaims(p *storage.SSOProvider, c *googleClaims) error {
	email := strings.ToLower(strings.TrimSpace(c.Email))
	if email == "" || !emailVerifiedClaim(c.EmailVerified) {
		return refuse("email_unverified")
	}
	hd := strings.ToLower(strings.TrimSpace(c.HD))
	if hd == "" || !slices.Contains(p.AllowedDomains, hd) {
		return refuse("hd_not_allowed")
	}
	at := strings.LastIndex(email, "@")
	if at < 0 || !slices.Contains(p.AllowedDomains, email[at+1:]) {
		return refuse("email_domain_not_allowed")
	}
	return nil
}

func (s *SSOSignIn) signIn(ctx context.Context, p *storage.SSOProvider, c *googleClaims) (*storage.LocalUser, error) {
	if id, err := s.identities.GetBySubject(ctx, c.Iss, c.Sub); err == nil {
		u, err := s.users.Get(ctx, id.UserID)
		if err != nil {
			return nil, refuse("account_missing")
		}
		if u.Disabled {
			return nil, refuse("account_disabled")
		}
		return u, nil
	} else if !errors.Is(err, storage.ErrNotFound) {
		return nil, err
	}

	email := strings.ToLower(strings.TrimSpace(c.Email))
	if _, err := s.users.GetByEmail(ctx, email); err == nil {
		// Never link by email (review point 1): the owner connects
		// Google from their account page instead.
		return nil, refuse("email_has_account")
	} else if !errors.Is(err, storage.ErrNotFound) {
		return nil, err
	}

	// With approval off the account gets the default role, but only if
	// that role is still non-privileged: its permissions may have been
	// widened since the provider was saved. If not, the account waits
	// for approval like any other.
	pending := p.RequireApproval
	var role *uuid.UUID
	roleRefused := false
	if !pending && p.DefaultRoleID != nil {
		usable, err := s.cfg.defaultRoleUsable(ctx, *p.DefaultRoleID)
		if err != nil {
			return nil, err
		}
		if usable {
			role = p.DefaultRoleID
		} else {
			pending, roleRefused = true, true
		}
	}
	pendingCap := 0
	if pending {
		settings, err := s.providers.GetSettings(ctx)
		if err != nil {
			return nil, err
		}
		pendingCap = settings.PendingCap
	}

	randomPW, err := randomURLToken(32)
	if err != nil {
		return nil, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(randomPW), passwordBcryptCost)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(c.Name)
	if name == "" {
		name = email
	}
	u := &storage.LocalUser{Email: email, PasswordHash: hash, DisplayName: name, PendingApproval: pending}
	ident := &storage.UserIdentity{ProviderType: p.Type, Issuer: c.Iss, Subject: c.Sub, EmailAtLink: email}
	if err := s.identities.CreateAccount(ctx, u, ident, role, "system:sso", pendingCap); err != nil {
		if errors.Is(err, storage.ErrPendingCap) {
			s.countCapRefusal(ctx, pendingCap)
			return nil, refuse("pending_cap")
		}
		if errors.Is(err, storage.ErrLocalUserExists) {
			return nil, refuse("email_has_account")
		}
		if errors.Is(err, storage.ErrIdentityTaken) {
			return nil, refuse("identity_taken")
		}
		return nil, err
	}
	// Audited only now that the account exists: a sign-in refused at the
	// waiting cap made no account, so no role was refused for it.
	if roleRefused {
		s.appendAudit(ctx, "system:sso", "sso_provider.default_role_refused", "sso_provider:"+p.ID.String(),
			storage.AuditStatusDenied, map[string]any{"provider_type": p.Type, "default_role_id": p.DefaultRoleID.String(),
				"reason": "default_role_privileged", "user_id": u.ID.String()})
	}
	action := "user.pending"
	if !pending {
		action = "user.sso_provision"
	}
	meta := map[string]any{"provider_type": p.Type, "email": email}
	if role != nil {
		meta["default_role_id"] = role.String()
	}
	s.appendAudit(ctx, "system:sso", action, "user:"+u.ID.String(), storage.AuditStatusSuccess, meta)
	return u, nil
}

// link binds the identity to the account of the session that started the
// round trip (Callback has checked it's the same session).
func (s *SSOSignIn) link(ctx context.Context, p *storage.SSOProvider, c *googleClaims, userID string) (*storage.LocalUser, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, refuse("other_session")
	}
	u, err := s.users.Get(ctx, uid)
	if err != nil || u.Disabled {
		return nil, refuse("account_disabled")
	}
	ident := &storage.UserIdentity{UserID: u.ID, ProviderType: p.Type, Issuer: c.Iss, Subject: c.Sub,
		EmailAtLink: strings.ToLower(strings.TrimSpace(c.Email))}
	if err := s.identities.Link(ctx, ident); err != nil {
		if errors.Is(err, storage.ErrIdentityTaken) {
			return nil, refuse("identity_taken")
		}
		return nil, err
	}
	s.appendAudit(ctx, "user:"+u.ID.String(), "user.identity_link", "user:"+u.ID.String(), storage.AuditStatusSuccess,
		map[string]any{"provider_type": p.Type, "email_at_link": ident.EmailAtLink})
	return u, nil
}

// AuditRepo is the audit log the service writes to.
func (s *SSOSignIn) AuditRepo() storage.AuditEventRepository { return s.audit }

// Identities lists an account's linked identities.
func (s *SSOSignIn) Identities(ctx context.Context, userID uuid.UUID) ([]*storage.UserIdentity, error) {
	return s.identities.ListByUser(ctx, userID)
}

// Unlink removes an account's identity of a provider type.
// storage.ErrIdentityRequired when that identity created the account:
// the account has no password anyone knows, so it would be locked out.
func (s *SSOSignIn) Unlink(ctx context.Context, userID uuid.UUID, providerType string) (*storage.UserIdentity, error) {
	return s.identities.Unlink(ctx, userID, providerType)
}

// HasPassword reports whether an account can sign in with a password.
func (s *SSOSignIn) HasPassword(ctx context.Context, userID uuid.UUID) (bool, error) {
	return s.identities.HasPassword(ctx, userID)
}

// countCapRefusal aggregates refusals at the waiting cap: the first in
// each window is audited, and so is the previous window's total, so a
// burst writes at most two audit rows per window instead of one per
// attempt.
func (s *SSOSignIn) countCapRefusal(ctx context.Context, limit int) {
	now := time.Now().UTC()
	window := now.Truncate(ssoRefusalWindow)
	key := s.rdb.Key("sso:cap_refused", strconv.FormatInt(window.Unix(), 10))
	raw := s.rdb.Raw()
	n, err := raw.HIncrBy(ctx, key, "count", 1).Result()
	if err != nil {
		return
	}
	_ = raw.HSetNX(ctx, key, "first", now.Format(time.RFC3339)).Err()
	_ = raw.HSet(ctx, key, "last", now.Format(time.RFC3339)).Err()
	_ = raw.Expire(ctx, key, 3*ssoRefusalWindow).Err()
	if n != 1 {
		return
	}
	s.appendAudit(ctx, "system:sso", "user.pending_refused", "auth:sso", storage.AuditStatusDenied, map[string]any{
		"window_start": window.Format(time.RFC3339), "window_minutes": int(ssoRefusalWindow.Minutes()),
		"first_in_window": true, "pending_cap": limit,
	})
	prev := s.rdb.Key("sso:cap_refused", strconv.FormatInt(window.Add(-ssoRefusalWindow).Unix(), 10))
	if ok, _ := raw.HSetNX(ctx, prev, "summarized", "1").Result(); ok {
		vals, err := raw.HGetAll(ctx, prev).Result()
		if err == nil && vals["count"] != "" {
			count, _ := strconv.Atoi(vals["count"])
			s.appendAudit(ctx, "system:sso", "user.pending_refused", "auth:sso", storage.AuditStatusDenied, map[string]any{
				"window_start": window.Add(-ssoRefusalWindow).Format(time.RFC3339), "window_minutes": int(ssoRefusalWindow.Minutes()),
				"count": count, "first": vals["first"], "last": vals["last"], "pending_cap": limit,
			})
		}
	}
}

// AuditRefusal records a refused round trip with its reason and the
// provider type. actor is "anonymous" at the start and the callback,
// where no session is visible, and the signed-in user for Finish.
// Claims beyond the reason are not recorded. A refusal at the waiting
// cap isn't recorded here: countCapRefusal aggregates those, so a burst
// can't write one row per attempt.
func (s *SSOSignIn) AuditRefusal(ctx context.Context, actor, providerType, purpose string, err error) {
	reason := "error"
	var r *SSORefusal
	if errors.As(err, &r) {
		reason = r.Reason
	}
	if reason == "pending_cap" {
		return
	}
	action := "auth.sso.callback"
	if purpose == SSOPurposeTest {
		action = "sso_provider.test"
	}
	s.appendAudit(ctx, actor, action, "auth:sso:"+providerType, storage.AuditStatusDenied,
		map[string]any{"provider_type": providerType, "purpose": purpose, "error_kind": reason})
}

// AuditSuccess records a successful round trip by actor: the user who
// signed in, or the signed-in user who redeemed a link or test ticket.
func (s *SSOSignIn) AuditSuccess(ctx context.Context, actor, providerType string, res *SSOCallbackResult) {
	resource := "auth:sso:" + providerType
	if res.User != nil {
		resource = "user:" + res.User.ID.String()
	}
	action := "auth.sso.callback"
	if res.Purpose == SSOPurposeTest {
		action = "sso_provider.test"
	}
	s.appendAudit(ctx, actor, action, resource, storage.AuditStatusSuccess,
		map[string]any{"provider_type": providerType, "purpose": res.Purpose})
}

func (s *SSOSignIn) appendAudit(ctx context.Context, actor, action, resource string, status storage.AuditStatus, meta map[string]any) {
	if s.audit == nil {
		return
	}
	if err := s.audit.Append(ctx, &storage.AuditEvent{Actor: actor, Action: action, Resource: resource, Status: status, Metadata: meta}); err != nil {
		slog.WarnContext(ctx, "audit append failed", "action", action, "resource", resource, "err", err)
	}
}

// oauthConfig builds the OAuth client for a provider from its current
// row, so a change takes effect on the next round trip. The redirect URI
// comes from the configured public address only. secret is nil when
// starting (the authorize URL doesn't need it).
func (s *SSOSignIn) oauthConfig(ctx context.Context, p *storage.SSOProvider, secret []byte) (*oauth2.Config, *oidc.Provider, error) {
	redirect, err := s.cfg.RedirectURL(ctx, p.Type)
	if err != nil {
		return nil, nil, err
	}
	if redirect == "" {
		return nil, nil, refuse("no_public_url")
	}
	provider, err := s.discover(ctx, GoogleIssuer)
	if err != nil {
		return nil, nil, err
	}
	return &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: string(secret),
		RedirectURL:  redirect,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}, provider, nil
}

func (s *SSOSignIn) discover(ctx context.Context, issuer string) (*oidc.Provider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.discovery[issuer]; ok {
		return p, nil
	}
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	p, err := oidc.NewProvider(dctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("services: discover %s: %w", issuer, err)
	}
	s.discovery[issuer] = p
	return p, nil
}
