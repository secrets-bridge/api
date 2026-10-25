package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/secrets-bridge/api/pkg/objectstore"
)

// buildVersion is set at link time via -ldflags '-X main.buildVersion=...'.
// Defaults to "dev" for `go run` and local builds.
var buildVersion = "dev"

// Deployment mode. Default ModeProduction so a missing/forgotten
// SB_ENV gives the safe behavior (LocalKMS rejected, dev seeder
// skipped).
const (
	ModeDev        = "dev"
	ModeProduction = "production"
)

// Config carries the runtime configuration for the api service.
//
// Concrete dependencies (Postgres DSN, Redis URL, OIDC issuer, etc.) are
// deliberately not on this struct yet — they land with their owning
// issue. Keeping Config minimal during the scaffolding phase makes it
// obvious which environment variables actually do something today.
type Config struct {
	// Addr is the network address the api listens on, e.g. ":8080".
	Addr string

	// ShutdownGrace bounds the graceful-shutdown wait.
	ShutdownGrace time.Duration

	// Env is the deployment mode (SB_ENV). Recognised values: "dev"
	// or "production"; default "production" so a forgotten env var
	// fails closed (LocalKMS rejected, dev seeder skipped).
	//
	// Two effects:
	//   1. KMS resolver (pkg/keymgmt.FromEnv) refuses BackendLocal
	//      when Env != "dev".
	//   2. Dev seeder runs only when Env == "dev" — see
	//      services.AuthService.BootstrapDevUsers.
	Env string

	// DevSeedPassword is the shared password the dev seeder assigns
	// to all three seeded users (admin / approver / requester) when
	// SB_ENV=dev. Optional — when unset, the seeder generates a
	// random password per user and logs it ONCE at WARN level so the
	// operator can capture it from the boot log.
	//
	// Production deployments leave this unset and rely on
	// BootstrapAdminEmail/Password (single break-glass admin) +
	// OIDC for everyone else once api#26 lands.
	DevSeedPassword string

	// BootstrapAdminUserID — when set AND `user_roles` has NO admin
	// grants at first boot, the api creates one assignment binding
	// this user_id to the seed `admin` role. Idempotent: if any admin
	// grant already exists, the bootstrap is a no-op.
	//
	// v1 escape hatch so operators can use the platform before the
	// OIDC login flow (api#26) ships. The value is an opaque user_id
	// matching the future OIDC `sub` claim; it is NOT a credential.
	BootstrapAdminUserID string

	// RetiredEnvSet names the retired settings (retiredEnv) that are
	// still set, so main can say they can be removed. Only the names are
	// kept, never the values.
	RetiredEnvSet []string

	// BootstrapAdminEmail / Password seed a local admin user on
	// first boot when local_users is empty. Idempotent: once any
	// user exists, the bootstrap step is a no-op.
	//
	// Recommended for break-glass; production deployments rotate the
	// password immediately after first login (UI surface for that
	// lands in a follow-up — for now operators update the row via
	// psql + bcrypt or simply mint another admin from a privileged
	// session).
	BootstrapAdminEmail    string
	BootstrapAdminPassword string

	// PublicURL is the install's public address, for example
	// https://secrets.example.com (SB_PUBLIC_URL). Sign-in redirect URIs
	// are built from it, never from request headers. When unset, an
	// admin saves it from the console (api#267); when set, it wins and
	// the console shows it read-only.
	PublicURL string

	// OIDC client config (Slice B). When OIDCIssuer is empty the OIDC
	// routes are NOT mounted and the local-admin login path stays the
	// only sign-in surface (compatible with A1 + A2 deployments).
	//
	// `Issuer` is the .well-known/openid-configuration root, e.g.
	// `https://authentik.example.com/application/o/secrets-bridge/`.
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string // public callback URL, must match an IdP-registered redirect
	OIDCScopes       string // space-separated; default "openid profile email"
	OIDCPostLogout   string // public post-logout URL (where the IdP sends users after end_session)

	// Slice E — group-claim → role mapping. When `OIDCGroupClaim` is
	// empty the reconciler short-circuits and JIT users get no
	// role grants (admin assigns from the UI). When set, the
	// callback reads the configured claim and reconciles
	// `user_roles` against `OIDCGroupMap` (the JSON parses at
	// boot via `ValidateOIDCGroupMap` so a typo fails the boot
	// rather than silently producing wrong access).
	OIDCGroupClaim string            // default "groups"
	OIDCGroupMap   map[string]string // raw value via SB_OIDC_GROUP_MAP env (JSON object)

	// MFADevAllowPwd is the interim unblock for app-level MFA (Slice
	// H). When true AND SB_ENV=dev, the SessionService treats any live
	// non-revoked session as MFA-fresh, bypassing the `last_mfa_at`
	// check. The IdP can return an empty `amr` (no MFA stage bound)
	// and Tier 2 paths still work for pilot operators.
	//
	// REFUSED at boot when SB_ENV=production — see ValidateMFADevFlag.
	// Drop the flag once Slice H4 (real /auth/mfa/{challenge,verify})
	// is live and staging operators have enrolled a real factor.
	MFADevAllowPwd bool

	// MFATOTPIssuer is rendered in the otpauth:// URI's `issuer=` param
	// and the label prefix (Slice H2). Authenticator apps display it
	// under the user's account name — keep it stable across deployments
	// or users see two entries on their phone for the same account.
	//
	// Defaults to "Secrets Bridge" when unset. Operators running an
	// internal-only deployment commonly override to something like
	// "Secrets Bridge (UAT)" so it doesn't shadow a prod account on the
	// same authenticator app.
	MFATOTPIssuer string

	// WebAuthn relying-party config (Slice H3). The routes under
	// /users/me/mfa/webauthn/* mount only when both `MFAWebAuthnRPID`
	// AND `MFAWebAuthnRPOrigins` are non-empty — operators who want
	// TOTP-only can leave the WebAuthn knobs unset and the service
	// stays disabled at boot.
	//
	// `RPID` MUST be the effective domain of the origin (e.g.
	// "sb.example.com"). Browsers reject the ceremony otherwise.
	//
	// `RPDisplayName` is rendered in the authenticator's enrollment
	// dialog ("Add Secrets Bridge?"). Free text.
	//
	// `RPOrigins` is the comma-separated allowlist of fully qualified
	// origins permitted to drive the ceremony. UAT typically lists
	// both the production https host AND http://localhost:5173 for
	// Vite dev work.
	MFAWebAuthnRPID          string
	MFAWebAuthnRPDisplayName string
	MFAWebAuthnRPOrigins     []string

	// OIDCTrustAMRForMFA controls whether the OIDC callback stamps
	// `last_mfa_at` based on the ID token's `amr` claim (Slice D
	// behaviour). Slice H4 inverted the default:
	//
	//   * false (post-H4 default): Control Plane owns MFA via
	//     /auth/mfa/{challenge,verify}. OIDC callback records `amr`
	//     in audit only — does NOT stamp the session.
	//   * true: legacy Slice D behaviour. Use when the IdP genuinely
	//     enforces MFA (Entra / Okta with strong policy) and the
	//     operator wants to skip the app-side step-up modal during a
	//     transition window. `amr` is matched against RFC 8176's
	//     strong-factor set.
	//
	// Default false; operators flip via `SB_OIDC_TRUSTED_AMR_MFA=true`
	// to opt into the legacy path.
	OIDCTrustAMRForMFA bool

	// RequireMFAAtLogin (Slice K) enforces MFA on EVERY authenticated
	// route, not just Tier-2 step-up. When false (default), Tier-1
	// browsing (lists, dashboards) only needs a session cookie; the
	// existing Slice D + H model. When true, a freshly-issued session
	// with no MFA stamp returns 401 step_up_required on every route
	// except a small carve-out set (logout, /users/me, /users/me/mfa/*,
	// /auth/mfa/{challenge,verify}). The SPA's existing onError
	// interceptor handles both the 401 (modal opens) and 412
	// mfa_enrollment_required (route to /me/mfa) flavours.
	//
	// On by default unless SB_ENV=dev (skills#105): with it off, an
	// account with no second factor can add its first one from the
	// session alone and then pass step-up, so step-up protects nothing
	// for it. With it on, a user with no factor enrolls right after
	// primary login. An explicit SB_REQUIRE_MFA_AT_LOGIN wins either
	// way; turning it off outside dev is logged at boot.
	RequireMFAAtLogin bool
	// RequireMFAAtLoginInvalid is true when SB_REQUIRE_MFA_AT_LOGIN is
	// set to something that isn't a boolean, so the default applied and
	// boot says so (mfaAtLoginWarnings).
	RequireMFAAtLoginInvalid bool

	// AllowInsecureHeaderAuth enables the legacy `X-User-Id` identity
	// header. OFF by default and independent of SB_ENV: honoured
	// unconditionally the header is a full auth bypass. Enable ONLY in
	// a trusted local dev loop, never on a routable deployment.
	AllowInsecureHeaderAuth bool

	// EPIC P (Provider Connections):
	// AllowInsecureVaultAddr=true permits http:// vault.address values
	// on provider_connections — the deployment-level override for
	// dev clusters. Audited at boot if true.
	AllowInsecureVaultAddr bool
	// AllowUnsealedWraps=true brings back the two legacy wrap shapes
	// (api#264): a plaintext-over-TLS `value` returned to an agent with
	// no X25519 public key on file, and a plaintext `value` accepted on
	// agent wrap creation. OFF by default, so wraps reach an agent only
	// sealed to its key. A break-glass for an agent that predates
	// wire-envelope; logged as a WARN at boot.
	AllowUnsealedWraps bool
	// ProviderConnRejectSecretValues=true (default) enforces the
	// AKIA / hvs. / JWT / OAuth regex check on scope values. The
	// deployment-level override (false) disables that pass; the
	// credential-shaped key refusal still runs unconditionally.
	ProviderConnRejectSecretValues bool

	// AllowDirectAgentMint gates the legacy POST /api/v1/agents direct
	// mint (api#183). OFF by default: the accepted Agent Onboarding model
	// is self-enrollment only (POST /provider-connections/:id/
	// agent-enrollment-token → POST /agents/enroll). Enable ONLY as an
	// explicit, audited break-glass admin mint. Does not affect any
	// already-minted agent's auth/heartbeat/job behavior.
	AllowDirectAgentMint bool

	// ObjectStore holds media (logos today). Nil when SB_OBJECTSTORE_*
	// is not configured: logo writes then answer 503. Set by main after
	// openObjectStore; ObjectStoreConfig supplies the key prefix.
	ObjectStore       objectstore.Store
	ObjectStoreConfig objectstore.Config
	// LogoBackfill runs the inline-logo backfill at start when an object
	// store is configured. SB_OBJECTSTORE_LOGO_BACKFILL, default true.
	LogoBackfill bool

	// GatewayDiscoveryLeaseTTL is the Argo CD discovery lease TTL
	// (SB_GATEWAY_DISCOVERY_LEASE_TTL, api#308, decision E-3): default
	// 5m, clamped to 1m to 15m. Zero means the default.
	GatewayDiscoveryLeaseTTL time.Duration
}

func loadConfig() Config {
	env := envOr("SB_ENV", ModeProduction)
	return Config{
		Addr:                           envOr("API_ADDR", ":8080"),
		LogoBackfill:                   envBool(envLogoBackfill, true),
		ShutdownGrace:                  envDuration("API_SHUTDOWN_GRACE", 15*time.Second),
		Env:                            env,
		AllowInsecureVaultAddr:         envBool("SB_ALLOW_INSECURE_VAULT_ADDR", false),
		AllowUnsealedWraps:             envBool("SB_ALLOW_UNSEALED_WRAPS", false),
		ProviderConnRejectSecretValues: envBool("SB_PROVIDER_CONN_REJECT_SECRETS", true),
		BootstrapAdminUserID:           envOr("SB_BOOTSTRAP_ADMIN_USER_ID", ""),
		RetiredEnvSet:                  retiredEnvSet(),
		BootstrapAdminEmail:            envOr("SB_BOOTSTRAP_ADMIN_EMAIL", ""),
		PublicURL:                      envOr("SB_PUBLIC_URL", ""),
		BootstrapAdminPassword:         envOr("SB_BOOTSTRAP_ADMIN_PASSWORD", ""),
		DevSeedPassword:                envOr("SB_DEV_SEED_PASSWORD", ""),
		OIDCIssuer:                     envOr("SB_OIDC_ISSUER", ""),
		OIDCClientID:                   envOr("SB_OIDC_CLIENT_ID", ""),
		OIDCClientSecret:               envOr("SB_OIDC_CLIENT_SECRET", ""),
		OIDCRedirectURL:                envOr("SB_OIDC_REDIRECT_URL", ""),
		OIDCScopes:                     envOr("SB_OIDC_SCOPES", "openid profile email"),
		OIDCPostLogout:                 envOr("SB_OIDC_POST_LOGOUT_REDIRECT", ""),
		OIDCGroupClaim:                 envOr("SB_OIDC_GROUP_CLAIM", "groups"),
		OIDCGroupMap:                   parseOIDCGroupMap(envOr("SB_OIDC_GROUP_MAP", "")),
		MFADevAllowPwd:                 envBool("SB_MFA_DEV_ALLOW_PWD", false),
		MFATOTPIssuer:                  envOr("SB_MFA_TOTP_ISSUER", "Secrets Bridge"),
		MFAWebAuthnRPID:                envOr("SB_MFA_WEBAUTHN_RP_ID", ""),
		MFAWebAuthnRPDisplayName:       envOr("SB_MFA_WEBAUTHN_RP_DISPLAY_NAME", "Secrets Bridge"),
		MFAWebAuthnRPOrigins:           splitCommaTrim(envOr("SB_MFA_WEBAUTHN_RP_ORIGINS", "")),
		OIDCTrustAMRForMFA:             envBool("SB_OIDC_TRUSTED_AMR_MFA", false),
		RequireMFAAtLogin:              envBool("SB_REQUIRE_MFA_AT_LOGIN", env != ModeDev),
		RequireMFAAtLoginInvalid:       envBoolInvalid("SB_REQUIRE_MFA_AT_LOGIN"),
		AllowInsecureHeaderAuth:        envBool("SB_ALLOW_INSECURE_HEADER_AUTH", false),
		AllowDirectAgentMint:           envBool("SB_ALLOW_DIRECT_AGENT_MINT", false),
		GatewayDiscoveryLeaseTTL:       envDuration("SB_GATEWAY_DISCOVERY_LEASE_TTL", 0),
	}
}

// splitCommaTrim parses a comma-separated list, trims whitespace,
// and drops empty entries. Used for env vars like
// SB_MFA_WEBAUTHN_RP_ORIGINS that accept a list.
func splitCommaTrim(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ValidateMFADevFlag refuses to honor SB_MFA_DEV_ALLOW_PWD=true when
// SB_ENV != "dev". The flag exists to unblock a staging pilot while
// Slice H4 is being built; it MUST NOT be set in production. main.go
// calls this at boot so a forgotten flag fails the rollout loudly
// instead of silently downgrading the step-up posture.
func (c Config) ValidateMFADevFlag() error {
	if c.MFADevAllowPwd && c.Env != ModeDev {
		return fmt.Errorf("SB_MFA_DEV_ALLOW_PWD=true requires SB_ENV=%s (got %q)", ModeDev, c.Env)
	}
	return nil
}

// parseOIDCGroupMap accepts a JSON object string and returns the
// parsed map. Empty input or a parse failure returns nil — the
// reconciler interprets nil as "no mapping configured" and treats
// JIT users as un-roled. Boot doesn't fail because some deployments
// genuinely want OIDC sign-in WITHOUT group-derived grants (admin
// assigns from the UI); failing the boot would force a useless
// "{}" env-var on every such install.
//
// Parse errors are logged at INFO during loadConfig's first read by
// the caller — `loadConfig` doesn't do logging today, so the
// initial implementation is silent. Operators who want strictness
// can validate via `ValidateOIDCGroupMap` from main.go at boot.
func parseOIDCGroupMap(raw string) map[string]string {
	if raw == "" {
		return nil
	}
	var out map[string]string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}

// ValidateOIDCGroupMap returns a non-nil error when SB_OIDC_GROUP_MAP
// was set but couldn't be parsed as a JSON object of {string:string}.
// main.go calls this so operators get a fail-loud signal on typos.
func (c Config) ValidateOIDCGroupMap() error {
	raw, ok := os.LookupEnv("SB_OIDC_GROUP_MAP")
	if !ok || raw == "" {
		return nil
	}
	var out map[string]string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return fmt.Errorf("SB_OIDC_GROUP_MAP must be a JSON object of {string:string}: %w", err)
	}
	for group, role := range out {
		if group == "" || role == "" {
			return errors.New("SB_OIDC_GROUP_MAP must not contain empty group or role names")
		}
	}
	return nil
}

// ValidateEnv returns an error when SB_ENV is set to an unknown
// value. The default (ModeProduction) and ModeDev are the only
// recognised modes; anything else means a typo that would otherwise
// silently fall through to ModeProduction's strict posture.
func (c Config) ValidateEnv() error {
	switch c.Env {
	case ModeDev, ModeProduction:
		return nil
	default:
		return fmt.Errorf("SB_ENV=%q is not recognised (allowed: %s, %s)", c.Env, ModeDev, ModeProduction)
	}
}

// retiredSetting is a setting the api no longer reads, and why.
type retiredSetting struct {
	name, note string
}

// Notes logged next to the names of retired settings that are still set.
const (
	retiredNoteJWT    = "sign-in is cookie-session only"
	retiredNoteArgoCD = "the Gateway is the only Argo CD client; nothing turns the control-plane integration back on"
)

// retiredEnv are settings the api no longer reads.
//
//   - SB_JWT_SECRET and SB_JWT_TOKEN_TTL signed and timed the login
//     bearer token, which login stopped issuing in M1 (api#191).
//   - SB_GITOPS_ENABLED and SB_ALLOW_INSECURE_ARGOCD_ADDR switched on
//     the control-plane Argo CD integration and allowed its http://
//     endpoints. It was removed at the Gateway R1 cutover
//     (secrets-bridge/gateway#13). They are not a switch any more.
var retiredEnv = []retiredSetting{
	{"SB_JWT_SECRET", retiredNoteJWT},
	{"SB_JWT_TOKEN_TTL", retiredNoteJWT},
	{"SB_GITOPS_ENABLED", retiredNoteArgoCD},
	{"SB_ALLOW_INSECURE_ARGOCD_ADDR", retiredNoteArgoCD},
}

// retiredEnvSet returns the names of the retiredEnv entries that are
// set to a non-empty value. It never returns or reads out the values.
func retiredEnvSet() []string {
	var set []string
	for _, r := range retiredEnv {
		if v, ok := os.LookupEnv(r.name); ok && v != "" {
			set = append(set, r.name)
		}
	}
	return set
}

func envBool(key string, fallback bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	if b, valid := parseBoolToken(v); valid {
		return b
	}
	return fallback
}

// envBoolInvalid reports a key that is set to something envBool doesn't
// read as a boolean, so it fell back to its default.
func envBoolInvalid(key string) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return false
	}
	_, valid := parseBoolToken(v)
	return !valid
}

func parseBoolToken(v string) (value, valid bool) {
	switch v {
	case "1", "true", "TRUE", "True", "yes", "YES":
		return true, true
	case "0", "false", "FALSE", "False", "no", "NO":
		return false, true
	}
	return false, false
}

// mfaAtLoginWarnings are the boot warnings about SB_REQUIRE_MFA_AT_LOGIN.
// They name the setting, never its value.
func mfaAtLoginWarnings(cfg Config) []string {
	var out []string
	if cfg.RequireMFAAtLoginInvalid {
		state := "off"
		if cfg.RequireMFAAtLogin {
			state = "on"
		}
		out = append(out, fmt.Sprintf("SB_REQUIRE_MFA_AT_LOGIN is not a boolean (use true or false), so the default for SB_ENV=%s applies: login-time MFA is %s", cfg.Env, state))
	}
	if !cfg.RequireMFAAtLogin && cfg.Env != ModeDev {
		out = append(out, "login-time MFA is OFF (SB_REQUIRE_MFA_AT_LOGIN=false) outside dev: an account with no second factor can add one from its session alone and then pass step-up")
	}
	return out
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}
