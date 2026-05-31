package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
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

	// GitOpsEnabled gates the read-only ArgoCD visibility integration
	// (BRD §26). Default OFF — operators opt in via Helm value or env
	// var. When false: the admin CRUD endpoints + user observation
	// endpoint are NOT mounted and the request lifecycle has no GitOps
	// fan-out step. Existing deployments behave exactly as before.
	GitOpsEnabled bool

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

	// JWTSecret is the HMAC key for HS256-signed login tokens. Must
	// be ≥32 bytes. Accepted as a base64 string OR raw bytes; the
	// loader picks whichever decode path yields ≥32 bytes.
	//
	// When unset, the api refuses to start (fail loud rather than
	// silently mint useless tokens).
	JWTSecret []byte

	// JWTTokenTTL bounds the login session lifetime. Default 8h —
	// matches typical admin-session expectations. Operators wanting
	// a tighter window override via SB_JWT_TOKEN_TTL.
	JWTTokenTTL time.Duration

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
	OIDCGroupClaim   string            // default "groups"
	OIDCGroupMap     map[string]string // raw value via SB_OIDC_GROUP_MAP env (JSON object)

	// MFADevAllowPwd is the interim unblock for app-level MFA (Slice
	// H). When true AND SB_ENV=dev, the SessionService treats any live
	// non-revoked session as MFA-fresh, bypassing the `last_mfa_at`
	// check. The IdP can return an empty `amr` (no MFA stage bound)
	// and Tier 2 paths still work for pilot operators.
	//
	// REFUSED at boot when SB_ENV=production — see ValidateMFADevFlag.
	// Drop the flag once Slice H4 (real /auth/mfa/{challenge,verify})
	// is live and qi UAT operators have enrolled a real factor.
	MFADevAllowPwd bool
}

func loadConfig() Config {
	return Config{
		Addr:                   envOr("API_ADDR", ":8080"),
		ShutdownGrace:          envDuration("API_SHUTDOWN_GRACE", 15*time.Second),
		Env:                    envOr("SB_ENV", ModeProduction),
		GitOpsEnabled:          envBool("SB_GITOPS_ENABLED", false),
		BootstrapAdminUserID:   envOr("SB_BOOTSTRAP_ADMIN_USER_ID", ""),
		JWTSecret:              loadJWTSecret(),
		JWTTokenTTL:            envDuration("SB_JWT_TOKEN_TTL", 8*time.Hour),
		BootstrapAdminEmail:    envOr("SB_BOOTSTRAP_ADMIN_EMAIL", ""),
		BootstrapAdminPassword: envOr("SB_BOOTSTRAP_ADMIN_PASSWORD", ""),
		DevSeedPassword:        envOr("SB_DEV_SEED_PASSWORD", ""),
		OIDCIssuer:             envOr("SB_OIDC_ISSUER", ""),
		OIDCClientID:           envOr("SB_OIDC_CLIENT_ID", ""),
		OIDCClientSecret:       envOr("SB_OIDC_CLIENT_SECRET", ""),
		OIDCRedirectURL:        envOr("SB_OIDC_REDIRECT_URL", ""),
		OIDCScopes:             envOr("SB_OIDC_SCOPES", "openid profile email"),
		OIDCPostLogout:         envOr("SB_OIDC_POST_LOGOUT_REDIRECT", ""),
		OIDCGroupClaim:         envOr("SB_OIDC_GROUP_CLAIM", "groups"),
		OIDCGroupMap:           parseOIDCGroupMap(envOr("SB_OIDC_GROUP_MAP", "")),
		MFADevAllowPwd:         envBool("SB_MFA_DEV_ALLOW_PWD", false),
	}
}

// ValidateMFADevFlag refuses to honor SB_MFA_DEV_ALLOW_PWD=true when
// SB_ENV != "dev". The flag exists to unblock the qi UAT pilot while
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

// loadJWTSecret reads SB_JWT_SECRET as base64 (preferred) or raw
// bytes. Returns nil when the env var is unset; main fails the boot
// in that case.
func loadJWTSecret() []byte {
	raw, ok := os.LookupEnv("SB_JWT_SECRET")
	if !ok || raw == "" {
		return nil
	}
	// Try base64 first.
	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil && len(decoded) >= 32 {
		return decoded
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(raw); err == nil && len(decoded) >= 32 {
		return decoded
	}
	// Fall back to raw bytes.
	return []byte(raw)
}

// ValidateJWTSecret returns an error when the secret is too short or
// missing. Called by main on boot.
func (c Config) ValidateJWTSecret() error {
	if len(c.JWTSecret) < 32 {
		return errors.New("SB_JWT_SECRET must be set and ≥32 bytes (base64 or raw)")
	}
	return nil
}

func envBool(key string, fallback bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	switch v {
	case "1", "true", "TRUE", "True", "yes", "YES":
		return true
	case "0", "false", "FALSE", "False", "no", "NO":
		return false
	default:
		return fallback
	}
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

