package main

import (
	"encoding/base64"
	"errors"
	"os"
	"time"
)

// buildVersion is set at link time via -ldflags '-X main.buildVersion=...'.
// Defaults to "dev" for `go run` and local builds.
var buildVersion = "dev"

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

	// GitOpsEnabled gates the read-only ArgoCD visibility integration
	// (BRD §26). Default OFF — operators opt in via Helm value or env
	// var. When false: the admin CRUD endpoints + user observation
	// endpoint are NOT mounted and the request lifecycle has no GitOps
	// fan-out step. Existing deployments behave exactly as before.
	GitOpsEnabled bool

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
}

func loadConfig() Config {
	return Config{
		Addr:                   envOr("API_ADDR", ":8080"),
		ShutdownGrace:          envDuration("API_SHUTDOWN_GRACE", 15*time.Second),
		GitOpsEnabled:          envBool("SB_GITOPS_ENABLED", false),
		BootstrapAdminUserID:   envOr("SB_BOOTSTRAP_ADMIN_USER_ID", ""),
		JWTSecret:              loadJWTSecret(),
		JWTTokenTTL:            envDuration("SB_JWT_TOKEN_TTL", 8*time.Hour),
		BootstrapAdminEmail:    envOr("SB_BOOTSTRAP_ADMIN_EMAIL", ""),
		BootstrapAdminPassword: envOr("SB_BOOTSTRAP_ADMIN_PASSWORD", ""),
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

