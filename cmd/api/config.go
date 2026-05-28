package main

import (
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
}

func loadConfig() Config {
	return Config{
		Addr:          envOr("API_ADDR", ":8080"),
		ShutdownGrace: envDuration("API_SHUTDOWN_GRACE", 15*time.Second),
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

