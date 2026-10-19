package main

import (
	"bytes"
	"log/slog"
	"slices"
	"strings"
	"testing"
)

// TestRetiredEnv_NamesOnly checks that a retired setting that is still
// set is reported by name, and that its value never reaches the config
// or the startup log.
func TestRetiredEnv_NamesOnly(t *testing.T) {
	const secretVal = "retired-jwt-secret-value-0123456789abcdef"
	const ttlVal = "8h-retired-ttl-value"

	t.Run("none set", func(t *testing.T) {
		t.Setenv("SB_JWT_SECRET", "")
		t.Setenv("SB_JWT_TOKEN_TTL", "")
		if got := retiredEnvSet(); len(got) != 0 {
			t.Fatalf("retiredEnvSet() = %v, want empty", got)
		}
		var buf bytes.Buffer
		logRetiredEnv(slog.New(slog.NewTextHandler(&buf, nil)), retiredEnvSet())
		if buf.Len() != 0 {
			t.Fatalf("logged %q with nothing set", buf.String())
		}
	})

	t.Run("both set", func(t *testing.T) {
		t.Setenv("SB_JWT_SECRET", secretVal)
		t.Setenv("SB_JWT_TOKEN_TTL", ttlVal)
		got := retiredEnvSet()
		if !slices.Equal(got, []string{"SB_JWT_SECRET", "SB_JWT_TOKEN_TTL"}) {
			t.Fatalf("retiredEnvSet() = %v", got)
		}
		cfg := loadConfig()
		if !slices.Equal(cfg.RetiredEnvSet, got) {
			t.Fatalf("Config.RetiredEnvSet = %v, want %v", cfg.RetiredEnvSet, got)
		}
		var buf bytes.Buffer
		logRetiredEnv(slog.New(slog.NewTextHandler(&buf, nil)), cfg.RetiredEnvSet)
		out := buf.String()
		for _, name := range got {
			if !strings.Contains(out, name) {
				t.Errorf("log %q does not name %s", out, name)
			}
		}
		for _, v := range []string{secretVal, ttlVal} {
			if strings.Contains(out, v) {
				t.Errorf("log leaks a retired value: %q", out)
			}
		}
	})
}
