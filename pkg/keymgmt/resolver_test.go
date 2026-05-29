package keymgmt_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/secrets-bridge/api/pkg/keymgmt"
)

func TestFromEnv_DevAllowsLocalBackend(t *testing.T) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	t.Setenv(keymgmt.EnvVarBackend, keymgmt.BackendLocal)
	t.Setenv(keymgmt.EnvVarMasterKey, base64.StdEncoding.EncodeToString(k))

	km, err := keymgmt.FromEnv(context.Background(), "dev")
	if err != nil {
		t.Fatalf("FromEnv dev+local: %v", err)
	}
	if km.CurrentKeyID() == "" {
		t.Fatal("KeyID empty")
	}
}

func TestFromEnv_DefaultBackendDevIsLocal(t *testing.T) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	t.Setenv(keymgmt.EnvVarBackend, "")
	t.Setenv(keymgmt.EnvVarMasterKey, base64.StdEncoding.EncodeToString(k))

	km, err := keymgmt.FromEnv(context.Background(), "dev")
	if err != nil {
		t.Fatalf("FromEnv dev+default: %v", err)
	}
	if !strings.HasPrefix(km.CurrentKeyID(), "local:") {
		t.Fatalf("expected local backend by default, got %q", km.CurrentKeyID())
	}
}

func TestFromEnv_ProductionRejectsLocalBackend(t *testing.T) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	t.Setenv(keymgmt.EnvVarBackend, keymgmt.BackendLocal)
	t.Setenv(keymgmt.EnvVarMasterKey, base64.StdEncoding.EncodeToString(k))

	_, err := keymgmt.FromEnv(context.Background(), "production")
	if err == nil {
		t.Fatal("expected production + local to be rejected")
	}
	if !strings.Contains(err.Error(), "is not allowed when SB_ENV") {
		t.Fatalf("error message should call out SB_ENV; got: %v", err)
	}
	if !strings.Contains(err.Error(), "vault-transit") || !strings.Contains(err.Error(), "aws-kms") {
		t.Fatalf("error message should name the two allowed production backends; got: %v", err)
	}
}

func TestFromEnv_DefaultBackendProductionRejected(t *testing.T) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	// Backend env unset → resolver defaults to local → production
	// must still reject. Guards against a forgotten SB_KMS_BACKEND.
	t.Setenv(keymgmt.EnvVarBackend, "")
	t.Setenv(keymgmt.EnvVarMasterKey, base64.StdEncoding.EncodeToString(k))

	if _, err := keymgmt.FromEnv(context.Background(), "production"); err == nil {
		t.Fatal("expected production + default-local to be rejected")
	}
}

func TestFromEnv_UnknownBackendRejected(t *testing.T) {
	t.Setenv(keymgmt.EnvVarBackend, "azure-key-vault")

	_, err := keymgmt.FromEnv(context.Background(), "dev")
	if err == nil {
		t.Fatal("expected unknown backend to be rejected")
	}
	if !strings.Contains(err.Error(), "unknown backend") {
		t.Fatalf("error should name 'unknown backend'; got: %v", err)
	}
}

func TestFromEnv_UnknownEnvBlocksLocal(t *testing.T) {
	// A typo in SB_ENV ("dvelopment") MUST fall to the production
	// path — only the exact string "dev" allows the local backend.
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	t.Setenv(keymgmt.EnvVarBackend, keymgmt.BackendLocal)
	t.Setenv(keymgmt.EnvVarMasterKey, base64.StdEncoding.EncodeToString(k))

	if _, err := keymgmt.FromEnv(context.Background(), "dvelopment"); err == nil {
		t.Fatal("expected typo'd SB_ENV to be treated as non-dev and reject local")
	}
}
