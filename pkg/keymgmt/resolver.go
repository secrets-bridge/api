package keymgmt

import (
	"context"
	"fmt"
	"os"
)

// EnvVarBackend selects which KeyManager implementation FromEnv
// constructs. Recognised values: "local" (default), "vault-transit",
// "aws-kms". Adding a new backend means: implementing KeyManager
// somewhere, then adding a case to FromEnv.
//
// Scope today: one master key per CP deployment, wrapping per-row
// data keys (envelope encryption). Per-tenant / per-project CMK
// selection is a future phase (Piece 8c) — it will thread a scope
// through the KeyManager interface; existing backends keep their
// no-scope constructors and a new resolver layer routes per row.
const EnvVarBackend = "SB_KMS_BACKEND"

const (
	BackendLocal        = "local"
	BackendVaultTransit = "vault-transit"
	BackendAWSKMS       = "aws-kms"
)

// FromEnv reads SB_KMS_BACKEND and constructs the matching KeyManager.
// Defaults to BackendLocal so dev deployments don't need extra config.
//
// The `env` argument is the deployment mode (Config.Env from SB_ENV).
// Only the value "dev" allows BackendLocal — every other value (the
// default "production", a typo, anything) rejects LocalKMS at boot.
// A LocalKMS master key is a single AES-256-GCM key on the api host;
// disk theft of that one secret would defeat the storage envelope
// (Piece 8a's defense-in-depth chain), so production must terminate
// the trust at an external KMS (Vault Transit OR AWS KMS).
//
// Each backend reads its own SB_KMS_<BACKEND>_* env vars; see the
// per-backend NewFromEnv constructor for the exact list.
//
// The returned KeyManager is ready for GenerateDataKey / DecryptDataKey
// calls. For Vault, that means an auth handshake has already happened.
func FromEnv(ctx context.Context, env string) (KeyManager, error) {
	backend := os.Getenv(EnvVarBackend)
	if backend == "" {
		backend = BackendLocal
	}

	if backend == BackendLocal && env != "dev" {
		return nil, fmt.Errorf(
			"keymgmt: backend %q is not allowed when SB_ENV=%q — production deployments must set SB_KMS_BACKEND to one of: %s, %s",
			backend, env, BackendVaultTransit, BackendAWSKMS,
		)
	}

	switch backend {
	case BackendLocal:
		return NewLocalKMSFromEnv()
	case BackendVaultTransit:
		return NewVaultTransitFromEnv(ctx)
	case BackendAWSKMS:
		return NewAWSKMSFromEnv(ctx)
	default:
		return nil, fmt.Errorf("keymgmt: unknown backend %q (set %s to one of: %s, %s, %s)", backend, EnvVarBackend, BackendLocal, BackendVaultTransit, BackendAWSKMS)
	}
}
