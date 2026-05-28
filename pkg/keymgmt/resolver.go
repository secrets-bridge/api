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
// Defaults to BackendLocal so existing deployments don't break.
//
// Each backend reads its own SB_KMS_<BACKEND>_* env vars; see the
// per-backend NewFromEnv constructor for the exact list.
//
// The returned KeyManager is ready for GenerateDataKey / DecryptDataKey
// calls. For Vault, that means an auth handshake has already happened.
func FromEnv(ctx context.Context) (KeyManager, error) {
	backend := os.Getenv(EnvVarBackend)
	if backend == "" {
		backend = BackendLocal
	}
	switch backend {
	case BackendLocal:
		return NewLocalKMSFromEnv()
	case BackendVaultTransit:
		return NewVaultTransitFromEnv(ctx)
	case BackendAWSKMS:
		return NewAWSKMSFromEnv(ctx)
	default:
		return nil, fmt.Errorf("keymgmt: unknown backend %q (set %s to one of: local, vault-transit, aws-kms)", backend, EnvVarBackend)
	}
}
