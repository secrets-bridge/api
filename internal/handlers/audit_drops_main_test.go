package handlers_test

import (
	"os"
	"testing"

	"github.com/secrets-bridge/api/internal/testutil/auditdrops"
)

// No real audit writer exercised by this package's tests may lose
// metadata to the allowlist (api#279).
func TestMain(m *testing.M) { os.Exit(auditdrops.Main(m)) }
