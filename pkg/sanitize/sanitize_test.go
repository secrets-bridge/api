package sanitize_test

import (
	"strings"
	"testing"

	"github.com/secrets-bridge/api/pkg/sanitize"
)

// Canary inputs are the same shape across api + worker tests so a
// regression in either layer is caught the same way.

func TestDiscoverError_Empty(t *testing.T) {
	if got := sanitize.DiscoverError(""); got != "" {
		t.Fatalf("empty input: got %q", got)
	}
}

func TestDiscoverError_NoMatch_PassesThrough(t *testing.T) {
	in := "vault: 503 backend unavailable"
	got := sanitize.DiscoverError(in)
	if got != in {
		t.Fatalf("no-match input mutated: got %q want %q", got, in)
	}
}

func TestDiscoverError_Truncates(t *testing.T) {
	in := strings.Repeat("a", sanitize.DiscoverMaxErrorLen+50)
	got := sanitize.DiscoverError(in)
	if len(got) > sanitize.DiscoverMaxErrorLen {
		t.Fatalf("not truncated: len=%d cap=%d", len(got), sanitize.DiscoverMaxErrorLen)
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("truncated output missing ellipsis: %q", got)
	}
}

// Canary 1: AWS access key id (AKIA + 16 alphanumerics).
func TestDiscoverError_RedactsAWSAccessKey(t *testing.T) {
	canary := "AKIAIOSFODNN7EXAMPLE"
	in := "aws-sm: forbidden — credential " + canary + " rejected"
	got := sanitize.DiscoverError(in)
	if strings.Contains(got, canary) {
		t.Fatalf("AWS key not redacted: %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("expected [REDACTED] marker: %q", got)
	}
}

// Canary 2: Vault token shape (hvs.{20+}).
func TestDiscoverError_RedactsVaultToken(t *testing.T) {
	canary := "hvs.CAESI" + strings.Repeat("X", 30)
	in := "vault: permission denied — token " + canary + " rejected"
	got := sanitize.DiscoverError(in)
	if strings.Contains(got, canary) {
		t.Fatalf("Vault token not redacted: %q", got)
	}
}

// Canary 3: JWT (3-part base64).
func TestDiscoverError_RedactsJWT(t *testing.T) {
	canary := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	in := "auth: rejected jwt " + canary
	got := sanitize.DiscoverError(in)
	if strings.Contains(got, canary) {
		t.Fatalf("JWT not redacted: %q", got)
	}
}

// Canary 4: Google OAuth token (ya29...).
func TestDiscoverError_RedactsOAuthToken(t *testing.T) {
	canary := "ya29.a0AfH6SMBx_some-google-oauth-token-string-here"
	in := "gcp: token rejected " + canary
	got := sanitize.DiscoverError(in)
	if strings.Contains(got, canary) {
		t.Fatalf("OAuth token not redacted: %q", got)
	}
}

// JSON blob > 200 chars — replace with redacted marker.
func TestDiscoverError_StripsLargeJSONBlob(t *testing.T) {
	blob := "{" + strings.Repeat(`"k":"v",`, 40) + `"end":"x"}` // > 200 chars
	in := "provider: 500 internal — response " + blob
	got := sanitize.DiscoverError(in)
	if strings.Contains(got, "\"k\":\"v\"") {
		t.Fatalf("JSON blob not stripped: %q", got)
	}
	if !strings.Contains(got, "{...body redacted...}") {
		t.Fatalf("expected blob redaction marker: %q", got)
	}
}

// Order matters: a credential inside a blob is caught by the regex
// pass BEFORE the blob is stripped. The output contains neither.
func TestDiscoverError_CredentialInsideJSONBlob_BothRedacted(t *testing.T) {
	canary := "AKIAIOSFODNN7EXAMPLE"
	blob := "{" + strings.Repeat(`"k":"v",`, 30) + `"access_key":"` + canary + `"}` // > 200 chars
	in := "aws-sm: 403 forbidden — response " + blob
	got := sanitize.DiscoverError(in)
	if strings.Contains(got, canary) {
		t.Fatalf("credential leaked: %q", got)
	}
}

// Idempotency: sanitizing already-clean output is a no-op.
func TestDiscoverError_Idempotent(t *testing.T) {
	in := "vault: 503 backend unavailable"
	once := sanitize.DiscoverError(in)
	twice := sanitize.DiscoverError(once)
	if twice != once {
		t.Fatalf("not idempotent: once=%q twice=%q", once, twice)
	}
}
