package sanitize_test

import (
	"strings"
	"testing"
	"unicode/utf8"

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

// API-S-27: agent job errors are capped, redacted and safe to store.
func TestJobError_CapsRedactsAndStripsControl(t *testing.T) {
	if got := sanitize.JobError(""); got != "" {
		t.Fatalf("empty input: got %q", got)
	}
	in := "get value: AccessDenied for AKIAABCDEFGHIJKLMNOP\x00 " + strings.Repeat("é", 100_000)
	got := sanitize.JobError(in)
	if len(got) > sanitize.JobMaxErrorLen {
		t.Fatalf("len = %d; want <= %d", len(got), sanitize.JobMaxErrorLen)
	}
	if strings.Contains(got, "AKIAABCDEFGHIJKLMNOP") || !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("credential not redacted: %q", got[:80])
	}
	if strings.ContainsRune(got, 0) {
		t.Fatal("NUL survived")
	}
	if !utf8.ValidString(got) || !strings.HasSuffix(got, "...") {
		t.Fatalf("truncation split a rune or lost its marker: %q", got[len(got)-8:])
	}
	short := "vault: 403 permission denied\non secret/data/team-alpha/uat/db"
	if got := sanitize.JobError(short); got != short {
		t.Fatalf("short error mutated: %q", got)
	}
}

// A credential straddling the final cut is still redacted, not left as a
// partial prefix.
func TestJobError_CredentialAtCutPoint(t *testing.T) {
	in := strings.Repeat("a", sanitize.JobMaxErrorLen-10) + "AKIAABCDEFGHIJKLMNOP"
	if got := sanitize.JobError(in); strings.Contains(got, "AKIAABC") {
		t.Fatalf("partial credential leaked at the cut: %q", got[len(got)-20:])
	}
}

func TestLogError_RedactsCredentialsAndKeepsContext(t *testing.T) {
	in := `keymgmt: vault transit decrypt: URL: PUT https://vault.example.com/v1/transit/decrypt/sb-key token=hvs.CAESIabcdefghijklmnopqrstuvwxyz0123`
	got := sanitize.LogError(in)
	if strings.Contains(got, "hvs.CAESI") {
		t.Fatalf("vault token survived: %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") || !strings.Contains(got, "vault.example.com/v1/transit/decrypt/sb-key") {
		t.Fatalf("log line lost its triage context: %q", got)
	}
}

func TestLogError_RoomierCapThanDiscover(t *testing.T) {
	in := strings.Repeat("e", sanitize.DiscoverMaxErrorLen*2)
	if got := sanitize.LogError(in); len(got) != len(in) {
		t.Fatalf("a %d-byte error should not be cut for the log; got %d", len(in), len(got))
	}
	long := strings.Repeat("e", sanitize.LogMaxErrorLen+100)
	if got := sanitize.LogError(long); len(got) > sanitize.LogMaxErrorLen {
		t.Fatalf("LogError len = %d; want <= %d", len(got), sanitize.LogMaxErrorLen)
	}
}

// A credential split by a control character must still be redacted: the
// strip runs before redaction, so the two halves can't be glued back
// together after the redaction pass has already missed them.
func TestJobError_CredentialSplitByControlChar(t *testing.T) {
	for _, in := range []string{
		"vault: denied for AKIAABCDEFGH\x00IJKLMNOP",
		"vault: denied for AKIAABCDEFGH\x07IJKLMNOP",
	} {
		got := sanitize.JobError(in)
		if strings.Contains(got, "AKIAABCDEFGHIJKLMNOP") || !strings.Contains(got, "[REDACTED]") {
			t.Fatalf("split credential survived: %q", got)
		}
	}
}

// Placeholder credentials for the newer patterns (api#279). None of
// them is a real token.
var credentialCanaries = map[string]string{
	"github classic":    "ghp_" + strings.Repeat("A1b2", 9),
	"github oauth":      "gho_" + strings.Repeat("Z9y8", 9),
	"github fine":       "github_pat_" + strings.Repeat("Ab12_", 6),
	"gitlab":            "glpat-" + strings.Repeat("x1Y2", 5),
	"slack bot":         "xoxb-" + "123456789012-abcdefABCDEF",
	"slack user":        "xoxp-" + "1234-5678-abcdefghij",
	"slack app":         "xoxa-" + "2-abcdefghijkl",
	"slack refresh":     "xoxr-" + "abcdefghijkl",
	"sk api key":        "sk-" + strings.Repeat("aB3d", 6),
	"sk project key":    "sk-proj-" + strings.Repeat("Qw7e", 6),
	"pem private key":   "-----BEGIN PRIVATE KEY----- MIIEvQIBADANBgkqhkiG9w0BAQEFAASC",
	"pem rsa multiline": "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
	"pem bare header":   "-----BEGIN",
}

func TestHasCredential_NewPatterns(t *testing.T) {
	for name, c := range credentialCanaries {
		for _, in := range []string{c, "prefix " + c + " suffix", "key=" + c} {
			if !sanitize.HasCredential(in) {
				t.Errorf("%s: HasCredential(%q) = false", name, in)
			}
		}
		got := sanitize.DiscoverError("provider said " + c + " and stopped")
		if strings.Contains(got, c) || !strings.Contains(got, "[REDACTED]") {
			t.Errorf("%s: not redacted: %q", name, got)
		}
	}
}

// Values that look a little like the prefixed tokens but are ordinary
// enums, names and ids: they must not be flagged.
func TestHasCredential_LegitimateValues(t *testing.T) {
	for _, in := range []string{
		"risk-high", "sk", "sk-1", "sk-short", "risk-" + strings.Repeat("a", 30), "desk-" + strings.Repeat("b", 30),
		"ghp_short", "github_pat", "glpat-1", "xoxb", "xoxz-" + strings.Repeat("c", 20),
		"secret.read", "provider_connection.create", "no_governing_binding", "DB_PASSWORD",
		"BEGIN", "----- section -----", "vault: 503 backend unavailable",
		"550e8400-e29b-41d4-a716-446655440000", "sha256:" + strings.Repeat("ab", 32),
	} {
		if sanitize.HasCredential(in) {
			t.Errorf("HasCredential(%q) = true, want false", in)
		}
	}
}

// A PEM block is redacted whole, header to END line, and the text
// after it survives.
func TestDiscoverError_RedactsPEMBlock(t *testing.T) {
	in := "tls: bad key -----BEGIN EC PRIVATE KEY-----\nMHcCAQEEI\n-----END EC PRIVATE KEY----- then 503"
	got := sanitize.LogError(in)
	if strings.Contains(got, "MHcCAQEEI") || strings.Contains(got, "BEGIN") {
		t.Fatalf("PEM body survived: %q", got)
	}
	if !strings.HasSuffix(got, "then 503") {
		t.Fatalf("text after the PEM block lost: %q", got)
	}
}
