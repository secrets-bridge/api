// Package sanitize provides shared text-sanitization primitives used
// by the API + worker before persisting error / log strings that may
// have transited a credential-bearing surface.
//
// Hard rule: the API is the source of truth for sanitization, but
// the worker also pre-sanitizes (defense in depth) so a credential-
// shaped substring NEVER lands in an audit table or a status column.
// EPIC P (Provider Connections) introduces last_discover_error +
// the worker's DB-backed DiscoverScheduler; both paths route through
// DiscoverError before any persistence call.
//
// The package is intentionally infra-free: no DB, no HTTP, no logger.
// Both api/internal/services and worker/internal/sweepers import it
// without crossing the `internal/` package boundary.
package sanitize

import (
	"regexp"
	"strings"
)

// DiscoverMaxErrorLen caps stored discover errors. Postgres has no
// column-level length cap on last_discover_error; the cap belongs at
// the surface that writes it. 280 is roomy enough for a provider
// status line ("vault: 503 backend unavailable") without inviting
// operators to paste runbooks into the column.
const DiscoverMaxErrorLen = 280

// secretPatterns are credential-shaped substrings that must be
// redacted before persistence. Each match collapses to `[REDACTED]`.
//
// Sources:
//   - AWS access key id    AKIA + 16 alphanumerics
//   - Vault token v1+      hvs.{20+}
//   - JWT (3-part base64)  eyJ{20+}.{20+}.{20+}
//   - Google OAuth token   ya29.{1+}
//
// The compile happens once at package load — the regexes are
// effectively constants. Adding a pattern is a one-line append.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[A-Z0-9]{16}`),
	regexp.MustCompile(`hvs\.[A-Za-z0-9_-]{20,}`),
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}`),
	regexp.MustCompile(`ya29\.[A-Za-z0-9_-]+`),
}

// jsonBlobPattern matches a JSON object 200+ chars long. The
// legitimate signal in a sweep error is the status code + provider
// name, not the response payload — providers return full secret
// bundles in error bodies often enough that stripping these is
// load-bearing.
var jsonBlobPattern = regexp.MustCompile(`\{[\s\S]{200,}\}`)

// DiscoverError runs the three-pass sanitizer required by EPIC P:
//
//  1. Replace every credential-shaped substring with [REDACTED].
//  2. Replace any JSON-ish blob > 200 chars with {...body redacted...}.
//  3. Truncate to DiscoverMaxErrorLen.
//
// The order is load-bearing: credentials are caught FIRST so a
// credential inside a long blob can't sneak through; the blob is
// then shrunk; the final cap catches anything still oversized.
// Truncating first would let the regex miss credentials that span
// the cut point.
//
// Empty input returns empty — callers should never persist the
// result without checking; an empty string means "no error".
func DiscoverError(raw string) string {
	out := raw

	// Step 1: redact credential-shaped substrings. Catches them
	// whether or not they live inside a larger blob.
	for _, re := range secretPatterns {
		out = re.ReplaceAllString(out, "[REDACTED]")
	}

	// Step 2: strip large JSON blobs. Any remaining response body
	// is collapsed to a marker before truncation runs.
	out = jsonBlobPattern.ReplaceAllString(out, "{...body redacted...}")

	// Step 3: truncate. Trailing ellipsis makes the cap visible to
	// operators reading the row in a dashboard.
	if len(out) > DiscoverMaxErrorLen {
		out = out[:DiscoverMaxErrorLen-3] + "..."
	}

	return strings.TrimSpace(out)
}
