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
	"unicode"
	"unicode/utf8"
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
//   - GitHub token         ghp_/gho_/ghu_/ghs_/ghr_ + 36, github_pat_ + 22
//   - GitLab token         glpat- + 20
//   - Slack token          xoxa-/xoxb-/xoxp-/xoxr- + 10
//   - "sk-" API key        sk- + 20 (OpenAI style keys)
//   - PEM block            -----BEGIN ..., up to its END line or the end
//
// The prefixed tokens must start at a word boundary and carry a long
// tail, so an enum such as "risk-high" or a short "sk-1" never matches.
//
// The compile happens once at package load — the regexes are
// effectively constants. Adding a pattern is a one-line append.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[A-Z0-9]{16}`),
	regexp.MustCompile(`hvs\.[A-Za-z0-9_-]{20,}`),
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}`),
	regexp.MustCompile(`ya29\.[A-Za-z0-9_-]+`),
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}`),
	regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,}`),
	regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}`),
	regexp.MustCompile(`\bxox[abpr]-[A-Za-z0-9-]{10,}`),
	regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}`),
	regexp.MustCompile(`-----BEGIN(?:[\s\S]*?-----END[^\n]*?-----|[\s\S]*)`),
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
	return scrub(raw, DiscoverMaxErrorLen)
}

// LogMaxErrorLen caps an internal error string written to the server
// log. Roomier than DiscoverMaxErrorLen because a log line is read by
// an operator during triage, not stored in a status column.
const LogMaxErrorLen = 1024

// LogError runs the same three passes as DiscoverError over an internal
// error (storage, KMS, Redis, provider, network) before it is written
// to the server log. Handlers return a stable message to the client and
// log this instead, so the triage detail survives but a credential that
// rode along in a wrapped error does not.
func LogError(raw string) string {
	return scrub(raw, LogMaxErrorLen)
}

// HasCredential reports whether s contains a credential-shaped
// substring (the same patterns DiscoverError redacts).
func HasCredential(s string) bool {
	for _, re := range secretPatterns {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// scrub is the shared pipeline: redact credentials, strip JSON blobs,
// truncate to max. The order is load-bearing (see DiscoverError).
func scrub(raw string, max int) string {
	out := redact(raw)

	// Step 3: truncate. Trailing ellipsis makes the cap visible to
	// operators reading the row in a dashboard.
	if len(out) > max {
		out = out[:max-3] + "..."
	}

	return strings.TrimSpace(out)
}

// redact runs steps 1 and 2 of the sanitizer: credential-shaped
// substrings first, then large JSON blobs.
func redact(raw string) string {
	out := raw

	// Step 1: redact credential-shaped substrings. Catches them
	// whether or not they live inside a larger blob.
	for _, re := range secretPatterns {
		out = re.ReplaceAllString(out, "[REDACTED]")
	}

	// Step 2: strip large JSON blobs. Any remaining response body
	// is collapsed to a marker before truncation runs.
	return jsonBlobPattern.ReplaceAllString(out, "{...body redacted...}")
}

// JobMaxErrorLen caps the error text an agent reports when it completes
// a job (API-S-27). The agent is the writer and the text is otherwise
// unbounded, so the cap lives here, at the surface that persists it.
const JobMaxErrorLen = 1024

// jobErrorScanLen bounds how much agent text the redaction regexes see.
// Anything past it can never reach the stored JobMaxErrorLen prefix, and
// it is far enough past that prefix that a credential straddling the
// final cut is still seen whole (and redacted) by step 1.
const jobErrorScanLen = 16 * 1024

// JobError sanitizes the free-text error an agent posts with a job
// outcome before it is stored: credentials and large JSON blobs are
// redacted exactly like DiscoverError, control characters (NUL breaks a
// Postgres text/jsonb write) are dropped, and the result is capped at
// JobMaxErrorLen bytes on a UTF-8 boundary.
func JobError(raw string) string {
	// Strip control characters BEFORE redacting: a credential split by a
	// NUL or an ANSI escape would slip past the redaction patterns and
	// then be glued back together by the strip.
	out := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, truncateUTF8(raw, jobErrorScanLen, ""))
	out = redact(out)
	return strings.TrimSpace(truncateUTF8(out, JobMaxErrorLen, "..."))
}

// truncateUTF8 cuts s to at most max bytes without splitting a rune;
// when it cuts, the result ends in suffix (counted inside max).
func truncateUTF8(s string, max int, suffix string) string {
	if len(s) <= max {
		return s
	}
	cut := max - len(suffix)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + suffix
}
