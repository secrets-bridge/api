// Package actordisplay resolves a raw `audit_events.actor` string
// ("user:<uuid>", "agent:<uuid>", "system:<kind>", or anything else)
// to a human-readable display label.
//
// Shared between the audit list handler (`internal/handlers/audit.go`)
// and the policy rule history service (R-follow-up #5 slice 1a,
// api#133). Per-request memoization is the caller's responsibility:
// pass a fresh map[string]string per request so the cache never leaks
// across requests.
//
// Hard rule (mirrors `internal/handlers/audit.go`'s historical
// posture): the display string is convenience text, NOT auth. Raw
// `actor` is always carried alongside on the wire so UIs can use it
// as a forensic anchor.
package actordisplay

import (
	"context"
	"strings"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// Resolver holds the repositories needed to enrich actor strings.
// Either repository may be nil — in that case the resolver falls back
// to the short-UUID placeholder for the corresponding actor kind.
type Resolver struct {
	users  storage.LocalUserRepository
	agents storage.AgentRepository
}

// New returns a Resolver bound to the given repositories. Pass nil
// for either to skip enrichment for that actor kind.
func New(users storage.LocalUserRepository, agents storage.AgentRepository) *Resolver {
	return &Resolver{users: users, agents: agents}
}

// Display returns the human-readable display string for `actor`.
//
// `cache` is a per-request memoization map. The same actor string
// typically repeats across many rows (one operator's session
// generates dozens of audit lines); a memoized lookup keeps the
// worst case to one repository call per distinct actor, not one
// per row.
//
// Pass a fresh `cache` map per request — the cache MUST NOT leak
// across requests or actor identity could be poisoned across users.
func (r *Resolver) Display(ctx context.Context, actor string, cache map[string]string) string {
	if actor == "" {
		return ""
	}
	if d, ok := cache[actor]; ok {
		return d
	}
	d := r.lookup(ctx, actor)
	cache[actor] = d
	return d
}

func (r *Resolver) lookup(ctx context.Context, actor string) string {
	// Built-in non-user actors. Keep the set small + explicit; the
	// reconciler/back-channel/etc. all emit through `system:<kind>`.
	if strings.HasPrefix(actor, "system:") {
		kind := strings.TrimPrefix(actor, "system:")
		switch kind {
		case "oidc":
			return "System (OIDC reconciler)"
		case "":
			return "System"
		default:
			return "System (" + kind + ")"
		}
	}

	if strings.HasPrefix(actor, "user:") && r.users != nil {
		raw := strings.TrimPrefix(actor, "user:")
		id, err := uuid.Parse(raw)
		if err != nil {
			return ShortFallback("user", raw)
		}
		u, err := r.users.Get(ctx, id)
		if err != nil || u == nil {
			return ShortFallback("user", raw)
		}
		switch {
		case u.Email != "":
			return u.Email
		case u.DisplayName != "":
			return u.DisplayName
		default:
			return ShortFallback("user", raw)
		}
	}

	if strings.HasPrefix(actor, "agent:") && r.agents != nil {
		raw := strings.TrimPrefix(actor, "agent:")
		id, err := uuid.Parse(raw)
		if err != nil {
			return ShortFallback("agent", raw)
		}
		a, err := r.agents.Get(ctx, id)
		if err != nil || a == nil {
			return ShortFallback("agent", raw)
		}
		if a.Name != "" {
			return "Agent " + a.Name
		}
		return ShortFallback("agent", raw)
	}

	// Unknown shape — return the raw actor string as the display.
	// UI tooltip will show the same value; no information lost.
	return actor
}

// ShortFallback renders a placeholder when the actor's UUID can't be
// resolved to a record (deleted user, agent revoked, malformed id).
// Truncates the UUID to 8 chars + ellipsis so the placeholder is
// recognisably short without leaking a useful identifier. Wire shape
// preserved from `internal/handlers/audit.go`'s historical output.
func ShortFallback(kind, raw string) string {
	short := raw
	if len(short) > 8 {
		short = short[:8] + "…"
	}
	return "unknown " + kind + " (" + short + ")"
}
