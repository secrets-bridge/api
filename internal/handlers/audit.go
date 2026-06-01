// Audit log handler — exposes the read-only audit event surface.
//
// The underlying `audit_events` table is append-only at the schema
// layer (BEFORE UPDATE / DELETE triggers reject mutations) and the
// `AuditEventRepository` interface deliberately omits Update / Delete
// methods. This handler only ever reads from it.
//
// Authorization: gated by `auth.Require(auth.PermAuditRead, …)` at
// route registration time. Permission keys: see
// `internal/auth/permissions.go`.

package handlers

import (
	"context"
	"encoding/hex"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// Audit handles GET /api/v1/audit-events.
type Audit struct {
	repo   storage.AuditEventRepository
	users  storage.LocalUserRepository
	agents storage.AgentRepository
}

// NewAudit binds the handler to the given repositories. `users` and
// `agents` are used to enrich audit rows with human-readable actor
// display strings (`actor_display`). Pass nil for either to fall back
// to raw `actor` strings — useful in tests that don't care about the
// enrichment path.
func NewAudit(
	repo storage.AuditEventRepository,
	users storage.LocalUserRepository,
	agents storage.AgentRepository,
) *Audit {
	return &Audit{repo: repo, users: users, agents: agents}
}

// AuditEventBody is the JSON wire shape for one audit_events row.
//
// `metadata` is opaque jsonb. Service-layer Append calls have
// already stripped any field that could carry a secret value (CLAUDE
// hard rule), so re-exporting it is safe.
//
// `actor_display` is a human-readable rendering of `actor`, resolved
// at response time. For `user:<uuid>` the user's email is preferred
// (falls back to display_name, then a short-uuid placeholder); for
// `agent:<uuid>` the agent's name; for `system:<kind>` a fixed label.
// The raw `actor` field stays in the payload so UIs can use it as a
// tooltip / forensic anchor — display is convenience, not auth.
type AuditEventBody struct {
	ID            string                 `json:"id"`
	Actor         string                 `json:"actor"`
	ActorDisplay  string                 `json:"actor_display"`
	Action        string                 `json:"action"`
	Resource      string                 `json:"resource"`
	Status        string                 `json:"status"`
	CorrelationID string                 `json:"correlation_id"`
	Metadata      map[string]any         `json:"metadata,omitempty"`
	OccurredAt    time.Time              `json:"occurred_at"`
	_             struct{}               `json:"-"`
}

// List handles GET /audit-events. Optional query params:
//
//	actor=<exact>
//	action=<exact>           // e.g. request.approve / wrap.retrieve
//	resource=<exact>
//	correlation_id=<uuid>    // drills into one request's chain
//	since=<RFC3339>
//	until=<RFC3339>
//	limit=<int>              // capped at 1000; default 100
//
// All filters are optional. The repository defaults the limit when
// zero is passed.
func (h *Audit) List(c fiber.Ctx) error {
	q := storage.AuditQuery{}

	q.Actor = c.Query("actor")
	q.Action = c.Query("action")
	q.Resource = c.Query("resource")

	if raw := c.Query("correlation_id"); raw != "" {
		id, err := parseUUID(raw)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "correlation_id: "+err.Error())
		}
		q.CorrelationID = id
	}

	if raw := c.Query("since"); raw != "" {
		t, err := parseRFC3339(raw)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "since: "+err.Error())
		}
		q.Since = t
	}
	if raw := c.Query("until"); raw != "" {
		t, err := parseRFC3339(raw)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "until: "+err.Error())
		}
		q.Until = t
	}

	if raw := c.Query("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return fiber.NewError(fiber.StatusBadRequest, "limit must be a non-negative integer")
		}
		q.Limit = n
	}

	rows, err := h.repo.Query(c.Context(), q)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	// Per-request resolver cache. The same actor string typically
	// repeats across many rows (one operator's session generates dozens
	// of audit lines); a memoized lookup keeps the worst case to one
	// SELECT per distinct actor, not one per row.
	cache := make(map[string]string)
	out := make([]AuditEventBody, 0, len(rows))
	for _, r := range rows {
		out = append(out, AuditEventBody{
			ID:            r.ID.String(),
			Actor:         r.Actor,
			ActorDisplay:  h.resolveActorDisplay(c.Context(), r.Actor, cache),
			Action:        r.Action,
			Resource:      r.Resource,
			Status:        string(r.Status),
			CorrelationID: r.CorrelationID.String(),
			Metadata:      r.Metadata,
			OccurredAt:    r.OccurredAt,
		})
	}
	return c.JSON(out)
}

// resolveActorDisplay turns a raw `actor` string (e.g. "user:<uuid>",
// "agent:<uuid>", "system:oidc") into a human-readable label. Failures
// degrade to a short placeholder so the UI never has to render a raw
// UUID. Results are memoised per-request through the supplied cache.
//
// Hard rule: this function may NOT include the full UUID in the
// fallback — operators triaging a leaked screenshot still need to be
// able to identify the principal forensically, but only via the
// already-present `actor` field. The display is convenience text.
func (h *Audit) resolveActorDisplay(ctx context.Context, actor string, cache map[string]string) string {
	if actor == "" {
		return ""
	}
	if d, ok := cache[actor]; ok {
		return d
	}
	d := h.lookupActorDisplay(ctx, actor)
	cache[actor] = d
	return d
}

func (h *Audit) lookupActorDisplay(ctx context.Context, actor string) string {
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

	if strings.HasPrefix(actor, "user:") && h.users != nil {
		raw := strings.TrimPrefix(actor, "user:")
		id, err := uuid.Parse(raw)
		if err != nil {
			return shortFallback("user", raw)
		}
		u, err := h.users.Get(ctx, id)
		if err != nil || u == nil {
			return shortFallback("user", raw)
		}
		switch {
		case u.Email != "":
			return u.Email
		case u.DisplayName != "":
			return u.DisplayName
		default:
			return shortFallback("user", raw)
		}
	}

	if strings.HasPrefix(actor, "agent:") && h.agents != nil {
		raw := strings.TrimPrefix(actor, "agent:")
		id, err := uuid.Parse(raw)
		if err != nil {
			return shortFallback("agent", raw)
		}
		a, err := h.agents.Get(ctx, id)
		if err != nil || a == nil {
			return shortFallback("agent", raw)
		}
		if a.Name != "" {
			return "Agent " + a.Name
		}
		return shortFallback("agent", raw)
	}

	// Unknown shape — return the raw actor string as the display.
	// UI tooltip will show the same value; no information lost.
	return actor
}

// shortFallback renders a placeholder when the actor's UUID can't be
// resolved to a record (deleted user, agent revoked, malformed id).
// Truncates the UUID to 8 chars + ellipsis so the placeholder is
// recognisably short without leaking a useful identifier.
func shortFallback(kind, raw string) string {
	short := raw
	if len(short) > 8 {
		short = short[:8] + "…"
	}
	return "unknown " + kind + " (" + short + ")"
}

// --- tiny helpers ---------------------------------------------------

func parseUUID(raw string) (uuid.UUID, error) {
	dec, err := url.QueryUnescape(raw)
	if err != nil {
		dec = raw
	}
	if len(dec) == 32 {
		// Accept hex-only form without dashes.
		if _, err := hex.DecodeString(dec); err == nil {
			id, err := uuid.Parse(dec)
			if err == nil {
				return id, nil
			}
		}
	}
	id, err := uuid.Parse(dec)
	if err != nil {
		return uuid.Nil, errors.New("invalid uuid")
	}
	return id, nil
}

func parseRFC3339(raw string) (time.Time, error) {
	dec, err := url.QueryUnescape(raw)
	if err != nil {
		dec = raw
	}
	t, err := time.Parse(time.RFC3339, dec)
	if err != nil {
		return time.Time{}, errors.New("expected RFC3339 timestamp")
	}
	return t, nil
}
