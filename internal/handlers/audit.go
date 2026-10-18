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
//
// What a reader sees: holders of role.edit, user_role.edit
// or team.edit at global scope see every event. Everyone else sees the
// events they caused, plus the whole trail of a request they can read
// (correlation_id=<request id>), approvers' votes included. The seeded
// developer role holds audit.read, so without this a global developer
// read every team's trail.

package handlers

import (
	"encoding/hex"
	"errors"
	"net/url"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/services/actordisplay"
	"github.com/secrets-bridge/api/pkg/storage"
)

// Audit handles GET /api/v1/audit-events.
type Audit struct {
	repo     storage.AuditEventRepository
	resolver *actordisplay.Resolver

	// Who sees what; see the package comment. Unset in tests that
	// don't wire it, and then every reader sees every event.
	grants   auth.Resolver
	requests requestReader
}

// requestReader answers "may the caller read this request", by the
// rule GET /requests/:id applies. Implemented by Requests.
type requestReader interface {
	CanRead(c fiber.Ctx, id uuid.UUID) (bool, error)
}

// auditSeeAll are the permissions that, held at global scope, show
// every actor's events. They match the console's Audit page, which
// lets these holders widen the actor filter.
var auditSeeAll = []auth.Permission{auth.PermRoleEdit, auth.PermUserRoleEdit, auth.PermTeamEdit}

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
	return &Audit{repo: repo, resolver: actordisplay.New(users, agents)}
}

// WithReaderScope limits what each reader sees (see the package
// comment): grants decides who sees everything, requests whose trails
// a reader may open.
func (h *Audit) WithReaderScope(grants auth.Resolver, requests requestReader) *Audit {
	h.grants = grants
	h.requests = requests
	return h
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
	ID            string         `json:"id"`
	Actor         string         `json:"actor"`
	ActorDisplay  string         `json:"actor_display"`
	Action        string         `json:"action"`
	Resource      string         `json:"resource"`
	Status        string         `json:"status"`
	CorrelationID string         `json:"correlation_id"`
	Metadata      map[string]any `json:"metadata,omitempty"`
	OccurredAt    time.Time      `json:"occurred_at"`
	_             struct{}       `json:"-"`
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
// zero is passed. A reader who may not see everything gets their own
// events only (an actor filter naming someone else returns nothing),
// unless correlation_id names a request they can read.
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

	own, err := h.ownEventsOnly(c, q.CorrelationID)
	if err != nil {
		return err
	}
	if own != "" {
		if q.Actor != "" && q.Actor != own {
			return c.JSON([]AuditEventBody{})
		}
		q.Actor = own
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
			ActorDisplay:  h.resolver.Display(c.Context(), r.Actor, cache),
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

// ownEventsOnly returns the caller's audit actor ("user:<id>") when the
// results must be limited to their own events, or "" when they may see
// every actor: they hold an auditSeeAll permission globally, or
// correlation is a request they can read.
func (h *Audit) ownEventsOnly(c fiber.Ctx, correlation uuid.UUID) (string, error) {
	if h.grants == nil {
		return "", nil
	}
	userID, ok := auth.IdentityFromContext(c.Context())
	if !ok {
		return "", fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}
	all, err := auth.HoldsAnyGlobal(c.Context(), h.grants, userID, auditSeeAll...)
	if err != nil {
		return "", fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	if all {
		return "", nil
	}
	if correlation != uuid.Nil && h.requests != nil {
		readable, err := h.requests.CanRead(c, correlation)
		if err != nil {
			return "", err
		}
		if readable {
			return "", nil
		}
	}
	return auth.AuditActor(c.Context()), nil
}

// Actor enrichment (resolveActorDisplay / lookupActorDisplay /
// shortFallback) moved to internal/services/actordisplay so
// PolicyHistoryService (R-follow-up #5 slice 1a, api#133) can reuse
// the same lookup + caching logic without duplicating ~80 lines.

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
