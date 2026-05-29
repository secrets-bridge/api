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
	"encoding/hex"
	"errors"
	"net/url"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// Audit handles GET /api/v1/audit-events.
type Audit struct {
	repo storage.AuditEventRepository
}

// NewAudit binds the handler to the given repository.
func NewAudit(repo storage.AuditEventRepository) *Audit { return &Audit{repo: repo} }

// AuditEventBody is the JSON wire shape for one audit_events row.
//
// `metadata` is opaque jsonb. Service-layer Append calls have
// already stripped any field that could carry a secret value (CLAUDE
// hard rule), so re-exporting it is safe.
type AuditEventBody struct {
	ID            string                 `json:"id"`
	Actor         string                 `json:"actor"`
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

	out := make([]AuditEventBody, 0, len(rows))
	for _, r := range rows {
		out = append(out, AuditEventBody{
			ID:            r.ID.String(),
			Actor:         r.Actor,
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
