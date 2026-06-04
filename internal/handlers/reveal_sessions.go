// Package handlers — reveal_sessions.go: HTTP layer for Slice M2.
//
// Endpoints mounted by main on /api/v1:
//
//	POST   /reveal-sessions             open a bulk reveal session for an approved/executed read request
//	GET    /reveal-sessions/me/active   list the caller's active sessions
//	POST   /reveal-sessions/:id/expire  end a session ahead of TTL (Hide Now / unmount)
//
// Responses NEVER carry secret values — the SPA picks each plaintext
// up via the existing single-shot retrieval endpoint
// (GET /requests/:id/wraps/:wrap_id). Open returns wrap_ids + key
// names; expire returns 204.
package handlers

import (
	"errors"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// RevealSessions is the HTTP layer over RevealSessionService.
type RevealSessions struct {
	svc *services.RevealSessionService
}

// NewRevealSessions binds the handler to the service.
func NewRevealSessions(svc *services.RevealSessionService) *RevealSessions {
	return &RevealSessions{svc: svc}
}

// OpenRevealSessionBody is the JSON the SPA POSTs to open a session.
type OpenRevealSessionBody struct {
	AccessRequestID string `json:"access_request_id"`
}

// RevealSessionResponseBody is what the SPA gets back from Open. NO
// envelopes, NO plaintext — the SPA loops over Wraps and calls the
// existing per-wrap retrieve endpoint, which is rate-limited + MFA-gated.
type RevealSessionResponseBody struct {
	SessionID       string             `json:"session_id"`
	AccessRequestID string             `json:"access_request_id"`
	EnvironmentID   string             `json:"environment_id"`
	ProjectID       string             `json:"project_id"`
	TTLSeconds      int                `json:"ttl_seconds"`
	OpenedAt        string             `json:"opened_at"`
	ExpiresAt       string             `json:"expires_at"`
	Wraps           []WrapHandleBody   `json:"wraps"`
}

// WrapHandleBody is a per-wrap value-free row.
type WrapHandleBody struct {
	WrapID  string `json:"wrap_id"`
	KeyName string `json:"key_name,omitempty"`
}

// RevealSessionSummaryBody is the row shape returned by ListActive.
type RevealSessionSummaryBody struct {
	SessionID       string `json:"session_id"`
	AccessRequestID string `json:"access_request_id,omitempty"`
	EnvironmentID   string `json:"environment_id"`
	ProjectID       string `json:"project_id"`
	TTLSeconds      int    `json:"ttl_seconds"`
	OpenedAt        string `json:"opened_at"`
	ExpiresAt       string `json:"expires_at"`
	WrapCount       int    `json:"wrap_count"`
}

// ExpireRevealSessionBody is the JSON the SPA POSTs to end a session.
type ExpireRevealSessionBody struct {
	Reason string `json:"reason"`
}

// Open handles POST /reveal-sessions.
func (h *RevealSessions) Open(c fiber.Ctx) error {
	userID, ok := auth.IdentityFromContext(c.Context())
	if !ok {
		return fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}

	var body OpenRevealSessionBody
	if err := c.Bind().Body(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if body.AccessRequestID == "" {
		return fiber.NewError(fiber.StatusBadRequest, "access_request_id is required")
	}
	reqID, err := uuid.Parse(body.AccessRequestID)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "access_request_id must be a UUID")
	}

	resp, err := h.svc.Open(c.Context(), services.OpenInput{
		UserID:    userID,
		RequestID: reqID,
	})
	if err != nil {
		return revealSessionErr(err)
	}

	wraps := make([]WrapHandleBody, len(resp.Wraps))
	for i, w := range resp.Wraps {
		wraps[i] = WrapHandleBody{WrapID: w.WrapID.String(), KeyName: w.KeyName}
	}

	accessReqID := ""
	if resp.Session.AccessRequestID != nil {
		accessReqID = resp.Session.AccessRequestID.String()
	}

	return c.Status(fiber.StatusCreated).JSON(RevealSessionResponseBody{
		SessionID:       resp.Session.ID.String(),
		AccessRequestID: accessReqID,
		EnvironmentID:   resp.Session.EnvironmentID.String(),
		ProjectID:       resp.Session.ProjectID.String(),
		TTLSeconds:      resp.Session.TTLSeconds,
		OpenedAt:        resp.Session.OpenedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
		ExpiresAt:       resp.Session.ExpiresAt.UTC().Format("2006-01-02T15:04:05.000Z"),
		Wraps:           wraps,
	})
}

// ListActive handles GET /reveal-sessions/me/active.
func (h *RevealSessions) ListActive(c fiber.Ctx) error {
	userID, ok := auth.IdentityFromContext(c.Context())
	if !ok {
		return fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}

	sessions, err := h.svc.ListActiveForUser(c.Context(), userID)
	if err != nil {
		return revealSessionErr(err)
	}

	out := make([]RevealSessionSummaryBody, 0, len(sessions))
	for _, s := range sessions {
		accessReqID := ""
		if s.AccessRequestID != nil {
			accessReqID = s.AccessRequestID.String()
		}
		out = append(out, RevealSessionSummaryBody{
			SessionID:       s.ID.String(),
			AccessRequestID: accessReqID,
			EnvironmentID:   s.EnvironmentID.String(),
			ProjectID:       s.ProjectID.String(),
			TTLSeconds:      s.TTLSeconds,
			OpenedAt:        s.OpenedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
			ExpiresAt:       s.ExpiresAt.UTC().Format("2006-01-02T15:04:05.000Z"),
			WrapCount:       len(s.WrapIDs),
		})
	}
	return c.Status(fiber.StatusOK).JSON(out)
}

// Expire handles POST /reveal-sessions/:id/expire.
func (h *RevealSessions) Expire(c fiber.Ctx) error {
	userID, ok := auth.IdentityFromContext(c.Context())
	if !ok {
		return fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}

	idRaw := c.Params("id")
	id, err := uuid.Parse(idRaw)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "id must be a UUID")
	}

	var body ExpireRevealSessionBody
	if err := c.Bind().Body(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	reason, err := parseExpireReason(body.Reason)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}

	if err := h.svc.MarkExpired(c.Context(), id, userID, reason); err != nil {
		return revealSessionErr(err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// parseExpireReason maps the wire string to the storage enum. Only
// user-initiated reasons are accepted at the handler — 'ttl' belongs
// to the worker sweeper (M3) and cannot be claimed by a SPA caller.
func parseExpireReason(raw string) (storage.RevealSessionExpiredReason, error) {
	switch storage.RevealSessionExpiredReason(raw) {
	case storage.RevealSessionExpiredUserHide:
		return storage.RevealSessionExpiredUserHide, nil
	case storage.RevealSessionExpiredUnmount:
		return storage.RevealSessionExpiredUnmount, nil
	default:
		return "", errors.New("reason must be 'user_hide' or 'unmount'")
	}
}

func revealSessionErr(err error) error {
	switch {
	case errors.Is(err, services.ErrInvalidInput):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	case errors.Is(err, storage.ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "reveal session or request not found")
	case errors.Is(err, services.ErrNotRequestOwner), errors.Is(err, services.ErrNotSessionOwner):
		return fiber.NewError(fiber.StatusForbidden, "caller does not own this resource")
	case errors.Is(err, services.ErrWrongRequest):
		return fiber.NewError(fiber.StatusNotFound, "request is not a read request")
	case errors.Is(err, services.ErrRequestNotApproved):
		return fiber.NewError(fiber.StatusConflict, "request not retrievable in current state")
	case errors.Is(err, services.ErrAllWrapsConsumed):
		return fiber.NewError(fiber.StatusGone, "all wraps already consumed")
	case errors.Is(err, services.ErrRevealSessionEnvMissing):
		return fiber.NewError(fiber.StatusConflict, "request has no environment binding")
	default:
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
}
