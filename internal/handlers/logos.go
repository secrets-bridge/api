// Package handlers, logos.go: project and team logo endpoints.
//
//	GET    /projects/:id/logo   read scope of GET /projects/:id
//	PUT    /projects/:id/logo   team.edit; raw image/png or image/jpeg body
//	DELETE /projects/:id/logo   team.edit
//	GET    /teams/:id/logo      same visibility as GET /teams/:id
//	PUT    /teams/:id/logo      team.edit
//	DELETE /teams/:id/logo      team.edit
//
// The image is served with a long private cache (the version is in the
// URL the console builds from logo_version), nosniff and a CSP that
// forbids everything, so a stored file can only ever render as an image.
// The image is streamed from object storage; the routes, headers, ETag
// and logo_version are the same as when it lived in Postgres. With no
// object store configured, PUT and DELETE answer 503.
package handlers

import (
	"errors"
	"log/slog"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// logoResponse is the PUT answer.
type logoResponse struct {
	LogoVersion string `json:"logo_version"`
}

// mapLogoErr turns service and storage errors into HTTP errors. owner is
// "project" or "team" for the not-found message.
func mapLogoErr(err error, owner string) error {
	switch {
	case errors.Is(err, services.ErrLogoUnsupportedType):
		return fiber.NewError(fiber.StatusUnsupportedMediaType, "logo must be a PNG or JPEG image")
	case errors.Is(err, services.ErrLogoTooLarge):
		return fiber.NewError(fiber.StatusRequestEntityTooLarge, "logo must be 64 KiB or smaller")
	case errors.Is(err, services.ErrLogoDimensions):
		return fiber.NewError(fiber.StatusUnprocessableEntity, "logo must be between 16 and 512 pixels on each side")
	case errors.Is(err, services.ErrLogoUnreadable):
		return fiber.NewError(fiber.StatusUnprocessableEntity, "logo could not be read as an image")
	case errors.Is(err, services.ErrLogoEntityNotFound):
		return fiber.NewError(fiber.StatusNotFound, owner+" not found")
	case errors.Is(err, storage.ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "logo not found")
	case errors.Is(err, services.ErrLogoStorageUnavailable):
		return fiber.NewError(fiber.StatusServiceUnavailable, "logo storage is not configured")
	case errors.Is(err, services.ErrLogoStorageFailed):
		return fiber.NewError(fiber.StatusServiceUnavailable, "logo storage is unavailable")
	}
	slog.Error("logo request failed", "owner", owner, "err", err)
	return fiber.NewError(fiber.StatusInternalServerError, "internal error")
}

// sendLogo streams the stored PNG with headers that keep it an image.
// A matching If-None-Match answers 304 without reading the object.
func sendLogo(c fiber.Ctx, svc *services.LogoService, kind storage.LogoKind, l *storage.Logo) error {
	etag := `"` + l.SHA256 + `"`
	c.Set(fiber.HeaderCacheControl, "private, max-age=31536000, immutable")
	c.Set(fiber.HeaderETag, etag)
	c.Set(fiber.HeaderXContentTypeOptions, "nosniff")
	c.Set(fiber.HeaderContentSecurityPolicy, "default-src 'none'; sandbox")
	c.Set(fiber.HeaderContentDisposition, `inline; filename="logo.png"`)
	if c.Get(fiber.HeaderIfNoneMatch) == etag {
		return c.SendStatus(fiber.StatusNotModified)
	}
	body, size, err := svc.Open(c.Context(), kind, l)
	if err != nil {
		// The year-long cache is for the image. A 404 or 503 kept under
		// the versioned URL would outlive the outage it reports.
		c.Set(fiber.HeaderCacheControl, "no-store")
		c.Response().Header.Del(fiber.HeaderETag)
		return mapLogoErr(err, string(kind))
	}
	c.Set(fiber.HeaderContentType, "image/png")
	// fasthttp closes body once it has been written.
	return c.SendStream(body, int(size))
}

// logoActor is the session identity of the caller, required for writes.
func logoActor(c fiber.Ctx) (string, error) {
	actor, ok := auth.IdentityFromContext(c.Context())
	if !ok || actor == "" {
		return "", fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}
	return actor, nil
}

// putLogo and deleteLogo are shared by the project and team routes.
func putLogo(c fiber.Ctx, svc *services.LogoService, kind storage.LogoKind, id uuid.UUID) error {
	actor, err := logoActor(c)
	if err != nil {
		return err
	}
	version, err := svc.Put(c.Context(), kind, id, c.Get(fiber.HeaderContentType), c.Body(), actor)
	if err != nil {
		return mapLogoErr(err, string(kind))
	}
	return c.JSON(logoResponse{LogoVersion: version})
}

func deleteLogo(c fiber.Ctx, svc *services.LogoService, kind storage.LogoKind, id uuid.UUID) error {
	actor, err := logoActor(c)
	if err != nil {
		return err
	}
	if err := svc.Delete(c.Context(), kind, id, actor); err != nil {
		return mapLogoErr(err, string(kind))
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// logoVersionPtr returns the version for id from a Versions map, or nil.
func logoVersionPtr(versions map[uuid.UUID]string, id uuid.UUID) *string {
	if v, ok := versions[id]; ok {
		return &v
	}
	return nil
}

// --- projects ----------------------------------------------------------

// WithLogos wires the logo service: the project logo routes and
// logo_version on project bodies. Returns the handler for chaining.
func (h *Tenancy) WithLogos(svc *services.LogoService) *Tenancy {
	h.logos = svc
	return h
}

// projectLogoVersions looks up logo_version for the given projects. A
// handler without the logo service reports none.
func (h *Tenancy) projectLogoVersions(c fiber.Ctx, ids []uuid.UUID) (map[uuid.UUID]string, error) {
	if h.logos == nil {
		return map[uuid.UUID]string{}, nil
	}
	v, err := h.logos.Versions(c.Context(), storage.LogoKindProject, ids)
	if err != nil {
		return nil, mapLogoErr(err, "project")
	}
	return v, nil
}

func (h *Tenancy) projectLogoID(c fiber.Ctx) (uuid.UUID, error) {
	if h.logos == nil {
		return uuid.Nil, fiber.NewError(fiber.StatusNotFound, "logo not found")
	}
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return uuid.Nil, fiber.NewError(fiber.StatusBadRequest, "invalid UUID")
	}
	return id, nil
}

// GetProjectLogo handles GET /projects/:id/logo. Same read scope as
// GET /projects/:id: an out-of-scope project is a 404.
func (h *Tenancy) GetProjectLogo(c fiber.Ctx) error {
	id, err := h.projectLogoID(c)
	if err != nil {
		return err
	}
	access, scoped, err := h.projectScope(c)
	if err != nil {
		return err
	}
	if scoped && !access.Covers(id) {
		return fiber.NewError(fiber.StatusNotFound, "project not found")
	}
	l, err := h.logos.Get(c.Context(), storage.LogoKindProject, id)
	if err != nil {
		return mapLogoErr(err, "project")
	}
	return sendLogo(c, h.logos, storage.LogoKindProject, l)
}

// PutProjectLogo handles PUT /projects/:id/logo.
func (h *Tenancy) PutProjectLogo(c fiber.Ctx) error {
	id, err := h.projectLogoID(c)
	if err != nil {
		return err
	}
	return putLogo(c, h.logos, storage.LogoKindProject, id)
}

// DeleteProjectLogo handles DELETE /projects/:id/logo.
func (h *Tenancy) DeleteProjectLogo(c fiber.Ctx) error {
	id, err := h.projectLogoID(c)
	if err != nil {
		return err
	}
	return deleteLogo(c, h.logos, storage.LogoKindProject, id)
}

// --- teams -------------------------------------------------------------

// WithLogos wires the logo service: the team logo routes and
// logo_version on team bodies. Returns the handler for chaining.
func (h *Teams) WithLogos(svc *services.LogoService) *Teams {
	h.logos = svc
	return h
}

func (h *Teams) teamLogoVersions(c fiber.Ctx, ids []uuid.UUID) (map[uuid.UUID]string, error) {
	if h.logos == nil {
		return map[uuid.UUID]string{}, nil
	}
	v, err := h.logos.Versions(c.Context(), storage.LogoKindTeam, ids)
	if err != nil {
		return nil, mapLogoErr(err, "team")
	}
	return v, nil
}

// teamBodyWithLogo renders one team with its logo_version.
func (h *Teams) teamBodyWithLogo(c fiber.Ctx, t *storage.Team) (teamBody, error) {
	b := teamToBody(t)
	versions, err := h.teamLogoVersions(c, []uuid.UUID{t.ID})
	if err != nil {
		return b, err
	}
	b.LogoVersion = logoVersionPtr(versions, t.ID)
	return b, nil
}

func (h *Teams) teamLogoID(c fiber.Ctx) (uuid.UUID, error) {
	if h.logos == nil {
		return uuid.Nil, fiber.NewError(fiber.StatusNotFound, "logo not found")
	}
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return uuid.Nil, fiber.NewError(fiber.StatusBadRequest, "invalid id")
	}
	return id, nil
}

// GetTeamLogo handles GET /teams/:id/logo. Visible to the same callers
// as GET /teams/:id.
func (h *Teams) GetTeamLogo(c fiber.Ctx) error {
	id, err := h.teamLogoID(c)
	if err != nil {
		return err
	}
	l, err := h.logos.Get(c.Context(), storage.LogoKindTeam, id)
	if err != nil {
		return mapLogoErr(err, "team")
	}
	return sendLogo(c, h.logos, storage.LogoKindTeam, l)
}

// PutTeamLogo handles PUT /teams/:id/logo.
func (h *Teams) PutTeamLogo(c fiber.Ctx) error {
	id, err := h.teamLogoID(c)
	if err != nil {
		return err
	}
	return putLogo(c, h.logos, storage.LogoKindTeam, id)
}

// DeleteTeamLogo handles DELETE /teams/:id/logo.
func (h *Teams) DeleteTeamLogo(c fiber.Ctx) error {
	id, err := h.teamLogoID(c)
	if err != nil {
		return err
	}
	return deleteLogo(c, h.logos, storage.LogoKindTeam, id)
}
