// Package handlers — project_secrets.go: admin CRUD over the
// project_secrets join table. Binds discovered catalog rows to
// projects with per-binding allowed_keys + allowed_ops, so the
// catalog filter (Slice B of api#43) and the submit-time
// authorisation check (Slice C) can join through these rows.
//
// Endpoints (admin-only, under /api/v1):
//
//   POST   /projects/:id/secrets               bind a secret to a project
//   GET    /projects/:id/secrets               list bindings (with secret detail)
//   PUT    /projects/:id/secrets/:secret_id    update allowed_keys / allowed_ops
//   DELETE /projects/:id/secrets/:secret_id    unbind
//
// Design notes:
//
//   - allowed_keys: nil means "every key the secret exposes is
//     allowed for this project". Non-nil = explicit allowlist. The
//     handler converts `null` / missing in JSON to nil and an empty
//     array to ErrEmptyAllowedKeys (refused — almost certainly a
//     typo for nil/missing).
//
//   - allowed_ops: defaults to ["read"] when missing. Defense in
//     depth — a binding accidentally created with no ops would be
//     useless; the schema CHECK also enforces subset {read,patch,
//     discover}.
//
//   - The bindings list returns the joined secret detail (ref,
//     provider_type, labels) so the UI doesn't have to do a second
//     fetch per row.
package handlers

import (
	"errors"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// ProjectSecrets is the HTTP layer over the project_secrets repository.
type ProjectSecrets struct {
	bindings storage.ProjectSecretRepository
	projects storage.ProjectRepository
	secrets  storage.SecretRepository
}

// NewProjectSecrets wires the handler.
func NewProjectSecrets(
	b storage.ProjectSecretRepository,
	p storage.ProjectRepository,
	s storage.SecretRepository,
) *ProjectSecrets {
	return &ProjectSecrets{bindings: b, projects: p, secrets: s}
}

// --- request / response shapes --------------------------------------

type bindingBody struct {
	ProjectID uuid.UUID `json:"project_id,omitempty"`
	SecretID  uuid.UUID `json:"secret_id"`
	// AllowedKeys is intentionally NOT omitempty: nil → JSON null
	// carries the "all keys allowed" semantic the field documents.
	// An absent JSON key forces every client to handle
	// undefined-vs-null ad-hoc; that gap caused ui#31 (TypeError on
	// `.map(undefined)` → blank /admin/projects).
	AllowedKeys *[]string `json:"allowed_keys"`
	AllowedOps  []string  `json:"allowed_ops,omitempty"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
	CreatedBy   string    `json:"created_by,omitempty"`

	// Joined secret detail; populated on List + Get responses.
	Secret *secretSummary `json:"secret,omitempty"`
}

type secretSummary struct {
	ID            uuid.UUID         `json:"id"`
	ClusterName   string            `json:"cluster_name"`
	ProviderType  string            `json:"provider_type"`
	SecretRef     string            `json:"secret_ref"`
	Status        string            `json:"status"`
	Labels        map[string]string `json:"labels,omitempty"`
}

type updateBindingBody struct {
	AllowedKeys *[]string `json:"allowed_keys,omitempty"`
	AllowedOps  []string  `json:"allowed_ops,omitempty"`
}

func bindingToBody(b *storage.ProjectSecret) bindingBody {
	resp := bindingBody{
		ProjectID:  b.ProjectID,
		SecretID:   b.SecretID,
		AllowedOps: b.AllowedOps,
		CreatedAt:  b.CreatedAt,
		UpdatedAt:  b.UpdatedAt,
		CreatedBy:  b.CreatedBy,
	}
	// Distinguish nil (all keys) from non-nil. The pointer trick
	// keeps `null` in the JSON when the binding allows everything.
	keys := b.AllowedKeys
	resp.AllowedKeys = &keys
	if keys == nil {
		resp.AllowedKeys = nil
	}
	return resp
}

func secretToSummary(s *storage.Secret) *secretSummary {
	labels := make(map[string]string, len(s.Labels))
	for k, v := range s.Labels {
		if str, ok := v.(string); ok {
			labels[k] = str
		}
	}
	return &secretSummary{
		ID:           s.ID,
		ClusterName:  s.ClusterName,
		ProviderType: s.ProviderType,
		SecretRef:    s.SecretRef,
		Status:       string(s.Status),
		Labels:       labels,
	}
}

// --- handlers --------------------------------------------------------

// Bind handles POST /projects/:id/secrets.
//
// Body:
//   {
//     "secret_id":    "<uuid>",
//     "allowed_keys": ["DB_HOST", "DB_PORT"]   // omit for "all keys"
//     "allowed_ops":  ["read"]                  // defaults to ["read"]
//   }
func (h *ProjectSecrets) Bind(c fiber.Ctx) error {
	projectID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid project id")
	}

	var body bindingBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if body.SecretID == uuid.Nil {
		return fiber.NewError(fiber.StatusBadRequest, "secret_id is required")
	}

	// Make sure the project + secret both exist; surface a clean 404
	// rather than letting the FK fire and leak driver text.
	if _, err := h.projects.Get(c.Context(), projectID); err != nil {
		return mapProjectSecretErr(err, "project not found")
	}
	if _, err := h.secrets.Get(c.Context(), body.SecretID); err != nil {
		return mapProjectSecretErr(err, "secret not found")
	}

	ops := body.AllowedOps
	if len(ops) == 0 {
		ops = []string{storage.OpRead}
	}

	var allowedKeys []string
	if body.AllowedKeys != nil {
		allowedKeys = *body.AllowedKeys
		if len(allowedKeys) == 0 {
			return fiber.NewError(fiber.StatusBadRequest,
				"allowed_keys must be omitted (all keys) or non-empty (allowlist)")
		}
	}

	binding := &storage.ProjectSecret{
		ProjectID:   projectID,
		SecretID:    body.SecretID,
		AllowedKeys: allowedKeys,
		AllowedOps:  ops,
		CreatedBy:   body.CreatedBy,
	}
	if err := h.bindings.Bind(c.Context(), binding); err != nil {
		switch {
		case errors.Is(err, storage.ErrAlreadyExists):
			return fiber.NewError(fiber.StatusConflict, "binding already exists")
		case errors.Is(err, storage.ErrEmptyAllowedKeys):
			return fiber.NewError(fiber.StatusBadRequest,
				"allowed_keys must be omitted (all keys) or non-empty (allowlist)")
		case errors.Is(err, storage.ErrEmptyAllowedOps):
			return fiber.NewError(fiber.StatusBadRequest, "allowed_ops must be non-empty")
		}
		return fiber.NewError(fiber.StatusInternalServerError, "bind failed")
	}

	resp := bindingToBody(binding)
	if sec, err := h.secrets.Get(c.Context(), binding.SecretID); err == nil {
		resp.Secret = secretToSummary(sec)
	}
	return c.Status(fiber.StatusCreated).JSON(resp)
}

// List handles GET /projects/:id/secrets.
func (h *ProjectSecrets) List(c fiber.Ctx) error {
	projectID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid project id")
	}
	if _, err := h.projects.Get(c.Context(), projectID); err != nil {
		return mapProjectSecretErr(err, "project not found")
	}

	bs, err := h.bindings.ListByProject(c.Context(), projectID)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "list failed")
	}

	out := make([]bindingBody, 0, len(bs))
	for _, b := range bs {
		body := bindingToBody(b)
		if sec, err := h.secrets.Get(c.Context(), b.SecretID); err == nil {
			body.Secret = secretToSummary(sec)
		}
		out = append(out, body)
	}
	return c.JSON(out)
}

// Update handles PUT /projects/:id/secrets/:secret_id.
func (h *ProjectSecrets) Update(c fiber.Ctx) error {
	projectID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid project id")
	}
	secretID, err := uuid.Parse(c.Params("secret_id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid secret id")
	}

	var body updateBindingBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}

	ops := body.AllowedOps
	if len(ops) == 0 {
		// PUT replaces — refuse silent "no ops" since the schema
		// CHECK refuses ARRAY[]::text[] anyway.
		return fiber.NewError(fiber.StatusBadRequest, "allowed_ops must be non-empty")
	}

	var allowedKeys []string
	if body.AllowedKeys != nil {
		allowedKeys = *body.AllowedKeys
		if len(allowedKeys) == 0 {
			return fiber.NewError(fiber.StatusBadRequest,
				"allowed_keys must be omitted (all keys) or non-empty (allowlist)")
		}
	}

	if err := h.bindings.Update(c.Context(), projectID, secretID, allowedKeys, ops); err != nil {
		switch {
		case errors.Is(err, storage.ErrNotFound):
			return fiber.NewError(fiber.StatusNotFound, "binding not found")
		case errors.Is(err, storage.ErrEmptyAllowedOps):
			return fiber.NewError(fiber.StatusBadRequest, "allowed_ops must be non-empty")
		}
		return fiber.NewError(fiber.StatusInternalServerError, "update failed")
	}

	binding, err := h.bindings.Get(c.Context(), projectID, secretID)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "post-update read failed")
	}
	resp := bindingToBody(binding)
	if sec, err := h.secrets.Get(c.Context(), secretID); err == nil {
		resp.Secret = secretToSummary(sec)
	}
	return c.JSON(resp)
}

// Unbind handles DELETE /projects/:id/secrets/:secret_id.
func (h *ProjectSecrets) Unbind(c fiber.Ctx) error {
	projectID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid project id")
	}
	secretID, err := uuid.Parse(c.Params("secret_id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid secret id")
	}
	if err := h.bindings.Unbind(c.Context(), projectID, secretID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "binding not found")
		}
		return fiber.NewError(fiber.StatusInternalServerError, "unbind failed")
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// --- helpers --------------------------------------------------------

func mapProjectSecretErr(err error, msg string) error {
	if errors.Is(err, storage.ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, msg)
	}
	return fiber.NewError(fiber.StatusInternalServerError, msg)
}
