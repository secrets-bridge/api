// Package handlers — project_secrets.go: admin CRUD over the
// project_secrets join table. Binds discovered catalog rows to
// projects with per-binding allowed_keys + allowed_ops, so the
// catalog filter (Slice B of api#43) and the submit-time
// authorisation check (Slice C) can join through these rows.
//
// Endpoints (admin-only, under /api/v1):
//
//	POST   /projects/:id/secrets               bind a secret to a project
//	GET    /projects/:id/secrets               list bindings (with secret detail)
//	PUT    /projects/:id/secrets/:secret_id    update allowed_keys / allowed_ops / environment_id
//	DELETE /projects/:id/secrets/:secret_id    unbind
//
// Design notes:
//
//   - environment_id scopes the binding to one environment of the
//     project. The column and the storage struct carried it from
//     Slice L3 onward, but no HTTP path ever set it, so the only rows
//     that had one came from the 0025 label-bridge backfill —
//     operators could not create an env-scoped binding through the
//     product. Both write paths now accept it. Omitting the field
//     preserves the previous behaviour exactly: nil on create, and
//     untouched on update, so a keys-only edit cannot detach a
//     binding from its environment.
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
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/pkg/storage"
)

// ProjectSecrets is the HTTP layer over the project_secrets repository.
type ProjectSecrets struct {
	bindings     storage.ProjectSecretRepository
	projects     storage.ProjectRepository
	secrets      storage.SecretRepository
	environments storage.EnvironmentRepository
	resolver     auth.Resolver
	teamScope    auth.TeamScopeResolver
	audit        storage.AuditEventRepository
}

// NewProjectSecrets wires the handler. The environment repository is
// needed to prove a supplied environment_id belongs to the project in
// the URL — the FK alone cannot catch a cross-project reference.
func NewProjectSecrets(
	b storage.ProjectSecretRepository,
	p storage.ProjectRepository,
	s storage.SecretRepository,
	e storage.EnvironmentRepository,
) *ProjectSecrets {
	return &ProjectSecrets{bindings: b, projects: p, secrets: s, environments: e}
}

// WithScope wires the read-path tenancy filter so GET /projects/:id/secrets
// (which exposes binding metadata: allowed_keys, allowed_ops, secret
// refs, labels) is restricted to callers whose grants cover the project.
// An out-of-scope project returns 404. When the resolver is nil the
// handler stays in legacy allow-all mode. Returns the handler for
// chaining.
func (h *ProjectSecrets) WithScope(r auth.Resolver, tr auth.TeamScopeResolver) *ProjectSecrets {
	h.resolver = r
	h.teamScope = tr
	return h
}

// WithAudit wires audit emission for Bind / Update / Unbind (API-N-05).
// These rows are what the request tenancy gate and the reveal allowlists
// read, so every change is recorded with the session actor. Returns the
// handler for chaining.
func (h *ProjectSecrets) WithAudit(a storage.AuditEventRepository) *ProjectSecrets {
	h.audit = a
	return h
}

// bindingAuditMeta is the ids-and-shape view of a binding for audit
// metadata. allowed_keys are key names from the allowlist, never values.
func bindingAuditMeta(b *storage.ProjectSecret) map[string]any {
	meta := map[string]any{
		"project_id":     b.ProjectID.String(),
		"secret_id":      b.SecretID.String(),
		"environment_id": uuidPtrMeta(b.EnvironmentID),
		"allowed_ops":    nonNilStrings(b.AllowedOps),
		"all_keys":       b.AllowedKeys == nil,
	}
	if b.AllowedKeys != nil {
		meta["allowed_keys"] = b.AllowedKeys
	}
	return meta
}

// authorizeProjectRead returns 404 when the caller's grants don't cover
// the project (never 403 — existence stays hidden). No-op when scoping
// isn't wired.
func (h *ProjectSecrets) authorizeProjectRead(c fiber.Ctx, projectID uuid.UUID) error {
	if h.resolver == nil {
		return nil
	}
	userID, ok := auth.IdentityFromContext(c.Context())
	if !ok {
		return fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}
	access, err := auth.ReadableProjectAccess(c.Context(), userID, h.resolver, h.teamScope)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	if !access.Covers(projectID) {
		return fiber.NewError(fiber.StatusNotFound, "project not found")
	}
	return nil
}

// authorizeProjectWrite gates the binding WRITE surfaces (Bind / Update /
// Unbind). Those were reachable by any authenticated user (API-04): the
// binding table is exactly what checkTenancy and the reveal allowlists
// read, so an attacker who could bind arbitrary catalog secrets to a
// project could widen their own reach through the request/reveal flow.
//
// The caller must hold integration.bind at a scope covering the project
// (a global grant, a project_id grant, or a team_id grant expanded
// through the subtree). Not covered → 403 out_of_scope_project, matching
// the submit-time tenancy gate (checkTenancy) rather than the read
// path's existence-hiding 404 — a write authorization failure is not an
// existence probe. No-op when scoping isn't wired (legacy / unit tests).
func (h *ProjectSecrets) authorizeProjectWrite(c fiber.Ctx, projectID uuid.UUID) error {
	if h.resolver == nil {
		return nil
	}
	userID, ok := auth.IdentityFromContext(c.Context())
	if !ok {
		return fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}
	access, err := auth.EffectiveProjectAccess(c.Context(), userID, auth.PermIntegrationBind, h.resolver, h.teamScope)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	if !access.Covers(projectID) {
		return fiber.NewError(fiber.StatusForbidden, "out_of_scope_project")
	}
	return nil
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
	// EnvironmentID binds this row to one environment of the project.
	// Omitted / null means the binding is not environment-scoped —
	// the pre-existing shape, preserved for back-compat.
	EnvironmentID *string   `json:"environment_id"`
	CreatedAt     time.Time `json:"created_at,omitempty"`
	UpdatedAt     time.Time `json:"updated_at,omitempty"`
	// CreatedBy is response-only. On Bind it is set from the session and
	// a value sent in the body is ignored.
	CreatedBy string `json:"created_by,omitempty"`

	// Joined secret detail; populated on List + Get responses.
	Secret *secretSummary `json:"secret,omitempty"`
}

type secretSummary struct {
	ID           uuid.UUID         `json:"id"`
	ClusterName  string            `json:"cluster_name"`
	ProviderType string            `json:"provider_type"`
	SecretRef    string            `json:"secret_ref"`
	Status       string            `json:"status"`
	Labels       map[string]string `json:"labels,omitempty"`
}

// updateBindingBody is the PUT input. Every field is optional and an
// absent key keeps the stored value.
//
//   - allowed_keys: null = every key (the documented "all keys" value),
//     a list = that allowlist, absent = unchanged. An omitted key used
//     to be read as null, so any edit that left it out quietly widened
//     an allowlist to every key.
//   - allowed_ops: absent = unchanged; a present list must be non-empty.
//   - environment_id: absent = unchanged; detaching is not offered
//     (unbind and re-bind instead).
type updateBindingBody struct {
	AllowedKeys   optionalStrings `json:"allowed_keys"`
	AllowedOps    *[]string       `json:"allowed_ops,omitempty"`
	EnvironmentID *string         `json:"environment_id,omitempty"`
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
	if b.EnvironmentID != nil {
		s := b.EnvironmentID.String()
		resp.EnvironmentID = &s
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
//
//	{
//	  "secret_id":    "<uuid>",
//	  "allowed_keys": ["DB_HOST", "DB_PORT"]   // omit for "all keys"
//	  "allowed_ops":  ["read"]                  // defaults to ["read"]
//	}
func (h *ProjectSecrets) Bind(c fiber.Ctx) error {
	projectID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid project id")
	}
	if err := h.authorizeProjectWrite(c, projectID); err != nil {
		return err
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
	if err := validateAllowedOps(ops); err != nil {
		return err
	}

	var allowedKeys []string
	if body.AllowedKeys != nil {
		allowedKeys = *body.AllowedKeys
		if len(allowedKeys) == 0 {
			return fiber.NewError(fiber.StatusBadRequest,
				"allowed_keys must be omitted (all keys) or non-empty (allowlist)")
		}
	}

	envID, err := h.resolveEnvironment(c, projectID, body.EnvironmentID)
	if err != nil {
		return err
	}

	binding := &storage.ProjectSecret{
		ProjectID:     projectID,
		SecretID:      body.SecretID,
		EnvironmentID: envID,
		AllowedKeys:   allowedKeys,
		AllowedOps:    ops,
		// Provenance is the session identity; a created_by in the body
		// is ignored (API-N-05).
		CreatedBy: sessionIdentity(c),
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
	auditWrite(c, h.audit, "project_secret.bind", projectSecretResource(projectID, binding.SecretID), bindingAuditMeta(binding))

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
	if err := h.authorizeProjectRead(c, projectID); err != nil {
		return err
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
	if err := h.authorizeProjectWrite(c, projectID); err != nil {
		return err
	}

	var body updateBindingBody
	if err := json.Unmarshal(c.Body(), &body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}

	current, err := h.bindings.Get(c.Context(), projectID, secretID)
	if err != nil {
		return mapProjectSecretErr(err, "binding not found")
	}

	ops := current.AllowedOps
	if body.AllowedOps != nil {
		ops = *body.AllowedOps
		if len(ops) == 0 {
			// The schema CHECK refuses ARRAY[]::text[] anyway.
			return fiber.NewError(fiber.StatusBadRequest, "allowed_ops must be non-empty")
		}
		if err := validateAllowedOps(ops); err != nil {
			return err
		}
	}

	allowedKeys := current.AllowedKeys
	if body.AllowedKeys.Set {
		allowedKeys = body.AllowedKeys.Value
		if allowedKeys != nil && len(allowedKeys) == 0 {
			return fiber.NewError(fiber.StatusBadRequest,
				"allowed_keys must be null (all keys) or non-empty (allowlist)")
		}
	}

	envID, err := h.resolveEnvironment(c, projectID, body.EnvironmentID)
	if err != nil {
		return err
	}

	if err := h.bindings.Update(c.Context(), projectID, secretID, allowedKeys, ops, envID); err != nil {
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
	auditWrite(c, h.audit, "project_secret.update", projectSecretResource(projectID, secretID), bindingAuditMeta(binding))
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
	if err := h.authorizeProjectWrite(c, projectID); err != nil {
		return err
	}
	// Snapshot before the delete so the audit records what access went.
	meta := map[string]any{"project_id": projectID.String(), "secret_id": secretID.String()}
	if existing, err := h.bindings.Get(c.Context(), projectID, secretID); err == nil {
		meta = bindingAuditMeta(existing)
	}
	if err := h.bindings.Unbind(c.Context(), projectID, secretID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "binding not found")
		}
		return fiber.NewError(fiber.StatusInternalServerError, "unbind failed")
	}
	auditWrite(c, h.audit, "project_secret.unbind", projectSecretResource(projectID, secretID), meta)
	return c.SendStatus(fiber.StatusNoContent)
}

func projectSecretResource(projectID, secretID uuid.UUID) string {
	return "project_secret:" + projectID.String() + "/" + secretID.String()
}

// sessionIdentity is the raw authenticated identity ("" when none), the
// form the sibling project_provider_connections.created_by column uses.
func sessionIdentity(c fiber.Ctx) string {
	id, _ := auth.IdentityFromContext(c.Context())
	return id
}

// --- helpers --------------------------------------------------------

func mapProjectSecretErr(err error, msg string) error {
	if errors.Is(err, storage.ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, msg)
	}
	return fiber.NewError(fiber.StatusInternalServerError, msg)
}

// validateAllowedOps refuses any operation outside the set the
// schema CHECK permits. Postgres rejects them anyway, but as a
// constraint violation that the repository surfaces as an opaque
// error and the handler maps to 500 — a client-supplied bad enum is
// a 400, and the caller deserves to be told which value was wrong.
func validateAllowedOps(ops []string) error {
	for _, op := range ops {
		switch op {
		case storage.OpRead, storage.OpPatch, storage.OpDiscover:
		default:
			return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf(
				"allowed_ops contains unknown operation %q (valid: %s, %s, %s)",
				op, storage.OpRead, storage.OpPatch, storage.OpDiscover))
		}
	}
	return nil
}

// resolveEnvironment turns the wire-level environment_id into a
// validated UUID scoped to projectID. Returns (nil, nil) when the
// caller omitted the field, which both write paths read as "leave the
// stored value alone".
//
// The project check is the load-bearing part: environments.id carries
// a foreign key, so a bogus UUID is caught by the database, but an
// environment belonging to a DIFFERENT project is a perfectly valid FK
// target. Without this check an operator could bind a secret to
// another project's environment and silently widen access.
func (h *ProjectSecrets) resolveEnvironment(c fiber.Ctx, projectID uuid.UUID, raw *string) (*uuid.UUID, error) {
	if raw == nil || *raw == "" {
		return nil, nil
	}
	envID, err := uuid.Parse(*raw)
	if err != nil {
		return nil, fiber.NewError(fiber.StatusBadRequest, "invalid environment_id")
	}
	env, err := h.environments.Get(c.Context(), envID)
	if err != nil {
		return nil, mapProjectSecretErr(err, "environment not found")
	}
	if env.ProjectID != projectID {
		return nil, fiber.NewError(fiber.StatusBadRequest,
			"environment_id does not belong to this project")
	}
	return &envID, nil
}
