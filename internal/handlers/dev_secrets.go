// Package handlers — dev_secrets.go: dev-facing endpoints rooted at
// /projects/:id/environments/:env_id.
//
// Three endpoints land here in Slice L4:
//
//   GET    /projects/:id/environments/:env_id/secrets
//          List key NAMES bound to the (project, env) pair via the
//          project_secrets join. No values — that's Slice M's reveal
//          page concern.
//
//   POST   /projects/:id/environments/:env_id/direct-reveal
//          Submit an auto-executed read request when the matched
//          policy says direct_reveal_allowed=true AND env.kind is
//          non_prod. PROD is rejected server-side BEFORE the policy
//          lookup so an operator-misconfigured rule cannot reach
//          this path. Permission `secret.reveal.direct` gates the
//          route at the middleware layer.
//
//   POST   /projects/:id/environments/:env_id/request
//          Submit a normal read request pre-populated with project
//          + env. Same lifecycle as POST /requests/read; the URL
//          shape matches the dev-facing sidebar tree.
//
// All three endpoints assume the caller is already authenticated.
// Team-membership scoping lands when api#26 (P0 auth) merges; for
// now the routes ride the existing stub middleware. The shape +
// behaviour above is what the SPA (Slice L5) consumes today.
package handlers

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// DevSecrets wires the per-env dev endpoints. Construction takes
// every repository + service the three endpoints need. All
// parameters are required; passing nil for any of them will panic
// on the first request.
type DevSecrets struct {
	projects        storage.ProjectRepository
	environments    storage.EnvironmentRepository
	projectSecrets  storage.ProjectSecretRepository
	secrets         storage.SecretRepository
	requests        *services.RequestService
	readScope       projectReadScope

	// Optional caller-scope check for SubmitEnvRequest (step 1 of the
	// POST /requests tenancy gate). Wire via WithScope; nil skips it.
	resolver  auth.Resolver
	teamScope auth.TeamScopeResolver
}

// NewDevSecrets binds the handler.
func NewDevSecrets(
	projects storage.ProjectRepository,
	environments storage.EnvironmentRepository,
	projectSecrets storage.ProjectSecretRepository,
	secrets storage.SecretRepository,
	requests *services.RequestService,
) *DevSecrets {
	return &DevSecrets{
		projects:       projects,
		environments:   environments,
		projectSecrets: projectSecrets,
		secrets:        secrets,
		requests:       requests,
	}
}

// WithReadScope wires the read-path project gate for ListEnvSecrets
// (API-N-04): a caller whose secret.list / secret.request grants don't
// cover the project gets 404. Returns the handler for chaining.
func (h *DevSecrets) WithReadScope(r auth.Resolver, tr auth.TeamScopeResolver) *DevSecrets {
	h.readScope = newProjectReadScope(r, tr)
	return h
}

// WithScope wires the caller-scope check SubmitEnvRequest runs before
// the service-level binding gate: the caller's secret.request grant must
// cover the URL project (the same step 1 POST /requests/read runs in
// checkTenancy). Team-scoped grants expand through tr when set.
func (h *DevSecrets) WithScope(r auth.Resolver, tr auth.TeamScopeResolver) *DevSecrets {
	h.resolver = r
	h.teamScope = tr
	return h
}

// EnvSecretKey is the value-free shape returned by ListEnvSecrets.
type EnvSecretKey struct {
	SecretID    string   `json:"secret_id"`
	SecretRef   string   `json:"secret_ref"`
	Provider    string   `json:"provider_type"`
	KeyName     string   `json:"key_name"`
	AllowedOps  []string `json:"allowed_ops"`
}

// ListEnvSecrets handles GET /projects/:id/environments/:env_id/secrets.
//
// Lists the project_secrets bindings that govern a request in this
// environment (scoped to it, or whole-project) and expands the result
// into one row per allowed key. When a
// project_secrets row has `allowed_keys=NULL`, the call returns one
// row per key discovered on the secret (via secrets.labels if
// populated, otherwise the wire shape is `key_name=""` to signal
// "all keys allowed by binding, key list not yet discovered").
//
// VALUE FREE — no plaintext, no ciphertext. Only NAMES.
func (h *DevSecrets) ListEnvSecrets(c fiber.Ctx) error {
	projectID, envID, err := parseProjectAndEnv(c)
	if err != nil {
		return err
	}
	// Project visibility first, before the env lookup, so an out-of-scope
	// caller learns nothing about the project or its environments.
	covered, err := h.readScope.covers(c, projectID)
	if err != nil {
		return err
	}
	if !covered {
		return fiber.NewError(fiber.StatusNotFound, "project not found")
	}

	// Resolve the env so 404 short-circuits before any join work.
	env, err := h.environments.Get(c.Context(), envID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "environment not found")
		}
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	if env.ProjectID != projectID {
		return fiber.NewError(fiber.StatusNotFound, "environment not in project")
	}

	bindings, err := h.projectSecrets.ListByProject(c.Context(), projectID)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	// Keep exactly the bindings the submit gate would accept for this
	// environment (services.GoverningBinding): one scoped to envID, or a
	// whole-project binding (NULL environment_id), which governs a request
	// in any environment of the project. A binding scoped to another
	// environment never applies. The same ref discovered on two clusters
	// can carry two bindings; only the governing one is listed, so the
	// list never offers a secret the gate would then refuse or route
	// through a different catalog row.
	type candidate struct {
		binding *storage.ProjectSecret
		secret  *storage.Secret
	}
	groups := map[string][]candidate{}
	var order []string
	for _, b := range bindings {
		if b.EnvironmentID != nil && *b.EnvironmentID != envID {
			continue
		}
		secret, err := h.secrets.Get(c.Context(), b.SecretID)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				continue // binding outlived its secret; benign
			}
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}
		key := secret.ProviderType + "\x00" + secret.SecretRef
		if _, seen := groups[key]; !seen {
			order = append(order, key)
		}
		groups[key] = append(groups[key], candidate{binding: b, secret: secret})
	}

	out := make([]EnvSecretKey, 0, len(order))
	for _, key := range order {
		cands := groups[key]
		bs := make([]*storage.ProjectSecret, len(cands))
		for i := range cands {
			bs[i] = cands[i].binding
		}
		i := services.GoverningBinding(bs, &envID)
		if i < 0 {
			continue
		}
		b, secret := cands[i].binding, cands[i].secret
		ops := append([]string(nil), b.AllowedOps...)
		if len(b.AllowedKeys) == 0 {
			// Binding allows every key — emit one row marker.
			out = append(out, EnvSecretKey{
				SecretID:   secret.ID.String(),
				SecretRef:  secret.SecretRef,
				Provider:   secret.ProviderType,
				KeyName:    "",
				AllowedOps: ops,
			})
			continue
		}
		for _, k := range b.AllowedKeys {
			out = append(out, EnvSecretKey{
				SecretID:   secret.ID.String(),
				SecretRef:  secret.SecretRef,
				Provider:   secret.ProviderType,
				KeyName:    k,
				AllowedOps: ops,
			})
		}
	}
	return c.JSON(out)
}

// DevRequestBody is the input shape for both SubmitEnvRequest and
// DirectReveal. The URL provides project + env_id; the body carries
// provider type + secret ref + justification + (optional) target keys.
//
// A `target_provider_config` field in the body is ignored (API-S-04):
// the agent honours kvMount/kvPrefix from a job payload, so the job's
// provider config is derived from the bound catalog row instead.
type DevRequestBody struct {
	TargetProviderType string   `json:"target_provider_type"`
	TargetSecretRef    string   `json:"target_secret_ref"`
	TargetKeys         []string `json:"target_keys"`
	Justification      string   `json:"justification"`
}

// DevRequestResponse is the shape returned by SubmitEnvRequest +
// DirectReveal.
type DevRequestResponse struct {
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
	// DirectReveal is true when the response describes an
	// auto-executed direct-reveal request (status will be `approved`
	// when this is true). The SPA uses this to decide whether to
	// start polling for wraps immediately vs. show the approval queue.
	DirectReveal bool `json:"direct_reveal,omitempty"`
}

// SubmitEnvRequest handles POST /projects/:id/environments/:env_id/request.
// Submits a read request for the project + environment in the URL. The
// standard approval lifecycle applies — the request lands in `pending`.
//
// It runs the same tenancy gate as POST /requests/read (api#154): the
// caller's secret.request must cover the project, the secret must be
// bound for read to this project in this environment, and every key must
// be inside a restrictive allowlist (RequestService.SubmitEnvRead).
// Refusals use the same stable 403 bodies as checkTenancy.
func (h *DevSecrets) SubmitEnvRequest(c fiber.Ctx) error {
	projectID, envID, err := parseProjectAndEnv(c)
	if err != nil {
		return err
	}
	env, err := h.loadEnv(c, projectID, envID)
	if err != nil {
		return err
	}

	requesterID, ok := auth.IdentityFromContext(c.Context())
	if !ok {
		return fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}

	var body DevRequestBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if body.TargetProviderType == "" || body.TargetSecretRef == "" {
		return fiber.NewError(fiber.StatusBadRequest, "target_provider_type and target_secret_ref are required")
	}
	if strings.TrimSpace(body.Justification) == "" {
		return fiber.NewError(fiber.StatusBadRequest, "justification is required")
	}

	if h.resolver != nil {
		access, err := auth.EffectiveProjectAccess(c.Context(), requesterID, auth.PermSecretRequest, h.resolver, h.teamScope)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}
		if !access.Covers(projectID) {
			return fiber.NewError(fiber.StatusForbidden, "out_of_scope_project")
		}
	}

	req, err := h.requests.SubmitEnvRead(c.Context(), services.EnvReadInput{
		RequesterID:        requesterID,
		Environment:        env,
		TargetProviderType: body.TargetProviderType,
		TargetSecretRef:    body.TargetSecretRef,
		TargetKeys:         body.TargetKeys,
		Justification:      body.Justification,
	})
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidInput):
			return fiber.NewError(fiber.StatusBadRequest, err.Error())
		case errors.Is(err, services.ErrSecretNotBound):
			return fiber.NewError(fiber.StatusForbidden, "out_of_scope_project")
		case errors.Is(err, services.ErrBindingOpNotAllowed):
			return fiber.NewError(fiber.StatusForbidden, "out_of_scope_op")
		case errors.Is(err, services.ErrKeyNotAllowed):
			return fiber.NewError(fiber.StatusForbidden, "out_of_scope_key")
		default:
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}
	}
	return c.Status(fiber.StatusCreated).JSON(DevRequestResponse{
		RequestID: req.ID.String(),
		Status:    string(req.Status),
	})
}

// DirectReveal handles POST /projects/:id/environments/:env_id/direct-reveal.
// Submits an auto-executed read request when the matched policy +
// non-prod env classification both green-light the path. PROD env
// hits 403 BEFORE the policy lookup.
//
// Route is gated by `auth.Require(PermSecretRevealDirect)` in main —
// callers without the perm never reach this handler.
func (h *DevSecrets) DirectReveal(c fiber.Ctx) error {
	projectID, envID, err := parseProjectAndEnv(c)
	if err != nil {
		return err
	}
	env, err := h.loadEnv(c, projectID, envID)
	if err != nil {
		return err
	}

	requesterID, ok := auth.IdentityFromContext(c.Context())
	if !ok {
		return fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}

	var body DevRequestBody
	if err := c.Bind().JSON(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if body.TargetProviderType == "" || body.TargetSecretRef == "" {
		return fiber.NewError(fiber.StatusBadRequest, "target_provider_type and target_secret_ref are required")
	}
	if strings.TrimSpace(body.Justification) == "" {
		return fiber.NewError(fiber.StatusBadRequest, "justification is required")
	}

	req, err := h.requests.SubmitDirectReveal(c.Context(), services.DirectRevealInput{
		RequesterID:        requesterID,
		Environment:        env,
		TargetProviderType: body.TargetProviderType,
		TargetSecretRef:    body.TargetSecretRef,
		TargetKeys:         body.TargetKeys,
		Justification:      body.Justification,
	})
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidInput):
			return fiber.NewError(fiber.StatusBadRequest, err.Error())
		case errors.Is(err, services.ErrDirectRevealOnProd):
			return fiber.NewError(fiber.StatusForbidden, "direct reveal is not permitted on prod environments")
		case errors.Is(err, services.ErrDirectRevealNotAllowed):
			return fiber.NewError(fiber.StatusForbidden, "matched policy does not permit direct reveal")
		case errors.Is(err, services.ErrSecretNotBound), errors.Is(err, services.ErrBindingOpNotAllowed):
			// One generic message for "not bound", "bound to another
			// environment" and "bound without read"; the audit row
			// (secret.reveal.direct.refused_binding) has the reason.
			return fiber.NewError(fiber.StatusForbidden, "secret is not available for reveal in this environment")
		case errors.Is(err, services.ErrKeyNotAllowed):
			return fiber.NewError(fiber.StatusForbidden, "requested key is not permitted by the binding allowlist")
		default:
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}
	}
	return c.Status(fiber.StatusCreated).JSON(DevRequestResponse{
		RequestID:    req.ID.String(),
		Status:       string(req.Status),
		DirectReveal: true,
	})
}

// --- helpers ---------------------------------------------------------

func parseProjectAndEnv(c fiber.Ctx) (uuid.UUID, uuid.UUID, error) {
	projectID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return uuid.Nil, uuid.Nil, fiber.NewError(fiber.StatusBadRequest, "invalid project id")
	}
	envID, err := uuid.Parse(c.Params("env_id"))
	if err != nil {
		return uuid.Nil, uuid.Nil, fiber.NewError(fiber.StatusBadRequest, "invalid environment id")
	}
	return projectID, envID, nil
}

func (h *DevSecrets) loadEnv(c fiber.Ctx, projectID, envID uuid.UUID) (*storage.Environment, error) {
	env, err := h.environments.Get(c.Context(), envID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fiber.NewError(fiber.StatusNotFound, "environment not found")
		}
		return nil, fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}
	if env.ProjectID != projectID {
		return nil, fiber.NewError(fiber.StatusNotFound, "environment not in project")
	}
	return env, nil
}
