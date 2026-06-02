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
// Joins `project_secrets` ON (project_id, environment_id) and
// expands the result into one row per allowed key. When a
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

	out := make([]EnvSecretKey, 0, len(bindings))
	for _, b := range bindings {
		// Slice L3 made environment_id authoritative. A binding without
		// env_id (un-backfilled legacy row) is skipped — operators see
		// it in the admin UI and fix.
		if b.EnvironmentID == nil || *b.EnvironmentID != envID {
			continue
		}
		secret, err := h.secrets.Get(c.Context(), b.SecretID)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				continue // binding outlived its secret; benign
			}
			return fiber.NewError(fiber.StatusInternalServerError, err.Error())
		}
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
// provider details + justification + (optional) target keys.
type DevRequestBody struct {
	TargetProviderType   string         `json:"target_provider_type"`
	TargetProviderConfig map[string]any `json:"target_provider_config"`
	TargetSecretRef      string         `json:"target_secret_ref"`
	TargetKeys           []string       `json:"target_keys"`
	Justification        string         `json:"justification"`
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
// Wraps the existing RequestService.SubmitRead with project_id +
// env name resolved from the URL. The standard approval lifecycle
// applies — the request lands in `pending`.
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

	req, err := h.requests.SubmitRead(c.Context(), services.ReadInput{
		RequesterID:          requesterID,
		ProjectID:            projectID.String(),
		Environment:          env.Name,
		TargetProviderType:   body.TargetProviderType,
		TargetProviderConfig: body.TargetProviderConfig,
		TargetSecretRef:      body.TargetSecretRef,
		TargetKeys:           body.TargetKeys,
		Justification:        body.Justification,
	})
	if err != nil {
		if errors.Is(err, services.ErrInvalidInput) {
			return fiber.NewError(fiber.StatusBadRequest, err.Error())
		}
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
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
		RequesterID:          requesterID,
		Environment:          env,
		TargetProviderType:   body.TargetProviderType,
		TargetProviderConfig: body.TargetProviderConfig,
		TargetSecretRef:      body.TargetSecretRef,
		TargetKeys:           body.TargetKeys,
		Justification:        body.Justification,
	})
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidInput):
			return fiber.NewError(fiber.StatusBadRequest, err.Error())
		case errors.Is(err, services.ErrDirectRevealOnProd):
			return fiber.NewError(fiber.StatusForbidden, "direct reveal is not permitted on prod environments")
		case errors.Is(err, services.ErrDirectRevealNotAllowed):
			return fiber.NewError(fiber.StatusForbidden, "matched policy does not permit direct reveal")
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
