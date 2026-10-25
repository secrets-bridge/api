package handlers

// Agent onboarding (api#178, v2 in skills#116): HTTP layer for
// enrollment-token generation (admin) and the two-step enrollment with
// proof of possession of a customer-generated key.

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/storage"
)

// GenerateEnrollmentTokenRequest is the admin body for
// POST /provider-connections/:id/agent-enrollment-token.
type GenerateEnrollmentTokenRequest struct {
	Name                 string `json:"name,omitempty"`
	ExpiresInSeconds     int    `json:"expires_in_seconds,omitempty"`
	ExpectedClusterName  string `json:"expected_cluster_name,omitempty"`
	ExpectedProviderType string `json:"expected_provider_type,omitempty"`
}

// EnrollmentTokenResponse returns the one-time token EXACTLY ONCE. ID
// is the token row, for POST /agent-enrollment-tokens/:id/revoke.
type EnrollmentTokenResponse struct {
	ID                   string            `json:"id"`
	EnrollmentToken      string            `json:"enrollment_token"`
	ExpiresAt            string            `json:"expires_at"`
	ProviderConnectionID string            `json:"provider_connection_id"`
	InstallHint          map[string]string `json:"install_hint"`
}

// GenerateEnrollmentToken handles POST
// /provider-connections/:id/agent-enrollment-token. Session-gated +
// agent.mint. NOT under the /api/v1/agents/ session-exempt prefix.
func (h *Agents) GenerateEnrollmentToken(c fiber.Ctx) error {
	connID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "provider connection id must be a UUID")
	}
	actor, ok := auth.IdentityFromContext(c.Context())
	if !ok || actor == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "authentication required")
	}
	var req GenerateEnrollmentTokenRequest
	if err := c.Bind().JSON(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}

	res, err := h.svc.GenerateEnrollmentToken(c.Context(), services.GenerateEnrollmentTokenInput{
		ProviderConnectionID: connID,
		Name:                 req.Name,
		ExpiresInSeconds:     req.ExpiresInSeconds,
		ExpectedClusterName:  req.ExpectedClusterName,
		ExpectedProviderType: req.ExpectedProviderType,
		CreatedBy:            actor,
	})
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrConnectionNotFound):
			return fiber.NewError(fiber.StatusNotFound, "provider connection not found")
		case errors.Is(err, services.ErrEnrollmentConnectionUnusable):
			return fiber.NewError(fiber.StatusConflict, "provider connection is not active")
		case errors.Is(err, services.ErrEnrollmentNotConfigured):
			return fiber.NewError(fiber.StatusServiceUnavailable, "agent enrollment is not configured")
		default:
			return fiber.NewError(fiber.StatusInternalServerError, "could not generate enrollment token")
		}
	}

	return c.Status(fiber.StatusCreated).JSON(EnrollmentTokenResponse{
		ID:                   res.ID.String(),
		EnrollmentToken:      res.Token,
		ExpiresAt:            res.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		ProviderConnectionID: res.ProviderConnectionID.String(),
		InstallHint:          enrollmentInstallHint(res, req.ExpectedClusterName),
	})
}

// Install hint names (skills#116). The enrollment runs on the customer
// side with the agent binary's enroll subcommand, which generates the
// X25519 key locally; the chart then mounts the resulting Secret read
// only. The token and the private key are never chart values.
const (
	agentChartRef       = "oci://ghcr.io/secrets-bridge/charts/secrets-bridge-agent"
	agentNamespace      = "secrets-bridge"
	agentIdentitySecret = "secrets-bridge-agent-identity"
	agentBinary         = "secrets-bridge-agent"
)

// hintValueRe is what a connection or request value may hold to go into
// the hint as typed. The hint is pasted into a shell, and helm splits a
// --set on commas, so a scope value like "kv,cp.endpoint=https://..."
// would add settings of its own. Scope values are free text (address
// and endpoint only pass url.Parse, which takes "$(...)" in a path).
var hintValueRe = regexp.MustCompile(`^[A-Za-z0-9._:/@%+-]+$`)

// hintValue returns v when it is safe to paste, else the placeholder.
func hintValue(v, placeholder string) string {
	if !hintValueRe.MatchString(v) {
		return placeholder
	}
	return v
}

// enrollmentInstallHint returns copy-paste commands for a new token:
//
//   - kubectl: run the local enroll and store the bundle straight into
//     the Kubernetes Secret the chart mounts;
//   - cli: run the local enroll and write the bundle to a 0600 file, to
//     put into AWS Secrets Manager or Vault (and sync with ESO);
//   - helm: the agent chart pointed at that Secret.
//
// No line carries the token (ui#151): both start with a silent prompt
// (`read -rs`; paste the token, then Enter) and hand it to the enroll
// command on stdin (--token-file -), so it never reaches a command line,
// shell history or the process arguments. The control plane URL, chart
// version and anything the connection doesn't say are <placeholders>,
// and so is any value hintValue refuses.
func enrollmentInstallHint(res *services.GeneratedEnrollmentToken, expectedCluster string) map[string]string {
	cluster := hintValue(firstSet(expectedCluster, res.ClusterName), "<cluster-name>")
	scope := func(k, placeholder string) string { return hintValue(res.Scope[k], placeholder) }

	enroll := agentBinary + " enroll --cp-endpoint <CONTROL_PLANE_URL> --token-file -" +
		" --name <agent-name> --cluster-name " + cluster + " --provider-type " + res.ProviderType
	sets := []string{
		"cp.endpoint=<CONTROL_PLANE_URL>",
		"clusterName=" + cluster,
		"agent.providerType=" + res.ProviderType,
		"identity.existingSecret=" + agentIdentitySecret,
	}
	switch res.ProviderType {
	case "vault":
		mount := "kv"
		if res.Scope["mount"] != "" {
			mount = scope("mount", "<kv-mount>")
		}
		sets = append(sets,
			"providers.vault.enabled=true",
			"providers.vault.addr="+scope("address", "<vault-address>"),
			"providers.vault.kvMount="+mount,
			"providers.vault.kubernetesRole=<vault-role>")
		if res.Scope["namespace"] != "" {
			sets = append(sets, "providers.vault.namespace="+scope("namespace", "<vault-namespace>"))
		}
		if res.Scope["kvPrefix"] != "" {
			sets = append(sets, "providers.vault.kvPrefix="+scope("kvPrefix", "<kv-prefix>"))
		}
	case "aws-sm":
		region := scope("region", "<aws-region>")
		enroll += " --region " + region
		sets = append(sets,
			"providers.awsSecretsManager.enabled=true",
			"providers.awsSecretsManager.region="+region)
		if res.Scope["endpoint"] != "" {
			sets = append(sets, "providers.awsSecretsManager.endpoint="+scope("endpoint", "<aws-endpoint>"))
		}
	}
	helm := "helm upgrade --install secrets-bridge-agent " + agentChartRef +
		" --version <chart-version> --namespace " + agentNamespace
	for _, s := range sets {
		helm += " --set " + s
	}

	const prompt = "read -rs SB_ENROLL_TOKEN\n"
	const feed = `printf '%s' "$SB_ENROLL_TOKEN" | `
	const unset = "\nunset SB_ENROLL_TOKEN"
	return map[string]string{
		"kubectl": prompt + feed + enroll + " --format env --output - | " +
			fmt.Sprintf("kubectl -n %s create secret generic %s --from-env-file=/dev/stdin", agentNamespace, agentIdentitySecret) +
			unset,
		"cli":  prompt + feed + enroll + " --format json --output agent-credentials.json" + unset,
		"helm": helm,
	}
}

// firstSet returns the first non-empty value.
func firstSet(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// SealedChallenge is a pkg/sealing envelope, all byte fields std base64.
// The plaintext is the 32-byte challenge nonce.
type SealedChallenge struct {
	Algorithm          string `json:"algorithm"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	Nonce              string `json:"nonce"`
	Ciphertext         string `json:"ciphertext"`
}

// ChallengeResponse is returned by both challenge endpoints (enroll and
// key rotation).
type ChallengeResponse struct {
	ChallengeID     string          `json:"challenge_id"`
	SealedChallenge SealedChallenge `json:"sealed_challenge"`
	ExpiresAt       string          `json:"expires_at"`
}

func challengeResponse(ch *services.KeyChallenge) ChallengeResponse {
	return ChallengeResponse{
		ChallengeID: ch.ChallengeID.String(),
		SealedChallenge: SealedChallenge{
			Algorithm:          ch.Sealed.Algorithm,
			EphemeralPublicKey: base64.StdEncoding.EncodeToString(ch.Sealed.EphemeralPublicKey),
			Nonce:              base64.StdEncoding.EncodeToString(ch.Sealed.Nonce),
			Ciphertext:         base64.StdEncoding.EncodeToString(ch.Sealed.Ciphertext),
		},
		ExpiresAt: ch.ExpiresAt.UTC().Format(time.RFC3339),
	}
}

// EnrollChallengeRequest is the body of POST /agents/enroll/challenge.
type EnrollChallengeRequest struct {
	SchemaVersion      string `json:"schema_version"`
	EnrollmentToken    string `json:"enrollment_token"`
	PublicKey          string `json:"public_key"`
	PublicKeyAlgorithm string `json:"public_key_algorithm"`
}

// EnrollChallenge handles POST /agents/enroll/challenge. Auth is the
// enrollment token only, which is validated here and NOT consumed. Like
// Enroll it is under the /api/v1/agents/ session-exempt prefix and is
// registered before the AgentAuth group.
func (h *Agents) EnrollChallenge(c fiber.Ctx) error {
	var req EnrollChallengeRequest
	if err := c.Bind().JSON(&req); err != nil {
		return enrollError(c, fiber.StatusBadRequest, "invalid_request")
	}
	ch, err := h.svc.EnrollChallenge(c.Context(), services.EnrollChallengeInput{
		SchemaVersion:      req.SchemaVersion,
		Token:              req.EnrollmentToken,
		PublicKey:          req.PublicKey,
		PublicKeyAlgorithm: req.PublicKeyAlgorithm,
	})
	if err != nil {
		return enrollErr(c, err)
	}
	return c.Status(fiber.StatusOK).JSON(challengeResponse(ch))
}

// EnrollRequest is the body of POST /agents/enroll (schema version 2).
type EnrollRequest struct {
	SchemaVersion     string `json:"schema_version"`
	EnrollmentToken   string `json:"enrollment_token"`
	ChallengeID       string `json:"challenge_id"`
	ChallengeResponse string `json:"challenge_response"`
	Name              string `json:"name"`
	ClusterName       string `json:"cluster_name,omitempty"`
	ProviderType      string `json:"provider_type,omitempty"`
	Region            string `json:"region,omitempty"`
}

// EnrollResponse returns the agent credential EXACTLY ONCE.
type EnrollResponse struct {
	AgentID                  string `json:"agent_id"`
	AgentSecret              string `json:"agent_secret"`
	PublicKeyFingerprint     string `json:"public_key_fingerprint"`
	PublicKeyVersion         int    `json:"public_key_version"`
	HeartbeatIntervalSeconds int    `json:"heartbeat_interval_seconds"`
	ClaimIntervalSeconds     int    `json:"claim_interval_seconds"`
}

// Enroll handles POST /agents/enroll. Auth is the enrollment token plus
// the challenge response: no session, no AgentAuth (the agent has no
// credential yet). Under the /api/v1/agents/ session-exempt prefix by
// design.
func (h *Agents) Enroll(c fiber.Ctx) error {
	var req EnrollRequest
	if err := c.Bind().JSON(&req); err != nil {
		return enrollError(c, fiber.StatusBadRequest, "invalid_request")
	}
	res, err := h.svc.Enroll(c.Context(), services.EnrollInput{
		SchemaVersion:     req.SchemaVersion,
		Token:             req.EnrollmentToken,
		ChallengeID:       req.ChallengeID,
		ChallengeResponse: req.ChallengeResponse,
		Name:              req.Name,
		ClusterName:       req.ClusterName,
		ProviderType:      req.ProviderType,
		Region:            req.Region,
	})
	if err != nil {
		return enrollErr(c, err)
	}
	return c.Status(fiber.StatusCreated).JSON(EnrollResponse{
		AgentID:                  res.AgentID.String(),
		AgentSecret:              res.AgentSecret,
		PublicKeyFingerprint:     res.PublicKeyFingerprint,
		PublicKeyVersion:         res.PublicKeyVersion,
		HeartbeatIntervalSeconds: res.HeartbeatIntervalSeconds,
		ClaimIntervalSeconds:     res.ClaimIntervalSeconds,
	})
}

func enrollError(c fiber.Ctx, status int, code string) error {
	return c.Status(status).JSON(fiber.Map{"error": code})
}

// enrollErr maps the enrollment and rotation errors to the generic
// bodies of the contract ({"error": "<code>"}). The specific reason is
// only in the audit row. No token, hash, nonce or key ever appears.
func enrollErr(c fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, services.ErrEnrollmentRejected):
		return enrollError(c, fiber.StatusUnauthorized, "enrollment_rejected")
	case errors.Is(err, services.ErrKeyRotationRejected):
		return enrollError(c, fiber.StatusUnauthorized, "key_rotation_rejected")
	case errors.Is(err, services.ErrInvalidPublicKey):
		return enrollError(c, fiber.StatusBadRequest, "invalid_public_key")
	case errors.Is(err, services.ErrUnsupportedSchemaVersion):
		return enrollError(c, fiber.StatusBadRequest, "unsupported_schema_version")
	case errors.Is(err, services.ErrInvalidInput):
		return enrollError(c, fiber.StatusBadRequest, "invalid_request")
	case errors.Is(err, services.ErrAgentNameTaken):
		return enrollError(c, fiber.StatusConflict, "agent_name_taken")
	case errors.Is(err, services.ErrEnrollmentNotConfigured), errors.Is(err, services.ErrKeyRotationNotConfigured):
		return enrollError(c, fiber.StatusServiceUnavailable, "enrollment_not_configured")
	}
	return enrollError(c, fiber.StatusInternalServerError, "enrollment_failed")
}
