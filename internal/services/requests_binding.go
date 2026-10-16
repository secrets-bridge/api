// Package services — requests_binding.go: the project_secrets binding
// gate for the plaintext-read submit paths, and the job-payload provider
// config derivation.
//
// Two rules live here:
//
//  1. A direct reveal or a per-env read request must name a secret the
//     project holds a READ binding for, and when that binding is scoped
//     to an environment it must be the environment in the URL (api#191
//     H2, API-S-03, api#154). Fail closed: no binding, a binding for a
//     different environment, a binding without the read op, or a key
//     outside a restrictive allowlist all refuse before any request row
//     is written, with a metadata-only audit row.
//
//  2. The provider config a job carries to the agent never comes from the
//     request body or from a stored request row. It is derived from the
//     bound catalog row (the config discovery recorded from the provider
//     connection) and filtered to the keys the agent accepts in a payload
//     (API-S-04 / API-18). A requester can no longer steer kvMount or
//     kvPrefix.
package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// ErrSecretNotBound is returned when a read-path submit names a secret
// the project has no binding for, or whose binding is scoped to another
// environment than the one in the URL. Maps to a generic 403 at the
// handler; the precise reason is in the audit row.
var ErrSecretNotBound = errors.New("services: secret is not bound to the project environment")

// ErrBindingOpNotAllowed is returned when the governing binding exists
// but its allowed_ops does not include the requested operation.
var ErrBindingOpNotAllowed = errors.New("services: binding does not allow the requested operation")

// Refusal reasons recorded in the *.refused_binding audit metadata. A
// finite enum so the audit UI can map them without parsing errors.
const (
	bindingRefusalNotBound      = "secret_not_bound"
	bindingRefusalEnvMismatch   = "binding_env_mismatch"
	bindingRefusalOpNotAllowed  = "op_not_allowed"
	bindingRefusalKeyNotAllowed = "key_not_allowed"
)

// boundSecret is one project_secrets binding together with the catalog
// row it binds.
type boundSecret struct {
	binding *storage.ProjectSecret
	secret  *storage.Secret
}

// projectBindingCandidates returns every (binding, catalog row) pair that
// binds (providerType, secretRef) to projectID. Callers must have checked
// that the repos are wired.
func (s *RequestService) projectBindingCandidates(ctx context.Context, projectID uuid.UUID, providerType, secretRef string) ([]boundSecret, error) {
	return findProjectBindings(ctx, s.bindings, s.secrets, projectID, providerType, secretRef)
}

// findProjectBindings returns every (binding, catalog row) pair that
// binds (providerType, secretRef) to projectID, in catalog order
// (cluster_name). The catalog identity is (cluster, provider_type, ref),
// so the same ref discovered on two clusters can yield two candidates,
// each bound to a different environment.
func findProjectBindings(ctx context.Context, bindings storage.ProjectSecretRepository, secrets storage.SecretRepository, projectID uuid.UUID, providerType, secretRef string) ([]boundSecret, error) {
	catalog, err := secrets.ListByRef(ctx, providerType, secretRef)
	if err != nil {
		return nil, fmt.Errorf("services: resolve catalog for binding: %w", err)
	}
	var out []boundSecret
	for _, sec := range catalog {
		b, err := bindings.Get(ctx, projectID, sec.ID)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				continue
			}
			return nil, fmt.Errorf("services: resolve binding: %w", err)
		}
		out = append(out, boundSecret{binding: b, secret: sec})
	}
	return out, nil
}

// GoverningBinding returns the index of the binding that governs a
// request made in envID, or -1 when none may govern it. This is the one
// environment rule every binding gate uses (direct reveal, the per-env
// request endpoint, the POST /requests tenancy gate, the reveal-session
// allowlist):
//
//   - a binding scoped to envID wins;
//   - otherwise a legacy binding with a NULL environment_id (pre-Slice-L3
//     row) applies, and the request's environment keeps deciding exactly
//     as it did before;
//   - a binding scoped to a DIFFERENT environment never applies, and with
//     no environment (envID nil) no env-scoped binding applies. A secret
//     bound to prod therefore cannot be requested or revealed under a
//     non-prod environment (API-S-03).
func GoverningBinding(bindings []*storage.ProjectSecret, envID *uuid.UUID) int {
	if envID != nil {
		for i, b := range bindings {
			if b.EnvironmentID != nil && *b.EnvironmentID == *envID {
				return i
			}
		}
	}
	for i, b := range bindings {
		if b.EnvironmentID == nil {
			return i
		}
	}
	return -1
}

// selectBinding applies GoverningBinding to (binding, catalog row)
// candidates. Non-strict callers (provider-config derivation for a row
// that was already authorized) fall back to the first candidate when no
// binding governs; strict callers get nil.
func selectBinding(cands []boundSecret, envID *uuid.UUID, strict bool) *boundSecret {
	bindings := make([]*storage.ProjectSecret, len(cands))
	for i := range cands {
		bindings[i] = cands[i].binding
	}
	if i := GoverningBinding(bindings, envID); i >= 0 {
		return &cands[i]
	}
	if strict || len(cands) == 0 {
		return nil
	}
	return &cands[0]
}

// requireReadBinding is the binding gate for the plaintext-read submit
// paths that carry an environment in the URL (direct reveal and the
// per-env request endpoint). It fails closed:
//
//   - binding repos not wired                  → ErrSecretNotBound
//   - no binding for (project, provider, ref)  → ErrSecretNotBound
//   - only bindings scoped to another env      → ErrSecretNotBound
//   - governing binding lacks the read op      → ErrBindingOpNotAllowed
//   - key outside a restrictive allowlist, or
//     no key named against one                 → ErrKeyNotAllowed
//
// Because an env-scoped binding only governs when its environment IS the
// URL environment, the env.kind check the caller already ran on the URL
// environment is the check on the binding's environment: a secret bound
// to a prod environment can no longer be revealed through a non-prod URL
// (API-S-03). A legacy NULL-environment binding keeps the pre-fix
// behaviour (the URL environment decides).
//
// Returns the governing binding and, on refusal, the audit reason.
func (s *RequestService) requireReadBinding(ctx context.Context, env *storage.Environment, providerType, secretRef string, keys []string) (*boundSecret, string, error) {
	if s.bindings == nil || s.secrets == nil {
		return nil, bindingRefusalNotBound, ErrSecretNotBound
	}
	cands, err := s.projectBindingCandidates(ctx, env.ProjectID, providerType, secretRef)
	if err != nil {
		return nil, "", err
	}
	sel := selectBinding(cands, &env.ID, true)
	if sel == nil {
		if len(cands) > 0 {
			return nil, bindingRefusalEnvMismatch, ErrSecretNotBound
		}
		return nil, bindingRefusalNotBound, ErrSecretNotBound
	}
	if !keyInAllowlist(sel.binding.AllowedOps, storage.OpRead) {
		return nil, bindingRefusalOpNotAllowed, ErrBindingOpNotAllowed
	}
	if err := checkBindingKeys(sel.binding, keys); err != nil {
		return nil, bindingRefusalKeyNotAllowed, err
	}
	return sel, "", nil
}

// checkBindingKeys enforces a binding's allowed_keys allowlist:
// AllowedKeys nil → every key is allowed; a restrictive list → every
// requested key must be in it, and an empty request is refused (empty
// target_keys means "every key", which would bypass the allowlist).
func checkBindingKeys(b *storage.ProjectSecret, keys []string) error {
	if b.AllowedKeys == nil {
		return nil
	}
	if len(keys) == 0 {
		return fmt.Errorf("%w: target_keys must be named within the binding allowlist", ErrKeyNotAllowed)
	}
	for _, k := range keys {
		if !keyInAllowlist(b.AllowedKeys, k) {
			return fmt.Errorf("%w: %q", ErrKeyNotAllowed, k)
		}
	}
	return nil
}

// auditBindingRefusal records a refused read-path submit. Metadata only:
// scope, requester, key COUNT and the refusal reason. No key names that
// were refused, no values. There is no request row yet, so the event is
// correlated to the environment (same shape as refused_prod).
func (s *RequestService) auditBindingRefusal(ctx context.Context, action, requesterID string, env *storage.Environment, providerType, secretRef string, keyCount int, reason string) {
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:         "user:" + requesterID,
		Action:        action,
		Resource:      "environment:" + env.ID.String(),
		Status:        storage.AuditStatusFailure,
		CorrelationID: env.ID,
		Metadata: map[string]any{
			"environment_id":       env.ID.String(),
			"environment_kind":     string(env.Kind),
			"project_id":           env.ProjectID.String(),
			"target_provider_type": providerType,
			"target_secret_ref":    secretRef,
			"requester_id":         requesterID,
			"key_count":            keyCount,
			"refusal_reason":       reason,
		},
	})
}

// agentPayloadConfigKeys lists, per provider type, the ONLY
// target_provider_config keys the agent accepts in a job payload (agent
// internal/executor/resolvers.go vaultPayloadAllowlist and
// awsPayloadAllowlist). Connection identity (address, namespace, auth,
// region, roleArn, endpoint) is pinned on the agent and refused there, so
// it is never put into a payload. Provider types not listed get an empty
// config.
var agentPayloadConfigKeys = map[string][]string{
	string(storage.ProviderConnectionTypeVault): {"kvMount", "kvPrefix"},
	string(storage.ProviderConnectionTypeAWSSM): {"tagFilter"},
}

// agentProviderConfig builds a job-payload provider config from
// operator-controlled metadata, keeping only the keys the agent accepts
// for providerType. Never nil.
func agentProviderConfig(providerType string, src map[string]any) map[string]any {
	out := map[string]any{}
	for _, k := range agentPayloadConfigKeys[providerType] {
		if v, ok := src[k]; ok && v != nil {
			out[k] = v
		}
	}
	return out
}

// boundProviderConfig derives the provider config for a read/patch
// request from the bound catalog row (the config discovery recorded from
// the provider connection's scope), filtered to the agent-accepted keys.
// It never looks at the request body or the stored request row. Returns
// an empty config when the binding repos are not wired, the project id
// does not parse, or no binding exists — the agent then uses its pinned
// defaults, which is exactly what the UI flows (which send no config)
// have always produced.
func (s *RequestService) boundProviderConfig(ctx context.Context, projectIDRaw string, envID *uuid.UUID, providerType, secretRef string) (map[string]any, error) {
	if s.bindings == nil || s.secrets == nil {
		return map[string]any{}, nil
	}
	projectID, err := uuid.Parse(projectIDRaw)
	if err != nil {
		return map[string]any{}, nil
	}
	cands, err := s.projectBindingCandidates(ctx, projectID, providerType, secretRef)
	if err != nil {
		return nil, err
	}
	sel := selectBinding(cands, envID, false)
	if sel == nil {
		return map[string]any{}, nil
	}
	return agentProviderConfig(sel.secret.ProviderType, sel.secret.ProviderConfig), nil
}

// EnvReadInput is the per-env request endpoint's input
// (POST /projects/:id/environments/:env_id/request). The handler resolves
// the environment from the URL; there is deliberately no provider config
// field (API-S-04).
type EnvReadInput struct {
	RequesterID        string
	Environment        *storage.Environment // already loaded by the handler
	TargetProviderType string
	TargetSecretRef    string
	TargetKeys         []string
	Justification      string
}

// SubmitEnvRead creates a pending read request for the per-env request
// endpoint. Unlike SubmitRead it applies the binding gate itself
// (api#154): the endpoint used to call SubmitRead directly and skipped
// the allowed_keys tenancy gate POST /requests/read runs. The gate is the
// same one direct reveal uses (requireReadBinding), so the secret must be
// bound for read to this project, in this environment (or via a legacy
// NULL-environment binding), with every key inside a restrictive
// allowlist.
func (s *RequestService) SubmitEnvRead(ctx context.Context, in EnvReadInput) (*storage.AccessRequest, error) {
	if in.RequesterID == "" || in.TargetProviderType == "" || in.TargetSecretRef == "" {
		return nil, fmt.Errorf("%w: requester_id, target_provider_type, target_secret_ref required", ErrInvalidInput)
	}
	if in.Environment == nil {
		return nil, fmt.Errorf("%w: environment is required", ErrInvalidInput)
	}
	if in.Justification == "" {
		return nil, fmt.Errorf("%w: justification required", ErrInvalidInput)
	}

	bound, reason, err := s.requireReadBinding(ctx, in.Environment, in.TargetProviderType, in.TargetSecretRef, in.TargetKeys)
	if err != nil {
		if reason != "" {
			s.auditBindingRefusal(ctx, "request.read.refused_binding", in.RequesterID, in.Environment,
				in.TargetProviderType, in.TargetSecretRef, len(in.TargetKeys), reason)
		}
		return nil, err
	}

	envID := in.Environment.ID
	return s.createReadRequest(ctx, ReadInput{
		RequesterID:        in.RequesterID,
		ProjectID:          in.Environment.ProjectID.String(),
		Environment:        in.Environment.Name,
		TargetProviderType: in.TargetProviderType,
		TargetSecretRef:    in.TargetSecretRef,
		TargetKeys:         in.TargetKeys,
		Justification:      in.Justification,
	}, &envID, in.Environment.Kind, agentProviderConfig(bound.secret.ProviderType, bound.secret.ProviderConfig))
}
