// Slice P2 — ProviderConnectionsService.
//
// Owns the validation + audit + sanitization layer between the HTTP
// handlers (P3) and the storage repositories (P1). Every mutation
// runs through this service so the rules — credential refusal,
// scope-shape per provider type, URL/ARN semantics, sanitization of
// discover errors — apply uniformly regardless of which handler
// called.
//
// Hard rules:
//   - scope is METADATA only. The credential-shaped key refusal +
//     secret-shaped value detection run BEFORE shape validation so
//     a payload that's both unknown-key AND credential-shaped fails
//     on the credential side (the higher-severity error).
//   - last_discover_error is sanitized via pkg/sanitize BEFORE
//     persistence. Two-layer defense: the worker pre-sanitizes too.
//   - audit events NEVER include scope, raw error text, or values —
//     only key names, type, status, has_error bool.

package services

// Import sites used by both the existing service surface and the
// EPIC Q scoped bind methods in provider_connections_binding.go.

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/auth"
	"github.com/secrets-bridge/api/pkg/sanitize"
	"github.com/secrets-bridge/api/pkg/storage"
)

// ProviderConnectionsService coordinates provider_connections CRUD +
// binding management + discovery scheduling callbacks. Constructed
// once at startup; thread-safe for concurrent calls.
type ProviderConnectionsService struct {
	repo     storage.ProviderConnectionRepository
	bindings storage.ProviderConnectionBindingRepository
	audit    storage.AuditEventRepository

	// rejectSecretValues is hard-on for v1. The deployment-level
	// override (SB_PROVIDER_CONN_REJECT_SECRETS=false) is read at
	// boot and audited; never per-connection.
	rejectSecretValues bool

	// allowInsecureVaultAddr permits http:// vault URLs. Hard-off
	// for v1; the deployment-level override is audited at boot.
	allowInsecureVaultAddr bool

	// EPIC Q (api#99) — populated by main via WithBinderScope so the
	// scoped bind/unbind methods can compute the project coverage gate
	// at call time. Nil disables the scoped path (the admin Bind path
	// is unaffected). Mirrors RequestService.WithApproverScope.
	binderResolver  auth.Resolver
	binderTeamScope auth.TeamScopeResolver

	// environments is the L1 source of truth for env.kind. Lazy-injected
	// via WithEnvironments so scoped bind/unbind can refuse env.kind=prod
	// without dragging the env repo into NewProviderConnections.
	environments storage.EnvironmentRepository
}

// NewProviderConnections constructs the service with safe defaults:
// secret-shaped value detection ON, insecure Vault URLs OFF. Tests
// may flip these via the With* options.
func NewProviderConnections(
	repo storage.ProviderConnectionRepository,
	bindings storage.ProviderConnectionBindingRepository,
	audit storage.AuditEventRepository,
) *ProviderConnectionsService {
	return &ProviderConnectionsService{
		repo:                   repo,
		bindings:               bindings,
		audit:                  audit,
		rejectSecretValues:     true,
		allowInsecureVaultAddr: false,
	}
}

// WithRejectSecretValues toggles secret-shaped value detection. The
// deployment-level env var SB_PROVIDER_CONN_REJECT_SECRETS=false is
// the only intended caller for `false`; never per-connection.
func (s *ProviderConnectionsService) WithRejectSecretValues(v bool) *ProviderConnectionsService {
	s.rejectSecretValues = v
	return s
}

// WithAllowInsecureVaultAddr permits http:// vault.address values.
// SB_ALLOW_INSECURE_VAULT_ADDR=true is the only intended caller.
func (s *ProviderConnectionsService) WithAllowInsecureVaultAddr(v bool) *ProviderConnectionsService {
	s.allowInsecureVaultAddr = v
	return s
}

// WithBinderScope wires the resolver pair the EPIC Q scoped bind/unbind
// path uses to compute project coverage for integration.bind callers.
// Pass nil to disable the scoped path — main always wires both in
// production.
func (s *ProviderConnectionsService) WithBinderScope(r auth.Resolver, tr auth.TeamScopeResolver) *ProviderConnectionsService {
	s.binderResolver = r
	s.binderTeamScope = tr
	return s
}

// WithEnvironments lets the scoped bind/unbind path validate
// env.kind != 'prod' without baking the env repo into the constructor.
func (s *ProviderConnectionsService) WithEnvironments(r storage.EnvironmentRepository) *ProviderConnectionsService {
	s.environments = r
	return s
}

// ---- input shapes --------------------------------------------------

// CreateInput is the shape the HTTP handler hands the service after
// JSON decoding. Service-layer validation runs before the storage call.
type CreateInput struct {
	Name                    string
	Type                    storage.ProviderConnectionType
	AuthMethod              string
	Scope                   map[string]string
	ClusterName             string
	Description             string
	Status                  storage.ProviderConnectionStatus
	DiscoverEnabled         bool
	DiscoverIntervalSeconds int

	// EPIC Q (api#99): default-deny on Create. Caller can flip to true
	// via the admin SPA toggle; scoped binders never reach Create.
	SelfServiceBindable bool

	// Actor + correlation_id for audit emission.
	ActorID       string
	CorrelationID uuid.UUID
}

// UpdateInput mirrors CreateInput but Type is immutable on edit (the
// handler enforces this; the service refuses if Type differs from
// the existing row).
type UpdateInput struct {
	Name                    string
	AuthMethod              string
	Scope                   map[string]string
	ClusterName             string
	Description             string
	Status                  storage.ProviderConnectionStatus
	DiscoverEnabled         bool
	DiscoverIntervalSeconds int

	// EPIC Q (api#99): nil = leave untouched. Lets P3 handler bodies
	// omit the flag without flipping it back to false.
	SelfServiceBindable *bool

	ActorID       string
	CorrelationID uuid.UUID
}

// BindInput is the shape for POST /provider-connections/:id/bindings.
type BindInput struct {
	ConnectionID  uuid.UUID
	ProjectID     uuid.UUID
	EnvironmentID *uuid.UUID
	Purpose       storage.ProjectProviderConnectionPurpose
	ActorID       string
}

// DeleteCounts is the body the handler returns on 409 connection_in_use
// so the admin UI can render "In use by N project bindings and M open
// requests" without a second round trip.
type DeleteCounts struct {
	BindingsCount     int
	OpenRequestsCount int
}

// ---- sentinels mapped to stable HTTP codes in P3 -------------------

var (
	ErrInvalidScope             = errors.New("services: invalid scope")
	ErrCredentialShapedKey      = errors.New("services: credential-shaped key in scope")
	ErrSecretShapedValue        = errors.New("services: secret-shaped value in scope")
	ErrInvalidProviderURL       = errors.New("services: invalid provider URL")
	ErrInvalidRoleArn           = errors.New("services: invalid AWS role ARN")
	ErrDescriptionTooLong       = errors.New("services: description too long")
	ErrDiscoverRequiresCluster  = errors.New("services: discover_enabled requires cluster_name")
	ErrInvalidDiscoverInterval  = errors.New("services: discover_interval_seconds must be between 60 and 86400")
	ErrConnectionDisabled       = errors.New("services: provider connection is disabled")
	ErrEnvironmentNotInProject  = errors.New("services: environment does not belong to project")
	ErrInvalidName              = errors.New("services: invalid name")
	ErrInvalidAuthMethod        = errors.New("services: invalid auth_method for provider type")
	ErrInvalidClusterName       = errors.New("services: invalid cluster_name")
	ErrTypeImmutable            = errors.New("services: provider connection type is immutable")

	// EPIC Q (api#99) — scoped binder sentinels mapped to stable
	// 403 codes in api#101 (Q2). See provider_connections_binding.go
	// for the gate chain.
	ErrConnectionNotSelfServiceBindable = errors.New("services: connection is not enabled for self-service binding")
	ErrProdBindingNotAllowedForScope    = errors.New("services: scoped binders cannot bind to prod environments")
	ErrOutOfScopeBinding                = errors.New("services: actor does not cover the target project/environment")
)

// ValidationDetail enriches a wrapped sentinel with metadata the
// handler surfaces in the structured error response body (e.g.
// {error_code: "credential_in_scope", banned_key: "awsAccessKeyID"}).
type ValidationDetail struct {
	Err          error
	BannedKey    string   // for ErrCredentialShapedKey
	Field        string   // for ErrSecretShapedValue, ErrInvalidProviderURL
	Reason       string   // for ErrInvalidProviderURL
	MissingKeys  []string // for ErrInvalidScope
	UnknownKeys  []string // for ErrInvalidScope
	Length       int      // for ErrDescriptionTooLong
	Cap          int      // for ErrDescriptionTooLong
}

// Error returns the wrapped sentinel's message; the handler reads
// the Detail fields directly for the response body.
func (v *ValidationDetail) Error() string { return v.Err.Error() }

// Unwrap lets errors.Is/As find the underlying sentinel.
func (v *ValidationDetail) Unwrap() error { return v.Err }

func wrapValidation(err error, opts ...func(*ValidationDetail)) error {
	d := &ValidationDetail{Err: err}
	for _, o := range opts {
		o(d)
	}
	return d
}

// ---- scope shape per provider type --------------------------------

type scopeShape struct {
	required []string
	allowed  []string
}

// scopeShapes is the canonical map of provider type -> required +
// allowed scope keys. Adding a new provider type touches one entry
// here + a new ProviderConnectionType constant + a schema migration.
var scopeShapes = map[storage.ProviderConnectionType]scopeShape{
	storage.ProviderConnectionTypeAWSSM: {
		required: []string{"region"},
		allowed:  []string{"region", "roleArn", "endpoint"},
	},
	storage.ProviderConnectionTypeVault: {
		required: []string{"address", "mount"},
		allowed:  []string{"address", "mount", "namespace", "kvPrefix"},
	},
	storage.ProviderConnectionTypeGCPSM: {
		required: []string{"projectID"},
		allowed:  []string{"projectID", "endpoint"},
	},
	storage.ProviderConnectionTypeAzureKV: {
		required: []string{"vaultName"},
		allowed:  []string{"vaultName", "tenantID"},
	},
	storage.ProviderConnectionTypeKubernetes: {
		required: []string{"context"},
		allowed:  []string{"context", "namespace"},
	},
}

// authMethodsByType is the canonical map of provider type -> allowed
// auth methods. The agent's resolver picks the actual auth chain at
// runtime; the metadata here gates what the admin form accepts.
var authMethodsByType = map[storage.ProviderConnectionType][]string{
	storage.ProviderConnectionTypeAWSSM:      {"default", "assume_role"},
	storage.ProviderConnectionTypeVault:      {"token", "kubernetes"},
	storage.ProviderConnectionTypeGCPSM:      {"default", "service_account"},
	storage.ProviderConnectionTypeAzureKV:    {"default", "service_principal"},
	storage.ProviderConnectionTypeKubernetes: {"in_cluster", "kubeconfig"},
}

// ---- credential / secret detection --------------------------------

// bannedScopeKeys is the case-insensitive denylist for scope keys.
// Match runs BEFORE shape validation so a payload that's both
// unknown-key AND credential-shaped fails on the credential side.
var bannedScopeKeys = []string{
	// Generic
	"credentials", "secret", "secrets", "password", "passphrase",
	// AWS
	"awsAccessKeyID", "awsSecretAccessKey", "awsSessionToken",
	"accessKeyID", "secretAccessKey", "sessionToken",
	// Vault
	"token", "vaultToken", "approleSecretID",
	// GCP / Azure
	"serviceAccountKey", "clientSecret", "subscriptionKey",
}

// secretValuePatterns are the regexes the service runs over every
// scope value (not just type-natural fields — an AKIA inside a Vault
// kvPrefix is still a credential).
var secretValuePatterns = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[A-Z0-9]{16}`),
	regexp.MustCompile(`hvs\.[A-Za-z0-9_-]{20,}`),
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}`),
	regexp.MustCompile(`ya29\.[A-Za-z0-9_-]+`),
}

// nameRe pins the name shape: lowercase letters, digits, hyphens,
// 1-120 chars. Matches the convention used by Workflows / Roles.
var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,119}$`)

// clusterNameRe is the same shape as nameRe — cluster names get the
// same length cap + regex.
var clusterNameRe = nameRe

// roleArnRe pins AWS IAM role ARNs: 12-digit account + role path/name.
var roleArnRe = regexp.MustCompile(`^arn:aws:iam::\d{12}:role/[A-Za-z0-9+=,.@_/-]+$`)

// descriptionMaxLen caps description at 500 chars after trimming.
const descriptionMaxLen = 500

// ---- validation ----------------------------------------------------

// validateScopeKeys runs credential refusal + (optional) secret
// detection BEFORE the shape check. Returns the first violation.
func (s *ProviderConnectionsService) validateScopeKeys(scope map[string]string) error {
	if scope == nil {
		// nil map is allowed for shape validation; the per-type
		// required-key check catches missing fields.
		return nil
	}
	for k, v := range scope {
		if k == "" {
			return wrapValidation(ErrInvalidScope)
		}
		for _, banned := range bannedScopeKeys {
			if strings.EqualFold(k, banned) {
				return wrapValidation(ErrCredentialShapedKey,
					func(d *ValidationDetail) { d.BannedKey = k })
			}
		}
		if s.rejectSecretValues {
			for _, re := range secretValuePatterns {
				if re.MatchString(v) {
					return wrapValidation(ErrSecretShapedValue,
						func(d *ValidationDetail) { d.Field = k })
				}
			}
		}
	}
	return nil
}

// validateScopeShape runs after key-level checks. Confirms every
// required key is present + no unknown keys are present.
func validateScopeShape(t storage.ProviderConnectionType, scope map[string]string) error {
	shape, ok := scopeShapes[t]
	if !ok {
		// Caller is expected to validate type first.
		return wrapValidation(ErrInvalidScope)
	}
	missing := []string{}
	for _, req := range shape.required {
		if v, ok := scope[req]; !ok || strings.TrimSpace(v) == "" {
			missing = append(missing, req)
		}
	}
	allowed := map[string]bool{}
	for _, k := range shape.allowed {
		allowed[k] = true
	}
	unknown := []string{}
	for k := range scope {
		if !allowed[k] {
			unknown = append(unknown, k)
		}
	}
	if len(missing) > 0 || len(unknown) > 0 {
		return wrapValidation(ErrInvalidScope, func(d *ValidationDetail) {
			d.MissingKeys = missing
			d.UnknownKeys = unknown
		})
	}
	return nil
}

// validateAuthMethod confirms the auth method is allowed for the
// provider type. Empty auth method is rejected.
func validateAuthMethod(t storage.ProviderConnectionType, method string) error {
	if method == "" {
		return wrapValidation(ErrInvalidAuthMethod)
	}
	allowed, ok := authMethodsByType[t]
	if !ok {
		return wrapValidation(ErrInvalidAuthMethod)
	}
	for _, a := range allowed {
		if a == method {
			return nil
		}
	}
	return wrapValidation(ErrInvalidAuthMethod)
}

// validateSemantic runs the per-type URL + ARN checks. Called after
// the shape check so required fields are guaranteed present.
func (s *ProviderConnectionsService) validateSemantic(t storage.ProviderConnectionType, scope map[string]string) error {
	switch t {
	case storage.ProviderConnectionTypeVault:
		if addr, ok := scope["address"]; ok {
			if err := s.validateProviderURL("address", addr, true); err != nil {
				return err
			}
		}
	case storage.ProviderConnectionTypeAWSSM:
		if arn, ok := scope["roleArn"]; ok && arn != "" {
			if !roleArnRe.MatchString(arn) {
				return wrapValidation(ErrInvalidRoleArn)
			}
		}
		if endpoint, ok := scope["endpoint"]; ok && endpoint != "" {
			if err := s.validateProviderURL("endpoint", endpoint, false); err != nil {
				return err
			}
		}
	case storage.ProviderConnectionTypeGCPSM:
		if endpoint, ok := scope["endpoint"]; ok && endpoint != "" {
			if err := s.validateProviderURL("endpoint", endpoint, false); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateProviderURL parses the URL and refuses:
//   - non-http/https schemes (always)
//   - http:// for Vault unless allowInsecureVaultAddr=true (caller
//     passes vaultSemantics=true to enforce)
//   - userinfo present (always)
//   - token/auth/secret query-string keys (always)
func (s *ProviderConnectionsService) validateProviderURL(field, raw string, vaultSemantics bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return wrapValidation(ErrInvalidProviderURL,
			func(d *ValidationDetail) { d.Field = field; d.Reason = "malformed" })
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return wrapValidation(ErrInvalidProviderURL,
			func(d *ValidationDetail) { d.Field = field; d.Reason = "scheme_not_allowed" })
	}
	if vaultSemantics && scheme == "http" && !s.allowInsecureVaultAddr {
		return wrapValidation(ErrInvalidProviderURL,
			func(d *ValidationDetail) { d.Field = field; d.Reason = "scheme_not_allowed" })
	}
	if u.User != nil {
		return wrapValidation(ErrInvalidProviderURL,
			func(d *ValidationDetail) { d.Field = field; d.Reason = "userinfo_present" })
	}
	for k := range u.Query() {
		low := strings.ToLower(k)
		if low == "token" || low == "auth" || low == "secret" {
			return wrapValidation(ErrInvalidProviderURL,
				func(d *ValidationDetail) { d.Field = field; d.Reason = "token_in_query" })
		}
	}
	return nil
}

// validateCommon runs the shared rules used by Create + Update.
// Returns the first violation in §3-locked order:
//
//   1. name regex
//   2. auth_method ∈ per-type allowed
//   3. credential-shaped key refusal
//   4. secret-shaped value detection
//   5. shape check
//   6. semantic checks (URL / ARN)
//   7. cluster_name regex
//   8. description ≤ 500
//   9. discover_enabled requires cluster_name
//   10. discover_interval_seconds 60-86400
func (s *ProviderConnectionsService) validateCommon(
	name string,
	t storage.ProviderConnectionType,
	authMethod string,
	scope map[string]string,
	clusterName string,
	description string,
	discoverEnabled bool,
	discoverInterval int,
) error {
	if !nameRe.MatchString(name) {
		return wrapValidation(ErrInvalidName)
	}
	if _, known := scopeShapes[t]; !known {
		return wrapValidation(ErrInvalidScope)
	}
	if err := validateAuthMethod(t, authMethod); err != nil {
		return err
	}
	if err := s.validateScopeKeys(scope); err != nil {
		return err
	}
	if err := validateScopeShape(t, scope); err != nil {
		return err
	}
	if err := s.validateSemantic(t, scope); err != nil {
		return err
	}
	if clusterName != "" && !clusterNameRe.MatchString(clusterName) {
		return wrapValidation(ErrInvalidClusterName)
	}
	if l := len(strings.TrimSpace(description)); l > descriptionMaxLen {
		return wrapValidation(ErrDescriptionTooLong, func(d *ValidationDetail) {
			d.Length = l
			d.Cap = descriptionMaxLen
		})
	}
	if discoverEnabled && clusterName == "" {
		return wrapValidation(ErrDiscoverRequiresCluster)
	}
	if discoverInterval < 60 || discoverInterval > 86400 {
		return wrapValidation(ErrInvalidDiscoverInterval)
	}
	return nil
}

// ---- service methods ----------------------------------------------

// ValidateCreate runs the full validation pass on a CreateInput
// without touching the repository. Handlers in P3 use it for early
// rejection (e.g. before authorisation lookups). Pure-validation
// tests use it to avoid the nil-repo panic on happy-path payloads.
func (s *ProviderConnectionsService) ValidateCreate(in CreateInput) error {
	return s.validateCommon(in.Name, in.Type, in.AuthMethod, in.Scope,
		in.ClusterName, in.Description, in.DiscoverEnabled, in.DiscoverIntervalSeconds)
}

// Create validates + persists a new provider_connections row.
// UNIQUE name conflicts surface as storage.ErrConnectionNameTaken
// (handlers map to 409 connection_name_taken).
func (s *ProviderConnectionsService) Create(ctx context.Context, in CreateInput) (*storage.ProviderConnection, error) {
	if err := s.ValidateCreate(in); err != nil {
		return nil, err
	}
	status := in.Status
	if status == "" {
		status = storage.ProviderConnectionStatusActive
	}
	ssb := in.SelfServiceBindable
	created, err := s.repo.Create(ctx, storage.ProviderConnectionInput{
		Name:                    in.Name,
		Type:                    in.Type,
		AuthMethod:              in.AuthMethod,
		Scope:                   in.Scope,
		Status:                  status,
		ClusterName:             in.ClusterName,
		Description:             strings.TrimSpace(in.Description),
		DiscoverEnabled:         in.DiscoverEnabled,
		DiscoverIntervalSeconds: in.DiscoverIntervalSeconds,
		SelfServiceBindable:     &ssb,
	})
	if err != nil {
		return nil, err
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:         actorOrAdmin(in.ActorID),
		Action:        "provider_connection.create",
		Resource:      "provider_connection:" + created.ID.String(),
		Status:        storage.AuditStatusSuccess,
		CorrelationID: in.CorrelationID,
		Metadata: map[string]any{
			"name":             created.Name,
			"type":             string(created.Type),
			"cluster_name":     created.ClusterName,
			"discover_enabled": created.DiscoverEnabled,
		},
	})
	return created, nil
}

// Update validates + persists changes. Type is immutable — if the
// caller passes a different Type than the stored row, the service
// returns ErrTypeImmutable.
func (s *ProviderConnectionsService) Update(ctx context.Context, id uuid.UUID, in UpdateInput) (*storage.ProviderConnection, error) {
	existing, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := s.validateCommon(in.Name, existing.Type, in.AuthMethod, in.Scope,
		in.ClusterName, in.Description, in.DiscoverEnabled, in.DiscoverIntervalSeconds); err != nil {
		return nil, err
	}
	status := in.Status
	if status == "" {
		status = existing.Status
	}
	changed := diffChangedKeys(existing, in, status)
	updated, err := s.repo.Update(ctx, id, storage.ProviderConnectionInput{
		Name:                    in.Name,
		Type:                    existing.Type,
		AuthMethod:              in.AuthMethod,
		Scope:                   in.Scope,
		Status:                  status,
		ClusterName:             in.ClusterName,
		Description:             strings.TrimSpace(in.Description),
		DiscoverEnabled:         in.DiscoverEnabled,
		DiscoverIntervalSeconds: in.DiscoverIntervalSeconds,
		SelfServiceBindable:     in.SelfServiceBindable,
	})
	if err != nil {
		return nil, err
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:         actorOrAdmin(in.ActorID),
		Action:        "provider_connection.update",
		Resource:      "provider_connection:" + updated.ID.String(),
		Status:        storage.AuditStatusSuccess,
		CorrelationID: in.CorrelationID,
		Metadata: map[string]any{
			"name":         updated.Name,
			"type":         string(updated.Type),
			"changed_keys": changed,
		},
	})
	return updated, nil
}

// Delete pre-flights the in-use check + emits the audit event with
// the binding + open-request counts captured at delete time.
//
// Returns (counts, ErrConnectionInUse) when the connection is bound
// or referenced by an open request — handlers map to 409
// connection_in_use with the counts in the body.
func (s *ProviderConnectionsService) Delete(ctx context.Context, id uuid.UUID, actorID string, correlationID uuid.UUID) (DeleteCounts, error) {
	existing, err := s.repo.Get(ctx, id)
	if err != nil {
		return DeleteCounts{}, err
	}
	bindings, err := s.repo.CountBindings(ctx, id)
	if err != nil {
		return DeleteCounts{}, err
	}
	openReqs, err := s.repo.CountOpenRequests(ctx, id)
	if err != nil {
		return DeleteCounts{}, err
	}
	counts := DeleteCounts{BindingsCount: bindings, OpenRequestsCount: openReqs}
	if bindings > 0 || openReqs > 0 {
		return counts, storage.ErrConnectionInUse
	}
	if err := s.repo.Delete(ctx, id); err != nil {
		return counts, err
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:         actorOrAdmin(actorID),
		Action:        "provider_connection.delete",
		Resource:      "provider_connection:" + existing.ID.String(),
		Status:        storage.AuditStatusSuccess,
		CorrelationID: correlationID,
		Metadata: map[string]any{
			"name":                          existing.Name,
			"type":                          string(existing.Type),
			"bindings_count_at_delete":      bindings,
			"open_requests_count_at_delete": openReqs,
		},
	})
	return counts, nil
}

// Get returns a single connection row by id.
func (s *ProviderConnectionsService) Get(ctx context.Context, id uuid.UUID) (*storage.ProviderConnection, error) {
	return s.repo.Get(ctx, id)
}

// List passes through the filter to the repository.
func (s *ProviderConnectionsService) List(ctx context.Context, f storage.ProviderConnectionListFilter) ([]*storage.ProviderConnection, error) {
	return s.repo.List(ctx, f)
}

// Bind adds a project_provider_connections row. Emits the
// provider_connection.bind audit event.
func (s *ProviderConnectionsService) Bind(ctx context.Context, in BindInput) (*storage.ProjectProviderConnectionBinding, error) {
	purpose := in.Purpose
	if purpose == "" {
		purpose = storage.ProjectProviderConnectionPurposeDestination
	}
	b, err := s.bindings.Bind(ctx, storage.ProjectProviderConnectionBindingInput{
		ProjectID:            in.ProjectID,
		EnvironmentID:        in.EnvironmentID,
		ProviderConnectionID: in.ConnectionID,
		Purpose:              purpose,
		CreatedBy:            in.ActorID,
	})
	if err != nil {
		return nil, err
	}
	envIDMeta := ""
	if b.EnvironmentID != nil {
		envIDMeta = b.EnvironmentID.String()
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    actorOrAdmin(in.ActorID),
		Action:   "provider_connection.bind",
		Resource: "provider_connection:" + in.ConnectionID.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: map[string]any{
			"connection_id":  in.ConnectionID.String(),
			"project_id":     in.ProjectID.String(),
			"environment_id": envIDMeta,
			"purpose":        string(purpose),
		},
	})
	return b, nil
}

// Unbind removes a binding by id + emits the unbind audit event.
func (s *ProviderConnectionsService) Unbind(ctx context.Context, bindingID uuid.UUID, actorID string) error {
	b, err := s.bindings.GetBinding(ctx, bindingID)
	if err != nil {
		return err
	}
	if err := s.bindings.Unbind(ctx, bindingID); err != nil {
		return err
	}
	envIDMeta := ""
	if b.EnvironmentID != nil {
		envIDMeta = b.EnvironmentID.String()
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    actorOrAdmin(actorID),
		Action:   "provider_connection.unbind",
		Resource: "provider_connection:" + b.ProviderConnectionID.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: map[string]any{
			"connection_id":  b.ProviderConnectionID.String(),
			"project_id":     b.ProjectID.String(),
			"environment_id": envIDMeta,
			"purpose":        string(b.Purpose),
		},
	})
	return nil
}

// ListBindings returns every binding referencing the given connection.
// Used by the admin UI's edit drawer.
func (s *ProviderConnectionsService) ListBindings(ctx context.Context, connectionID uuid.UUID) ([]*storage.ProjectProviderConnectionBinding, error) {
	return s.bindings.ListForConnection(ctx, connectionID)
}

// ListForProjectEnv is the developer dropdown surface. Returns the
// sanitized ProviderConnectionSummary projection; the handler in P3
// gates this with `secret.request` scoped to (project, environment).
//
// NO audit event — per §3 Q1 sign-off, dropdown reads are not audited.
func (s *ProviderConnectionsService) ListForProjectEnv(ctx context.Context, projectID uuid.UUID, envID uuid.UUID) ([]storage.ProviderConnectionSummary, error) {
	return s.bindings.ListForProjectEnv(ctx, projectID, envID)
}

// ListDueForDiscovery is the worker scheduler surface. Returns the
// value-free DiscoverTarget projection.
func (s *ProviderConnectionsService) ListDueForDiscovery(ctx context.Context, now time.Time) ([]storage.DiscoverTarget, error) {
	return s.repo.ListDueForDiscovery(ctx, now)
}

// MarkDiscoverStarted flips the row to status=running. Called by the
// worker scheduler BEFORE enqueueing the discover job.
func (s *ProviderConnectionsService) MarkDiscoverStarted(ctx context.Context, id uuid.UUID, now time.Time) error {
	return s.repo.MarkDiscoverStarted(ctx, id, now)
}

// MarkDiscoverFinished writes a terminal status + sanitizes the
// error string BEFORE persistence. The sanitizer runs even when the
// worker pre-sanitized — two layers because the consequence of a
// credential landing in last_discover_error is irreversible.
//
// Emits the provider_connection.discover_finished audit event with
// has_error: bool. The error text itself is NEVER in audit metadata.
func (s *ProviderConnectionsService) MarkDiscoverFinished(ctx context.Context, id uuid.UUID, status, rawErr string, now time.Time) error {
	clean := sanitize.DiscoverError(rawErr)
	if err := s.repo.MarkDiscoverFinished(ctx, id, status, clean, now); err != nil {
		return err
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "worker",
		Action:   "provider_connection.discover_finished",
		Resource: "provider_connection:" + id.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: map[string]any{
			"connection_id": id.String(),
			"status":        status,
			"has_error":     clean != "",
		},
	})
	return nil
}

// OnDiscoverJobCompleted is the JobService.OnCompleted hook. Filters
// to discover-typed jobs and routes them to MarkDiscoverFinished
// with the worker's reported status. P3 wires this in main.go
// alongside RequestService.OnJobCompleted.
//
// The job's Payload carries the connection_id; if missing, the hook
// is a silent no-op (best effort — discover jobs created outside
// this service won't have the key).
func (s *ProviderConnectionsService) OnDiscoverJobCompleted(ctx context.Context, job *storage.SyncJob) {
	if job == nil || job.JobType != storage.JobTypeDiscover {
		return
	}
	rawID, ok := job.Payload["connection_id"].(string)
	if !ok || rawID == "" {
		return
	}
	id, err := uuid.Parse(rawID)
	if err != nil {
		return
	}
	status := storage.DiscoverStatusFailure
	if job.Status == storage.JobStatusSucceeded {
		status = storage.DiscoverStatusSuccess
	}
	_ = s.MarkDiscoverFinished(ctx, id, status, job.Error, time.Now())
}

// ---- helpers ------------------------------------------------------

func actorOrAdmin(id string) string {
	if id == "" {
		return "admin"
	}
	return id
}

// diffChangedKeys returns the column names that differ between an
// existing row and the incoming Update input. Used for the audit
// metadata changed_keys field — operators see "scope, status" without
// the values themselves landing in the audit table.
func diffChangedKeys(existing *storage.ProviderConnection, in UpdateInput, status storage.ProviderConnectionStatus) []string {
	out := []string{}
	if existing.Name != in.Name {
		out = append(out, "name")
	}
	if existing.AuthMethod != in.AuthMethod {
		out = append(out, "auth_method")
	}
	if !sameStringMap(existing.Scope, in.Scope) {
		out = append(out, "scope")
	}
	if existing.ClusterName != in.ClusterName {
		out = append(out, "cluster_name")
	}
	if strings.TrimSpace(existing.Description) != strings.TrimSpace(in.Description) {
		out = append(out, "description")
	}
	if existing.Status != status {
		out = append(out, "status")
	}
	if existing.DiscoverEnabled != in.DiscoverEnabled {
		out = append(out, "discover_enabled")
	}
	if existing.DiscoverIntervalSeconds != in.DiscoverIntervalSeconds {
		out = append(out, "discover_interval_seconds")
	}
	return out
}

func sameStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		if vb, ok := b[k]; !ok || vb != va {
			return false
		}
	}
	return true
}

