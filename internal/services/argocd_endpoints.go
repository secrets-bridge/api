// Package services — argocd_endpoints.go: per-environment ArgoCD
// endpoint registration + KMS-wrapped token handling.
//
// The plaintext token is accepted ONCE at create / rotate; the service
// immediately envelope-encrypts it via the configured KeyManager
// backend and stores the resulting `{ciphertext, nonce, dek_ciphertext,
// kms_key_id}` envelope in argocd_endpoints. PostgreSQL NEVER sees
// the plaintext.
//
// Decrypt happens inside this package on demand (when the observation
// worker needs to call ArgoCD). Callers MUST zero the returned token
// after the HTTP call completes.
package services

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/keymgmt"
	"github.com/secrets-bridge/api/pkg/storage"
)

// ArgoCDEndpointService manages argocd_endpoints + the token envelope.
type ArgoCDEndpointService struct {
	repo  storage.ArgoCDEndpointRepository
	km    keymgmt.KeyManager
	audit storage.AuditEventRepository
}

// NewArgoCDEndpointService binds the service.
func NewArgoCDEndpointService(repo storage.ArgoCDEndpointRepository, km keymgmt.KeyManager, audit storage.AuditEventRepository) *ArgoCDEndpointService {
	return &ArgoCDEndpointService{repo: repo, km: km, audit: audit}
}

// CreateInput is the data the admin handler POSTs.
//
// Token is the plaintext ArgoCD account token. The service envelope-
// encrypts it via KeyManager and zeroes the slice before returning;
// callers MUST NOT reuse it.
type CreateArgoCDEndpointInput struct {
	Name          string
	EnvironmentID *uuid.UUID
	BaseURL       string
	Token         []byte // plaintext; zeroed by the service after wrap
	TLSCAPEM      string
	TLSServerName string
}

// Create wraps the token via KeyManager and persists the row.
func (s *ArgoCDEndpointService) Create(ctx context.Context, in CreateArgoCDEndpointInput) (*storage.ArgoCDEndpoint, error) {
	if in.Name == "" {
		return nil, errors.New("services: argocd endpoint name required")
	}
	if in.BaseURL == "" {
		return nil, errors.New("services: argocd endpoint base url required")
	}
	if len(in.Token) == 0 {
		return nil, errors.New("services: argocd endpoint token required")
	}
	if s.km == nil {
		return nil, errors.New("services: KeyManager not configured")
	}
	dek, err := s.km.GenerateDataKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("services: generate dek: %w", err)
	}
	defer zero(dek.Plaintext)
	ct, nonce, err := encryptArgoCDToken(in.Token, dek.Plaintext)
	zero(in.Token)
	if err != nil {
		return nil, fmt.Errorf("services: encrypt token: %w", err)
	}
	e := &storage.ArgoCDEndpoint{
		Name:                    in.Name,
		EnvironmentID:           in.EnvironmentID,
		BaseURL:                 in.BaseURL,
		TokenCiphertext:         ct,
		TokenDataKeyCiphertext:  dek.Ciphertext,
		TokenNonce:              nonce,
		TokenKMSKeyID:           dek.KeyID,
		TLSCAPEM:                in.TLSCAPEM,
		TLSServerName:           in.TLSServerName,
		Enabled:                 true,
	}
	if err := s.repo.Create(ctx, e); err != nil {
		return nil, fmt.Errorf("services: persist argocd endpoint: %w", err)
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "admin",
		Action:   "argocd_endpoint.create",
		Resource: "argocd_endpoint:" + e.ID.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: map[string]any{
			"name":         e.Name,
			"base_url":     e.BaseURL,
			"kms_key_id":   e.TokenKMSKeyID,
			"environment":  e.EnvironmentID,
		},
	})
	return e, nil
}

// Get returns the row WITHOUT the decrypted token. Use ResolveToken
// when you need the plaintext.
func (s *ArgoCDEndpointService) Get(ctx context.Context, id uuid.UUID) (*storage.ArgoCDEndpoint, error) {
	return s.repo.Get(ctx, id)
}

// List returns every active endpoint.
func (s *ArgoCDEndpointService) List(ctx context.Context) ([]*storage.ArgoCDEndpoint, error) {
	return s.repo.List(ctx)
}

// ResolveToken decrypts the endpoint's token and returns it. Caller
// MUST zero the returned slice after use.
func (s *ArgoCDEndpointService) ResolveToken(ctx context.Context, e *storage.ArgoCDEndpoint) ([]byte, error) {
	if e == nil {
		return nil, errors.New("services: nil endpoint")
	}
	if s.km == nil {
		return nil, errors.New("services: KeyManager not configured")
	}
	dek, err := s.km.DecryptDataKey(ctx, e.TokenDataKeyCiphertext, e.TokenKMSKeyID)
	if err != nil {
		return nil, fmt.Errorf("services: decrypt dek: %w", err)
	}
	defer zero(dek)
	return decryptArgoCDToken(e.TokenCiphertext, e.TokenNonce, dek)
}

// SetEnabled toggles the enabled flag.
func (s *ArgoCDEndpointService) SetEnabled(ctx context.Context, id uuid.UUID, enabled bool) error {
	if err := s.repo.SetEnabled(ctx, id, enabled); err != nil {
		return err
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "admin",
		Action:   "argocd_endpoint.set_enabled",
		Resource: "argocd_endpoint:" + id.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: map[string]any{"enabled": enabled},
	})
	return nil
}

// SoftDelete removes the row. Audit history that references the
// argocd_endpoint_id stays resolvable because we soft-delete.
func (s *ArgoCDEndpointService) SoftDelete(ctx context.Context, id uuid.UUID) error {
	if err := s.repo.SoftDelete(ctx, id); err != nil {
		return err
	}
	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "admin",
		Action:   "argocd_endpoint.delete",
		Resource: "argocd_endpoint:" + id.String(),
		Status:   storage.AuditStatusSuccess,
	})
	return nil
}

// Discover calls ArgoCD via the configured endpoint and returns the
// list of applications visible to the registered token. Used by the
// admin UI's bulk-create-from-discovered-apps flow.
//
// `project` is an optional ArgoCD project name filter. Empty = no
// filter.
//
// Audits a `argocd_endpoint.discover` event with the count of apps
// returned and the filter (if any) in metadata. NEVER persists the
// returned data.
//
// The caller (handler) supplies a `factory` that knows how to build
// an `AppLister` from a Config — keeping the service test-friendly
// (real factory wraps argocd.New; tests inject a fake).
func (s *ArgoCDEndpointService) Discover(
	ctx context.Context,
	id uuid.UUID,
	project string,
	factory ArgoCDClientFactory,
) ([]DiscoveredApp, error) {
	ep, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if !ep.Enabled {
		return nil, errors.New("services: endpoint is disabled")
	}
	tok, err := s.ResolveToken(ctx, ep)
	if err != nil {
		return nil, fmt.Errorf("services: resolve token: %w", err)
	}
	defer zero(tok)

	client, err := factory(ArgoCDClientConfig{
		BaseURL:       ep.BaseURL,
		Token:         string(tok),
		TLSCAPEM:      ep.TLSCAPEM,
		TLSServerName: ep.TLSServerName,
	})
	if err != nil {
		return nil, fmt.Errorf("services: build argocd client: %w", err)
	}

	apps, err := client.ListApplications(ctx, project)
	if err != nil {
		_ = s.audit.Append(ctx, &storage.AuditEvent{
			Actor:    "admin",
			Action:   "argocd_endpoint.discover",
			Resource: "argocd_endpoint:" + id.String(),
			Status:   storage.AuditStatusFailure,
			Metadata: map[string]any{"project_filter": project, "error_kind": "list_failed"},
		})
		return nil, fmt.Errorf("services: list applications: %w", err)
	}

	_ = s.audit.Append(ctx, &storage.AuditEvent{
		Actor:    "admin",
		Action:   "argocd_endpoint.discover",
		Resource: "argocd_endpoint:" + id.String(),
		Status:   storage.AuditStatusSuccess,
		Metadata: map[string]any{"project_filter": project, "app_count": len(apps)},
	})
	return apps, nil
}

// ArgoCDClientConfig is the slim subset of pkg/argocd.Config the
// service needs. Decoupled so the service doesn't import pkg/argocd
// at compile time — keeps the factory injectable for tests.
type ArgoCDClientConfig struct {
	BaseURL       string
	Token         string
	TLSCAPEM      string
	TLSServerName string
}

// AppLister is the interface the service uses to call ArgoCD. The real
// implementation is `*argocd.Client`; tests inject a fake.
type AppLister interface {
	ListApplications(ctx context.Context, project string) ([]DiscoveredApp, error)
}

// ArgoCDClientFactory builds an AppLister from a config. The real
// factory wraps pkg/argocd.New; the wiring lives in cmd/api/main.go
// so this package doesn't drag pkg/argocd into its imports.
type ArgoCDClientFactory func(ArgoCDClientConfig) (AppLister, error)

// DiscoveredApp is the trimmed shape returned to the admin UI. Mirrors
// the relevant subset of pkg/argocd.Application — kept here so callers
// don't have to import pkg/argocd to consume the result.
//
// NO manifests, NO sync revisions of secrets, NO sensitive metadata.
type DiscoveredApp struct {
	Name                 string `json:"name"`
	Namespace            string `json:"namespace,omitempty"`
	Project              string `json:"project,omitempty"`
	DestinationServer    string `json:"destination_server,omitempty"`
	DestinationCluster   string `json:"destination_cluster,omitempty"`
	DestinationNamespace string `json:"destination_namespace,omitempty"`
	HealthStatus         string `json:"health_status,omitempty"`
	SyncStatus           string `json:"sync_status,omitempty"`
}

// UpdateHealth pass-through wrapper.
func (s *ArgoCDEndpointService) UpdateHealth(ctx context.Context, id uuid.UUID, ok bool, errMsg string) error {
	healthErr := errMsg
	if ok {
		healthErr = ""
	}
	return s.repo.UpdateHealth(ctx, id, time.Now(), healthErr)
}

// encryptArgoCDToken AES-256-GCMs the token with the DEK.
func encryptArgoCDToken(plaintext, dek []byte) (ciphertext, nonce []byte, err error) {
	if len(dek) != 32 {
		return nil, nil, fmt.Errorf("services: DEK must be 32 bytes, got %d", len(dek))
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, nil, fmt.Errorf("services: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("services: gcm: %w", err)
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("services: random nonce: %w", err)
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// decryptArgoCDToken reverses encryptArgoCDToken.
func decryptArgoCDToken(ciphertext, nonce, dek []byte) ([]byte, error) {
	if len(dek) != 32 {
		return nil, fmt.Errorf("services: DEK must be 32 bytes, got %d", len(dek))
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("services: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("services: gcm: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("services: aes-gcm open: %w", err)
	}
	return plaintext, nil
}
