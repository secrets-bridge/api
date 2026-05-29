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
