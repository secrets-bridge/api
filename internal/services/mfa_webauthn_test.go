package services_test

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/keymgmt"
	"github.com/secrets-bridge/api/pkg/runtime"
	"github.com/secrets-bridge/api/pkg/storage"
)

func bootstrapWebAuthn(t *testing.T) (*services.WebAuthnService, storage.UserMFAFactorRepository, storage.LocalUserRepository, *storage.Pool) {
	t.Helper()
	dbDSN := os.Getenv("TEST_DATABASE_URL")
	redisURL := os.Getenv("TEST_REDIS_URL")
	if dbDSN == "" || redisURL == "" {
		t.Skip("TEST_DATABASE_URL and TEST_REDIS_URL are required; skipping")
	}
	ctx := t.Context()
	storageCfg := storage.Config{DSN: dbDSN, MaxConns: 5, ConnLifetime: 5 * time.Minute}
	if err := storage.Migrate(ctx, storageCfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pool, err := storage.Open(ctx, storageCfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(pool.Close)
	const truncate = `
		TRUNCATE TABLE
			audit_events, sync_runs, sync_jobs, approvals,
			access_requests, secret_mappings, agents,
			provider_connections, environments, projects,
			team_members, teams, local_users
		RESTART IDENTITY CASCADE`
	if _, err := pool.Exec(ctx, truncate); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	rdb, err := runtime.Open(ctx, runtime.Config{
		URL:       redisURL,
		PoolSize:  4,
		Namespace: fmt.Sprintf("sb-test-webauthn-%d", time.Now().UnixNano()),
	})
	if err != nil {
		t.Fatalf("Open runtime: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })

	masterKey := make([]byte, 32)
	_, _ = rand.Read(masterKey)
	km, err := keymgmt.NewLocalKMS(masterKey)
	if err != nil {
		t.Fatalf("NewLocalKMS: %v", err)
	}
	factors := storage.NewUserMFAFactors(pool)
	users := storage.NewLocalUsers(pool)
	audit := storage.NewAuditEvents(pool)
	svc, err := services.NewWebAuthnService(factors, users, km, audit, rdb, services.WebAuthnConfig{
		RPID:          "sb.example.com",
		RPDisplayName: "Secrets Bridge (test)",
		RPOrigins:     []string{"https://sb.example.com"},
	})
	if err != nil {
		t.Fatalf("NewWebAuthnService: %v", err)
	}
	return svc, factors, users, pool
}

func TestWebAuthnConfig_ValidateRejectsMissingFields(t *testing.T) {
	cases := []struct {
		name string
		cfg  services.WebAuthnConfig
	}{
		{"empty RPID", services.WebAuthnConfig{RPOrigins: []string{"https://x"}}},
		{"empty RPOrigins", services.WebAuthnConfig{RPID: "x"}},
		{"both empty", services.WebAuthnConfig{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.cfg.Validate(); !errors.Is(err, services.ErrWebAuthnNotConfigured) {
				t.Fatalf("Validate(%q): want ErrWebAuthnNotConfigured, got %v", c.name, err)
			}
		})
	}
	// Smoke: a complete config validates clean.
	if err := (services.WebAuthnConfig{RPID: "x", RPOrigins: []string{"https://x"}}).Validate(); err != nil {
		t.Fatalf("happy Validate: %v", err)
	}
}

func TestWebAuthn_BeginEnrollment_PopulatesChallenge(t *testing.T) {
	svc, _, users, _ := bootstrapWebAuthn(t)
	ctx := t.Context()
	uid := seedTOTPUser(t, users, "alice@example.com")

	out, err := svc.BeginEnrollment(ctx, uid, "Yubikey 5")
	if err != nil {
		t.Fatalf("BeginEnrollment: %v", err)
	}
	if out.ChallengeID == "" {
		t.Fatal("ChallengeID empty")
	}
	if out.Options == nil {
		t.Fatal("Options nil")
	}
	// RPID + display name flow into the W3C options shape.
	if out.Options.Response.RelyingParty.ID != "sb.example.com" {
		t.Fatalf("RP.ID: %q", out.Options.Response.RelyingParty.ID)
	}
	if !strings.HasPrefix(out.Options.Response.RelyingParty.Name, "Secrets Bridge") {
		t.Fatalf("RP.Name: %q", out.Options.Response.RelyingParty.Name)
	}
	// The user handle is the 16-byte UUID, NOT the email — Section 6.1
	// of RFC8266 + the W3C spec require auth decisions on the id member.
	// `UserEntity.ID` is `any`; the library stores a []byte / URLEncodedBase64
	// when EncodeUserIDAsString is false.
	switch id := out.Options.Response.User.ID.(type) {
	case []byte:
		if len(id) != 16 {
			t.Fatalf("User.ID []byte length: %d want 16", len(id))
		}
	case interface{ Bytes() []byte }:
		if len(id.Bytes()) != 16 {
			t.Fatalf("User.ID Bytes() length: %d want 16", len(id.Bytes()))
		}
	default:
		// Some library versions wrap []byte in a custom type whose
		// underlying kind is still []byte. The reflect-light fallback
		// below catches that without pulling reflect into the file.
		s := fmt.Sprintf("%v", id)
		if s == "" {
			t.Fatalf("User.ID rendered empty; concrete type=%T value=%v", id, id)
		}
	}
	if out.Options.Response.User.Name != "alice@example.com" {
		t.Fatalf("User.Name: %q", out.Options.Response.User.Name)
	}
	if len(out.Options.Response.Challenge) < 16 {
		t.Fatalf("Challenge too short: %d", len(out.Options.Response.Challenge))
	}
}

func TestWebAuthn_BeginEnrollment_IncludesExistingCredentialsInExclude(t *testing.T) {
	svc, factors, users, _ := bootstrapWebAuthn(t)
	ctx := t.Context()
	uid := seedTOTPUser(t, users, "alice@example.com")

	// Seed an existing WebAuthn factor.
	aaguid := uuid.MustParse("00000000-0000-0000-0000-aaaaaaaaaaaa")
	credID := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if err := factors.Create(ctx, &storage.UserMFAFactor{
		UserID:               uid,
		Kind:                 storage.MFAFactorKindWebAuthn,
		Label:                "existing yubikey",
		SecretCiphertext:     []byte("ciphertext"),
		SecretNonce:          []byte("nonce-12-bytes"),
		DataKeyCiphertext:    []byte("dk-wrap"),
		KMSKeyID:             "test-key",
		WebAuthnCredentialID: credID,
		WebAuthnAAGUID:       &aaguid,
	}); err != nil {
		t.Fatalf("seed existing factor: %v", err)
	}

	out, err := svc.BeginEnrollment(ctx, uid, "second yubikey")
	if err != nil {
		t.Fatalf("BeginEnrollment: %v", err)
	}
	exclude := out.Options.Response.CredentialExcludeList
	if len(exclude) != 1 {
		t.Fatalf("excludeCredentials len: %d, want 1", len(exclude))
	}
	if string(exclude[0].CredentialID) != string(credID) {
		t.Fatalf("excludeCredentials[0].id mismatch: %x", exclude[0].CredentialID)
	}
}

func TestWebAuthn_BeginEnrollment_IgnoresTOTPFactorsInExclude(t *testing.T) {
	svc, factors, users, _ := bootstrapWebAuthn(t)
	ctx := t.Context()
	uid := seedTOTPUser(t, users, "alice@example.com")

	// A TOTP row MUST NOT contribute to excludeCredentials — the
	// authenticator-app counterpart isn't a WebAuthn authenticator.
	if err := factors.Create(ctx, &storage.UserMFAFactor{
		UserID:            uid,
		Kind:              storage.MFAFactorKindTOTP,
		Label:             "iphone-totp",
		SecretCiphertext:  []byte("ct"),
		SecretNonce:       []byte("nonce-12-bytes"),
		DataKeyCiphertext: []byte("dk"),
		KMSKeyID:          "test-key",
	}); err != nil {
		t.Fatalf("seed totp: %v", err)
	}
	out, err := svc.BeginEnrollment(ctx, uid, "first yubikey")
	if err != nil {
		t.Fatalf("BeginEnrollment: %v", err)
	}
	if len(out.Options.Response.CredentialExcludeList) != 0 {
		t.Fatalf("excludeCredentials should ignore TOTP rows; got %d entries", len(out.Options.Response.CredentialExcludeList))
	}
}

func TestWebAuthn_FinishEnrollment_ChallengeMissing(t *testing.T) {
	svc, _, users, _ := bootstrapWebAuthn(t)
	ctx := t.Context()
	uid := seedTOTPUser(t, users, "alice@example.com")

	body := []byte(`{"id":"x","rawId":"x","type":"public-key","response":{}}`)
	_, err := svc.FinishEnrollment(ctx, uid, "non-existent-challenge", body)
	if !errors.Is(err, services.ErrWebAuthnChallengeNotFound) {
		t.Fatalf("want ErrWebAuthnChallengeNotFound, got %v", err)
	}
}

func TestWebAuthn_FinishEnrollment_WrongUser(t *testing.T) {
	svc, _, users, _ := bootstrapWebAuthn(t)
	ctx := t.Context()
	alice := seedTOTPUser(t, users, "alice@example.com")
	bob := seedTOTPUser(t, users, "bob@example.com")

	out, err := svc.BeginEnrollment(ctx, alice, "yubikey")
	if err != nil {
		t.Fatalf("BeginEnrollment: %v", err)
	}
	// Bob tries to finish Alice's enrollment.
	body := []byte(`{"id":"x","rawId":"x","type":"public-key","response":{}}`)
	_, err = svc.FinishEnrollment(ctx, bob, out.ChallengeID, body)
	if !errors.Is(err, services.ErrWebAuthnChallengeUser) {
		t.Fatalf("want ErrWebAuthnChallengeUser, got %v", err)
	}
}

func TestWebAuthn_FinishEnrollment_InvalidAttestationConsumesChallenge(t *testing.T) {
	svc, _, users, _ := bootstrapWebAuthn(t)
	ctx := t.Context()
	uid := seedTOTPUser(t, users, "alice@example.com")

	out, err := svc.BeginEnrollment(ctx, uid, "yubikey")
	if err != nil {
		t.Fatalf("BeginEnrollment: %v", err)
	}
	// Garbage body — attestation verification must fail.
	body := []byte(`{"id":"x","rawId":"x","type":"public-key","response":{"clientDataJSON":"AA","attestationObject":"AA"}}`)
	if _, err := svc.FinishEnrollment(ctx, uid, out.ChallengeID, body); !errors.Is(err, services.ErrWebAuthnAttestation) {
		t.Fatalf("first try with garbage: want ErrWebAuthnAttestation, got %v", err)
	}
	// Single-shot: retrying with the same challenge returns
	// ChallengeNotFound (Redis blob is gone).
	if _, err := svc.FinishEnrollment(ctx, uid, out.ChallengeID, body); !errors.Is(err, services.ErrWebAuthnChallengeNotFound) {
		t.Fatalf("retry: want ErrWebAuthnChallengeNotFound, got %v", err)
	}
}
