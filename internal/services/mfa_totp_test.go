package services_test

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 mandates HMAC-SHA1 for TOTP
	"encoding/base32"
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

// bootstrapTOTP wires up a TOTP service against the live Postgres +
// Redis containers. SKIP when either env var is missing.
func bootstrapTOTP(t *testing.T) (*services.TOTPService, storage.UserMFAFactorRepository, storage.LocalUserRepository, *storage.Pool, *clockSource) {
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
		Namespace: fmt.Sprintf("sb-test-totp-%d", time.Now().UnixNano()),
	})
	if err != nil {
		t.Fatalf("Open runtime: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })

	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	km, err := keymgmt.NewLocalKMS(masterKey)
	if err != nil {
		t.Fatalf("NewLocalKMS: %v", err)
	}

	factors := storage.NewUserMFAFactors(pool)
	users := storage.NewLocalUsers(pool)
	audit := storage.NewAuditEvents(pool)
	clk := &clockSource{now: time.Unix(1_700_000_000, 0).UTC()}
	svc := services.NewTOTPService(factors, km, audit, rdb, services.TOTPConfig{
		Issuer: "Secrets Bridge (test)",
		Clock:  clk.Now,
	})
	return svc, factors, users, pool, clk
}

// clockSource lets tests advance time deterministically through the
// 30-second TOTP window.
type clockSource struct{ now time.Time }

func (c *clockSource) Now() time.Time     { return c.now }
func (c *clockSource) Advance(d time.Duration) { c.now = c.now.Add(d) }

func seedTOTPUser(t *testing.T, users storage.LocalUserRepository, email string) uuid.UUID {
	t.Helper()
	u := &storage.LocalUser{
		Email:        email,
		PasswordHash: []byte("$2a$10$dummybcryptdummybcryptdummybcryptdummybcryptdummybcryp"),
		DisplayName:  email,
	}
	if err := users.Create(t.Context(), u); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return u.ID
}

// readTOTPSecret reads the base32 secret out of an Enroll provisioning
// URI so the test can compute the expected 6-digit code.
func readTOTPSecret(t *testing.T, b32 string) []byte {
	t.Helper()
	if pad := len(b32) % 8; pad != 0 {
		b32 = b32 + strings.Repeat("=", 8-pad)
	}
	secret, err := base32.StdEncoding.DecodeString(b32)
	if err != nil {
		t.Fatalf("decode secret base32: %v", err)
	}
	return secret
}

// Reach into the package for the unexported generateTOTP. We can't
// import it from services_test, so this test recreates the algorithm
// for the verifier path — RFC 6238 §5.3 is short.
func expectedCode(t *testing.T, secret []byte, at time.Time) string {
	t.Helper()
	// We deliberately import services for any helper that's exported.
	// generateTOTP isn't, so the test mirrors the spec inline.
	step := uint64(at.Unix()) / 30
	return formatCode(hmacSHA1Truncated(secret, step))
}

func TestTOTP_EnrollAndConfirm_HappyPath(t *testing.T) {
	svc, factors, users, _, clk := bootstrapTOTP(t)
	ctx := t.Context()
	uid := seedTOTPUser(t, users, "alice@example.com")

	out, err := svc.Enroll(ctx, uid, "iPhone", "alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if out.ChallengeID == "" || out.SecretBase32 == "" || out.ProvisioningURI == "" {
		t.Fatalf("Enroll missing fields: %+v", out)
	}
	if !strings.HasPrefix(out.ProvisioningURI, "otpauth://totp/") {
		t.Fatalf("ProvisioningURI: %q", out.ProvisioningURI)
	}

	secret := readTOTPSecret(t, out.SecretBase32)
	code := expectedCode(t, secret, clk.Now())

	factor, err := svc.ConfirmEnroll(ctx, uid, out.ChallengeID, code)
	if err != nil {
		t.Fatalf("ConfirmEnroll: %v", err)
	}
	if factor.Kind != storage.MFAFactorKindTOTP {
		t.Fatalf("Kind: %q", factor.Kind)
	}
	if factor.Label != "iPhone" {
		t.Fatalf("Label: %q", factor.Label)
	}
	persisted, err := factors.Get(ctx, factor.ID)
	if err != nil {
		t.Fatalf("Get after confirm: %v", err)
	}
	if len(persisted.SecretCiphertext) == 0 || persisted.KMSKeyID == "" {
		t.Fatalf("persisted row missing envelope columns: %+v", persisted)
	}
}

func TestTOTP_ConfirmEnroll_WrongCode_ConsumesChallenge(t *testing.T) {
	svc, _, users, _, _ := bootstrapTOTP(t)
	ctx := t.Context()
	uid := seedTOTPUser(t, users, "alice@example.com")

	out, err := svc.Enroll(ctx, uid, "phone", "alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if _, err := svc.ConfirmEnroll(ctx, uid, out.ChallengeID, "000000"); !errors.Is(err, services.ErrTOTPInvalidCode) {
		t.Fatalf("wrong code: want ErrTOTPInvalidCode, got %v", err)
	}
	// Second attempt — challenge is gone.
	if _, err := svc.ConfirmEnroll(ctx, uid, out.ChallengeID, "000000"); !errors.Is(err, services.ErrTOTPChallengeNotFound) {
		t.Fatalf("retry: want ErrTOTPChallengeNotFound, got %v", err)
	}
}

func TestTOTP_ConfirmEnroll_WrongUser(t *testing.T) {
	svc, _, users, _, clk := bootstrapTOTP(t)
	ctx := t.Context()
	alice := seedTOTPUser(t, users, "alice@example.com")
	bob := seedTOTPUser(t, users, "bob@example.com")

	out, err := svc.Enroll(ctx, alice, "phone", "alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	secret := readTOTPSecret(t, out.SecretBase32)
	code := expectedCode(t, secret, clk.Now())
	// Bob attempts to confirm Alice's enrollment with the right code.
	if _, err := svc.ConfirmEnroll(ctx, bob, out.ChallengeID, code); !errors.Is(err, services.ErrTOTPChallengeUser) {
		t.Fatalf("wrong-user confirm: want ErrTOTPChallengeUser, got %v", err)
	}
}

func TestTOTP_ConfirmEnroll_DuplicateLabel(t *testing.T) {
	svc, _, users, _, clk := bootstrapTOTP(t)
	ctx := t.Context()
	uid := seedTOTPUser(t, users, "alice@example.com")

	// First enrollment succeeds.
	out1, _ := svc.Enroll(ctx, uid, "phone", "alice@example.com")
	secret1 := readTOTPSecret(t, out1.SecretBase32)
	if _, err := svc.ConfirmEnroll(ctx, uid, out1.ChallengeID, expectedCode(t, secret1, clk.Now())); err != nil {
		t.Fatalf("first confirm: %v", err)
	}

	// Second enrollment with the same label collides at persist time.
	out2, _ := svc.Enroll(ctx, uid, "phone", "alice@example.com")
	secret2 := readTOTPSecret(t, out2.SecretBase32)
	if _, err := svc.ConfirmEnroll(ctx, uid, out2.ChallengeID, expectedCode(t, secret2, clk.Now())); !errors.Is(err, storage.ErrMFALabelExists) {
		t.Fatalf("duplicate label: want ErrMFALabelExists, got %v", err)
	}
}

func TestTOTP_Verify_HappyPath_TouchesLastUsed(t *testing.T) {
	svc, factors, users, _, clk := bootstrapTOTP(t)
	ctx := t.Context()
	uid := seedTOTPUser(t, users, "alice@example.com")

	out, _ := svc.Enroll(ctx, uid, "phone", "alice@example.com")
	secret := readTOTPSecret(t, out.SecretBase32)
	factor, err := svc.ConfirmEnroll(ctx, uid, out.ChallengeID, expectedCode(t, secret, clk.Now()))
	if err != nil {
		t.Fatalf("ConfirmEnroll: %v", err)
	}
	if persisted, _ := factors.Get(ctx, factor.ID); persisted.LastUsedAt != nil {
		t.Fatalf("LastUsedAt should be nil after enrollment (it's a separate step from Verify)")
	}

	// Advance past the current step so the next code is different.
	clk.Advance(60 * time.Second)
	if err := svc.Verify(ctx, factor.ID, expectedCode(t, secret, clk.Now())); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	persisted, _ := factors.Get(ctx, factor.ID)
	if persisted.LastUsedAt == nil {
		t.Fatal("Verify should have stamped LastUsedAt")
	}
}

func TestTOTP_Verify_SkewWindow_AcceptsPreviousAndNextStep(t *testing.T) {
	svc, _, users, _, clk := bootstrapTOTP(t)
	ctx := t.Context()
	uid := seedTOTPUser(t, users, "alice@example.com")

	out, _ := svc.Enroll(ctx, uid, "phone", "alice@example.com")
	secret := readTOTPSecret(t, out.SecretBase32)
	factor, _ := svc.ConfirmEnroll(ctx, uid, out.ChallengeID, expectedCode(t, secret, clk.Now()))

	// Code from the PREVIOUS step (user's watch is 30s behind).
	codePrev := expectedCode(t, secret, clk.Now().Add(-30*time.Second))
	if err := svc.Verify(ctx, factor.ID, codePrev); err != nil {
		t.Fatalf("prev-step code rejected: %v", err)
	}
	// Code from the NEXT step (user's watch is 30s ahead).
	codeNext := expectedCode(t, secret, clk.Now().Add(30*time.Second))
	if err := svc.Verify(ctx, factor.ID, codeNext); err != nil {
		t.Fatalf("next-step code rejected: %v", err)
	}
	// Code from TWO steps ago — outside the ±1 window → rejected.
	codeFar := expectedCode(t, secret, clk.Now().Add(-90*time.Second))
	if err := svc.Verify(ctx, factor.ID, codeFar); !errors.Is(err, services.ErrTOTPInvalidCode) {
		t.Fatalf("far-skew code: want ErrTOTPInvalidCode, got %v", err)
	}
}

func TestTOTP_Verify_RejectsNonNumeric(t *testing.T) {
	svc, _, users, _, clk := bootstrapTOTP(t)
	ctx := t.Context()
	uid := seedTOTPUser(t, users, "alice@example.com")
	out, _ := svc.Enroll(ctx, uid, "phone", "alice@example.com")
	secret := readTOTPSecret(t, out.SecretBase32)
	factor, _ := svc.ConfirmEnroll(ctx, uid, out.ChallengeID, expectedCode(t, secret, clk.Now()))

	cases := []string{"abcdef", "12345", "1234567", "12 345", "12345a"}
	for _, c := range cases {
		if err := svc.Verify(ctx, factor.ID, c); !errors.Is(err, services.ErrTOTPInvalidCode) {
			t.Fatalf("Verify(%q): want ErrTOTPInvalidCode, got %v", c, err)
		}
	}
}

func TestTOTP_Verify_RejectsNonTOTPFactor(t *testing.T) {
	svc, factors, users, _, _ := bootstrapTOTP(t)
	ctx := t.Context()
	uid := seedTOTPUser(t, users, "alice@example.com")

	// Insert a WebAuthn factor directly; verify it can't be TOTP-verified.
	aaguid := uuid.MustParse("00000000-0000-0000-0000-aaaaaaaaaaaa")
	f := &storage.UserMFAFactor{
		UserID:               uid,
		Kind:                 storage.MFAFactorKindWebAuthn,
		Label:                "yubikey",
		SecretCiphertext:     []byte("ciphertext"),
		SecretNonce:          []byte("nonce-12-bytes"),
		DataKeyCiphertext:    []byte("dk-wrap"),
		KMSKeyID:             "test-key",
		WebAuthnCredentialID: []byte{0x01, 0x02},
		WebAuthnAAGUID:       &aaguid,
	}
	if err := factors.Create(ctx, f); err != nil {
		t.Fatalf("Create webauthn: %v", err)
	}
	if err := svc.Verify(ctx, f.ID, "123456"); !errors.Is(err, services.ErrTOTPFactorWrongKind) {
		t.Fatalf("Verify webauthn: want ErrTOTPFactorWrongKind, got %v", err)
	}
}

func TestTOTP_Verify_FactorNotFound(t *testing.T) {
	svc, _, _, _, _ := bootstrapTOTP(t)
	if err := svc.Verify(t.Context(), uuid.New(), "123456"); !errors.Is(err, services.ErrTOTPFactorNotFound) {
		t.Fatalf("Verify(missing): want ErrTOTPFactorNotFound, got %v", err)
	}
}

func TestTOTP_ProvisioningURI_CarriesIssuerAndStandardParams(t *testing.T) {
	svc, _, users, _, _ := bootstrapTOTP(t)
	uid := seedTOTPUser(t, users, "alice@example.com")
	out, err := svc.Enroll(t.Context(), uid, "phone", "alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	uri := out.ProvisioningURI
	// The label portion of the path encodes spaces as %20 (RFC 3986
	// path-encoding) and leaves '@' unescaped. The query carries the
	// same issuer with '+' for spaces because url.Values uses
	// www-form encoding.
	for _, want := range []string{
		"otpauth://totp/",
		"Secrets%20Bridge%20%28test%29:alice@example.com",
		"issuer=Secrets+Bridge+%28test%29",
		"algorithm=SHA1",
		"digits=6",
		"period=30",
		"secret=" + out.SecretBase32,
	} {
		if !strings.Contains(uri, want) {
			t.Fatalf("ProvisioningURI missing %q; got %q", want, uri)
		}
	}
}

// --- RFC 6238 reference implementation for tests --------------------
//
// We can't import the unexported `generateTOTP` from the services
// package, so this is a hand-rolled mirror to compute expected codes.
// Identical to the production path; if the two ever diverge, all the
// happy-path tests above fail.

func hmacSHA1Truncated(secret []byte, step uint64) uint32 {
	var ctr [8]byte
	for i := 7; i >= 0; i-- {
		ctr[i] = byte(step & 0xff)
		step >>= 8
	}
	mac := hmac.New(sha1.New, secret)
	mac.Write(ctr[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	truncated := uint32(sum[offset]&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	return truncated
}

func formatCode(truncated uint32) string {
	mod := uint32(1_000_000)
	return fmt.Sprintf("%06d", truncated%mod)
}
