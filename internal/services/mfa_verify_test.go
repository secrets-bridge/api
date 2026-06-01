package services_test

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/internal/services"
	"github.com/secrets-bridge/api/pkg/keymgmt"
	"github.com/secrets-bridge/api/pkg/runtime"
	"github.com/secrets-bridge/api/pkg/storage"
)

// bootstrapMFAVerify wires the full chain — TOTP + WebAuthn + session
// + verify orchestration — against the live Postgres + Redis.
func bootstrapMFAVerify(t *testing.T) (*services.MFAVerifyService, *services.SessionService, *services.TOTPService, storage.UserMFAFactorRepository, storage.LocalUserRepository, *clockSource, *storage.Pool) {
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
		Namespace: fmt.Sprintf("sb-test-mfaverify-%d", time.Now().UnixNano()),
	})
	if err != nil {
		t.Fatalf("runtime.Open: %v", err)
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
	clk := &clockSource{now: time.Unix(1_700_000_000, 0).UTC()}

	totpSvc := services.NewTOTPService(factors, km, audit, rdb, services.TOTPConfig{
		Issuer: "Secrets Bridge (test)",
		Clock:  clk.Now,
	})
	webauthnSvc, err := services.NewWebAuthnService(factors, users, km, audit, rdb, services.WebAuthnConfig{
		RPID:          "sb.example.com",
		RPDisplayName: "Secrets Bridge (test)",
		RPOrigins:     []string{"https://sb.example.com"},
		Clock:         clk.Now,
	})
	if err != nil {
		t.Fatalf("NewWebAuthnService: %v", err)
	}
	sessionSvc := services.NewSessionService(storage.NewSessions(pool), audit)
	verifySvc := services.NewMFAVerifyService(factors, totpSvc, webauthnSvc, sessionSvc, audit, rdb, services.MFAVerifyConfig{
		Clock: clk.Now,
	})
	return verifySvc, sessionSvc, totpSvc, factors, users, clk, pool
}

func issueSessionFor(t *testing.T, svc *services.SessionService, userID uuid.UUID) uuid.UUID {
	t.Helper()
	out, err := svc.Issue(t.Context(), userID, "127.0.0.1", "test")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return out.Session.ID
}

func TestMFAVerify_BeginChallenge_RejectsUnknownKind(t *testing.T) {
	verify, sess, _, _, users, _, _ := bootstrapMFAVerify(t)
	uid := seedTOTPUser(t, users, "alice@example.com")
	sid := issueSessionFor(t, sess, uid)

	if _, err := verify.BeginChallenge(t.Context(), sid, uid, "magic"); !errors.Is(err, services.ErrMFAUnknownKind) {
		t.Fatalf("want ErrMFAUnknownKind, got %v", err)
	}
}

func TestMFAVerify_BeginChallenge_NoFactorsAtAll(t *testing.T) {
	verify, sess, _, _, users, _, _ := bootstrapMFAVerify(t)
	uid := seedTOTPUser(t, users, "alice@example.com")
	sid := issueSessionFor(t, sess, uid)

	// User has no enrolled factor; TOTP request returns NoFactors so
	// the SPA can route to /me/mfa.
	if _, err := verify.BeginChallenge(t.Context(), sid, uid, services.ChallengeKindTOTP); !errors.Is(err, services.ErrMFANoFactors) {
		t.Fatalf("totp NoFactors: got %v", err)
	}
	if _, err := verify.BeginChallenge(t.Context(), sid, uid, services.ChallengeKindWebAuthn); !errors.Is(err, services.ErrMFANoFactors) {
		t.Fatalf("webauthn NoFactors: got %v", err)
	}
}

func TestMFAVerify_BeginChallenge_KindNotEnrolled(t *testing.T) {
	verify, sess, _, factors, users, _, _ := bootstrapMFAVerify(t)
	ctx := t.Context()
	uid := seedTOTPUser(t, users, "alice@example.com")
	sid := issueSessionFor(t, sess, uid)

	// User has TOTP enrolled but no WebAuthn — webauthn challenge
	// must return KindNotEnrolled (distinct from NoFactors).
	if err := factors.Create(ctx, &storage.UserMFAFactor{
		UserID:            uid,
		Kind:              storage.MFAFactorKindTOTP,
		Label:             "phone",
		SecretCiphertext:  []byte("ct"),
		SecretNonce:       []byte("nonce-12byte"),
		DataKeyCiphertext: []byte("dk"),
		KMSKeyID:          "test-key",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := verify.BeginChallenge(ctx, sid, uid, services.ChallengeKindWebAuthn); !errors.Is(err, services.ErrMFAKindNotEnrolled) {
		t.Fatalf("want ErrMFAKindNotEnrolled, got %v", err)
	}
}

func TestMFAVerify_TOTP_HappyPath_StampsLastMFA(t *testing.T) {
	verify, sess, totp, _, users, clk, _ := bootstrapMFAVerify(t)
	ctx := t.Context()
	uid := seedTOTPUser(t, users, "alice@example.com")
	sid := issueSessionFor(t, sess, uid)

	// Enroll a real TOTP factor via the SHARED totp service so its
	// clock matches the verify service's clock — otherwise the
	// expectedCode from clk.Now() doesn't match what TOTP.Verify
	// computes from real time.
	enroll, err := totp.Enroll(ctx, uid, "phone", "alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	secret := decodeTOTPSecret(t, enroll.SecretBase32)
	factor, err := totp.ConfirmEnroll(ctx, uid, enroll.ChallengeID, expectedCode(t, secret, clk.Now()))
	if err != nil {
		t.Fatalf("ConfirmEnroll: %v", err)
	}

	// Step-up flow.
	chal, err := verify.BeginChallenge(ctx, sid, uid, services.ChallengeKindTOTP)
	if err != nil {
		t.Fatalf("BeginChallenge: %v", err)
	}
	if chal.Options != nil {
		t.Fatal("Options must be nil for TOTP")
	}
	// Advance a step so the verify code is from a different window
	// than ConfirmEnroll's code (proves Verify recomputes).
	clk.Advance(60 * time.Second)
	err = verify.Verify(ctx, sid, uid, services.VerifyRequest{
		ChallengeID: chal.ChallengeID,
		FactorID:    &factor.ID,
		Code:        expectedCode(t, secret, clk.Now()),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Session row's last_mfa_at must now be populated.
	row, err := storage.NewSessions(getPoolForTest(t)).GetByTokenHash(ctx, sessTokenHashByID(t, sess, sid))
	if err != nil {
		t.Fatalf("session lookup: %v", err)
	}
	if row.LastMFAAt == nil {
		t.Fatal("LastMFAAt nil after successful verify")
	}
}

func TestMFAVerify_TOTP_BurnsChallenge(t *testing.T) {
	verify, sess, totp, _, users, clk, _ := bootstrapMFAVerify(t)
	ctx := t.Context()
	uid := seedTOTPUser(t, users, "alice@example.com")
	sid := issueSessionFor(t, sess, uid)

	enroll, _ := totp.Enroll(ctx, uid, "phone", "alice@example.com")
	secret := decodeTOTPSecret(t, enroll.SecretBase32)
	factor, err := totp.ConfirmEnroll(ctx, uid, enroll.ChallengeID, expectedCode(t, secret, clk.Now()))
	if err != nil {
		t.Fatalf("ConfirmEnroll: %v", err)
	}

	chal, _ := verify.BeginChallenge(ctx, sid, uid, services.ChallengeKindTOTP)
	// First try with WRONG code → invalid. Challenge burned regardless.
	if err := verify.Verify(ctx, sid, uid, services.VerifyRequest{
		ChallengeID: chal.ChallengeID,
		FactorID:    &factor.ID,
		Code:        "000000",
	}); !errors.Is(err, services.ErrMFAInvalid) {
		t.Fatalf("wrong code: want ErrMFAInvalid, got %v", err)
	}
	// Second try with RIGHT code against the same challenge → gone.
	clk.Advance(60 * time.Second)
	if err := verify.Verify(ctx, sid, uid, services.VerifyRequest{
		ChallengeID: chal.ChallengeID,
		FactorID:    &factor.ID,
		Code:        expectedCode(t, secret, clk.Now()),
	}); !errors.Is(err, services.ErrMFAChallengeNotFound) {
		t.Fatalf("replay: want ErrMFAChallengeNotFound, got %v", err)
	}
}

func TestMFAVerify_TOTP_WrongUserChallenge(t *testing.T) {
	verify, sess, totp, _, users, clk, _ := bootstrapMFAVerify(t)
	ctx := t.Context()
	alice := seedTOTPUser(t, users, "alice@example.com")
	bob := seedTOTPUser(t, users, "bob@example.com")
	aliceSid := issueSessionFor(t, sess, alice)
	bobSid := issueSessionFor(t, sess, bob)

	enroll, _ := totp.Enroll(ctx, alice, "phone", "alice@example.com")
	secret := decodeTOTPSecret(t, enroll.SecretBase32)
	aliceFactor, err := totp.ConfirmEnroll(ctx, alice, enroll.ChallengeID, expectedCode(t, secret, clk.Now()))
	if err != nil {
		t.Fatalf("ConfirmEnroll: %v", err)
	}

	chal, _ := verify.BeginChallenge(ctx, aliceSid, alice, services.ChallengeKindTOTP)
	// Bob tries to verify Alice's challenge.
	err = verify.Verify(ctx, bobSid, bob, services.VerifyRequest{
		ChallengeID: chal.ChallengeID,
		FactorID:    &aliceFactor.ID,
		Code:        expectedCode(t, secret, clk.Now()),
	})
	if !errors.Is(err, services.ErrMFAChallengeUser) {
		t.Fatalf("want ErrMFAChallengeUser, got %v", err)
	}
}

func TestMFAVerify_TOTP_FactorMustBelongToUser(t *testing.T) {
	verify, sess, _, factors, users, _, _ := bootstrapMFAVerify(t)
	ctx := t.Context()
	alice := seedTOTPUser(t, users, "alice@example.com")
	bob := seedTOTPUser(t, users, "bob@example.com")
	bobSid := issueSessionFor(t, sess, bob)

	// Seed an Alice-owned TOTP factor + a Bob-owned TOTP factor.
	bobFactor := &storage.UserMFAFactor{
		UserID:            bob,
		Kind:              storage.MFAFactorKindTOTP,
		Label:             "bob phone",
		SecretCiphertext:  []byte("ct"),
		SecretNonce:       []byte("nonce-12byte"),
		DataKeyCiphertext: []byte("dk"),
		KMSKeyID:          "test-key",
	}
	if err := factors.Create(ctx, bobFactor); err != nil {
		t.Fatalf("bob seed: %v", err)
	}
	aliceFactor := &storage.UserMFAFactor{
		UserID:            alice,
		Kind:              storage.MFAFactorKindTOTP,
		Label:             "alice phone",
		SecretCiphertext:  []byte("ct"),
		SecretNonce:       []byte("nonce-12byte"),
		DataKeyCiphertext: []byte("dk"),
		KMSKeyID:          "test-key",
	}
	if err := factors.Create(ctx, aliceFactor); err != nil {
		t.Fatalf("alice seed: %v", err)
	}

	// Bob starts a challenge but passes Alice's factor_id at Verify.
	chal, _ := verify.BeginChallenge(ctx, bobSid, bob, services.ChallengeKindTOTP)
	if err := verify.Verify(ctx, bobSid, bob, services.VerifyRequest{
		ChallengeID: chal.ChallengeID,
		FactorID:    &aliceFactor.ID,
		Code:        "123456",
	}); !errors.Is(err, services.ErrMFAInvalid) {
		t.Fatalf("cross-user factor: want ErrMFAInvalid, got %v", err)
	}
}

func TestMFAVerify_AnyEnrolled(t *testing.T) {
	verify, _, _, factors, users, _, _ := bootstrapMFAVerify(t)
	ctx := t.Context()
	uid := seedTOTPUser(t, users, "alice@example.com")

	got, err := verify.AnyEnrolled(ctx, uid)
	if err != nil || got {
		t.Fatalf("empty user AnyEnrolled: %v %v", got, err)
	}
	if err := factors.Create(ctx, &storage.UserMFAFactor{
		UserID:            uid,
		Kind:              storage.MFAFactorKindTOTP,
		Label:             "phone",
		SecretCiphertext:  []byte("ct"),
		SecretNonce:       []byte("nonce-12byte"),
		DataKeyCiphertext: []byte("dk"),
		KMSKeyID:          "test-key",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	got, err = verify.AnyEnrolled(ctx, uid)
	if err != nil || !got {
		t.Fatalf("after seed AnyEnrolled: %v %v", got, err)
	}
}

func TestMFAVerify_WebAuthn_BeginChallenge_NoEnrolled(t *testing.T) {
	verify, sess, _, factors, users, _, _ := bootstrapMFAVerify(t)
	ctx := t.Context()
	uid := seedTOTPUser(t, users, "alice@example.com")
	sid := issueSessionFor(t, sess, uid)
	// Seed only TOTP.
	if err := factors.Create(ctx, &storage.UserMFAFactor{
		UserID:            uid,
		Kind:              storage.MFAFactorKindTOTP,
		Label:             "phone",
		SecretCiphertext:  []byte("ct"),
		SecretNonce:       []byte("nonce-12byte"),
		DataKeyCiphertext: []byte("dk"),
		KMSKeyID:          "test-key",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := verify.BeginChallenge(ctx, sid, uid, services.ChallengeKindWebAuthn); !errors.Is(err, services.ErrMFAKindNotEnrolled) {
		t.Fatalf("want ErrMFAKindNotEnrolled, got %v", err)
	}
}

func TestMFAVerify_WebAuthn_BeginChallenge_HappyPath(t *testing.T) {
	verify, sess, _, factors, users, _, _ := bootstrapMFAVerify(t)
	ctx := t.Context()
	uid := seedTOTPUser(t, users, "alice@example.com")
	sid := issueSessionFor(t, sess, uid)
	aaguid := uuid.MustParse("00000000-0000-0000-0000-aaaaaaaaaaaa")
	if err := factors.Create(ctx, &storage.UserMFAFactor{
		UserID:               uid,
		Kind:                 storage.MFAFactorKindWebAuthn,
		Label:                "yubikey",
		SecretCiphertext:     []byte("ct"),
		SecretNonce:          []byte("nonce-12byte"),
		DataKeyCiphertext:    []byte("dk"),
		KMSKeyID:             "test-key",
		WebAuthnCredentialID: []byte{0x01, 0x02, 0x03},
		WebAuthnAAGUID:       &aaguid,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	out, err := verify.BeginChallenge(ctx, sid, uid, services.ChallengeKindWebAuthn)
	if err != nil {
		t.Fatalf("BeginChallenge: %v", err)
	}
	if out.Kind != services.ChallengeKindWebAuthn || out.ChallengeID == "" || out.Options == nil {
		t.Fatalf("unexpected challenge: %+v", out)
	}
	// AllowedCredentials should contain the seeded credential id.
	if len(out.Options.Response.AllowedCredentials) != 1 {
		t.Fatalf("AllowedCredentials len: %d", len(out.Options.Response.AllowedCredentials))
	}
}

// --- helpers ---------------------------------------------------------

func decodeTOTPSecret(t *testing.T, b32 string) []byte {
	t.Helper()
	if pad := len(b32) % 8; pad != 0 {
		b32 = b32 + repeatChar('=', 8-pad)
	}
	out, err := base32.StdEncoding.DecodeString(b32)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	return out
}

func repeatChar(c byte, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return string(b)
}

// getPoolForTest opens a fresh pool against TEST_DATABASE_URL for
// direct row inspection. Callers t.Cleanup themselves implicitly via
// the helper test scope.
func getPoolForTest(t *testing.T) *storage.Pool {
	t.Helper()
	pool, err := storage.Open(t.Context(), storage.Config{
		DSN:          os.Getenv("TEST_DATABASE_URL"),
		MaxConns:     2,
		ConnLifetime: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// sessTokenHashByID returns the sha256 hash that maps to the
// stored session row, by listing all sessions for the user and
// matching on id. We don't have a public token-hash-by-id getter
// since cookies are write-once, but for tests we can query the
// session row directly.
func sessTokenHashByID(t *testing.T, _ *services.SessionService, sid uuid.UUID) []byte {
	t.Helper()
	pool := getPoolForTest(t)
	var hash []byte
	if err := pool.QueryRow(t.Context(),
		`SELECT token_hash FROM sessions WHERE id = $1`, sid,
	).Scan(&hash); err != nil {
		t.Fatalf("token hash lookup: %v", err)
	}
	return hash
}
