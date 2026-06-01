package storage_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// Helper — provisions a local_users row so factor rows can attach
// to a real FK target. Returns the user id.
func newMFAUser(t *testing.T, pool *storage.Pool, email string) uuid.UUID {
	t.Helper()
	ctx := t.Context()
	users := storage.NewLocalUsers(pool)
	u := &storage.LocalUser{
		Email:        email,
		PasswordHash: []byte("$2a$10$dummybcryptdummybcryptdummybcryptdummybcryptdummybcryp"),
		DisplayName:  email,
	}
	if err := users.Create(ctx, u); err != nil {
		t.Fatalf("seed user %s: %v", email, err)
	}
	return u.ID
}

func newTOTPFactor(userID uuid.UUID, label string) *storage.UserMFAFactor {
	return &storage.UserMFAFactor{
		UserID:            userID,
		Kind:              storage.MFAFactorKindTOTP,
		Label:             label,
		SecretCiphertext:  []byte("totp-ciphertext"),
		SecretNonce:       []byte("totp-nonce-12byte"),
		DataKeyCiphertext: []byte("data-key-wrap"),
		KMSKeyID:          "arn:aws:kms:us-east-1:000000000000:key/test-key",
	}
}

func newWebAuthnFactor(userID uuid.UUID, label string, credID []byte) *storage.UserMFAFactor {
	aaguid := uuid.MustParse("00000000-0000-0000-0000-aaaaaaaaaaaa")
	return &storage.UserMFAFactor{
		UserID:               userID,
		Kind:                 storage.MFAFactorKindWebAuthn,
		Label:                label,
		SecretCiphertext:     []byte("cose-public-key-ciphertext"),
		SecretNonce:          []byte("webauthn-nonce-12"),
		DataKeyCiphertext:    []byte("data-key-wrap"),
		KMSKeyID:             "arn:aws:kms:us-east-1:000000000000:key/test-key",
		WebAuthnCredentialID: credID,
		WebAuthnSignCount:    0,
		WebAuthnAAGUID:       &aaguid,
	}
}

func TestUserMFAFactors_CreateAndGet_TOTP(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	uid := newMFAUser(t, pool, "alice@example.com")
	repo := storage.NewUserMFAFactors(pool)

	f := newTOTPFactor(uid, "iPhone backup")
	if err := repo.Create(ctx, f); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if f.ID == uuid.Nil {
		t.Fatal("Create did not populate ID")
	}
	if f.CreatedAt.IsZero() {
		t.Fatal("Create did not populate CreatedAt")
	}

	got, err := repo.Get(ctx, f.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Kind != storage.MFAFactorKindTOTP {
		t.Fatalf("Get kind: %q", got.Kind)
	}
	if got.Label != "iPhone backup" {
		t.Fatalf("Get label: %q", got.Label)
	}
	if got.WebAuthnCredentialID != nil {
		t.Fatal("TOTP row leaked webauthn_credential_id")
	}
	if got.WebAuthnAAGUID != nil {
		t.Fatal("TOTP row leaked webauthn_aaguid")
	}
	if got.LastUsedAt != nil {
		t.Fatal("LastUsedAt should be nil on fresh row")
	}
}

func TestUserMFAFactors_CreateAndGet_WebAuthn(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	uid := newMFAUser(t, pool, "bob@example.com")
	repo := storage.NewUserMFAFactors(pool)

	credID := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	f := newWebAuthnFactor(uid, "Yubikey 5", credID)
	if err := repo.Create(ctx, f); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.GetByWebAuthnCredentialID(ctx, credID)
	if err != nil {
		t.Fatalf("GetByWebAuthnCredentialID: %v", err)
	}
	if got.ID != f.ID {
		t.Fatalf("GetByWebAuthnCredentialID returned wrong row: got %s want %s", got.ID, f.ID)
	}
	if got.Kind != storage.MFAFactorKindWebAuthn {
		t.Fatalf("Kind: %q", got.Kind)
	}
	if got.WebAuthnAAGUID == nil || *got.WebAuthnAAGUID != *f.WebAuthnAAGUID {
		t.Fatalf("AAGUID round-trip: %v", got.WebAuthnAAGUID)
	}
}

func TestUserMFAFactors_RejectsDuplicateLabelPerUser(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	uid := newMFAUser(t, pool, "alice@example.com")
	repo := storage.NewUserMFAFactors(pool)

	if err := repo.Create(ctx, newTOTPFactor(uid, "phone")); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	err := repo.Create(ctx, newTOTPFactor(uid, "phone"))
	if !errors.Is(err, storage.ErrMFALabelExists) {
		t.Fatalf("duplicate label: want ErrMFALabelExists, got %v", err)
	}
}

func TestUserMFAFactors_AllowsSameLabelAcrossUsers(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	alice := newMFAUser(t, pool, "alice@example.com")
	bob := newMFAUser(t, pool, "bob@example.com")
	repo := storage.NewUserMFAFactors(pool)

	if err := repo.Create(ctx, newTOTPFactor(alice, "phone")); err != nil {
		t.Fatalf("alice Create: %v", err)
	}
	if err := repo.Create(ctx, newTOTPFactor(bob, "phone")); err != nil {
		t.Fatalf("bob Create: %v", err)
	}
}

func TestUserMFAFactors_RejectsDuplicateWebAuthnCredentialID(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	alice := newMFAUser(t, pool, "alice@example.com")
	bob := newMFAUser(t, pool, "bob@example.com")
	repo := storage.NewUserMFAFactors(pool)

	credID := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	if err := repo.Create(ctx, newWebAuthnFactor(alice, "key", credID)); err != nil {
		t.Fatalf("alice Create: %v", err)
	}
	err := repo.Create(ctx, newWebAuthnFactor(bob, "key", credID))
	if !errors.Is(err, storage.ErrMFACredentialExists) {
		t.Fatalf("duplicate credential_id across users: want ErrMFACredentialExists, got %v", err)
	}
}

func TestUserMFAFactors_RejectsWebAuthnWithoutCredentialID(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	uid := newMFAUser(t, pool, "alice@example.com")
	repo := storage.NewUserMFAFactors(pool)

	f := newWebAuthnFactor(uid, "broken", nil)
	f.WebAuthnCredentialID = nil
	if err := repo.Create(ctx, f); err == nil {
		t.Fatal("expected validation error for webauthn without credential_id")
	}
}

func TestUserMFAFactors_RejectsTOTPWithWebAuthnMetadata(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	uid := newMFAUser(t, pool, "alice@example.com")
	repo := storage.NewUserMFAFactors(pool)

	f := newTOTPFactor(uid, "broken")
	f.WebAuthnCredentialID = []byte{0x01}
	if err := repo.Create(ctx, f); err == nil {
		t.Fatal("expected validation error for totp carrying webauthn metadata")
	}
}

func TestUserMFAFactors_ListForUser_OrderAndIsolation(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	alice := newMFAUser(t, pool, "alice@example.com")
	bob := newMFAUser(t, pool, "bob@example.com")
	repo := storage.NewUserMFAFactors(pool)

	first := newTOTPFactor(alice, "alpha")
	if err := repo.Create(ctx, first); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	// Force a small clock gap so ORDER BY created_at DESC is stable.
	time.Sleep(10 * time.Millisecond)
	second := newWebAuthnFactor(alice, "beta", []byte{0x99})
	if err := repo.Create(ctx, second); err != nil {
		t.Fatalf("second Create: %v", err)
	}
	// Bob's factor must NOT show up in alice's list.
	if err := repo.Create(ctx, newTOTPFactor(bob, "bob-phone")); err != nil {
		t.Fatalf("bob Create: %v", err)
	}

	got, err := repo.ListForUser(ctx, alice)
	if err != nil {
		t.Fatalf("ListForUser: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListForUser len: %d; rows=%+v", len(got), got)
	}
	if got[0].ID != second.ID {
		t.Fatalf("ListForUser order: want most recent first; got %s then %s", got[0].ID, got[1].ID)
	}

	n, err := repo.CountForUser(ctx, alice)
	if err != nil || n != 2 {
		t.Fatalf("CountForUser alice: n=%d err=%v", n, err)
	}
	n, err = repo.CountForUser(ctx, bob)
	if err != nil || n != 1 {
		t.Fatalf("CountForUser bob: n=%d err=%v", n, err)
	}
}

func TestUserMFAFactors_DeleteScopedByUser(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	alice := newMFAUser(t, pool, "alice@example.com")
	bob := newMFAUser(t, pool, "bob@example.com")
	repo := storage.NewUserMFAFactors(pool)

	aliceFactor := newTOTPFactor(alice, "phone")
	if err := repo.Create(ctx, aliceFactor); err != nil {
		t.Fatalf("alice Create: %v", err)
	}

	// Bob attempting to delete Alice's factor by id MUST fail.
	if err := repo.Delete(ctx, aliceFactor.ID, bob); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("cross-user Delete: want ErrNotFound, got %v", err)
	}
	if _, err := repo.Get(ctx, aliceFactor.ID); err != nil {
		t.Fatalf("alice's factor should still exist after cross-user delete: %v", err)
	}

	// Alice's own delete succeeds.
	if err := repo.Delete(ctx, aliceFactor.ID, alice); err != nil {
		t.Fatalf("alice Delete: %v", err)
	}
	if _, err := repo.Get(ctx, aliceFactor.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("after delete, Get expected ErrNotFound, got %v", err)
	}
}

func TestUserMFAFactors_TouchLastUsed(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	uid := newMFAUser(t, pool, "alice@example.com")
	repo := storage.NewUserMFAFactors(pool)

	f := newTOTPFactor(uid, "phone")
	if err := repo.Create(ctx, f); err != nil {
		t.Fatalf("Create: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	if err := repo.TouchLastUsed(ctx, f.ID, now); err != nil {
		t.Fatalf("TouchLastUsed: %v", err)
	}
	got, err := repo.Get(ctx, f.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.LastUsedAt == nil || !got.LastUsedAt.UTC().Equal(now) {
		t.Fatalf("LastUsedAt: %v want %v", got.LastUsedAt, now)
	}

	if err := repo.TouchLastUsed(ctx, uuid.New(), now); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("TouchLastUsed(missing): want ErrNotFound, got %v", err)
	}
}

func TestUserMFAFactors_IncrementSignCount_MonotonicEnforcement(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	uid := newMFAUser(t, pool, "alice@example.com")
	repo := storage.NewUserMFAFactors(pool)

	cred := []byte{0x42, 0x42}
	f := newWebAuthnFactor(uid, "key", cred)
	if err := repo.Create(ctx, f); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := repo.IncrementSignCount(ctx, f.ID, 5); err != nil {
		t.Fatalf("IncrementSignCount 0→5: %v", err)
	}
	got, _ := repo.Get(ctx, f.ID)
	if got.WebAuthnSignCount != 5 {
		t.Fatalf("after 0→5: %d", got.WebAuthnSignCount)
	}

	// Equal counter is a regression (spec requires STRICT increase).
	if err := repo.IncrementSignCount(ctx, f.ID, 5); !errors.Is(err, storage.ErrSignCountRegression) {
		t.Fatalf("5→5: want ErrSignCountRegression, got %v", err)
	}
	// Decreasing is the clone-detection case.
	if err := repo.IncrementSignCount(ctx, f.ID, 3); !errors.Is(err, storage.ErrSignCountRegression) {
		t.Fatalf("5→3: want ErrSignCountRegression, got %v", err)
	}
	// 5→7 succeeds.
	if err := repo.IncrementSignCount(ctx, f.ID, 7); err != nil {
		t.Fatalf("5→7: %v", err)
	}

	if err := repo.IncrementSignCount(ctx, uuid.New(), 1); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("missing id: want ErrNotFound, got %v", err)
	}
}

func TestUserMFAFactors_IncrementSignCount_RejectsTOTP(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	uid := newMFAUser(t, pool, "alice@example.com")
	repo := storage.NewUserMFAFactors(pool)

	f := newTOTPFactor(uid, "phone")
	if err := repo.Create(ctx, f); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := repo.IncrementSignCount(ctx, f.ID, 1); !errors.Is(err, storage.ErrKindMismatch) {
		t.Fatalf("totp IncrementSignCount: want ErrKindMismatch, got %v", err)
	}
}

func TestUserMFAFactors_FKCascadeOnUserDelete(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	uid := newMFAUser(t, pool, "alice@example.com")
	repo := storage.NewUserMFAFactors(pool)

	if err := repo.Create(ctx, newTOTPFactor(uid, "phone")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM local_users WHERE id = $1`, uid); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	n, err := repo.CountForUser(ctx, uid)
	if err != nil {
		t.Fatalf("CountForUser after cascade: %v", err)
	}
	if n != 0 {
		t.Fatalf("factor row survived FK cascade: %d remaining", n)
	}
}

func TestUserMFAFactors_GetByWebAuthnCredentialID_NotFoundForTOTP(t *testing.T) {
	pool := freshDB(t)
	ctx := t.Context()
	uid := newMFAUser(t, pool, "alice@example.com")
	repo := storage.NewUserMFAFactors(pool)

	if err := repo.Create(ctx, newTOTPFactor(uid, "phone")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Looking up any rawId should miss — partial index excludes TOTP rows.
	if _, err := repo.GetByWebAuthnCredentialID(ctx, []byte{0x01}); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}
