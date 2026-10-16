package storage_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/storage"
)

// SetExpiry may only shorten a wrap's lifetime. It used to overwrite
// expires_at unconditionally, so a state transition that "refreshed" a
// wrap to now + TTL could push an already-expired wrap back into the
// future and make it retrievable again.

func seedWrap(t *testing.T, repo *storage.SecretWraps, expiresAt time.Time) *storage.SecretWrap {
	t.Helper()
	w := &storage.SecretWrap{
		KeyName:           "DB_PASSWORD",
		EncryptedValue:    []byte("ciphertext-placeholder"),
		Nonce:             []byte("nonce-placeholder"),
		DataKeyCiphertext: []byte("dek-placeholder"),
		KMSKeyID:          "local:test",
		ContentHash:       make([]byte, 32),
		ByteLength:        12,
		ExpiresAt:         expiresAt,
	}
	if err := repo.Create(t.Context(), w); err != nil {
		t.Fatalf("seed wrap: %v", err)
	}
	return w
}

func wrapExpiry(t *testing.T, pool *storage.Pool, id uuid.UUID) time.Time {
	t.Helper()
	var at time.Time
	if err := pool.QueryRow(t.Context(), `SELECT expires_at FROM secret_wraps WHERE id = $1`, id).Scan(&at); err != nil {
		t.Fatalf("read expires_at: %v", err)
	}
	return at
}

func TestSecretWraps_SetExpiry_NeverRevivesExpiredWrap(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewSecretWraps(pool)
	ctx := t.Context()

	expired := time.Now().Add(-time.Minute).UTC().Truncate(time.Microsecond)
	w := seedWrap(t, repo, expired)

	if err := repo.SetExpiry(ctx, w.ID, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SetExpiry on expired wrap: %v", err)
	}
	if got := wrapExpiry(t, pool, w.ID); !got.Equal(expired) {
		t.Fatalf("expired wrap's expires_at moved from %v to %v; SetExpiry must never extend", expired, got)
	}
	if err := repo.MarkConsumed(ctx, w.ID, uuid.New(), time.Now()); !errors.Is(err, storage.ErrExpired) {
		t.Fatalf("MarkConsumed after SetExpiry = %v; want ErrExpired (wrap must stay dead)", err)
	}
}

func TestSecretWraps_SetExpiry_NeverTouchesConsumedWrap(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewSecretWraps(pool)
	ctx := t.Context()

	w := seedWrap(t, repo, time.Now().Add(time.Minute))
	if err := repo.MarkConsumedByUser(ctx, w.ID, "user-a", time.Now()); err != nil {
		t.Fatalf("MarkConsumedByUser: %v", err)
	}
	before := wrapExpiry(t, pool, w.ID)

	if err := repo.SetExpiry(ctx, w.ID, time.Now().Add(24*time.Hour)); !errors.Is(err, storage.ErrAlreadyConsumed) {
		t.Fatalf("SetExpiry on consumed wrap = %v; want ErrAlreadyConsumed", err)
	}
	if got := wrapExpiry(t, pool, w.ID); !got.Equal(before) {
		t.Fatalf("consumed wrap's expires_at moved from %v to %v", before, got)
	}
}

func TestSecretWraps_SetExpiry_OnlyShortensLiveWrap(t *testing.T) {
	pool := freshDB(t)
	repo := storage.NewSecretWraps(pool)
	ctx := t.Context()

	original := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	w := seedWrap(t, repo, original)

	// A later deadline is ignored.
	if err := repo.SetExpiry(ctx, w.ID, original.Add(24*time.Hour)); err != nil {
		t.Fatalf("SetExpiry later: %v", err)
	}
	if got := wrapExpiry(t, pool, w.ID); !got.Equal(original) {
		t.Fatalf("live wrap extended from %v to %v; want unchanged", original, got)
	}

	// An earlier deadline shortens it.
	shorter := time.Now().Add(5 * time.Minute).UTC().Truncate(time.Microsecond)
	if err := repo.SetExpiry(ctx, w.ID, shorter); err != nil {
		t.Fatalf("SetExpiry earlier: %v", err)
	}
	if got := wrapExpiry(t, pool, w.ID); !got.Equal(shorter) {
		t.Fatalf("expires_at = %v; want shortened to %v", got, shorter)
	}

	// Missing wrap is still ErrNotFound.
	if err := repo.SetExpiry(ctx, uuid.New(), shorter); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("SetExpiry on missing wrap = %v; want ErrNotFound", err)
	}
}
