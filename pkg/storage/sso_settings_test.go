package storage_test

// hatmast2r's pass on api#272: two saves of different settings fields
// can't undo each other. The new row is built from the one read under
// the row lock.

import (
	"testing"
	"time"

	"github.com/secrets-bridge/api/pkg/storage"
)

func TestSSOStore_SettingsSavesDontUndoEachOther(t *testing.T) {
	pool := freshDB(t)
	store := storage.NewSSOStore(pool)
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `UPDATE sso_settings SET public_url = NULL, pending_cap = 50`); err != nil {
		t.Fatal(err)
	}

	// Another save holds the row and changes the address.
	other, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Rollback(ctx) }()
	if _, err := other.Exec(ctx, `SELECT 1 FROM sso_settings WHERE id FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	if _, err := other.Exec(ctx, `UPDATE sso_settings SET public_url = 'https://secrets.example.com'`); err != nil {
		t.Fatal(err)
	}

	// This save changes only the cap, and waits for the row.
	cap7 := 7
	done := make(chan error, 1)
	go func() {
		_, _, err := store.UpdateSettings(ctx, nil, &cap7, "user:b")
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("UpdateSettings didn't wait for the row: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if err := other.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}

	st, err := store.GetSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.PublicURL != "https://secrets.example.com" || st.PendingCap != 7 {
		t.Fatalf("settings = %q, %d; want both saves kept", st.PublicURL, st.PendingCap)
	}
}
