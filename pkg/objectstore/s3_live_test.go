package objectstore_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/secrets-bridge/api/pkg/objectstore"
	"github.com/secrets-bridge/api/pkg/objectstore/objectstoretest"
)

// Live tests against an S3-compatible server; see objectstoretest for
// the TEST_OBJECTSTORE_* variables. CI runs them against MinIO.

func TestS3Live_RoundTrip(t *testing.T) {
	store, cfg := objectstoretest.Live(t)
	ctx := t.Context()
	key := cfg.Key("logos", "project", "00000000-0000-0000-0000-000000000001", "abc.png")
	data := []byte("\x89PNG\r\n\x1a\nnot-really-a-png")

	if _, err := store.Head(ctx, key); !errors.Is(err, objectstore.ErrNotFound) {
		t.Fatalf("Head before Put = %v, want ErrNotFound", err)
	}
	if _, err := store.Get(ctx, key); !errors.Is(err, objectstore.ErrNotFound) {
		t.Fatalf("Get before Put = %v, want ErrNotFound", err)
	}
	if err := store.Put(ctx, key, bytes.NewReader(data), int64(len(data)), "image/png"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	info, err := store.Head(ctx, key)
	if err != nil || info.Size != int64(len(data)) || info.ContentType != "image/png" {
		t.Fatalf("Head = %+v, %v", info, err)
	}
	obj, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, _ := io.ReadAll(obj.Body)
	_ = obj.Body.Close()
	if !bytes.Equal(got, data) || obj.Size != int64(len(data)) {
		t.Fatalf("Get returned %q (%d)", got, obj.Size)
	}
	// Overwrite is allowed (content-addressed keys write the same bytes).
	if err := store.Put(ctx, key, bytes.NewReader(data), int64(len(data)), "image/png"); err != nil {
		t.Fatalf("second Put: %v", err)
	}
	if err := store.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get(ctx, key); !errors.Is(err, objectstore.ErrNotFound) {
		t.Fatalf("Get after Delete = %v", err)
	}
	if err := store.Delete(ctx, key); err != nil {
		t.Fatalf("Delete of a missing key = %v, want nil", err)
	}
}

func TestS3Live_MissingBucketFailsCheck(t *testing.T) {
	cfg := objectstoretest.LiveConfig(t)
	cfg.Bucket = "sb-test-does-not-exist"
	store, err := objectstore.NewS3(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Check(t.Context()); err == nil {
		t.Fatal("Check passed for a bucket that does not exist")
	}
	if _, err := store.Get(t.Context(), "k"); err == nil || errors.Is(err, objectstore.ErrNotFound) {
		t.Fatalf("Get on a missing bucket = %v; must be an error other than ErrNotFound", err)
	}
}
