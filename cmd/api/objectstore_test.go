package main

import (
	"strings"
	"testing"

	"github.com/secrets-bridge/api/pkg/objectstore"
	"github.com/secrets-bridge/api/pkg/objectstore/objectstoretest"
)

func clearObjectStoreEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{objectstore.EnvBucket, objectstore.EnvRegion, objectstore.EnvEndpoint,
		objectstore.EnvPathStyle, objectstore.EnvPrefix, objectstore.EnvSSE, objectstore.EnvKMSKeyID} {
		t.Setenv(k, "")
	}
}

// Not configured boots without a store; logo writes then answer 503.
func TestOpenObjectStore_NotConfigured(t *testing.T) {
	clearObjectStoreEnv(t)
	store, cfg, err := openObjectStore(t.Context(), ModeDev)
	if err != nil || store != nil || cfg.Enabled() {
		t.Fatalf("unset = %v, %+v, %v; want no store and no error", store, cfg, err)
	}
}

// A half-done configuration refuses to boot.
func TestOpenObjectStore_MisconfiguredFails(t *testing.T) {
	clearObjectStoreEnv(t)
	t.Setenv(objectstore.EnvRegion, "us-east-1")
	if _, _, err := openObjectStore(t.Context(), ModeDev); err == nil || !strings.Contains(err.Error(), objectstore.EnvBucket) {
		t.Fatalf("region without bucket = %v", err)
	}
	t.Setenv(objectstore.EnvBucket, "example-bucket")
	t.Setenv(objectstore.EnvSSE, "aws:kms")
	if _, _, err := openObjectStore(t.Context(), ModeDev); err == nil || !strings.Contains(err.Error(), objectstore.EnvKMSKeyID) {
		t.Fatalf("aws:kms without key = %v", err)
	}
}

// Against the live server: a reachable bucket opens, a missing one
// refuses to boot.
func TestOpenObjectStore_Live(t *testing.T) {
	live := objectstoretest.LiveConfig(t)
	clearObjectStoreEnv(t)
	t.Setenv(objectstore.EnvBucket, live.Bucket)
	t.Setenv(objectstore.EnvRegion, live.Region)
	t.Setenv(objectstore.EnvEndpoint, live.Endpoint)
	t.Setenv(objectstore.EnvPathStyle, "true")
	t.Setenv(objectstore.EnvPrefix, "boot-check")
	store, cfg, err := openObjectStore(t.Context(), ModeDev)
	if err != nil || store == nil || cfg.Prefix != "boot-check" {
		t.Fatalf("live open = %v, %+v, %v", store, cfg, err)
	}
	t.Setenv(objectstore.EnvBucket, "sb-test-does-not-exist")
	if _, _, err := openObjectStore(t.Context(), ModeDev); err == nil {
		t.Fatal("a missing bucket did not fail the boot check")
	}
}

// Outside dev a plain http:// endpoint refuses to boot, before any
// client is built. The chart refuses it too, but the api is the one that
// sees SB_OBJECTSTORE_* set outside the chart.
func TestOpenObjectStore_ProductionRefusesHTTP(t *testing.T) {
	clearObjectStoreEnv(t)
	t.Setenv(objectstore.EnvBucket, "example-bucket")
	t.Setenv(objectstore.EnvRegion, "us-east-1")
	t.Setenv(objectstore.EnvEndpoint, "http://minio.example.com:9000")
	store, _, err := openObjectStore(t.Context(), ModeProduction)
	if err == nil || store != nil || !strings.Contains(err.Error(), objectstore.EnvEndpoint) || !strings.Contains(err.Error(), "http://") {
		t.Fatalf("production with an http endpoint = %v, %v; want a boot refusal naming %s", store, err, objectstore.EnvEndpoint)
	}
}

// The same http:// endpoint is fine in dev (local MinIO).
func TestOpenObjectStore_DevAllowsHTTP_Live(t *testing.T) {
	live := objectstoretest.LiveConfig(t)
	if !strings.HasPrefix(live.Endpoint, "http://") {
		t.Skip("live endpoint is not http://")
	}
	clearObjectStoreEnv(t)
	t.Setenv(objectstore.EnvBucket, live.Bucket)
	t.Setenv(objectstore.EnvRegion, live.Region)
	t.Setenv(objectstore.EnvEndpoint, live.Endpoint)
	t.Setenv(objectstore.EnvPathStyle, "true")
	if store, _, err := openObjectStore(t.Context(), ModeDev); err != nil || store == nil {
		t.Fatalf("dev with the live http endpoint = %v, %v", store, err)
	}
	if _, _, err := openObjectStore(t.Context(), ModeProduction); err == nil {
		t.Fatal("production with the live http endpoint booted")
	}
}
