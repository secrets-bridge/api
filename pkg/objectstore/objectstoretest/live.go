package objectstoretest

import (
	"errors"
	"os"
	"strings"
	"testing"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"

	"github.com/secrets-bridge/api/pkg/objectstore"
)

// Environment for live tests against an S3-compatible server (MinIO in
// CI and in docker-compose):
//
//	TEST_OBJECTSTORE_ENDPOINT    e.g. http://localhost:9000; unset skips live tests
//	TEST_OBJECTSTORE_BUCKET      default "sb-test" (created when missing)
//	TEST_OBJECTSTORE_REGION      default "us-east-1"
//	TEST_OBJECTSTORE_ACCESS_KEY  copied to AWS_ACCESS_KEY_ID for the test
//	TEST_OBJECTSTORE_SECRET_KEY  copied to AWS_SECRET_ACCESS_KEY for the test
const (
	EnvTestEndpoint  = "TEST_OBJECTSTORE_ENDPOINT"
	EnvTestBucket    = "TEST_OBJECTSTORE_BUCKET"
	EnvTestRegion    = "TEST_OBJECTSTORE_REGION"
	EnvTestAccessKey = "TEST_OBJECTSTORE_ACCESS_KEY"
	EnvTestSecretKey = "TEST_OBJECTSTORE_SECRET_KEY"
)

// LiveConfig returns a Config for the live test server, with a prefix
// unique to this test so tests never see each other's objects, and
// sets the AWS credential variables for the test's duration. It skips
// the test when TEST_OBJECTSTORE_ENDPOINT is unset. The bucket is
// created if it doesn't exist.
func LiveConfig(t *testing.T) objectstore.Config {
	t.Helper()
	endpoint := os.Getenv(EnvTestEndpoint)
	if endpoint == "" {
		t.Skip(EnvTestEndpoint + " not set; skipping live object storage test")
	}
	if v := os.Getenv(EnvTestAccessKey); v != "" {
		t.Setenv("AWS_ACCESS_KEY_ID", v)
	}
	if v := os.Getenv(EnvTestSecretKey); v != "" {
		t.Setenv("AWS_SECRET_ACCESS_KEY", v)
	}
	cfg := objectstore.Config{
		Bucket:    envOr(EnvTestBucket, "sb-test"),
		Region:    envOr(EnvTestRegion, "us-east-1"),
		Endpoint:  endpoint,
		PathStyle: true,
		Prefix:    "test-" + strings.ToLower(uuid.NewString()[:8]),
	}
	client, err := objectstore.NewS3Client(t.Context(), cfg)
	if err != nil {
		t.Fatalf("live object store client: %v", err)
	}
	_, err = client.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: awsv2.String(cfg.Bucket)})
	var owned *s3types.BucketAlreadyOwnedByYou
	var exists *s3types.BucketAlreadyExists
	if err != nil && !errors.As(err, &owned) && !errors.As(err, &exists) {
		t.Fatalf("create test bucket: %v", err)
	}
	return cfg
}

// Live returns an S3 store on the live test server; see LiveConfig.
func Live(t *testing.T) (*objectstore.S3, objectstore.Config) {
	t.Helper()
	cfg := LiveConfig(t)
	store, err := objectstore.NewS3(t.Context(), cfg)
	if err != nil {
		t.Fatalf("live object store: %v", err)
	}
	if err := store.Check(t.Context()); err != nil {
		t.Fatalf("live object store check: %v", err)
	}
	return store, cfg
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
