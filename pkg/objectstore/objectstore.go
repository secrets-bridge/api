// Package objectstore stores media (images and other uploads) in
// S3-compatible object storage, so Postgres keeps only metadata.
//
// It holds media only. Secret values never go to object storage.
//
// The api talks to the backend through the small Store interface. The
// one production implementation is S3 (AWS S3, or any S3 API such as
// MinIO), configured from SB_OBJECTSTORE_* environment variables:
//
//	SB_OBJECTSTORE_BUCKET      bucket name; empty (and nothing else set) disables object storage
//	SB_OBJECTSTORE_REGION      region; required when the bucket is set
//	SB_OBJECTSTORE_ENDPOINT    optional endpoint override for S3-compatible servers or VPC endpoints
//	SB_OBJECTSTORE_FORCE_PATH_STYLE  "true" for path-style addressing (MinIO and most self-hosted servers)
//	SB_OBJECTSTORE_PREFIX      optional key prefix, for sharing a bucket
//	SB_OBJECTSTORE_SSE         unset/empty (no SSE header; the bucket default applies), "AES256" or "aws:kms"
//	SB_OBJECTSTORE_KMS_KEY_ID  KMS key ARN, id or alias; required with SSE=aws:kms, refused otherwise
//
// Credentials come from the default AWS SDK chain (IRSA, instance role,
// AWS_* variables, shared profile), the same posture as the aws-kms key
// manager. There are no credential settings of its own.
package objectstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// ErrNotFound is returned by Get and Head when the key has no object.
var ErrNotFound = errors.New("objectstore: object not found")

// Object is an object being read. The caller must close Body.
type Object struct {
	Body        io.ReadCloser
	Size        int64
	ContentType string
}

// Info describes a stored object without its contents.
type Info struct {
	Size        int64
	ContentType string
}

// Store is the object-storage backend. Keys are full object keys, the
// prefix already applied (see Config.Key); callers persist them as-is so
// a later prefix change can't silently point existing rows elsewhere.
type Store interface {
	// Put writes body (size bytes) under key, replacing any object there.
	Put(ctx context.Context, key string, body io.ReadSeeker, size int64, contentType string) error
	// Get opens the object at key, or returns ErrNotFound.
	Get(ctx context.Context, key string) (*Object, error)
	// Head returns the object's size and type, or ErrNotFound.
	Head(ctx context.Context, key string) (*Info, error)
	// Delete removes the object at key. Deleting a key with no object
	// is not an error.
	Delete(ctx context.Context, key string) error
}

// Env var names, in one place so the chart and the operator docs can
// mirror them.
const (
	EnvBucket    = "SB_OBJECTSTORE_BUCKET"
	EnvRegion    = "SB_OBJECTSTORE_REGION"
	EnvEndpoint  = "SB_OBJECTSTORE_ENDPOINT"
	EnvPathStyle = "SB_OBJECTSTORE_FORCE_PATH_STYLE"
	EnvPrefix    = "SB_OBJECTSTORE_PREFIX"
	EnvSSE       = "SB_OBJECTSTORE_SSE"
	EnvKMSKeyID  = "SB_OBJECTSTORE_KMS_KEY_ID"
)

// Server-side encryption modes accepted in SB_OBJECTSTORE_SSE.
const (
	SSENone   = ""
	SSEAES256 = "AES256"
	SSEKMS    = "aws:kms"
)

// Config is the object-storage configuration.
type Config struct {
	Bucket    string
	Region    string
	Endpoint  string
	PathStyle bool
	Prefix    string // normalised: no leading or trailing slash
	SSE       string
	KMSKeyID  string
}

// Enabled reports whether object storage is configured.
func (c Config) Enabled() bool { return c.Bucket != "" }

// Key joins parts under the configured prefix with "/".
func (c Config) Key(parts ...string) string {
	if c.Prefix != "" {
		parts = append([]string{c.Prefix}, parts...)
	}
	return strings.Join(parts, "/")
}

// LoadConfig reads the SB_OBJECTSTORE_* variables and validates them.
// With none set it returns a disabled Config and no error. Any setting
// without a bucket, or an invalid value, is an error, so a half-done
// configuration fails at boot instead of at the first upload.
func LoadConfig() (Config, error) {
	return parseConfig(os.Getenv)
}

func parseConfig(getenv func(string) string) (Config, error) {
	get := func(k string) string { return strings.TrimSpace(getenv(k)) }
	c := Config{
		Bucket:   get(EnvBucket),
		Region:   get(EnvRegion),
		Endpoint: get(EnvEndpoint),
		Prefix:   strings.Trim(get(EnvPrefix), "/"),
		SSE:      get(EnvSSE),
		KMSKeyID: get(EnvKMSKeyID),
	}
	pathStyle := get(EnvPathStyle)
	if pathStyle != "" {
		v, err := strconv.ParseBool(pathStyle)
		if err != nil {
			return Config{}, fmt.Errorf("objectstore: %s must be true or false", EnvPathStyle)
		}
		c.PathStyle = v
	}

	if c.Bucket == "" {
		for _, k := range []string{EnvRegion, EnvEndpoint, EnvPathStyle, EnvPrefix, EnvSSE, EnvKMSKeyID} {
			if get(k) != "" {
				return Config{}, fmt.Errorf("objectstore: %s is set but %s is empty; set the bucket or unset the other %s* variables", k, EnvBucket, "SB_OBJECTSTORE_")
			}
		}
		return Config{}, nil
	}
	if c.Region == "" {
		return Config{}, fmt.Errorf("objectstore: %s is required when %s is set", EnvRegion, EnvBucket)
	}
	switch c.SSE {
	case SSENone, SSEAES256, SSEKMS:
	default:
		return Config{}, fmt.Errorf("objectstore: %s must be empty, %q or %q", EnvSSE, SSEAES256, SSEKMS)
	}
	if c.SSE == SSEKMS && c.KMSKeyID == "" {
		return Config{}, fmt.Errorf("objectstore: %s is required with %s=%s", EnvKMSKeyID, EnvSSE, SSEKMS)
	}
	if c.KMSKeyID != "" && c.SSE != SSEKMS {
		return Config{}, fmt.Errorf("objectstore: %s is only used with %s=%s", EnvKMSKeyID, EnvSSE, SSEKMS)
	}
	if c.Endpoint != "" && !strings.HasPrefix(c.Endpoint, "https://") && !strings.HasPrefix(c.Endpoint, "http://") {
		return Config{}, fmt.Errorf("objectstore: %s must be an http:// or https:// URL", EnvEndpoint)
	}
	for _, seg := range strings.Split(c.Prefix, "/") {
		if c.Prefix != "" && (seg == "" || seg == "." || seg == "..") {
			return Config{}, fmt.Errorf("objectstore: %s has an empty, . or .. segment", EnvPrefix)
		}
	}
	return c, nil
}
