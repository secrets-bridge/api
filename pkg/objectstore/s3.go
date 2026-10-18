package objectstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// S3 is the Store on AWS S3 or any S3-compatible server.
//
// Objects are private: no ACL is ever set, and the api serves them
// itself so the existing authorization stays in front of every read.
type S3 struct {
	client  s3Client
	cfg     Config
	timeout time.Duration
}

// callTimeout bounds every call to the store, a Get until its body is
// closed. The SDK switches its own S3 read timeout off and a request's
// context may never be cancelled, so a store that accepts the
// connection and then stalls would otherwise hold the goroutine and the
// connection for good. Logos are at most 64 KiB, so this is generous.
const callTimeout = 10 * time.Second

// call returns ctx bounded by the store's call timeout.
func (s *S3) call(ctx context.Context) (context.Context, context.CancelFunc) {
	t := s.timeout
	if t <= 0 {
		t = callTimeout
	}
	return context.WithTimeout(ctx, t)
}

// cancelOnClose ends a Get's context when its body is closed.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c cancelOnClose) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}

// s3Client is the slice of the SDK S3 client S3 uses. The interface
// lets unit tests inject a fake; *s3.Client satisfies it.
type s3Client interface {
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
	HeadBucket(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
}

// NewS3 builds the S3 store for an enabled Config, with credentials
// from the default AWS SDK chain. It does not contact the bucket; call
// Check for that.
func NewS3(ctx context.Context, cfg Config) (*S3, error) {
	client, err := NewS3Client(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &S3{client: client, cfg: cfg, timeout: callTimeout}, nil
}

// NewS3Client returns the SDK client NewS3 uses. Exported for tests and
// tooling that need bucket-level calls (for example creating a test
// bucket on MinIO); the api itself only goes through Store.
func NewS3Client(ctx context.Context, cfg Config) (*s3.Client, error) {
	if !cfg.Enabled() {
		return nil, errors.New("objectstore: no bucket configured")
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Region))
	if err != nil {
		return nil, fmt.Errorf("objectstore: aws config: %w", err)
	}
	return s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = awsv2.String(cfg.Endpoint)
			// S3-compatible servers vary in support for the SDK's
			// default flexible checksums; send them only when an
			// operation requires one.
			o.RequestChecksumCalculation = awsv2.RequestChecksumCalculationWhenRequired
			o.ResponseChecksumValidation = awsv2.ResponseChecksumValidationWhenRequired
		}
		o.UsePathStyle = cfg.PathStyle
	}), nil
}

// newS3WithClient wires a fake client in unit tests.
func newS3WithClient(c s3Client, cfg Config) *S3 {
	return &S3{client: c, cfg: cfg, timeout: callTimeout}
}

// Config returns the store's configuration.
func (s *S3) Config() Config { return s.cfg }

// Check confirms the bucket is reachable with the current credentials
// (HeadBucket, which needs s3:ListBucket). The api calls it at boot so
// a wrong bucket, region, endpoint or role fails there.
func (s *S3) Check(ctx context.Context) error {
	ctx, cancel := s.call(ctx)
	defer cancel()
	if _, err := s.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: awsv2.String(s.cfg.Bucket)}); err != nil {
		return fmt.Errorf("objectstore: bucket %q is not reachable: %w", s.cfg.Bucket, err)
	}
	return nil
}

// Put writes one object with the configured server-side encryption.
func (s *S3) Put(ctx context.Context, key string, body io.ReadSeeker, size int64, contentType string) error {
	in := &s3.PutObjectInput{
		Bucket:        awsv2.String(s.cfg.Bucket),
		Key:           awsv2.String(key),
		Body:          body,
		ContentLength: awsv2.Int64(size),
		ContentType:   awsv2.String(contentType),
	}
	switch s.cfg.SSE {
	case SSEAES256:
		in.ServerSideEncryption = s3types.ServerSideEncryptionAes256
	case SSEKMS:
		in.ServerSideEncryption = s3types.ServerSideEncryptionAwsKms
		if s.cfg.KMSKeyID != "" {
			in.SSEKMSKeyId = awsv2.String(s.cfg.KMSKeyID)
		}
	}
	ctx, cancel := s.call(ctx)
	defer cancel()
	if _, err := s.client.PutObject(ctx, in); err != nil {
		return fmt.Errorf("objectstore: put: %w", err)
	}
	return nil
}

// Get opens one object.
func (s *S3) Get(ctx context.Context, key string) (*Object, error) {
	ctx, cancel := s.call(ctx)
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: awsv2.String(s.cfg.Bucket),
		Key:    awsv2.String(key),
	})
	if err != nil {
		cancel()
		if isNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("objectstore: get: %w", err)
	}
	return &Object{
		Body:        cancelOnClose{ReadCloser: out.Body, cancel: cancel},
		Size:        awsv2.ToInt64(out.ContentLength),
		ContentType: awsv2.ToString(out.ContentType),
	}, nil
}

// Head reads one object's metadata.
func (s *S3) Head(ctx context.Context, key string) (*Info, error) {
	ctx, cancel := s.call(ctx)
	defer cancel()
	out, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: awsv2.String(s.cfg.Bucket),
		Key:    awsv2.String(key),
	})
	if err != nil {
		if isNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("objectstore: head: %w", err)
	}
	return &Info{Size: awsv2.ToInt64(out.ContentLength), ContentType: awsv2.ToString(out.ContentType)}, nil
}

// Delete removes one object. S3 answers 204 for a missing key, so this
// is idempotent; a 404 from a stricter server is treated the same way.
func (s *S3) Delete(ctx context.Context, key string) error {
	ctx, cancel := s.call(ctx)
	defer cancel()
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: awsv2.String(s.cfg.Bucket),
		Key:    awsv2.String(key),
	})
	if err != nil && !isNotFound(err) {
		return fmt.Errorf("objectstore: delete: %w", err)
	}
	return nil
}

// isNotFound recognises a missing object: NoSuchKey from GetObject,
// NotFound (a bare 404 with no body) from HeadObject. A missing bucket
// is a configuration error, never a missing object.
func isNotFound(err error) bool {
	var nsk *s3types.NoSuchKey
	var nf *s3types.NotFound
	if errors.As(err, &nsk) || errors.As(err, &nf) {
		return true
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "NoSuchKey", "NotFound":
			return true
		case "NoSuchBucket":
			return false
		}
	}
	var respErr *awshttp.ResponseError
	return errors.As(err, &respErr) && respErr.HTTPStatusCode() == http.StatusNotFound
}
