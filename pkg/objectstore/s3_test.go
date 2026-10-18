package objectstore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// fakeS3 records the last request and returns canned errors.
type fakeS3 struct {
	put     *s3.PutObjectInput
	putBody []byte
	err     error
	objects map[string][]byte
}

func (f *fakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.put = in
	f.putBody, _ = io.ReadAll(in.Body)
	f.objects[*in.Key] = f.putBody
	return &s3.PutObjectOutput{}, nil
}

func (f *fakeS3) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	b, ok := f.objects[*in.Key]
	if !ok {
		return nil, &s3types.NoSuchKey{}
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(b)), ContentLength: awsv2.Int64(int64(len(b))), ContentType: awsv2.String("image/png")}, nil
}

func (f *fakeS3) HeadObject(_ context.Context, in *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	b, ok := f.objects[*in.Key]
	if !ok {
		return nil, &s3types.NotFound{}
	}
	return &s3.HeadObjectOutput{ContentLength: awsv2.Int64(int64(len(b)))}, nil
}

func (f *fakeS3) DeleteObject(_ context.Context, in *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	delete(f.objects, *in.Key)
	return &s3.DeleteObjectOutput{}, nil
}

func (f *fakeS3) HeadBucket(context.Context, *s3.HeadBucketInput, ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	return nil, f.err
}

func newFake() *fakeS3 { return &fakeS3{objects: map[string][]byte{}} }

func TestS3_PutSetsEncryptionAndLength(t *testing.T) {
	cases := []struct {
		cfg     Config
		wantSSE s3types.ServerSideEncryption
		wantKey string
	}{
		{Config{Bucket: "example-bucket"}, "", ""},
		{Config{Bucket: "example-bucket", SSE: SSEAES256}, s3types.ServerSideEncryptionAes256, ""},
		{Config{Bucket: "example-bucket", SSE: SSEKMS, KMSKeyID: "alias/example"}, s3types.ServerSideEncryptionAwsKms, "alias/example"},
	}
	for _, tc := range cases {
		f := newFake()
		s := newS3WithClient(f, tc.cfg)
		if err := s.Put(t.Context(), "k", bytes.NewReader([]byte("data")), 4, "image/png"); err != nil {
			t.Fatal(err)
		}
		in := f.put
		if *in.Bucket != "example-bucket" || *in.Key != "k" || *in.ContentLength != 4 || *in.ContentType != "image/png" || string(f.putBody) != "data" {
			t.Fatalf("put input %+v", in)
		}
		if in.ServerSideEncryption != tc.wantSSE || awsv2.ToString(in.SSEKMSKeyId) != tc.wantKey {
			t.Fatalf("%+v: SSE %q key %q", tc.cfg, in.ServerSideEncryption, awsv2.ToString(in.SSEKMSKeyId))
		}
		if in.ACL != "" {
			t.Fatalf("an ACL was set: %q", in.ACL)
		}
	}
}

func TestS3_NotFoundMapping(t *testing.T) {
	f := newFake()
	s := newS3WithClient(f, Config{Bucket: "example-bucket"})
	if _, err := s.Get(t.Context(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get missing = %v", err)
	}
	if _, err := s.Head(t.Context(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Head missing = %v", err)
	}
	if err := s.Delete(t.Context(), "missing"); err != nil {
		t.Fatalf("Delete missing = %v", err)
	}

	// A bare 404 (HEAD responses carry no error body).
	f.err = &awshttp.ResponseError{ResponseError: &smithyhttp.ResponseError{
		Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusNotFound}},
		Err:      errors.New("not found"),
	}}
	if _, err := s.Head(t.Context(), "k"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Head bare 404 = %v", err)
	}

	// A missing bucket is a configuration problem, not a missing object.
	f.err = &smithy.GenericAPIError{Code: "NoSuchBucket", Message: "no bucket"}
	if _, err := s.Get(t.Context(), "k"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("Get on missing bucket = %v; must not be ErrNotFound", err)
	}
	if err := s.Delete(t.Context(), "k"); err == nil {
		t.Fatal("Delete on a missing bucket reported success")
	}
	if err := s.Check(t.Context()); err == nil || !strings.Contains(err.Error(), "example-bucket") {
		t.Fatalf("Check = %v", err)
	}
	f.err = errors.New("access denied")
	if err := s.Put(t.Context(), "k", bytes.NewReader(nil), 0, "image/png"); err == nil {
		t.Fatal("Put error swallowed")
	}
}

func TestS3_GetRoundTrip(t *testing.T) {
	f := newFake()
	s := newS3WithClient(f, Config{Bucket: "example-bucket"})
	if err := s.Put(t.Context(), "a/b.png", bytes.NewReader([]byte("png")), 3, "image/png"); err != nil {
		t.Fatal(err)
	}
	obj, err := s.Get(t.Context(), "a/b.png")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = obj.Body.Close() }()
	b, _ := io.ReadAll(obj.Body)
	if string(b) != "png" || obj.Size != 3 || obj.ContentType != "image/png" {
		t.Fatalf("got %q %+v", b, obj)
	}
	if info, err := s.Head(t.Context(), "a/b.png"); err != nil || info.Size != 3 {
		t.Fatalf("Head = %+v %v", info, err)
	}
	if s.Config().Bucket != "example-bucket" {
		t.Fatal("Config")
	}
}

// stallS3 takes every call and never answers, like a store that accepts
// the connection and then stalls. A call returns only when its context
// ends; a Get answers at once with a body that stalls the same way.
type stallS3 struct{}

func (stallS3) PutObject(ctx context.Context, _ *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (stallS3) GetObject(ctx context.Context, _ *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return &s3.GetObjectOutput{Body: stallBody{ctx}, ContentLength: awsv2.Int64(1)}, nil
}

func (stallS3) HeadObject(ctx context.Context, _ *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (stallS3) DeleteObject(ctx context.Context, _ *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (stallS3) HeadBucket(ctx context.Context, _ *s3.HeadBucketInput, _ ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

type stallBody struct{ ctx context.Context }

func (b stallBody) Read([]byte) (int, error) {
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}

func (stallBody) Close() error { return nil }

// Every call ends with an error once the call timeout passes, even with
// a context that is never cancelled (what a Fiber handler passes in).
func TestS3_StalledStoreCallsEnd(t *testing.T) {
	s := newS3WithClient(stallS3{}, Config{Bucket: "example-bucket"})
	s.timeout = 50 * time.Millisecond
	ctx := context.Background()
	calls := map[string]func() error{
		"put":    func() error { return s.Put(ctx, "k", bytes.NewReader([]byte("x")), 1, "image/png") },
		"head":   func() error { _, err := s.Head(ctx, "k"); return err },
		"delete": func() error { return s.Delete(ctx, "k") },
		"check":  func() error { return s.Check(ctx) },
		"get": func() error {
			o, err := s.Get(ctx, "k")
			if err != nil {
				return err
			}
			defer func() { _ = o.Body.Close() }()
			_, err = io.ReadAll(o.Body)
			return err
		},
	}
	done := make(chan string, len(calls))
	for name, call := range calls {
		go func() {
			if err := call(); err == nil {
				t.Errorf("%s: no error from a stalled store", name)
			}
			done <- name
		}()
	}
	deadline := time.After(5 * time.Second)
	for range calls {
		select {
		case <-done:
		case <-deadline:
			t.Fatalf("calls still waiting on a stalled store after 5s")
		}
	}
}
