package objectstore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

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
