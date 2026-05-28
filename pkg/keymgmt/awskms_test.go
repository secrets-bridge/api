package keymgmt

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// fakeKMSClient is a hand-rolled stand-in for *kms.Client that lets
// the test drive both happy + error paths without booting LocalStack
// for every unit run.
type fakeKMSClient struct {
	// GenerateDataKey behavior
	generateReturn *kms.GenerateDataKeyOutput
	generateErr    error
	generateCalls  []*kms.GenerateDataKeyInput

	// Decrypt behavior
	decryptReturn *kms.DecryptOutput
	decryptErr    error
	decryptCalls  []*kms.DecryptInput
}

func (f *fakeKMSClient) GenerateDataKey(_ context.Context, in *kms.GenerateDataKeyInput, _ ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	f.generateCalls = append(f.generateCalls, in)
	if f.generateErr != nil {
		return nil, f.generateErr
	}
	return f.generateReturn, nil
}

func (f *fakeKMSClient) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	f.decryptCalls = append(f.decryptCalls, in)
	if f.decryptErr != nil {
		return nil, f.decryptErr
	}
	return f.decryptReturn, nil
}

func newTestAWSKMS(t *testing.T, fake *fakeKMSClient) *AWSKMS {
	t.Helper()
	return &AWSKMS{
		client: fake,
		keyID:  "alias/sb-wrap",
		region: "us-east-1",
	}
}

func TestAWSKMS_GenerateDataKey_HappyPath(t *testing.T) {
	plain := make([]byte, 32)
	if _, err := rand.Read(plain); err != nil {
		t.Fatalf("rand: %v", err)
	}
	resolvedARN := "arn:aws:kms:us-east-1:123456789012:key/abcd-1234-5678-90ef"
	fake := &fakeKMSClient{
		generateReturn: &kms.GenerateDataKeyOutput{
			Plaintext:      plain,
			CiphertextBlob: []byte("opaque-aws-kms-ciphertext-blob"),
			KeyId:          awsv2.String(resolvedARN),
		},
	}
	km := newTestAWSKMS(t, fake)

	dek, err := km.GenerateDataKey(context.Background())
	if err != nil {
		t.Fatalf("GenerateDataKey: %v", err)
	}
	if len(dek.Plaintext) != 32 {
		t.Fatalf("plaintext len = %d want 32", len(dek.Plaintext))
	}
	if string(dek.Ciphertext) != "opaque-aws-kms-ciphertext-blob" {
		t.Fatalf("ciphertext round-trip wrong")
	}
	// KeyID must carry the resolved ARN, not the alias the caller
	// supplied — that's how operators audit which exact CMK wrapped
	// each row after the alias has been rotated.
	wantPrefix := "aws-kms:us-east-1:"
	if !strings.HasPrefix(dek.KeyID, wantPrefix) {
		t.Fatalf("KeyID = %q, want prefix %q", dek.KeyID, wantPrefix)
	}
	if !strings.Contains(dek.KeyID, resolvedARN) {
		t.Fatalf("KeyID = %q does not include resolved ARN %q", dek.KeyID, resolvedARN)
	}

	// And the SDK call must request AES_256 (not AES_128).
	if len(fake.generateCalls) != 1 {
		t.Fatalf("GenerateDataKey called %d times", len(fake.generateCalls))
	}
	if fake.generateCalls[0].KeySpec != kmstypes.DataKeySpecAes256 {
		t.Fatalf("KeySpec = %v, want AES_256", fake.generateCalls[0].KeySpec)
	}
	if awsv2.ToString(fake.generateCalls[0].KeyId) != "alias/sb-wrap" {
		t.Fatalf("KeyId sent = %q, want the configured alias", awsv2.ToString(fake.generateCalls[0].KeyId))
	}
}

func TestAWSKMS_GenerateDataKey_WrongPlaintextLength(t *testing.T) {
	// A KeySpec=AES_256 GenerateDataKey must return 32 bytes; anything
	// else is a CMK misconfiguration or a malformed SDK response. We
	// fail loud so a 16-byte data key never silently weakens the wrap.
	fake := &fakeKMSClient{
		generateReturn: &kms.GenerateDataKeyOutput{
			Plaintext:      make([]byte, 16),
			CiphertextBlob: []byte("blob"),
		},
	}
	km := newTestAWSKMS(t, fake)
	_, err := km.GenerateDataKey(context.Background())
	if err == nil || !strings.Contains(err.Error(), "32-byte") {
		t.Fatalf("got %v, want length-validation error", err)
	}
}

func TestAWSKMS_GenerateDataKey_EmptyCiphertext(t *testing.T) {
	fake := &fakeKMSClient{
		generateReturn: &kms.GenerateDataKeyOutput{
			Plaintext:      make([]byte, 32),
			CiphertextBlob: nil,
		},
	}
	km := newTestAWSKMS(t, fake)
	_, err := km.GenerateDataKey(context.Background())
	if err == nil || !strings.Contains(err.Error(), "empty ciphertext") {
		t.Fatalf("got %v, want empty-ciphertext error", err)
	}
}

func TestAWSKMS_GenerateDataKey_SDKError(t *testing.T) {
	fake := &fakeKMSClient{
		generateErr: errors.New("AccessDeniedException: not authorized for kms:GenerateDataKey"),
	}
	km := newTestAWSKMS(t, fake)
	_, err := km.GenerateDataKey(context.Background())
	if err == nil || !strings.Contains(err.Error(), "AccessDeniedException") {
		t.Fatalf("got %v, want SDK error propagated", err)
	}
}

func TestAWSKMS_DecryptDataKey_HappyPath(t *testing.T) {
	plain := make([]byte, 32)
	if _, err := rand.Read(plain); err != nil {
		t.Fatalf("rand: %v", err)
	}
	fake := &fakeKMSClient{
		decryptReturn: &kms.DecryptOutput{Plaintext: plain},
	}
	km := newTestAWSKMS(t, fake)
	got, err := km.DecryptDataKey(context.Background(),
		[]byte("opaque-aws-kms-ciphertext-blob"),
		"aws-kms:us-east-1:arn:aws:kms:...:key/abcd")
	if err != nil {
		t.Fatalf("DecryptDataKey: %v", err)
	}
	if len(got) != 32 || string(got) != string(plain) {
		t.Fatalf("plaintext round-trip wrong")
	}
	if len(fake.decryptCalls) != 1 {
		t.Fatalf("Decrypt called %d times", len(fake.decryptCalls))
	}
	if string(fake.decryptCalls[0].CiphertextBlob) != "opaque-aws-kms-ciphertext-blob" {
		t.Fatalf("ciphertext not forwarded verbatim")
	}
}

func TestAWSKMS_DecryptDataKey_EmptyCiphertext(t *testing.T) {
	fake := &fakeKMSClient{}
	km := newTestAWSKMS(t, fake)
	_, err := km.DecryptDataKey(context.Background(), nil, "")
	if err == nil || !strings.Contains(err.Error(), "empty ciphertext") {
		t.Fatalf("got %v, want empty-ciphertext error", err)
	}
	if len(fake.decryptCalls) != 0 {
		t.Fatal("Decrypt should not be called for empty ciphertext")
	}
}

func TestAWSKMS_DecryptDataKey_WrongPlaintextLength(t *testing.T) {
	// Defends against a CMK misconfiguration that wrapped a 16-byte
	// key — we'd otherwise return a slice that AES-256-GCM can't use,
	// and the failure would surface in some random aes.NewCipher call
	// far from the source of the bug.
	fake := &fakeKMSClient{
		decryptReturn: &kms.DecryptOutput{Plaintext: make([]byte, 16)},
	}
	km := newTestAWSKMS(t, fake)
	_, err := km.DecryptDataKey(context.Background(), []byte("blob"), "")
	if err == nil || !strings.Contains(err.Error(), "32") {
		t.Fatalf("got %v, want length-validation error", err)
	}
}

func TestAWSKMS_CurrentKeyID(t *testing.T) {
	km := &AWSKMS{
		keyID:  "arn:aws:kms:us-east-1:123456789012:key/abcd",
		region: "us-east-1",
	}
	got := km.CurrentKeyID()
	want := "aws-kms:us-east-1:arn:aws:kms:us-east-1:123456789012:key/abcd"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestAWSKMS_FromEnv_ValidatesRequiredVars(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			name: "missing region",
			env:  map[string]string{EnvAWSKMSKeyID: "alias/k"},
			want: EnvAWSKMSRegion,
		},
		{
			name: "missing key id",
			env:  map[string]string{EnvAWSKMSRegion: "us-east-1"},
			want: EnvAWSKMSKeyID,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvAWSKMSRegion, tc.env[EnvAWSKMSRegion])
			t.Setenv(EnvAWSKMSKeyID, tc.env[EnvAWSKMSKeyID])
			t.Setenv(EnvAWSKMSEndpoint, "")
			_, err := NewAWSKMSFromEnv(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error mentioning %q", err, tc.want)
			}
		})
	}
}

func TestAWSKMS_FromEnv_BuildsClientFromEnv(t *testing.T) {
	// Resolver smoke test: env vars populate the struct correctly.
	// We can't exercise the real SDK without making a network call,
	// but we can confirm the constructor returns a valid AWSKMS with
	// the resolved keyID + region in place.
	t.Setenv(EnvAWSKMSRegion, "eu-west-1")
	t.Setenv(EnvAWSKMSKeyID, "arn:aws:kms:eu-west-1:123456789012:key/test")
	t.Setenv(EnvAWSKMSEndpoint, "http://localhost:4566")
	km, err := NewAWSKMSFromEnv(context.Background())
	if err != nil {
		t.Fatalf("NewAWSKMSFromEnv: %v", err)
	}
	if km.region != "eu-west-1" {
		t.Fatalf("region = %q", km.region)
	}
	if km.keyID != "arn:aws:kms:eu-west-1:123456789012:key/test" {
		t.Fatalf("keyID = %q", km.keyID)
	}
	if km.client == nil {
		t.Fatal("client is nil")
	}
}

func TestResolver_RoutesToAWSKMS(t *testing.T) {
	t.Setenv(EnvVarBackend, BackendAWSKMS)
	t.Setenv(EnvAWSKMSRegion, "us-east-1")
	t.Setenv(EnvAWSKMSKeyID, "alias/sb-wrap")
	t.Setenv(EnvAWSKMSEndpoint, "")
	km, err := FromEnv(context.Background())
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if _, ok := km.(*AWSKMS); !ok {
		t.Fatalf("FromEnv returned %T, want *AWSKMS", km)
	}
}
