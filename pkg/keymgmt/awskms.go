package keymgmt

import (
	"context"
	"errors"
	"fmt"
	"os"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// AWSKMS implements KeyManager using AWS Key Management Service.
//
// One CMK per deployment wraps every per-row data key (envelope
// encryption). Credentials come from the default AWS SDK chain — IRSA
// in EKS, instance role on EC2, AWS_* env vars / shared profile in
// dev. secrets-bridge does NOT introduce new credential env vars, the
// same precedent as the aws-sm provider (Piece 4d).
//
// Why AWS KMS as the third backend:
//   - Operators on AWS already pay for KMS; reusing it avoids running a
//     separate Vault deployment just for envelope encryption
//   - HSM-backed CMKs (xks / cloudhsm) give FIPS 140-3 Level 3 storage
//     of the master key without additional CP-side code
//   - IAM-scoped GenerateDataKey + Decrypt permissions; the CP role
//     never holds the master key bytes
//
// Future Piece 8c will let different projects / tenants point at
// different CMKs by threading a scope through the KeyManager
// interface; today it is one CMK per CP instance.
type AWSKMS struct {
	client kmsClient
	keyID  string // ARN, key id, or alias
	region string
}

// kmsClient is the small slice of the AWS SDK KMS client used by
// AWSKMS. Defining the interface here lets unit tests inject a fake;
// the real *kms.Client satisfies the same shape.
type kmsClient interface {
	GenerateDataKey(ctx context.Context, params *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// Env var names. Documented here in one place so the helm chart /
// operator docs can mirror them.
const (
	EnvAWSKMSRegion   = "SB_KMS_AWS_REGION"
	EnvAWSKMSKeyID    = "SB_KMS_AWS_KEY_ID"    // ARN, key id, or alias/<name>
	EnvAWSKMSEndpoint = "SB_KMS_AWS_ENDPOINT"  // optional — LocalStack / VPC endpoint
)

// NewAWSKMSFromEnv reads the SB_KMS_AWS_* env vars and builds an
// AWSKMS. Errors if region or key id are missing.
//
// The endpoint override is optional. When set, it's wired through the
// SDK client's BaseEndpoint so LocalStack and VPC endpoints can be
// used without forking the codebase.
func NewAWSKMSFromEnv(ctx context.Context) (*AWSKMS, error) {
	region := os.Getenv(EnvAWSKMSRegion)
	if region == "" {
		return nil, fmt.Errorf("keymgmt: %s is required for aws-kms", EnvAWSKMSRegion)
	}
	keyID := os.Getenv(EnvAWSKMSKeyID)
	if keyID == "" {
		return nil, fmt.Errorf("keymgmt: %s is required (the CMK ARN / id / alias that wraps data keys)", EnvAWSKMSKeyID)
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("keymgmt: aws config: %w", err)
	}

	var client *kms.Client
	if endpoint := os.Getenv(EnvAWSKMSEndpoint); endpoint != "" {
		client = kms.NewFromConfig(cfg, func(o *kms.Options) {
			o.BaseEndpoint = awsv2.String(endpoint)
		})
	} else {
		client = kms.NewFromConfig(cfg)
	}

	return &AWSKMS{
		client: client,
		keyID:  keyID,
		region: region,
	}, nil
}

// GenerateDataKey calls KMS GenerateDataKey with KeySpec=AES_256. AWS
// returns the plaintext 32-byte key + its KMS-wrapped ciphertext. The
// plaintext lives in CP memory only between Wrap and the immediate
// AES-GCM encrypt; the ciphertext is what persists.
func (a *AWSKMS) GenerateDataKey(ctx context.Context) (DataKey, error) {
	out, err := a.client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:   awsv2.String(a.keyID),
		KeySpec: kmstypes.DataKeySpecAes256,
	})
	if err != nil {
		return DataKey{}, fmt.Errorf("keymgmt: aws kms generate data key: %w", err)
	}
	if len(out.Plaintext) != 32 {
		return DataKey{}, fmt.Errorf("keymgmt: expected 32-byte datakey, got %d", len(out.Plaintext))
	}
	if len(out.CiphertextBlob) == 0 {
		return DataKey{}, errors.New("keymgmt: aws kms returned empty ciphertext blob")
	}
	// AWS echoes back the resolved KeyId (full ARN even when the input
	// was an alias). Storing the resolved ARN in the row's kms_key_id
	// lets operators audit which exact CMK wrapped each row.
	resolvedKey := a.keyID
	if out.KeyId != nil && *out.KeyId != "" {
		resolvedKey = *out.KeyId
	}
	return DataKey{
		Plaintext:  out.Plaintext,
		Ciphertext: out.CiphertextBlob,
		KeyID:      "aws-kms:" + a.region + ":" + resolvedKey,
	}, nil
}

// DecryptDataKey calls KMS Decrypt with the wrapped data key. The
// keyID arg is informational — KMS resolves the CMK from the
// ciphertext blob itself.
func (a *AWSKMS) DecryptDataKey(ctx context.Context, ciphertext []byte, keyID string) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, errors.New("keymgmt: aws kms decrypt called with empty ciphertext")
	}
	// keyID is informational here — the CMK that wraps a blob is
	// embedded in the blob itself, and AWS verifies it during Decrypt.
	// We accept the arg only so the interface stays symmetric.
	_ = keyID

	out, err := a.client.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob: ciphertext,
		KeyId:          awsv2.String(a.keyID),
	})
	if err != nil {
		return nil, fmt.Errorf("keymgmt: aws kms decrypt: %w", err)
	}
	if len(out.Plaintext) != 32 {
		return nil, fmt.Errorf("keymgmt: aws kms decrypt returned %d-byte plaintext, expected 32", len(out.Plaintext))
	}
	return out.Plaintext, nil
}

// CurrentKeyID returns a stable identifier for the configured CMK.
// The blob-embedded version is what KMS uses for decrypt routing.
func (a *AWSKMS) CurrentKeyID() string {
	return "aws-kms:" + a.region + ":" + a.keyID
}
