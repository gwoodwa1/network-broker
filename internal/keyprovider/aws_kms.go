package keyprovider

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

var ErrKeyUnavailable = errors.New("key is not enabled for the required operation")

type KMSAPI interface {
	DescribeKey(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
	Verify(context.Context, *kms.VerifyInput, ...func(*kms.Options)) (*kms.VerifyOutput, error)
}

// KMSSigningProvider keeps private signing material inside AWS KMS. Purpose
// configuration may use an alias, but signed records receive the immutable key
// ARN returned by DescribeKey so alias rotation cannot change their verifier.
type KMSSigningProvider struct {
	client    KMSAPI
	keys      map[string]string
	algorithm types.SigningAlgorithmSpec
}

func NewKMSSigningProvider(client KMSAPI, purposeKeys map[string]string,
	algorithm types.SigningAlgorithmSpec,
) (*KMSSigningProvider, error) {
	if client == nil || len(purposeKeys) == 0 || !supportedKMSAlgorithm(algorithm) {
		return nil, fmt.Errorf("KMS client, purpose keys and a SHA-256 signing algorithm are required")
	}
	keys := make(map[string]string, len(purposeKeys))
	for purpose, reference := range purposeKeys {
		if purpose == "" || reference == "" {
			return nil, fmt.Errorf("KMS signing purpose and key reference are required")
		}
		keys[purpose] = reference
	}

	return &KMSSigningProvider{client: client, keys: keys, algorithm: algorithm}, nil
}

func (p *KMSSigningProvider) CurrentSigningKey(ctx context.Context, purpose string) (SigningKey, error) {
	reference, ok := p.keys[purpose]
	if !ok {
		return SigningKey{}, ErrKeyNotFound
	}
	description, err := p.client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &reference})
	if err != nil {
		return SigningKey{}, fmt.Errorf("describe KMS signing key: %w", err)
	}
	if description.KeyMetadata == nil || description.KeyMetadata.Arn == nil ||
		description.KeyMetadata.KeyState != types.KeyStateEnabled ||
		description.KeyMetadata.KeyUsage != types.KeyUsageTypeSignVerify ||
		!slices.Contains(description.KeyMetadata.SigningAlgorithms, p.algorithm) {
		return SigningKey{}, ErrKeyUnavailable
	}

	return SigningKey{Reference: *description.KeyMetadata.Arn, Algorithm: string(p.algorithm)}, nil
}

func (p *KMSSigningProvider) Sign(ctx context.Context, reference string, payload []byte) ([]byte, error) {
	if reference == "" || len(payload) == 0 {
		return nil, fmt.Errorf("KMS signing key reference and payload are required")
	}
	digest := sha256.Sum256(payload)
	output, err := p.client.Sign(ctx, &kms.SignInput{
		KeyId: &reference, Message: digest[:], MessageType: types.MessageTypeDigest,
		SigningAlgorithm: p.algorithm,
	})
	if err != nil {
		return nil, fmt.Errorf("KMS sign: %w", err)
	}
	if len(output.Signature) == 0 {
		return nil, fmt.Errorf("KMS returned an empty signature")
	}

	return append([]byte(nil), output.Signature...), nil
}

func (p *KMSSigningProvider) Verify(ctx context.Context, reference, algorithm string,
	payload, signature []byte,
) error {
	spec := types.SigningAlgorithmSpec(algorithm)
	if reference == "" || len(payload) == 0 || len(signature) == 0 || !supportedKMSAlgorithm(spec) {
		return ErrInvalidSignature
	}
	digest := sha256.Sum256(payload)
	output, err := p.client.Verify(ctx, &kms.VerifyInput{
		KeyId: &reference, Message: digest[:], MessageType: types.MessageTypeDigest,
		Signature: signature, SigningAlgorithm: spec,
	})
	if err != nil {
		return fmt.Errorf("KMS verify: %w", err)
	}
	if !output.SignatureValid {
		return ErrInvalidSignature
	}

	return nil
}

type TenantPurpose struct {
	TenantID string
	Purpose  string
}

// KMSEncryptionProvider resolves tenant-purpose configuration to an immutable,
// enabled AWS KMS key ARN. It never requests or returns plaintext key material.
type KMSEncryptionProvider struct {
	client KMSAPI
	keys   map[TenantPurpose]string
}

func NewKMSEncryptionProvider(client KMSAPI,
	tenantKeys map[TenantPurpose]string,
) (*KMSEncryptionProvider, error) {
	if client == nil || len(tenantKeys) == 0 {
		return nil, fmt.Errorf("KMS client and tenant-purpose keys are required")
	}
	keys := make(map[TenantPurpose]string, len(tenantKeys))
	for binding, reference := range tenantKeys {
		if binding.TenantID == "" || binding.Purpose == "" || reference == "" {
			return nil, fmt.Errorf("KMS tenant, purpose and key reference are required")
		}
		keys[binding] = reference
	}

	return &KMSEncryptionProvider{client: client, keys: keys}, nil
}

func (p *KMSEncryptionProvider) CurrentEncryptionKey(ctx context.Context, tenantID, purpose string) (string, error) {
	reference, ok := p.keys[TenantPurpose{TenantID: tenantID, Purpose: purpose}]
	if !ok {
		return "", ErrKeyNotFound
	}
	description, err := p.client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &reference})
	if err != nil {
		return "", fmt.Errorf("describe KMS encryption key: %w", err)
	}
	if description.KeyMetadata == nil || description.KeyMetadata.Arn == nil ||
		description.KeyMetadata.KeyState != types.KeyStateEnabled ||
		description.KeyMetadata.KeyUsage != types.KeyUsageTypeEncryptDecrypt {
		return "", ErrKeyUnavailable
	}

	return *description.KeyMetadata.Arn, nil
}

func supportedKMSAlgorithm(algorithm types.SigningAlgorithmSpec) bool {
	return algorithm == types.SigningAlgorithmSpecEcdsaSha256 ||
		algorithm == types.SigningAlgorithmSpecRsassaPkcs1V15Sha256 ||
		algorithm == types.SigningAlgorithmSpecRsassaPssSha256
}
