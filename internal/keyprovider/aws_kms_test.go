package keyprovider

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type kmsFixture struct {
	descriptions map[string]*types.KeyMetadata
	lastSign     *kms.SignInput
	verifyValid  bool
}

func (f *kmsFixture) DescribeKey(_ context.Context, input *kms.DescribeKeyInput,
	_ ...func(*kms.Options),
) (*kms.DescribeKeyOutput, error) {
	metadata, ok := f.descriptions[*input.KeyId]
	if !ok {
		return nil, errors.New("unknown fixture key")
	}

	return &kms.DescribeKeyOutput{KeyMetadata: metadata}, nil
}

func (f *kmsFixture) Sign(_ context.Context, input *kms.SignInput,
	_ ...func(*kms.Options),
) (*kms.SignOutput, error) {
	f.lastSign = input

	return &kms.SignOutput{Signature: []byte("kms-signature")}, nil
}

func (f *kmsFixture) Verify(_ context.Context, _ *kms.VerifyInput,
	_ ...func(*kms.Options),
) (*kms.VerifyOutput, error) {
	return &kms.VerifyOutput{SignatureValid: f.verifyValid}, nil
}

func TestKMSSigningProviderResolvesAliasToImmutableARNAndUsesDigest(t *testing.T) {
	arn := "arn:aws:kms:eu-west-2:123456789012:key/signing-v1"
	client := &kmsFixture{descriptions: map[string]*types.KeyMetadata{
		"alias/evidence": {
			Arn: &arn, KeyState: types.KeyStateEnabled, KeyUsage: types.KeyUsageTypeSignVerify,
			SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256},
		},
	}, verifyValid: true}
	provider, err := NewKMSSigningProvider(client, map[string]string{"evidence-envelope": "alias/evidence"},
		types.SigningAlgorithmSpecEcdsaSha256)
	if err != nil {
		t.Fatal(err)
	}
	key, err := provider.CurrentSigningKey(context.Background(), "evidence-envelope")
	if err != nil {
		t.Fatal(err)
	}
	if key.Reference != arn || key.Algorithm != string(types.SigningAlgorithmSpecEcdsaSha256) {
		t.Fatalf("unexpected resolved key: %+v", key)
	}
	signature, err := provider.Sign(context.Background(), key.Reference, []byte("evidence"))
	if err != nil {
		t.Fatal(err)
	}
	if len(signature) == 0 || client.lastSign == nil || len(client.lastSign.Message) != 32 ||
		client.lastSign.MessageType != types.MessageTypeDigest {
		t.Fatalf("KMS signing did not receive a SHA-256 digest: %+v", client.lastSign)
	}
	if err := provider.Verify(context.Background(), key.Reference, key.Algorithm,
		[]byte("evidence"), signature); err != nil {
		t.Fatal(err)
	}
	rotatedARN := "arn:aws:kms:eu-west-2:123456789012:key/signing-v2"
	client.descriptions["alias/evidence"] = &types.KeyMetadata{
		Arn: &rotatedARN, KeyState: types.KeyStateEnabled, KeyUsage: types.KeyUsageTypeSignVerify,
		SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256},
	}
	rotated, err := provider.CurrentSigningKey(context.Background(), "evidence-envelope")
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Reference != rotatedARN || key.Reference == rotated.Reference {
		t.Fatalf("KMS alias rotation did not resolve to a new immutable ARN: before=%+v after=%+v", key, rotated)
	}
	if err := provider.Verify(context.Background(), key.Reference, key.Algorithm,
		[]byte("evidence"), signature); err != nil {
		t.Fatalf("historical ARN did not remain verifiable after alias rotation: %v", err)
	}
}

func TestKMSProvidersFailClosedForDisabledOrCrossTenantKeys(t *testing.T) {
	signingARN := "arn:aws:kms:eu-west-2:123456789012:key/signing-disabled"
	encryptionARN := "arn:aws:kms:eu-west-2:123456789012:key/encryption-v1"
	client := &kmsFixture{descriptions: map[string]*types.KeyMetadata{
		"alias/signing": {
			Arn: &signingARN, KeyState: types.KeyStateDisabled, KeyUsage: types.KeyUsageTypeSignVerify,
			SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256},
		},
		"alias/tenant-a": {
			Arn: &encryptionARN, KeyState: types.KeyStateEnabled, KeyUsage: types.KeyUsageTypeEncryptDecrypt,
		},
	}}
	signing, err := NewKMSSigningProvider(client, map[string]string{"execution-grant": "alias/signing"},
		types.SigningAlgorithmSpecEcdsaSha256)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signing.CurrentSigningKey(context.Background(), "execution-grant"); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("expected disabled signing key rejection, got %v", err)
	}
	encryption, err := NewKMSEncryptionProvider(client, map[TenantPurpose]string{
		{TenantID: "tenant-a", Purpose: "captured-artefact"}: "alias/tenant-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	reference, err := encryption.CurrentEncryptionKey(context.Background(), "tenant-a", "captured-artefact")
	if err != nil || reference != encryptionARN {
		t.Fatalf("unexpected encryption key %q: %v", reference, err)
	}
	if _, err := encryption.CurrentEncryptionKey(context.Background(), "tenant-b", "captured-artefact"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected tenant isolation, got %v", err)
	}
}
