package keyprovider

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
)

func TestSigningKeyringRetainsVerificationKeysAcrossRotation(t *testing.T) {
	_, firstPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := NewEd25519Keyring("signing-key-v1", firstPrivate)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	first, err := keyring.CurrentSigningKey(ctx, "evidence")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("lineage")
	signature, err := keyring.Sign(ctx, first.Reference, payload)
	if err != nil {
		t.Fatal(err)
	}
	_, secondPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyring.Rotate("signing-key-v2", secondPrivate); err != nil {
		t.Fatal(err)
	}
	current, err := keyring.CurrentSigningKey(ctx, "evidence")
	if err != nil || current.Reference != "signing-key-v2" {
		t.Fatalf("unexpected current signing key: %+v error=%v", current, err)
	}
	if err := keyring.Verify(ctx, first.Reference, first.Algorithm, payload, signature); err != nil {
		t.Fatalf("old signature no longer verifies after rotation: %v", err)
	}
	if err := keyring.Verify(ctx, first.Reference, first.Algorithm, []byte("tampered"), signature); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected invalid signature, got %v", err)
	}
}

func TestEncryptionKeyringReturnsOpaqueTenantReferences(t *testing.T) {
	keyring := NewEncryptionKeyring()
	if err := keyring.Rotate("tenant-a", "kms://evidence/key/v1"); err != nil {
		t.Fatal(err)
	}
	reference, err := keyring.CurrentEncryptionKey(context.Background(), "tenant-a", "captured-artefact")
	if err != nil || reference != "kms://evidence/key/v1" {
		t.Fatalf("unexpected encryption reference %q: %v", reference, err)
	}
	if _, err := keyring.CurrentEncryptionKey(context.Background(), "tenant-b", "captured-artefact"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected tenant-specific key lookup to fail, got %v", err)
	}
}
