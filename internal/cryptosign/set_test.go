package cryptosign

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"network_broker/internal/keyprovider"
)

func TestSignatureSetSupportsDualSigningAndRejectsStripping(t *testing.T) {
	first := newKeyring(t, "key-1")
	second := newKeyring(t, "key-2")
	manager, err := NewManager([]keyprovider.SigningProvider{first, second}, Policy{
		MinimumValidSignatures: 2, RequiredAlgorithms: []string{keyprovider.Ed25519Algorithm},
	})
	if err != nil {
		t.Fatal(err)
	}
	canonical := []byte(`{"receipt_id":"receipt-1"}`)
	set, err := manager.Sign(context.Background(), "disclosure-receipt", "disclosure-receipt/v1", canonical)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Signatures) != 2 {
		t.Fatalf("expected two signatures, got %d", len(set.Signatures))
	}
	if err := manager.Verify(context.Background(), "disclosure-receipt/v1", canonical, set); err != nil {
		t.Fatalf("verify signature set: %v", err)
	}
	stripped := set
	stripped.Signatures = append([]Entry(nil), set.Signatures[:1]...)
	if err := manager.Verify(context.Background(), "disclosure-receipt/v1", canonical, stripped); !errors.Is(err, ErrPolicyUnsatisfied) {
		t.Fatalf("expected stripped signature policy failure, got %v", err)
	}
}

func TestSignatureSetRejectsSubstitutionReplayAndMutation(t *testing.T) {
	manager, err := NewManager([]keyprovider.SigningProvider{newKeyring(t, "key-1")}, Policy{MinimumValidSignatures: 1})
	if err != nil {
		t.Fatal(err)
	}
	canonical := []byte(`{"receipt_id":"receipt-1"}`)
	set, err := manager.Sign(context.Background(), "disclosure-receipt", "disclosure-receipt/v1", canonical)
	if err != nil {
		t.Fatal(err)
	}
	mutatedAlgorithm := set
	mutatedAlgorithm.Signatures = append([]Entry(nil), set.Signatures...)
	mutatedAlgorithm.Signatures[0].Algorithm = "ML-DSA-65"
	if err := manager.Verify(context.Background(), "disclosure-receipt/v1", canonical, mutatedAlgorithm); !errors.Is(err, ErrInvalidSet) {
		t.Fatalf("expected algorithm substitution rejection, got %v", err)
	}
	if err := manager.Verify(context.Background(), "evidence-envelope/v1", canonical, set); !errors.Is(err, ErrInvalidSet) {
		t.Fatalf("expected cross-domain replay rejection, got %v", err)
	}
	if err := manager.Verify(context.Background(), "disclosure-receipt/v1", []byte(`{"receipt_id":"receipt-2"}`), set); !errors.Is(err, ErrInvalidSet) {
		t.Fatalf("expected payload mutation rejection, got %v", err)
	}
}

func TestSignatureSetRetainsHistoricalVerificationAfterRotation(t *testing.T) {
	keyring := newKeyring(t, "key-1")
	manager, err := NewManager([]keyprovider.SigningProvider{keyring}, Policy{MinimumValidSignatures: 1})
	if err != nil {
		t.Fatal(err)
	}
	canonical := []byte(`{"receipt_id":"receipt-1"}`)
	set, err := manager.Sign(context.Background(), "disclosure-receipt", "disclosure-receipt/v1", canonical)
	if err != nil {
		t.Fatal(err)
	}
	_, rotatedPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyring.Rotate("key-2", rotatedPrivate); err != nil {
		t.Fatal(err)
	}
	if err := manager.Verify(context.Background(), "disclosure-receipt/v1", canonical, set); err != nil {
		t.Fatalf("historical signature failed after rotation: %v", err)
	}
}

func TestSigningPayloadV1Vector(t *testing.T) {
	canonical := []byte(`{"receipt_id":"receipt-1"}`)
	got, err := signingPayload("disclosure-receipt/v1", canonical)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("network-broker-signature-set/v1\x00network-broker-json/v1\x00disclosure-receipt/v1\x00" +
		`{"receipt_id":"receipt-1"}`)
	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected signing payload vector\ngot:  %q\nwant: %q", got, want)
	}
}

func newKeyring(t *testing.T, reference string) *keyprovider.Ed25519Keyring {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := keyprovider.NewEd25519Keyring(reference, private)
	if err != nil {
		t.Fatal(err)
	}
	return keyring
}
