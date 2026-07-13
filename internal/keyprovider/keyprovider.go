// Package keyprovider defines opaque signing and encryption key boundaries.
// Providers retain key material; callers persist only stable key references.
package keyprovider

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
)

const Ed25519Algorithm = "Ed25519"

var (
	ErrKeyNotFound      = errors.New("key reference was not found")
	ErrInvalidSignature = errors.New("signature verification failed")
)

type SigningKey struct {
	Reference string
	Algorithm string
}

type SigningProvider interface {
	CurrentSigningKey(context.Context, string) (SigningKey, error)
	Sign(context.Context, string, []byte) ([]byte, error)
	Verify(context.Context, string, string, []byte, []byte) error
}

type EncryptionProvider interface {
	CurrentEncryptionKey(context.Context, string, string) (string, error)
}

type StaticEncryptionProvider struct {
	Reference string
}

func (p StaticEncryptionProvider) CurrentEncryptionKey(_ context.Context, tenantID, purpose string) (string, error) {
	if p.Reference == "" || tenantID == "" || purpose == "" {
		return "", fmt.Errorf("encryption key reference, tenant and purpose are required")
	}

	return p.Reference, nil
}

// Ed25519Keyring is an in-process reference provider. Production deployments
// should implement SigningProvider with KMS or HSM operations.
type Ed25519Keyring struct {
	mu      sync.RWMutex
	current string
	private map[string]ed25519.PrivateKey
	public  map[string]ed25519.PublicKey
}

func NewEd25519Keyring(reference string, private ed25519.PrivateKey) (*Ed25519Keyring, error) {
	keyring := &Ed25519Keyring{
		private: make(map[string]ed25519.PrivateKey), public: make(map[string]ed25519.PublicKey),
	}
	if err := keyring.Rotate(reference, private); err != nil {
		return nil, err
	}

	return keyring, nil
}

func (k *Ed25519Keyring) Rotate(reference string, private ed25519.PrivateKey) error {
	if k == nil || reference == "" || len(private) != ed25519.PrivateKeySize {
		return fmt.Errorf("signing key reference and Ed25519 private key are required")
	}
	public, ok := private.Public().(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("derive Ed25519 public key")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, exists := k.private[reference]; exists {
		return fmt.Errorf("signing key reference already exists")
	}
	k.private[reference] = append(ed25519.PrivateKey(nil), private...)
	k.public[reference] = append(ed25519.PublicKey(nil), public...)
	k.current = reference

	return nil
}

func (k *Ed25519Keyring) CurrentSigningKey(_ context.Context, purpose string) (SigningKey, error) {
	if k == nil || purpose == "" {
		return SigningKey{}, fmt.Errorf("signing purpose is required")
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.current == "" {
		return SigningKey{}, ErrKeyNotFound
	}

	return SigningKey{Reference: k.current, Algorithm: Ed25519Algorithm}, nil
}

func (k *Ed25519Keyring) Sign(_ context.Context, reference string, payload []byte) ([]byte, error) {
	if k == nil || reference == "" || len(payload) == 0 {
		return nil, fmt.Errorf("signing key reference and payload are required")
	}
	k.mu.RLock()
	private, ok := k.private[reference]
	k.mu.RUnlock()
	if !ok {
		return nil, ErrKeyNotFound
	}

	return ed25519.Sign(private, payload), nil
}

func (k *Ed25519Keyring) Verify(_ context.Context, reference, algorithm string,
	payload, signature []byte,
) error {
	if k == nil || reference == "" || algorithm != Ed25519Algorithm || len(payload) == 0 {
		return ErrInvalidSignature
	}
	k.mu.RLock()
	public, ok := k.public[reference]
	k.mu.RUnlock()
	if !ok {
		return ErrKeyNotFound
	}
	if !ed25519.Verify(public, payload, signature) {
		return ErrInvalidSignature
	}

	return nil
}

// EncryptionKeyring stores opaque references only. It deliberately cannot
// return raw encryption key material.
type EncryptionKeyring struct {
	mu      sync.RWMutex
	current map[string]string
}

func NewEncryptionKeyring() *EncryptionKeyring {
	return &EncryptionKeyring{current: make(map[string]string)}
}

func (k *EncryptionKeyring) Rotate(tenantID, reference string) error {
	if k == nil || tenantID == "" || reference == "" {
		return fmt.Errorf("tenant and encryption key reference are required")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.current[tenantID] = reference

	return nil
}

func (k *EncryptionKeyring) CurrentEncryptionKey(_ context.Context, tenantID, purpose string) (string, error) {
	if k == nil || tenantID == "" || purpose == "" {
		return "", fmt.Errorf("tenant and encryption purpose are required")
	}
	k.mu.RLock()
	reference, ok := k.current[tenantID]
	k.mu.RUnlock()
	if !ok {
		return "", ErrKeyNotFound
	}

	return reference, nil
}
