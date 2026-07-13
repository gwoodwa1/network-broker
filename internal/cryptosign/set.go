// Package cryptosign provides versioned, domain-separated signature sets.
package cryptosign

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"network_broker/internal/keyprovider"
)

const (
	SetVersionV1       = "network-broker-signature-set/v1"
	CanonicalJSONV1    = "network-broker-json/v1"
	maximumSignatures  = 8
	maximumDomainBytes = 128
	maximumPayloadSize = 16 << 20
)

var (
	ErrInvalidSet        = errors.New("signature set is invalid")
	ErrPolicyUnsatisfied = errors.New("signature policy is not satisfied")
)

// Entry records one independently verifiable signature and its immutable key
// reference. Value contains only the signature bytes, never key material.
type Entry struct {
	Algorithm    string `json:"algorithm"`
	KeyReference string `json:"key_reference"`
	Value        []byte `json:"value"`
}

// Set is embedded in a signed object. Domain is checked by the verifier and
// prevents a valid signature for one object type being replayed as another.
type Set struct {
	Version          string  `json:"version"`
	Canonicalisation string  `json:"canonicalisation"`
	Domain           string  `json:"domain"`
	Signatures       []Entry `json:"signatures"`
}

// Policy states the minimum verification requirement. RequiredAlgorithms is
// set semantics: each named algorithm must have at least one valid signature.
type Policy struct {
	MinimumValidSignatures int
	RequiredAlgorithms     []string
}

// Manager creates and verifies signature sets across one or more opaque key
// providers. Production callers can combine classical and post-quantum
// providers without exposing private key material to domain packages.
type Manager struct {
	providers []keyprovider.SigningProvider
	policy    Policy
}

func NewManager(providers []keyprovider.SigningProvider, policy Policy) (*Manager, error) {
	if len(providers) == 0 || len(providers) > maximumSignatures || policy.MinimumValidSignatures <= 0 ||
		policy.MinimumValidSignatures > len(providers) {
		return nil, fmt.Errorf("providers and signature policy are invalid: %w", ErrPolicyUnsatisfied)
	}
	for _, provider := range providers {
		if provider == nil {
			return nil, fmt.Errorf("nil signing provider: %w", ErrInvalidSet)
		}
	}
	required := append([]string(nil), policy.RequiredAlgorithms...)
	sort.Strings(required)
	for index, algorithm := range required {
		if algorithm == "" || index > 0 && algorithm == required[index-1] {
			return nil, fmt.Errorf("required algorithms are invalid: %w", ErrPolicyUnsatisfied)
		}
	}
	return &Manager{
		providers: append([]keyprovider.SigningProvider(nil), providers...),
		policy:    Policy{MinimumValidSignatures: policy.MinimumValidSignatures, RequiredAlgorithms: required},
	}, nil
}

// Sign signs the same canonical payload with every configured provider.
func (m *Manager) Sign(ctx context.Context, purpose, domain string, canonical []byte) (Set, error) {
	if m == nil {
		return Set{}, fmt.Errorf("signature manager is required: %w", ErrInvalidSet)
	}
	payload, err := signingPayload(domain, canonical)
	if err != nil {
		return Set{}, err
	}
	set := Set{Version: SetVersionV1, Canonicalisation: CanonicalJSONV1, Domain: domain}
	seen := make(map[string]struct{}, len(m.providers))
	for _, provider := range m.providers {
		key, keyErr := provider.CurrentSigningKey(ctx, purpose)
		if keyErr != nil {
			return Set{}, fmt.Errorf("resolve signing key: %w", keyErr)
		}
		identity := key.Algorithm + "\x00" + key.Reference
		if key.Algorithm == "" || key.Reference == "" {
			return Set{}, fmt.Errorf("provider returned incomplete key metadata: %w", ErrInvalidSet)
		}
		if _, exists := seen[identity]; exists {
			return Set{}, fmt.Errorf("duplicate signature key %q: %w", key.Reference, ErrInvalidSet)
		}
		seen[identity] = struct{}{}
		value, signErr := provider.Sign(ctx, key.Reference, payload)
		if signErr != nil {
			return Set{}, fmt.Errorf("sign with %q: %w", key.Reference, signErr)
		}
		if len(value) == 0 {
			return Set{}, fmt.Errorf("provider returned an empty signature: %w", ErrInvalidSet)
		}
		set.Signatures = append(set.Signatures, Entry{Algorithm: key.Algorithm, KeyReference: key.Reference, Value: value})
	}
	sort.Slice(set.Signatures, func(i, j int) bool {
		if set.Signatures[i].Algorithm != set.Signatures[j].Algorithm {
			return set.Signatures[i].Algorithm < set.Signatures[j].Algorithm
		}
		return set.Signatures[i].KeyReference < set.Signatures[j].KeyReference
	})
	if err := m.policySatisfied(set.Signatures); err != nil {
		return Set{}, err
	}
	return set, nil
}

// Verify requires every presented signature to be valid and also enforces the
// configured minimum and required-algorithm policy. This makes injected,
// substituted and stripped signature entries fail closed.
func (m *Manager) Verify(ctx context.Context, expectedDomain string, canonical []byte, set Set) error {
	if m == nil || set.Version != SetVersionV1 || set.Canonicalisation != CanonicalJSONV1 ||
		set.Domain != expectedDomain || len(set.Signatures) == 0 || len(set.Signatures) > maximumSignatures {
		return ErrInvalidSet
	}
	payload, err := signingPayload(expectedDomain, canonical)
	if err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(set.Signatures))
	for _, signature := range set.Signatures {
		identity := signature.Algorithm + "\x00" + signature.KeyReference
		if signature.Algorithm == "" || signature.KeyReference == "" || len(signature.Value) == 0 {
			return ErrInvalidSet
		}
		if _, exists := seen[identity]; exists {
			return ErrInvalidSet
		}
		seen[identity] = struct{}{}
		verified := false
		for _, provider := range m.providers {
			if provider.Verify(ctx, signature.KeyReference, signature.Algorithm, payload, signature.Value) == nil {
				verified = true
				break
			}
		}
		if !verified {
			return ErrInvalidSet
		}
	}
	return m.policySatisfied(set.Signatures)
}

func (m *Manager) policySatisfied(signatures []Entry) error {
	if len(signatures) < m.policy.MinimumValidSignatures {
		return ErrPolicyUnsatisfied
	}
	algorithms := make([]string, 0, len(signatures))
	for _, signature := range signatures {
		algorithms = append(algorithms, signature.Algorithm)
	}
	for _, required := range m.policy.RequiredAlgorithms {
		if !slices.Contains(algorithms, required) {
			return ErrPolicyUnsatisfied
		}
	}
	return nil
}

func signingPayload(domain string, canonical []byte) ([]byte, error) {
	if domain == "" || len(domain) > maximumDomainBytes || strings.IndexByte(domain, 0) >= 0 ||
		len(canonical) == 0 || len(canonical) > maximumPayloadSize {
		return nil, fmt.Errorf("domain or canonical payload is invalid: %w", ErrInvalidSet)
	}
	var payload bytes.Buffer
	payload.WriteString(SetVersionV1)
	payload.WriteByte(0)
	payload.WriteString(CanonicalJSONV1)
	payload.WriteByte(0)
	payload.WriteString(domain)
	payload.WriteByte(0)
	payload.Write(canonical)
	return payload.Bytes(), nil
}
