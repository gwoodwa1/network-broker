// Package artefacts stores immutable captured and sanitised evidence objects.
package artefacts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"
)

const TransformationManifestVersionV1 = "network-broker-sanitisation-manifest/v1"

type CapturedRef struct {
	URI              string
	SHA256Digest     string
	ByteCount        uint64
	MediaType        string
	Transport        string
	CapturedAt       time.Time
	AttemptID        string
	EncryptionKeyRef string
}

type TransformationManifest struct {
	ManifestVersion   string `json:",omitempty"`
	PipelineID        string
	PipelineVersion   string
	RulesVersion      string `json:",omitempty"`
	InputDigest       string `json:",omitempty"`
	OutputDigest      string `json:",omitempty"`
	OverallStatus     string `json:",omitempty"`
	RedactionsApplied []string
	TaintedFields     []string                `json:",omitempty"`
	Outcomes          []TransformationOutcome `json:",omitempty"`
	Quarantined       bool                    `json:",omitempty"`
	Truncated         bool
	OriginalByteCount uint64
	OutputByteCount   uint64
}

type TransformationOutcome struct {
	Action       string
	ReasonCode   string
	JSONPath     string
	RulePosition uint64 `json:",omitempty"`
	Count        uint64
}

type SanitisedRef struct {
	URI                          string
	SHA256Digest                 string
	ByteCount                    uint64
	MediaType                    string
	ParentCapturedDigest         string
	TransformationManifestDigest string
	CreatedAt                    time.Time
}

type Store struct {
	mu      sync.RWMutex
	objects map[string][]byte
}

func NewStore() *Store { return &Store{objects: make(map[string][]byte)} }

func (s *Store) PutCapturedForTenant(_ context.Context, tenantID string, payload []byte,
	mediaType, transport, attemptID, encryptionKeyRef string, capturedAt time.Time,
) (CapturedRef, error) {
	if invalidSegment(tenantID) {
		return CapturedRef{}, fmt.Errorf("tenant is required")
	}

	return s.PutCaptured(payload, mediaType, transport, attemptID, encryptionKeyRef, capturedAt)
}

func (s *Store) PutSanitisedForTenant(_ context.Context, tenantID string, payload []byte,
	mediaType string, parent CapturedRef, manifest TransformationManifest, createdAt time.Time,
) (SanitisedRef, error) {
	if invalidSegment(tenantID) || parent.URI == "" {
		return SanitisedRef{}, fmt.Errorf("tenant and captured parent are required")
	}

	return s.PutSanitised(payload, mediaType, parent.SHA256Digest, manifest, createdAt)
}

func (s *Store) PutCaptured(payload []byte, mediaType, transport, attemptID, encryptionKeyRef string, capturedAt time.Time) (CapturedRef, error) {
	if len(payload) == 0 || mediaType == "" || transport == "" || attemptID == "" || encryptionKeyRef == "" || capturedAt.IsZero() {
		return CapturedRef{}, fmt.Errorf("captured payload and metadata are required")
	}
	digest, uri := s.put("captured", payload)
	return CapturedRef{
		URI: uri, SHA256Digest: digest, ByteCount: uint64(len(payload)), MediaType: mediaType,
		Transport: transport, CapturedAt: capturedAt.UTC(), AttemptID: attemptID, EncryptionKeyRef: encryptionKeyRef,
	}, nil
}

func (s *Store) PutSanitised(payload []byte, mediaType, parentDigest string, manifest TransformationManifest, createdAt time.Time) (SanitisedRef, error) {
	if len(payload) == 0 || mediaType == "" || parentDigest == "" || manifest.PipelineID == "" || manifest.PipelineVersion == "" || createdAt.IsZero() {
		return SanitisedRef{}, fmt.Errorf("sanitised payload, parent, manifest and creation time are required")
	}
	if manifest.OutputByteCount != uint64(len(payload)) {
		return SanitisedRef{}, fmt.Errorf("manifest output byte count does not match payload")
	}
	if manifest.ManifestVersion != "" &&
		(manifest.InputDigest != parentDigest || manifest.OutputDigest != digestBytes(payload)) {
		return SanitisedRef{}, fmt.Errorf("manifest input or output digest does not match artefact lineage")
	}
	if err := validateTransformationManifest(manifest); err != nil {
		return SanitisedRef{}, err
	}
	parentURI := fmt.Sprintf("artefact://captured/sha256/%s", parentDigest)
	s.mu.RLock()
	_, parentExists := s.objects[parentURI]
	s.mu.RUnlock()
	if !parentExists {
		return SanitisedRef{}, fmt.Errorf("parent captured artefact %q not found", parentDigest)
	}
	manifestDigest, err := transformationDigest(manifest)
	if err != nil {
		return SanitisedRef{}, err
	}
	digest, uri := s.put("sanitised", payload)
	return SanitisedRef{
		URI: uri, SHA256Digest: digest, ByteCount: uint64(len(payload)), MediaType: mediaType,
		ParentCapturedDigest: parentDigest, TransformationManifestDigest: manifestDigest, CreatedAt: createdAt.UTC(),
	}, nil
}

func validateTransformationManifest(manifest TransformationManifest) error {
	if err := validateManifestIdentityAndBounds(manifest); err != nil {
		return err
	}
	if manifest.ManifestVersion != "" &&
		(!validDigest(manifest.InputDigest) || !validDigest(manifest.OutputDigest) ||
			!validOverallStatus(manifest)) {
		return fmt.Errorf("versioned transformation manifest digests or status are invalid")
	}
	return validateManifestEntries(manifest)
}

func validateManifestIdentityAndBounds(manifest TransformationManifest) error {
	if manifest.ManifestVersion != "" && manifest.ManifestVersion != TransformationManifestVersionV1 {
		return fmt.Errorf("unsupported transformation manifest version %q", manifest.ManifestVersion)
	}
	if manifest.ManifestVersion != "" && unsafeManifestValue(manifest.ManifestVersion, 128) ||
		unsafeManifestValue(manifest.PipelineID, 128) || unsafeManifestValue(manifest.PipelineVersion, 128) ||
		manifest.RulesVersion != "" && unsafeManifestValue(manifest.RulesVersion, 128) ||
		len(manifest.RedactionsApplied) > 256 || len(manifest.TaintedFields) > 512 || len(manifest.Outcomes) > 512 {
		return fmt.Errorf("transformation manifest identity or entry bounds are invalid")
	}
	return nil
}

func validateManifestEntries(manifest TransformationManifest) error {
	for _, value := range append(append([]string(nil), manifest.RedactionsApplied...), manifest.TaintedFields...) {
		if unsafeManifestValue(value, 512) {
			return fmt.Errorf("transformation manifest field is invalid")
		}
	}
	for _, item := range manifest.Outcomes {
		if unsafeManifestValue(item.Action, 64) || unsafeManifestValue(item.ReasonCode, 128) ||
			unsafeManifestValue(item.JSONPath, 512) || item.Count == 0 {
			return fmt.Errorf("transformation outcome is invalid")
		}
	}
	return nil
}

func validOverallStatus(manifest TransformationManifest) bool {
	switch manifest.OverallStatus {
	case "clean":
		return !manifest.Quarantined && len(manifest.TaintedFields) == 0
	case "tainted":
		return !manifest.Quarantined && len(manifest.TaintedFields) > 0
	case "quarantined":
		return manifest.Quarantined
	default:
		return false
	}
}

func unsafeManifestValue(value string, maximum int) bool {
	return value == "" || len(value) > maximum || strings.IndexFunc(value, unicode.IsControl) >= 0
}

func (s *Store) Get(uri string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	payload, ok := s.objects[uri]
	if !ok {
		return nil, fmt.Errorf("artefact %q not found", uri)
	}
	return append([]byte(nil), payload...), nil
}

func (s *Store) put(class string, payload []byte) (digest, uri string) {
	digest = digestBytes(payload)
	uri = fmt.Sprintf("artefact://%s/sha256/%s", class, digest)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.objects[uri]; !exists {
		s.objects[uri] = append([]byte(nil), payload...)
	}
	return digest, uri
}

func digestBytes(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}
