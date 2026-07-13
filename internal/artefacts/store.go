// Package artefacts stores immutable captured and sanitised evidence objects.
package artefacts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

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
	PipelineID        string
	PipelineVersion   string
	RedactionsApplied []string
	Truncated         bool
	OriginalByteCount uint64
	OutputByteCount   uint64
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
	parentURI := fmt.Sprintf("artefact://captured/sha256/%s", parentDigest)
	s.mu.RLock()
	_, parentExists := s.objects[parentURI]
	s.mu.RUnlock()
	if !parentExists {
		return SanitisedRef{}, fmt.Errorf("parent captured artefact %q not found", parentDigest)
	}
	manifestDigest := digestBytes([]byte(fmt.Sprintf("%s\x00%s\x00%v\x00%t\x00%d\x00%d", manifest.PipelineID,
		manifest.PipelineVersion, manifest.RedactionsApplied, manifest.Truncated, manifest.OriginalByteCount, manifest.OutputByteCount)))
	digest, uri := s.put("sanitised", payload)
	return SanitisedRef{
		URI: uri, SHA256Digest: digest, ByteCount: uint64(len(payload)), MediaType: mediaType,
		ParentCapturedDigest: parentDigest, TransformationManifestDigest: manifestDigest, CreatedAt: createdAt.UTC(),
	}, nil
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
