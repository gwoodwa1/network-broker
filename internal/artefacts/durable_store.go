package artefacts

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
)

const (
	MaximumArtefactBytes  = 16 * 1024 * 1024
	sha256DigestHexLength = 64
)

var (
	ErrArtefactNotFound = errors.New("artefact was not found")
	ErrIntegrityFailure = errors.New("artefact integrity verification failed")
	ErrMetadataConflict = errors.New("immutable artefact metadata conflicts with an existing record")
)

type Class string

const (
	ClassCaptured  Class = "captured"
	ClassSanitised Class = "sanitised"
)

// Metadata is an immutable tenant-scoped lineage record. ObjectKey points to
// content-addressed bytes and may be shared by multiple immutable records.
type Metadata struct {
	ArtefactID       string
	TenantID         string
	Class            Class
	URI              string
	ObjectKey        string
	SHA256Digest     string
	ByteCount        uint64
	MediaType        string
	Transport        string
	AttemptID        string
	EncryptionKeyRef string
	ParentArtefactID string
	ParentDigest     string
	Manifest         *TransformationManifest
	ManifestDigest   string
	CreatedAt        time.Time
}

type MetadataRepository interface {
	Create(context.Context, Metadata) error
	Get(context.Context, string, string) (Metadata, error)
}

type BlobStore interface {
	PutIfAbsent(context.Context, string, []byte, string, string) error
	Get(context.Context, string) (io.ReadCloser, error)
}

// PipelineStore is the tenant-aware storage boundary used by evidence
// assembly. Store and DurableStore both implement it.
type PipelineStore interface {
	PutCapturedForTenant(context.Context, string, []byte, string, string, string, string, time.Time) (CapturedRef, error)
	PutSanitisedForTenant(context.Context, string, []byte, string, CapturedRef, TransformationManifest, time.Time) (SanitisedRef, error)
}

type DurableStore struct {
	metadata MetadataRepository
	blobs    BlobStore
}

func NewDurableStore(metadata MetadataRepository, blobs BlobStore) (*DurableStore, error) {
	if metadata == nil || blobs == nil {
		return nil, fmt.Errorf("artefact metadata repository and blob store are required")
	}

	return &DurableStore{metadata: metadata, blobs: blobs}, nil
}

func (s *DurableStore) PutCapturedForTenant(ctx context.Context, tenantID string, payload []byte,
	mediaType, transport, attemptID, encryptionKeyRef string, capturedAt time.Time,
) (CapturedRef, error) {
	if err := validateCommon(tenantID, payload, mediaType, capturedAt); err != nil {
		return CapturedRef{}, err
	}
	if transport == "" || attemptID == "" || encryptionKeyRef == "" {
		return CapturedRef{}, fmt.Errorf("captured transport, attempt and encryption key are required")
	}
	digest := digestBytes(payload)
	metadata := newMetadata(tenantID, ClassCaptured, digest, len(payload), mediaType, capturedAt, attemptID)
	metadata.Transport = transport
	metadata.AttemptID = attemptID
	metadata.EncryptionKeyRef = encryptionKeyRef
	if err := s.persist(ctx, metadata, payload); err != nil {
		return CapturedRef{}, err
	}

	return capturedRef(metadata), nil
}

func (s *DurableStore) PutSanitisedForTenant(ctx context.Context, tenantID string, payload []byte,
	mediaType string, parent CapturedRef, manifest TransformationManifest, createdAt time.Time,
) (SanitisedRef, error) {
	if err := validateCommon(tenantID, payload, mediaType, createdAt); err != nil {
		return SanitisedRef{}, err
	}
	if parent.URI == "" || parent.SHA256Digest == "" || manifest.PipelineID == "" ||
		manifest.PipelineVersion == "" || manifest.OriginalByteCount != parent.ByteCount ||
		manifest.OutputByteCount != boundedByteCount(len(payload)) {
		return SanitisedRef{}, fmt.Errorf("sanitised parent and matching transformation manifest are required")
	}
	parentMetadata, err := s.metadata.Get(ctx, tenantID, parent.URI)
	if err != nil {
		return SanitisedRef{}, fmt.Errorf("get captured parent: %w", err)
	}
	if parentMetadata.Class != ClassCaptured || parentMetadata.SHA256Digest != parent.SHA256Digest {
		return SanitisedRef{}, fmt.Errorf("captured parent metadata does not match the supplied reference")
	}
	manifestDigest, err := transformationDigest(manifest)
	if err != nil {
		return SanitisedRef{}, err
	}
	digest := digestBytes(payload)
	metadata := newMetadata(tenantID, ClassSanitised, digest, len(payload), mediaType, createdAt,
		parentMetadata.ArtefactID+"\x00"+manifestDigest)
	metadata.ParentArtefactID = parentMetadata.ArtefactID
	metadata.ParentDigest = parent.SHA256Digest
	metadata.ManifestDigest = manifestDigest
	manifestCopy := manifest
	manifestCopy.RedactionsApplied = append([]string(nil), manifest.RedactionsApplied...)
	metadata.Manifest = &manifestCopy
	if err := s.persist(ctx, metadata, payload); err != nil {
		return SanitisedRef{}, err
	}

	return sanitisedRef(metadata), nil
}

func (s *DurableStore) Get(ctx context.Context, tenantID, uri string) (payload []byte, metadata Metadata, err error) {
	if invalidSegment(tenantID) || uri == "" {
		return nil, Metadata{}, fmt.Errorf("tenant and artefact URI are required")
	}
	metadata, err = s.metadata.Get(ctx, tenantID, uri)
	if err != nil {
		return nil, Metadata{}, err
	}
	reader, err := s.blobs.Get(ctx, metadata.ObjectKey)
	if err != nil {
		return nil, Metadata{}, fmt.Errorf("get artefact object: %w", err)
	}
	defer func() {
		if closeErr := reader.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close artefact object: %w", closeErr))
		}
	}()
	payload, err = io.ReadAll(io.LimitReader(reader, MaximumArtefactBytes+1))
	if err != nil {
		return nil, Metadata{}, fmt.Errorf("read artefact object: %w", err)
	}
	if uint64(len(payload)) != metadata.ByteCount || digestBytes(payload) != metadata.SHA256Digest {
		return nil, Metadata{}, ErrIntegrityFailure
	}

	return payload, metadata, nil
}

func (s *DurableStore) persist(ctx context.Context, metadata Metadata, payload []byte) error {
	if err := s.blobs.PutIfAbsent(ctx, metadata.ObjectKey, payload, metadata.SHA256Digest, metadata.MediaType); err != nil {
		return fmt.Errorf("store immutable artefact object: %w", err)
	}
	if err := s.metadata.Create(ctx, metadata); err != nil {
		return fmt.Errorf("record immutable artefact metadata: %w", err)
	}

	return nil
}

func newMetadata(tenantID string, class Class, digest string, size int, mediaType string, createdAt time.Time,
	identity string,
) Metadata {
	objectKey := objectKey(tenantID, class, digest)
	stableIdentity := strings.Join([]string{tenantID, string(class), identity, digest}, "\x00")
	idDigest := sha256.Sum256([]byte(stableIdentity))
	artefactID := "artefact-" + hex.EncodeToString(idDigest[:16])

	return Metadata{
		ArtefactID: artefactID, TenantID: tenantID, Class: class, URI: "artefact://" + artefactID,
		ObjectKey: objectKey, SHA256Digest: digest, ByteCount: boundedByteCount(size), MediaType: mediaType,
		CreatedAt: createdAt.UTC().Truncate(time.Microsecond),
	}
}

func boundedByteCount(size int) uint64 {
	// #nosec G115 -- size always comes from a payload already bounded to 16 MiB.
	return uint64(size)
}

func objectKey(tenantID string, class Class, digest string) string {
	tenant := base64.RawURLEncoding.EncodeToString([]byte(tenantID))

	return fmt.Sprintf("tenants/%s/%s/sha256/%s/%s", tenant, class, digest[:2], digest)
}

func validateCommon(tenantID string, payload []byte, mediaType string, createdAt time.Time) error {
	if invalidSegment(tenantID) || len(payload) == 0 || len(payload) > MaximumArtefactBytes ||
		mediaType == "" || createdAt.IsZero() {
		return fmt.Errorf("tenant, bounded payload, media type and creation time are required")
	}

	return nil
}

func invalidSegment(value string) bool {
	return value == "" || len(value) > 128 || strings.IndexFunc(value, func(char rune) bool {
		return unicode.IsSpace(char) || unicode.IsControl(char)
	}) >= 0
}

func transformationDigest(manifest TransformationManifest) (string, error) {
	payload, err := json.Marshal(manifest)
	if err != nil {
		return "", fmt.Errorf("encode transformation manifest: %w", err)
	}

	return digestBytes(payload), nil
}

func capturedRef(metadata Metadata) CapturedRef {
	return CapturedRef{
		URI: metadata.URI, SHA256Digest: metadata.SHA256Digest, ByteCount: metadata.ByteCount,
		MediaType: metadata.MediaType, Transport: metadata.Transport, CapturedAt: metadata.CreatedAt,
		AttemptID: metadata.AttemptID, EncryptionKeyRef: metadata.EncryptionKeyRef,
	}
}

func sanitisedRef(metadata Metadata) SanitisedRef {
	return SanitisedRef{
		URI: metadata.URI, SHA256Digest: metadata.SHA256Digest, ByteCount: metadata.ByteCount,
		MediaType: metadata.MediaType, ParentCapturedDigest: metadata.ParentDigest,
		TransformationManifestDigest: metadata.ManifestDigest, CreatedAt: metadata.CreatedAt,
	}
}
