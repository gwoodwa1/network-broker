package artefacts

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type metadataStub struct {
	values map[string]Metadata
}

func (s *metadataStub) Create(_ context.Context, metadata Metadata) error {
	key := metadata.TenantID + "\x00" + metadata.URI
	if existing, ok := s.values[key]; ok && existing.ArtefactID != metadata.ArtefactID {
		return ErrMetadataConflict
	}
	s.values[key] = metadata

	return nil
}

func (s *metadataStub) Get(_ context.Context, tenantID, uri string) (Metadata, error) {
	metadata, ok := s.values[tenantID+"\x00"+uri]
	if !ok {
		return Metadata{}, ErrArtefactNotFound
	}

	return metadata, nil
}

type blobStub struct {
	values map[string][]byte
}

func (s *blobStub) PutIfAbsent(_ context.Context, key string, payload []byte, digest, _ string) error {
	if existing, ok := s.values[key]; ok {
		if digestBytes(existing) != digest {
			return ErrIntegrityFailure
		}

		return nil
	}
	s.values[key] = append([]byte(nil), payload...)

	return nil
}

func (s *blobStub) Get(_ context.Context, key string) (io.ReadCloser, error) {
	payload, ok := s.values[key]
	if !ok {
		return nil, ErrArtefactNotFound
	}

	return io.NopCloser(bytes.NewReader(payload)), nil
}

func TestDurableStorePreservesTenantScopedImmutableLineage(t *testing.T) {
	metadata := &metadataStub{values: make(map[string]Metadata)}
	blobs := &blobStub{values: make(map[string][]byte)}
	store, err := NewDurableStore(metadata, blobs)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 13, 14, 0, 0, 0, time.UTC)
	captured, err := store.PutCapturedForTenant(context.Background(), "tenant/a", []byte("secret=one"),
		"text/plain", "gnmi", "attempt-1", "kms-key-1", now)
	if err != nil {
		t.Fatal(err)
	}
	manifest := TransformationManifest{
		PipelineID: "default", PipelineVersion: "v1", RedactionsApplied: []string{"secret"},
		OriginalByteCount: 10, OutputByteCount: 17,
	}
	sanitised, err := store.PutSanitisedForTenant(context.Background(), "tenant/a", []byte("secret=[REDACTED]"),
		"text/plain", captured, manifest, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if captured.URI == sanitised.URI || sanitised.ParentCapturedDigest != captured.SHA256Digest {
		t.Fatalf("lineage was not preserved: captured=%+v sanitised=%+v", captured, sanitised)
	}
	for key := range blobs.values {
		if strings.Contains(key, "tenant/a") || !strings.HasPrefix(key, "tenants/") {
			t.Fatalf("object key is not safely tenant scoped: %q", key)
		}
	}
	got, gotMetadata, err := store.Get(context.Background(), "tenant/a", sanitised.URI)
	if err != nil || string(got) != "secret=[REDACTED]" || gotMetadata.ParentArtefactID == "" {
		t.Fatalf("unexpected durable artefact: payload=%q metadata=%+v error=%v", got, gotMetadata, err)
	}
	if _, _, err := store.Get(context.Background(), "tenant-b", sanitised.URI); !errors.Is(err, ErrArtefactNotFound) {
		t.Fatalf("expected tenant isolation, got %v", err)
	}
}

func TestDurableStoreDetectsObjectCorruption(t *testing.T) {
	metadata := &metadataStub{values: make(map[string]Metadata)}
	blobs := &blobStub{values: make(map[string][]byte)}
	store, err := NewDurableStore(metadata, blobs)
	if err != nil {
		t.Fatal(err)
	}
	captured, err := store.PutCapturedForTenant(context.Background(), "tenant-a", []byte("captured"),
		"text/plain", "gnmi", "attempt-1", "kms-key-1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	record, err := metadata.Get(context.Background(), "tenant-a", captured.URI)
	if err != nil {
		t.Fatal(err)
	}
	blobs.values[record.ObjectKey] = []byte("corrupted")
	if _, _, err := store.Get(context.Background(), "tenant-a", captured.URI); !errors.Is(err, ErrIntegrityFailure) {
		t.Fatalf("expected integrity failure, got %v", err)
	}
}

func TestDurableStoreRejectsOversizedPayload(t *testing.T) {
	store, err := NewDurableStore(&metadataStub{values: make(map[string]Metadata)},
		&blobStub{values: make(map[string][]byte)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.PutCapturedForTenant(context.Background(), "tenant-a",
		[]byte(strings.Repeat("x", MaximumArtefactBytes+1)), "text/plain", "gnmi", "attempt-1", "key-1", time.Now())
	if err == nil {
		t.Fatal("expected oversized payload to fail")
	}
}
