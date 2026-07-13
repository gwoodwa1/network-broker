//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"network_broker/internal/artefacts"
	"network_broker/migrations"
)

type integrationBlobStore struct {
	mu      sync.RWMutex
	objects map[string][]byte
}

func (s *integrationBlobStore) PutIfAbsent(_ context.Context, key string, payload []byte, digest, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.objects[key]; ok {
		if !bytes.Equal(existing, payload) {
			return artefacts.ErrIntegrityFailure
		}

		return nil
	}
	s.objects[key] = append([]byte(nil), payload...)

	return nil
}

func (s *integrationBlobStore) Get(_ context.Context, key string) (io.ReadCloser, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	payload, ok := s.objects[key]
	if !ok {
		return nil, artefacts.ErrArtefactNotFound
	}

	return io.NopCloser(bytes.NewReader(payload)), nil
}

func TestPostgresArtefactMetadataAndDurableStore(t *testing.T) {
	databaseURL := os.Getenv("POSTGRES_TEST_DSN")
	if databaseURL == "" {
		t.Skip("POSTGRES_TEST_DSN is not configured")
	}
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close postgres: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := migrations.Apply(ctx, database); err != nil {
		t.Fatal(err)
	}
	repository, err := artefacts.NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	blobs := &integrationBlobStore{objects: make(map[string][]byte)}
	store, err := artefacts.NewDurableStore(repository, blobs)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 13, 15, 0, 0, 0, time.UTC)
	captured, err := store.PutCapturedForTenant(ctx, "artefact-tenant", []byte("secret=one"),
		"text/plain", "gnmi", "attempt-integration", "kms-key-1", now)
	if err != nil {
		t.Fatal(err)
	}
	idempotent, err := store.PutCapturedForTenant(ctx, "artefact-tenant", []byte("secret=one"),
		"text/plain", "gnmi", "attempt-integration", "kms-key-1", now)
	if err != nil || idempotent.URI != captured.URI {
		t.Fatalf("unexpected idempotent captured write: first=%+v second=%+v error=%v", captured, idempotent, err)
	}
	manifest := artefacts.TransformationManifest{
		PipelineID: "default", PipelineVersion: "v1", RedactionsApplied: []string{"secret"},
		OriginalByteCount: 10, OutputByteCount: 17,
	}
	sanitised, err := store.PutSanitisedForTenant(ctx, "artefact-tenant", []byte("secret=[REDACTED]"),
		"text/plain", captured, manifest, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	payload, metadata, err := store.Get(ctx, "artefact-tenant", sanitised.URI)
	if err != nil || string(payload) != "secret=[REDACTED]" || metadata.ParentArtefactID == "" {
		t.Fatalf("unexpected durable retrieval: payload=%q metadata=%+v error=%v", payload, metadata, err)
	}
	if _, _, err := store.Get(ctx, "other-tenant", sanitised.URI); !errors.Is(err, artefacts.ErrArtefactNotFound) {
		t.Fatalf("expected cross-tenant lookup to be indistinguishable from missing, got %v", err)
	}
	if _, err := database.ExecContext(ctx,
		`UPDATE broker_artefacts SET media_type = 'tampered' WHERE artefact_id = $1`, metadata.ArtefactID); err == nil {
		t.Fatal("expected immutable artefact trigger to reject mutation")
	}
}
