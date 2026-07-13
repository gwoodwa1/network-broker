package artefacts

import (
	"bytes"
	"testing"
	"time"
)

func TestStorePreservesDistinctImmutableLineageObjects(t *testing.T) {
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	store := NewStore()
	captured, err := store.PutCaptured([]byte("secret=one"), "text/plain", "gnmi", "attempt-1", "key-1", now)
	if err != nil {
		t.Fatal(err)
	}
	manifest := TransformationManifest{PipelineID: "default", PipelineVersion: "v1", RedactionsApplied: []string{"secret"}, OriginalByteCount: 10, OutputByteCount: 17}
	sanitised, err := store.PutSanitised([]byte("secret=[REDACTED]"), "text/plain", captured.SHA256Digest, manifest, now)
	if err != nil {
		t.Fatal(err)
	}
	if captured.URI == sanitised.URI || captured.SHA256Digest == sanitised.SHA256Digest || sanitised.ParentCapturedDigest != captured.SHA256Digest {
		t.Fatalf("lineage was not preserved: captured=%+v sanitised=%+v", captured, sanitised)
	}
	got, err := store.Get(captured.URI)
	if err != nil {
		t.Fatal(err)
	}
	got[0] = 'X'
	again, _ := store.Get(captured.URI)
	if !bytes.Equal(again, []byte("secret=one")) {
		t.Fatal("caller mutated stored artefact")
	}
}
