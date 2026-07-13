package artefacts

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
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
	manifest := TransformationManifest{PipelineID: "default", PipelineVersion: "v1", RedactionsApplied: []string{"configured-redaction-0001"}, OriginalByteCount: 10, OutputByteCount: 17}
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
	again, err := store.Get(captured.URI)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, []byte("secret=one")) {
		t.Fatal("caller mutated stored artefact")
	}
}

func TestVersionedTransformationManifestUsesExternalSchemaAndRoundTrips(t *testing.T) {
	manifest := TransformationManifest{
		ManifestVersion: TransformationManifestVersionV1, PipelineID: "default", PipelineVersion: "v2",
		RulesVersion: "rules-v1", InputDigest: strings.Repeat("a", 64), OutputDigest: strings.Repeat("b", 64),
		OverallStatus: "tainted", RedactionsApplied: []string{}, TaintedFields: []string{"$/interface_name"},
		Outcomes: []TransformationOutcome{{
			Action: "tainted", ReasonCode: "device_controlled_free_text", JSONPath: "$/interface_name",
			RulePosition: 3, Count: 1,
		}},
		OriginalByteCount: 10, OutputByteCount: 10,
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(payload, []byte(`"manifest_version"`)) || bytes.Contains(payload, []byte(`"ManifestVersion"`)) {
		t.Fatalf("versioned manifest does not use the published JSON contract: %s", payload)
	}
	var decoded TransformationManifest
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, manifest) {
		t.Fatalf("manifest round trip changed: got %+v want %+v", decoded, manifest)
	}
}

func TestTransformationManifestRejectsUnboundedOrInvalidAuditData(t *testing.T) {
	manifest := TransformationManifest{
		PipelineID: "default", PipelineVersion: "v2", RulesVersion: "rules-v1",
		Outcomes: []TransformationOutcome{{Action: "rejected", ReasonCode: "invalid_json", JSONPath: "$", Count: 1}},
	}
	if err := validateTransformationManifest(manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Outcomes[0].JSONPath = strings.Repeat("x", 513)
	if err := validateTransformationManifest(manifest); err == nil {
		t.Fatal("expected oversized manifest path to be rejected")
	}
	manifest.Outcomes[0].JSONPath = "$"
	manifest.Outcomes[0].Count = 0
	if err := validateTransformationManifest(manifest); err == nil {
		t.Fatal("expected zero-count manifest outcome to be rejected")
	}
}

func TestLegacyTransformationManifestCanonicalJSONIsStable(t *testing.T) {
	manifest := TransformationManifest{
		PipelineID: "default", PipelineVersion: "v1", RedactionsApplied: []string{"legacy-rule"},
		OriginalByteCount: 10, OutputByteCount: 17,
	}
	digest, err := transformationDigest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	legacyJSON := []byte(`{"PipelineID":"default","PipelineVersion":"v1","RedactionsApplied":["legacy-rule"],"Truncated":false,"OriginalByteCount":10,"OutputByteCount":17}`)
	if digest != digestBytes(legacyJSON) {
		t.Fatalf("legacy manifest serialization changed: got %s want %s", digest, digestBytes(legacyJSON))
	}
}
