package evidence

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"network_broker/internal/artefacts"
	"network_broker/internal/keyprovider"
	"network_broker/internal/parsing"
)

type attemptVerifier struct{ err error }

func (v attemptVerifier) VerifyCurrentAttempt(string, string, int64, time.Time) error { return v.err }

func TestAssemblerSignsCompleteLineage(t *testing.T) {
	assembler := newAssembler(t, attemptVerifier{})
	envelope, err := assembler.Assemble(validInput())
	if err != nil {
		t.Fatal(err)
	}
	if envelope.EvidenceID == "" || envelope.Sanitised.ParentCapturedDigest != envelope.Captured.SHA256Digest {
		t.Fatalf("unexpected envelope: %+v", envelope)
	}
	if err := assembler.Verify(envelope); err != nil {
		t.Fatal(err)
	}
	tampered := envelope
	tampered.InterfaceState.OperationalState = "down"
	if err := assembler.Verify(tampered); err == nil {
		t.Fatal("expected tampered observation to fail signature verification")
	}
	manifestTampered := envelope
	manifestTampered.Sanitised.TransformationManifestDigest = "different-manifest"
	if err := assembler.Verify(manifestTampered); err == nil {
		t.Fatal("expected a changed sanitisation manifest digest to fail signature verification")
	}
}

func TestAssemblerRejectsStaleAttemptAndBrokenLineage(t *testing.T) {
	assembler := newAssembler(t, attemptVerifier{err: errors.New("stale fence")})
	if _, err := assembler.Assemble(validInput()); err == nil {
		t.Fatal("expected stale attempt to be rejected")
	}
	assembler = newAssembler(t, attemptVerifier{})
	input := validInput()
	input.Sanitised.ParentCapturedDigest = "different"
	if _, err := assembler.Assemble(input); err == nil {
		t.Fatal("expected broken artefact lineage to be rejected")
	}
}

func TestAssemblerVerifiesEvidenceAcrossSigningKeyRotation(t *testing.T) {
	_, firstPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := keyprovider.NewEd25519Keyring("evidence-signing-v1", firstPrivate)
	if err != nil {
		t.Fatal(err)
	}
	assembler, err := NewAssemblerWithProvider("v1", keyring, attemptVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := assembler.AssembleContext(context.Background(), validInput())
	if err != nil {
		t.Fatal(err)
	}
	_, secondPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyring.Rotate("evidence-signing-v2", secondPrivate); err != nil {
		t.Fatal(err)
	}
	secondInput := validInput()
	secondInput.AcceptedAttemptID = "attempt-2"
	second, err := assembler.AssembleContext(context.Background(), secondInput)
	if err != nil {
		t.Fatal(err)
	}
	if first.Attribution.SigningKeyRef != "evidence-signing-v1" ||
		second.Attribution.SigningKeyRef != "evidence-signing-v2" {
		t.Fatalf("signing key references do not show rotation: first=%q second=%q",
			first.Attribution.SigningKeyRef, second.Attribution.SigningKeyRef)
	}
	if err := assembler.Verify(first); err != nil {
		t.Fatalf("old evidence did not verify after rotation: %v", err)
	}
	if err := assembler.Verify(second); err != nil {
		t.Fatalf("new evidence did not verify: %v", err)
	}
}

func newAssembler(t *testing.T, verifier AttemptVerifier) *Assembler {
	t.Helper()
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	assembler, err := NewAssembler("v1", private, verifier)
	if err != nil {
		t.Fatal(err)
	}
	return assembler
}

func validInput() AssemblyInput {
	observed := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	return AssemblyInput{
		TenantID: "tenant-1", ClaimFingerprint: "claim-hash", TaskID: "task-1",
		TargetSnapshotID: "snapshot-1", TargetID: "target-1", RecipeID: "gnmi_interface_get", RecipeVersion: "v1",
		TriggerDecisionID: "trigger-1", PlanningDecisionID: "planning-1", ExecutionDecisionID: "execution-1",
		ExecutionGrantID: "grant-1", AcceptedAttemptID: "attempt-1", FencingToken: 7, CompatibilityRecordHash: "compat-hash",
		Captured:  artefacts.CapturedRef{URI: "captured", SHA256Digest: "captured-hash", ByteCount: 10},
		Sanitised: artefacts.SanitisedRef{URI: "sanitised", SHA256Digest: "sanitised-hash", ParentCapturedDigest: "captured-hash", TransformationManifestDigest: "manifest-hash"},
		ParserID:  "parser-1", ParserVersion: "v1", NormaliserVersion: "v1", Completeness: 1,
		ValidUntil: observed.Add(5 * time.Minute), Observation: parsing.InterfaceOperationalState{SchemaVersion: "v1", InterfaceName: "Ethernet1", OperationalState: "up", ObservedAt: observed},
		CollectorIdentity: "spiffe://example.test/collector/a", CollectorVersion: "v1", AuditReference: "audit-1", AssembledAt: observed.Add(time.Second),
	}
}
