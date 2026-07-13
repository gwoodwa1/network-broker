// Package evidence assembles and signs lineage-complete evidence envelopes.
package evidence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"network_broker/internal/artefacts"
	"network_broker/internal/parsing"
)

type AttemptVerifier interface {
	VerifyCurrentAttempt(taskID, collectorID string, fencingToken int64, at time.Time) error
}

type Attribution struct {
	CollectorIdentity        string
	CollectorVersion         string
	EvidenceAssemblerVersion string
	AuditReference           string
	SignatureAlgorithm       string
	Signature                []byte
}

type EvidenceEnvelope struct {
	EvidenceID              string
	TenantID                string
	ClaimFingerprint        string
	TaskID                  string
	TargetSnapshotID        string
	TargetID                string
	RecipeID                string
	RecipeVersion           string
	TriggerDecisionID       string
	PlanningDecisionID      string
	ExecutionDecisionID     string
	ExecutionGrantID        string
	AcceptedAttemptID       string
	FencingToken            int64
	CompatibilityRecordHash string
	Captured                artefacts.CapturedRef
	Sanitised               artefacts.SanitisedRef
	ParserID                string
	ParserVersion           string
	NormaliserVersion       string
	Completeness            float64
	ObservedAt              time.Time
	ValidUntil              time.Time
	InterfaceState          parsing.InterfaceOperationalState
	Attribution             Attribution
}

type AssemblyInput struct {
	TenantID                string
	ClaimFingerprint        string
	TaskID                  string
	TargetSnapshotID        string
	TargetID                string
	RecipeID                string
	RecipeVersion           string
	TriggerDecisionID       string
	PlanningDecisionID      string
	ExecutionDecisionID     string
	ExecutionGrantID        string
	AcceptedAttemptID       string
	FencingToken            int64
	CompatibilityRecordHash string
	Captured                artefacts.CapturedRef
	Sanitised               artefacts.SanitisedRef
	ParserID                string
	ParserVersion           string
	NormaliserVersion       string
	Completeness            float64
	ValidUntil              time.Time
	Observation             parsing.InterfaceOperationalState
	CollectorIdentity       string
	CollectorVersion        string
	AuditReference          string
	AssembledAt             time.Time
}

type Assembler struct {
	version  string
	private  ed25519.PrivateKey
	public   ed25519.PublicKey
	verifier AttemptVerifier
}

func NewAssembler(version string, private ed25519.PrivateKey, verifier AttemptVerifier) (*Assembler, error) {
	if version == "" || len(private) != ed25519.PrivateKeySize || verifier == nil {
		return nil, fmt.Errorf("assembler version, signing key and attempt verifier are required")
	}
	public, ok := private.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("derive assembler public key")
	}
	return &Assembler{version: version, private: private, public: public, verifier: verifier}, nil
}

func (a *Assembler) Assemble(input AssemblyInput) (EvidenceEnvelope, error) {
	if err := validateInput(input); err != nil {
		return EvidenceEnvelope{}, err
	}
	if err := a.verifier.VerifyCurrentAttempt(input.TaskID, input.CollectorIdentity, input.FencingToken, input.AssembledAt); err != nil {
		return EvidenceEnvelope{}, fmt.Errorf("verify current fenced attempt: %w", err)
	}
	if input.Sanitised.ParentCapturedDigest != input.Captured.SHA256Digest {
		return EvidenceEnvelope{}, fmt.Errorf("sanitised artefact does not descend from captured artefact")
	}
	envelope := EvidenceEnvelope{
		TenantID: input.TenantID, ClaimFingerprint: input.ClaimFingerprint, TaskID: input.TaskID,
		TargetSnapshotID: input.TargetSnapshotID, TargetID: input.TargetID,
		RecipeID: input.RecipeID, RecipeVersion: input.RecipeVersion,
		TriggerDecisionID: input.TriggerDecisionID, PlanningDecisionID: input.PlanningDecisionID,
		ExecutionDecisionID: input.ExecutionDecisionID, ExecutionGrantID: input.ExecutionGrantID,
		AcceptedAttemptID: input.AcceptedAttemptID, FencingToken: input.FencingToken,
		CompatibilityRecordHash: input.CompatibilityRecordHash, Captured: input.Captured, Sanitised: input.Sanitised,
		ParserID: input.ParserID, ParserVersion: input.ParserVersion, NormaliserVersion: input.NormaliserVersion,
		Completeness: input.Completeness, ObservedAt: input.Observation.ObservedAt.UTC(), ValidUntil: input.ValidUntil.UTC(),
		InterfaceState: input.Observation,
		Attribution: Attribution{
			CollectorIdentity: input.CollectorIdentity, CollectorVersion: input.CollectorVersion,
			EvidenceAssemblerVersion: a.version, AuditReference: input.AuditReference, SignatureAlgorithm: "Ed25519",
		},
	}
	unsigned, err := signingPayload(envelope)
	if err != nil {
		return EvidenceEnvelope{}, err
	}
	id := sha256.Sum256(unsigned)
	envelope.EvidenceID = "evidence-" + hex.EncodeToString(id[:16])
	unsigned, err = signingPayload(envelope)
	if err != nil {
		return EvidenceEnvelope{}, err
	}
	envelope.Attribution.Signature = ed25519.Sign(a.private, unsigned)
	return envelope, nil
}

func (a *Assembler) Verify(envelope EvidenceEnvelope) error {
	payload, err := signingPayload(envelope)
	if err != nil {
		return err
	}
	if !ed25519.Verify(a.public, payload, envelope.Attribution.Signature) {
		return fmt.Errorf("evidence envelope signature is invalid")
	}
	return nil
}

func validateInput(input AssemblyInput) error {
	required := []string{
		input.TenantID, input.ClaimFingerprint, input.TaskID, input.TargetSnapshotID,
		input.TargetID, input.RecipeID, input.RecipeVersion, input.TriggerDecisionID,
		input.PlanningDecisionID, input.ExecutionDecisionID, input.ExecutionGrantID,
		input.AcceptedAttemptID, input.CompatibilityRecordHash, input.ParserID,
		input.ParserVersion, input.NormaliserVersion, input.CollectorIdentity,
		input.CollectorVersion, input.AuditReference,
	}
	for _, value := range required {
		if value == "" {
			return fmt.Errorf("evidence identity, lineage and attribution fields are required")
		}
	}
	if input.FencingToken <= 0 || input.Completeness < 0 || input.Completeness > 1 || input.AssembledAt.IsZero() ||
		input.ValidUntil.IsZero() || !input.ValidUntil.After(input.Observation.ObservedAt) {
		return fmt.Errorf("evidence fence, completeness and validity values are invalid")
	}
	if input.Captured.SHA256Digest == "" || input.Sanitised.SHA256Digest == "" || input.Observation.SchemaVersion == "" {
		return fmt.Errorf("captured, sanitised and normalised evidence are required")
	}
	return nil
}

func signingPayload(envelope EvidenceEnvelope) ([]byte, error) {
	envelopeCopy := envelope
	envelopeCopy.Attribution.Signature = nil
	payload, err := json.Marshal(envelopeCopy)
	if err != nil {
		return nil, fmt.Errorf("encode evidence envelope: %w", err)
	}
	return payload, nil
}
