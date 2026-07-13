package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"network_broker/internal/artefacts"
	"network_broker/internal/collector"
	"network_broker/internal/parsing"
	"network_broker/internal/sanitise"
	"network_broker/internal/transport"
)

// PipelineSink is the trusted boundary from captured bytes to a signed,
// schema-validated envelope. Captured and sanitised payloads stay in the
// artefact store; the envelope contains immutable references only.
type PipelineSink struct {
	Artefacts         *artefacts.Store
	Sanitiser         sanitise.Pipeline
	Parser            parsing.InterfaceStateParser
	Assembler         *Assembler
	TransportName     string
	EncryptionKeyRef  string
	CollectorVersion  string
	NormaliserVersion string
	Validity          time.Duration
	Now               func() time.Time

	mu        sync.RWMutex
	envelopes map[string]EvidenceEnvelope
}

func NewPipelineSink(store *artefacts.Store, sanitiser sanitise.Pipeline, parser parsing.InterfaceStateParser,
	assembler *Assembler, transportName, encryptionKeyRef, collectorVersion, normaliserVersion string,
	validity time.Duration, now func() time.Time,
) (*PipelineSink, error) {
	if store == nil || assembler == nil || transportName == "" || encryptionKeyRef == "" || collectorVersion == "" ||
		normaliserVersion == "" || validity <= 0 {
		return nil, fmt.Errorf("pipeline stores, identities, versions and positive validity are required")
	}
	if now == nil {
		now = time.Now
	}
	return &PipelineSink{
		Artefacts: store, Sanitiser: sanitiser, Parser: parser, Assembler: assembler,
		TransportName: transportName, EncryptionKeyRef: encryptionKeyRef, CollectorVersion: collectorVersion,
		NormaliserVersion: normaliserVersion, Validity: validity, Now: now, envelopes: make(map[string]EvidenceEnvelope),
	}, nil
}

func (s *PipelineSink) WriteCaptured(_ context.Context, task collector.Task, lease collector.Lease, captured transport.CapturedBytes) (attemptID, evidenceID string, err error) {
	if captured.TargetID != task.TargetID {
		return "", "", fmt.Errorf("captured target does not match task target")
	}
	if sha256.Sum256(captured.Payload) != captured.Digest {
		return "", "", fmt.Errorf("captured payload digest does not match transport metadata")
	}
	now := s.Now().UTC()
	attemptID = fmt.Sprintf("attempt-%s-%d", task.ID, lease.FencingToken)
	capturedRef, err := s.Artefacts.PutCaptured(captured.Payload, "application/json", s.TransportName, attemptID, s.EncryptionKeyRef, captured.CapturedAt)
	if err != nil {
		return "", "", err
	}
	sanitisedPayload, manifest, err := s.Sanitiser.Transform(captured.Payload)
	if err != nil {
		return "", "", err
	}
	sanitisedRef, err := s.Artefacts.PutSanitised(sanitisedPayload, "application/json", capturedRef.SHA256Digest, manifest, now)
	if err != nil {
		return "", "", err
	}
	observation, err := s.Parser.Parse(sanitisedPayload)
	if err != nil {
		return "", "", err
	}
	envelope, err := s.Assembler.Assemble(AssemblyInput{
		TenantID: task.TenantID, ClaimFingerprint: task.ClaimFingerprint, TaskID: task.ID,
		TargetSnapshotID: task.TargetSnapshotID, TargetID: task.TargetID, RecipeID: task.RecipeID,
		RecipeVersion: task.RecipeVersion, TriggerDecisionID: task.TriggerDecisionID,
		PlanningDecisionID: task.PlanningDecisionID, ExecutionDecisionID: task.ExecutionDecisionID,
		ExecutionGrantID: task.ExecutionGrantID, AcceptedAttemptID: attemptID, FencingToken: lease.FencingToken,
		CompatibilityRecordHash: task.CompatibilityHash, Captured: capturedRef, Sanitised: sanitisedRef,
		ParserID: s.Parser.ID, ParserVersion: s.Parser.Version, NormaliserVersion: s.NormaliserVersion,
		Completeness: 1, ValidUntil: now.Add(s.Validity), Observation: observation,
		CollectorIdentity: lease.Owner, CollectorVersion: s.CollectorVersion,
		AuditReference: "audit-" + task.ID + "-" + hex.EncodeToString(captured.Digest[:8]), AssembledAt: now,
	})
	if err != nil {
		return "", "", err
	}
	s.mu.Lock()
	s.envelopes[envelope.EvidenceID] = envelope
	s.mu.Unlock()
	return attemptID, envelope.EvidenceID, nil
}

func (s *PipelineSink) Get(evidenceID string) (EvidenceEnvelope, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	envelope, ok := s.envelopes[evidenceID]
	if !ok {
		return EvidenceEnvelope{}, fmt.Errorf("evidence %q not found", evidenceID)
	}
	return envelope, nil
}
