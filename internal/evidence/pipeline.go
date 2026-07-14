package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"network_broker/internal/artefacts"
	"network_broker/internal/collector"
	"network_broker/internal/keyprovider"
	"network_broker/internal/parsing"
	"network_broker/internal/sanitise"
	"network_broker/internal/transport"
)

// PipelineSink is the trusted boundary from captured bytes to a signed,
// schema-validated envelope. Captured and sanitised payloads stay in the
// artefact store; the envelope contains immutable references only.
type PipelineSink struct {
	Artefacts         artefacts.PipelineStore
	Sanitiser         sanitise.Pipeline
	Parser            parsing.InterfaceStateParser
	Assembler         *Assembler
	TransportName     string
	EncryptionKeys    keyprovider.EncryptionProvider
	CollectorVersion  string
	NormaliserVersion string
	Validity          time.Duration
	Now               func() time.Time
	Envelopes         Repository
}

func NewPipelineSink(store artefacts.PipelineStore, sanitiser sanitise.Pipeline, parser parsing.InterfaceStateParser,
	assembler *Assembler, transportName, encryptionKeyRef, collectorVersion, normaliserVersion string,
	validity time.Duration, now func() time.Time,
) (*PipelineSink, error) {
	if encryptionKeyRef == "" {
		return nil, fmt.Errorf("pipeline encryption key reference is required")
	}

	return NewPipelineSinkWithKeyProvider(store, sanitiser, parser, assembler, transportName,
		keyprovider.StaticEncryptionProvider{Reference: encryptionKeyRef}, collectorVersion,
		normaliserVersion, validity, now)
}

func NewPipelineSinkWithKeyProvider(store artefacts.PipelineStore, sanitiser sanitise.Pipeline,
	parser parsing.InterfaceStateParser, assembler *Assembler, transportName string,
	encryptionKeys keyprovider.EncryptionProvider, collectorVersion, normaliserVersion string,
	validity time.Duration, now func() time.Time,
) (*PipelineSink, error) {
	return NewPipelineSinkWithRepositories(store, sanitiser, parser, assembler, transportName,
		encryptionKeys, NewMemoryRepository(), collectorVersion, normaliserVersion, validity, now)
}

// NewPipelineSinkWithRepositories constructs a pipeline with durable key and
// immutable envelope persistence boundaries.
func NewPipelineSinkWithRepositories(store artefacts.PipelineStore, sanitiser sanitise.Pipeline,
	parser parsing.InterfaceStateParser, assembler *Assembler, transportName string,
	encryptionKeys keyprovider.EncryptionProvider, envelopes Repository,
	collectorVersion, normaliserVersion string, validity time.Duration, now func() time.Time,
) (*PipelineSink, error) {
	if store == nil || assembler == nil || transportName == "" || encryptionKeys == nil || collectorVersion == "" ||
		envelopes == nil || normaliserVersion == "" || validity <= 0 {
		return nil, fmt.Errorf("pipeline stores, identities, versions and positive validity are required")
	}
	if now == nil {
		now = time.Now
	}
	return &PipelineSink{
		Artefacts: store, Sanitiser: sanitiser, Parser: parser, Assembler: assembler,
		TransportName: transportName, EncryptionKeys: encryptionKeys, CollectorVersion: collectorVersion,
		NormaliserVersion: normaliserVersion, Validity: validity, Now: now, Envelopes: envelopes,
	}, nil
}

func (s *PipelineSink) WriteCaptured(ctx context.Context, task collector.Task, lease collector.Lease, captured transport.CapturedBytes) (attemptID, evidenceID string, err error) {
	if captured.TargetID != task.TargetID {
		return "", "", fmt.Errorf("captured target does not match task target")
	}
	if sha256.Sum256(captured.Payload) != captured.Digest {
		return "", "", fmt.Errorf("captured payload digest does not match transport metadata")
	}
	if captured.MediaType == "" {
		return "", "", fmt.Errorf("captured payload media type is required")
	}
	now := s.Now().UTC()
	attemptID = fmt.Sprintf("attempt-%s-%d", task.ID, lease.FencingToken)
	encryptionKeyRef, err := s.EncryptionKeys.CurrentEncryptionKey(ctx, task.TenantID, "captured-artefact")
	if err != nil {
		return "", "", fmt.Errorf("resolve captured artefact encryption key: %w", err)
	}
	capturedRef, err := s.Artefacts.PutCapturedForTenant(ctx, task.TenantID, captured.Payload, captured.MediaType,
		s.TransportName, attemptID, encryptionKeyRef, captured.CapturedAt)
	if err != nil {
		return "", "", err
	}
	sanitisedPayload, manifest, err := s.Sanitiser.Transform(captured.Payload)
	if err != nil {
		return "", "", err
	}
	sanitisedMediaType := captured.MediaType
	if manifest.Quarantined {
		sanitisedMediaType = "application/json"
	}
	sanitisedRef, err := s.Artefacts.PutSanitisedForTenant(ctx, task.TenantID, sanitisedPayload,
		sanitisedMediaType, capturedRef, manifest, now)
	if err != nil {
		return "", "", err
	}
	if manifest.Quarantined {
		return "", "", fmt.Errorf("sanitised artefact %q: %w", sanitisedRef.URI, sanitise.ErrQuarantined)
	}
	observation, err := s.Parser.ParseWithManifest(sanitisedPayload, sanitisedRef.MediaType, manifest)
	if err != nil {
		return "", "", err
	}
	envelope, err := s.Assembler.AssembleContext(ctx, AssemblyInput{
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
	if err := s.Envelopes.Create(ctx, envelope); err != nil {
		return "", "", fmt.Errorf("persist evidence envelope: %w", err)
	}
	return attemptID, envelope.EvidenceID, nil
}

func (s *PipelineSink) Get(evidenceID string) (EvidenceEnvelope, error) {
	return s.Envelopes.GetByID(context.Background(), evidenceID)
}

func (s *PipelineSink) GetForTenant(ctx context.Context, tenantID, evidenceID string) (EvidenceEnvelope, error) {
	return s.Envelopes.GetForTenant(ctx, tenantID, evidenceID)
}
