//go:build integration

package integration_test

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"network_broker/internal/artefacts"
	"network_broker/internal/collector"
	"network_broker/internal/cryptosign"
	"network_broker/internal/disclosure"
	"network_broker/internal/evidence"
	"network_broker/internal/keyprovider"
	"network_broker/internal/parsing"
	"network_broker/internal/retrieval"
	"network_broker/migrations"
)

func TestEvidenceAndDisclosureAuthoritySurviveRestart(t *testing.T) {
	databaseURL := os.Getenv("POSTGRES_TEST_DSN")
	if databaseURL == "" {
		t.Skip("POSTGRES_TEST_DSN is not configured")
	}
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := database.Close(); closeErr != nil {
			t.Errorf("close postgres: %v", closeErr)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := migrations.Apply(ctx, database); err != nil {
		t.Fatal(err)
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	now := time.Now().UTC().Truncate(time.Microsecond)
	taskRepository, envelope := createDurableEnvelope(t, ctx, database, suffix)
	envelopeRepository, err := evidence.NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := envelopeRepository.Create(ctx, envelope); err != nil {
		t.Fatal(err)
	}
	if err := taskRepository.BeginCommitContext(ctx, envelope.TaskID, envelope.Attribution.CollectorIdentity,
		envelope.FencingToken, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := taskRepository.CommitContext(ctx, envelope.TaskID, envelope.Attribution.CollectorIdentity,
		envelope.FencingToken, envelope.AcceptedAttemptID, envelope.EvidenceID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	restartedEvidenceRepository, err := evidence.NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	storedEnvelope, err := restartedEvidenceRepository.GetForTenant(ctx, envelope.TenantID, envelope.EvidenceID)
	if err != nil || storedEnvelope.AcceptedAttemptID != envelope.AcceptedAttemptID {
		t.Fatalf("evidence envelope did not survive restart: envelope=%+v error=%v", storedEnvelope, err)
	}
	if _, err := restartedEvidenceRepository.GetForTenant(ctx, "other-tenant", envelope.EvidenceID); !errors.Is(err, evidence.ErrEnvelopeNotFound) {
		t.Fatalf("expected tenant-isolated evidence lookup, got %v", err)
	}

	signing := disclosureSigningManager(t, suffix)
	disclosureRepository, err := disclosure.NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	service, err := disclosure.NewServiceWithRepositoryAndSigning(func() time.Time { return now.Add(4 * time.Second) },
		disclosureRepository, signing)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := service.EvaluateContext(ctx, disclosure.DecisionRequest{
		ActorID: "actor-" + suffix, TenantID: envelope.TenantID, EvidenceID: envelope.EvidenceID,
		Representation: "normalised", PolicyBundleDigest: strings.Repeat("d", 64),
		InputDigest: strings.Repeat("e", 64), PermittedFields: []string{"interface_name", "operational_state"},
		AllowTaintedFields: true, TTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	retrievalService := retrieval.Service{Evidence: restartedEvidenceRepository, Disclosure: service}
	request := retrieval.Request{
		ActorID: decision.ActorID, TenantID: decision.TenantID, EvidenceID: envelope.EvidenceID,
		DecisionID: decision.DecisionID, RequestID: "request-" + suffix, Fields: []string{"operational_state"},
	}
	first, err := retrievalService.RetrieveNormalised(ctx, request)
	if err != nil {
		t.Fatal(err)
	}

	restartedDisclosureRepository, err := disclosure.NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	restartedService, err := disclosure.NewServiceWithRepositoryAndSigning(
		func() time.Time { return now.Add(5 * time.Second) }, restartedDisclosureRepository, signing)
	if err != nil {
		t.Fatal(err)
	}
	restartedRetrieval := retrieval.Service{Evidence: restartedEvidenceRepository, Disclosure: restartedService}
	second, err := restartedRetrieval.RetrieveNormalised(ctx, request)
	if err != nil || second.Receipt.ReceiptID != first.Receipt.ReceiptID {
		t.Fatalf("idempotent disclosure did not survive restart: first=%+v second=%+v error=%v",
			first.Receipt, second.Receipt, err)
	}
	if err := restartedService.VerifyReceipt(ctx, second.Receipt); err != nil {
		t.Fatalf("persisted receipt signature did not verify: %v", err)
	}
	request.Fields = []string{"interface_name"}
	if _, err := restartedRetrieval.RetrieveNormalised(ctx, request); !errors.Is(err, disclosure.ErrReceiptConflict) {
		t.Fatalf("expected conflicting request reuse to fail closed, got %v", err)
	}
	if _, err := database.ExecContext(ctx, `
		UPDATE broker_disclosure_receipts SET actor_id = 'tampered' WHERE receipt_id = $1`,
		first.Receipt.ReceiptID); err == nil {
		t.Fatal("expected append-only receipt trigger to reject mutation")
	}
}

func createDurableEnvelope(t *testing.T, ctx context.Context, database *sql.DB,
	suffix string,
) (*collector.PostgresRepository, evidence.EvidenceEnvelope) {
	t.Helper()
	tasks, err := collector.NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	task := collector.Task{
		ID: "task-evidence-" + suffix, TenantID: "tenant-evidence-" + suffix,
		ResolutionID: "resolution-" + suffix, ClaimFingerprint: "claim-" + suffix,
		TargetSnapshotID: "snapshot-" + suffix, TargetSnapshotHash: strings.Repeat("1", 64),
		TargetID: "router-1", RecipeID: "gnmi_interface_get", RecipeVersion: "v1",
		TriggerDecisionID: "trigger-" + suffix, PlanningDecisionID: "planning-" + suffix,
		CompatibilityHash: strings.Repeat("2", 64),
	}
	if err := tasks.AddContext(ctx, task); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	collectorID := "spiffe://example.test/collector/evidence"
	lease, err := tasks.AcquireContext(ctx, task.ID, collectorID, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := tasks.StartExecutionContext(ctx, task.ID, collectorID, lease.FencingToken, now); err != nil {
		t.Fatal(err)
	}
	if err := tasks.RecordExecutionAuthorityContext(ctx, task.ID, collectorID, lease.FencingToken,
		"execution-"+suffix, "grant-"+suffix, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	assembler, err := evidence.NewAssembler("assembler-v1", private, tasks)
	if err != nil {
		t.Fatal(err)
	}
	attemptID := fmt.Sprintf("attempt-%s-%d", task.ID, lease.FencingToken)
	envelope, err := assembler.AssembleContext(ctx, evidence.AssemblyInput{
		TenantID: task.TenantID, ClaimFingerprint: task.ClaimFingerprint, TaskID: task.ID,
		TargetSnapshotID: task.TargetSnapshotID, TargetID: task.TargetID, RecipeID: task.RecipeID,
		RecipeVersion: task.RecipeVersion, TriggerDecisionID: task.TriggerDecisionID,
		PlanningDecisionID: task.PlanningDecisionID, ExecutionDecisionID: "execution-" + suffix,
		ExecutionGrantID: "grant-" + suffix, AcceptedAttemptID: attemptID, FencingToken: lease.FencingToken,
		CompatibilityRecordHash: task.CompatibilityHash,
		Captured: artefacts.CapturedRef{
			URI: "artefact://captured/" + suffix, SHA256Digest: strings.Repeat("a", 64), ByteCount: 128,
			MediaType: "application/json", Transport: "gnmi", CapturedAt: now,
			AttemptID: attemptID, EncryptionKeyRef: "kms://tenant/evidence/v1",
		},
		Sanitised: artefacts.SanitisedRef{
			URI: "artefact://sanitised/" + suffix, SHA256Digest: strings.Repeat("b", 64), ByteCount: 96,
			MediaType: "application/json", ParentCapturedDigest: strings.Repeat("a", 64),
			TransformationManifestDigest: strings.Repeat("c", 64), CreatedAt: now,
		},
		ParserID: "interface-state", ParserVersion: "v1", NormaliserVersion: "v1", Completeness: 1,
		ValidUntil: now.Add(5 * time.Minute), Observation: parsing.InterfaceOperationalState{
			SchemaVersion: "v1", InterfaceName: "Ethernet1", OperationalState: "up", ObservedAt: now,
			TaintedFields: []string{"interface_name"},
		},
		CollectorIdentity: collectorID, CollectorVersion: "collector-v1",
		AuditReference: "audit-" + suffix, AssembledAt: now.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}

	return tasks, envelope
}

func disclosureSigningManager(t *testing.T, suffix string) *cryptosign.Manager {
	t.Helper()
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := keyprovider.NewEd25519Keyring("receipt-key-"+suffix, private)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := cryptosign.NewManager([]keyprovider.SigningProvider{keyring}, cryptosign.Policy{
		MinimumValidSignatures: 1, RequiredAlgorithms: []string{keyprovider.Ed25519Algorithm},
	})
	if err != nil {
		t.Fatal(err)
	}

	return manager
}
