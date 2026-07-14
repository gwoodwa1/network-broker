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
	"network_broker/internal/evidence"
	"network_broker/internal/parsing"
	"network_broker/migrations"
)

func TestPostgresCollectorTaskSurvivesRestartAndRejectsStaleFence(t *testing.T) {
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
	repositoryBeforeRestart, err := collector.NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	taskID := fmt.Sprintf("collector-restart-%d", time.Now().UnixNano())
	task := durableCollectorTask(taskID)
	if err := repositoryBeforeRestart.AddContext(ctx, task); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	firstLease, err := repositoryBeforeRestart.AcquireContext(ctx, taskID, "spiffe://example.test/collector/a",
		now, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := repositoryBeforeRestart.StartExecutionContext(ctx, taskID, firstLease.Owner,
		firstLease.FencingToken, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := repositoryBeforeRestart.RecordExecutionAuthorityContext(ctx, taskID, firstLease.Owner,
		firstLease.FencingToken, "decision-first", "grant-first", now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}

	// Constructing a new repository instance models loss of all process-local
	// state while retaining the database authority record.
	repositoryAfterRestart, err := collector.NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repositoryAfterRestart.AcquireContext(ctx, taskID, firstLease.Owner,
		now.Add(3*time.Second), 10*time.Second); !errors.Is(err, collector.ErrLeaseHeld) {
		t.Fatalf("expected live pre-restart lease to remain authoritative, got %v", err)
	}
	secondLease, err := repositoryAfterRestart.AcquireContext(ctx, taskID, firstLease.Owner,
		now.Add(11*time.Second), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if secondLease.FencingToken != firstLease.FencingToken+1 {
		t.Fatalf("expected a new fencing epoch, first=%d second=%d",
			firstLease.FencingToken, secondLease.FencingToken)
	}
	if err := repositoryBeforeRestart.VerifyCurrentAttempt(taskID, firstLease.Owner,
		firstLease.FencingToken, now.Add(12*time.Second)); !errors.Is(err, collector.ErrStaleFence) {
		t.Fatalf("expected pre-restart attempt to be fenced, got %v", err)
	}
	if err := repositoryAfterRestart.StartExecutionContext(ctx, taskID, secondLease.Owner,
		secondLease.FencingToken, now.Add(12*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := repositoryAfterRestart.RecordExecutionAuthorityContext(ctx, taskID, secondLease.Owner,
		secondLease.FencingToken, "decision-second", "grant-second", now.Add(13*time.Second)); err != nil {
		t.Fatal(err)
	}
	evidenceEnvelope := persistRestartEvidence(t, ctx, database, repositoryAfterRestart, taskID, secondLease,
		now.Add(13*time.Second))
	if err := repositoryAfterRestart.BeginCommitContext(ctx, taskID, secondLease.Owner,
		secondLease.FencingToken, now.Add(14*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := repositoryAfterRestart.CommitContext(ctx, taskID, secondLease.Owner,
		secondLease.FencingToken, evidenceEnvelope.AcceptedAttemptID, evidenceEnvelope.EvidenceID,
		now.Add(15*time.Second)); err != nil {
		t.Fatal(err)
	}

	repositoryAfterSecondRestart, err := collector.NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := repositoryAfterSecondRestart.GetContext(ctx, taskID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != collector.TaskSucceeded || stored.AcceptedAttemptID != evidenceEnvelope.AcceptedAttemptID ||
		stored.AcceptedEvidenceID != evidenceEnvelope.EvidenceID || stored.ExecutionGrantID != "grant-second" {
		t.Fatalf("unexpected persisted collector task: %+v", stored)
	}
	if err := repositoryAfterSecondRestart.CommitContext(ctx, taskID, secondLease.Owner,
		secondLease.FencingToken, "attempt-third", "evidence-third", now.Add(16*time.Second)); !errors.Is(err, collector.ErrDuplicateCommit) {
		t.Fatalf("expected exactly-one accepted result after restart, got %v", err)
	}
}

func persistRestartEvidence(t *testing.T, ctx context.Context, database *sql.DB,
	tasks *collector.PostgresRepository, taskID string, lease collector.Lease, assembledAt time.Time,
) evidence.EvidenceEnvelope {
	t.Helper()
	task, err := tasks.GetContext(ctx, taskID)
	if err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	assembler, err := evidence.NewAssembler("restart-test-v1", private, tasks)
	if err != nil {
		t.Fatal(err)
	}
	attemptID := fmt.Sprintf("attempt-%s-%d", taskID, lease.FencingToken)
	envelope, err := assembler.AssembleContext(ctx, evidence.AssemblyInput{
		TenantID: task.TenantID, ClaimFingerprint: task.ClaimFingerprint, TaskID: task.ID,
		TargetSnapshotID: task.TargetSnapshotID, TargetID: task.TargetID, RecipeID: task.RecipeID,
		RecipeVersion: task.RecipeVersion, TriggerDecisionID: task.TriggerDecisionID,
		PlanningDecisionID: task.PlanningDecisionID, ExecutionDecisionID: task.ExecutionDecisionID,
		ExecutionGrantID: task.ExecutionGrantID, AcceptedAttemptID: attemptID, FencingToken: lease.FencingToken,
		CompatibilityRecordHash: task.CompatibilityHash,
		Captured: artefacts.CapturedRef{
			URI: "artefact://restart/captured", SHA256Digest: strings.Repeat("a", 64), ByteCount: 16,
			MediaType: "application/json", Transport: "gnmi", CapturedAt: assembledAt,
			AttemptID: attemptID, EncryptionKeyRef: "kms://restart/v1",
		},
		Sanitised: artefacts.SanitisedRef{
			URI: "artefact://restart/sanitised", SHA256Digest: strings.Repeat("b", 64), ByteCount: 16,
			MediaType: "application/json", ParentCapturedDigest: strings.Repeat("a", 64),
			TransformationManifestDigest: strings.Repeat("c", 64), CreatedAt: assembledAt,
		},
		ParserID: "interface-state", ParserVersion: "v1", NormaliserVersion: "v1", Completeness: 1,
		ValidUntil: assembledAt.Add(time.Minute), Observation: parsing.InterfaceOperationalState{
			SchemaVersion: "v1", InterfaceName: "Ethernet1", OperationalState: "up", ObservedAt: assembledAt,
			TaintedFields: []string{"interface_name"},
		},
		CollectorIdentity: lease.Owner, CollectorVersion: "restart-test-v1",
		AuditReference: "audit-restart", AssembledAt: assembledAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := evidence.NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Create(ctx, envelope); err != nil {
		t.Fatal(err)
	}

	return envelope
}

func durableCollectorTask(taskID string) collector.Task {
	return collector.Task{
		ID: taskID, TenantID: "tenant-integration", ResolutionID: "resolution-integration",
		ClaimFingerprint: "claim-sha256", TargetSnapshotID: "snapshot-integration",
		TargetSnapshotHash: "snapshot-sha256", TargetID: "router-1", TargetEndpoint: "router-1:57400",
		RecipeID: "gnmi_interface_get", RecipeVersion: "v1", TriggerDecisionID: "decision-trigger",
		PlanningDecisionID: "decision-planning", CompatibilityHash: "compatibility-sha256",
	}
}
