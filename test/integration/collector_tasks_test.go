//go:build integration

package integration_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"network_broker/internal/collector"
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
	t.Cleanup(func() {
		if _, cleanupErr := database.ExecContext(context.Background(),
			`DELETE FROM broker_collector_tasks WHERE id = $1`, taskID); cleanupErr != nil {
			t.Errorf("delete integration collector task: %v", cleanupErr)
		}
	})
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
	if err := repositoryAfterRestart.BeginCommitContext(ctx, taskID, secondLease.Owner,
		secondLease.FencingToken, now.Add(14*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := repositoryAfterRestart.CommitContext(ctx, taskID, secondLease.Owner,
		secondLease.FencingToken, "attempt-second", "evidence-second", now.Add(15*time.Second)); err != nil {
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
	if stored.State != collector.TaskSucceeded || stored.AcceptedAttemptID != "attempt-second" ||
		stored.AcceptedEvidenceID != "evidence-second" || stored.ExecutionGrantID != "grant-second" {
		t.Fatalf("unexpected persisted collector task: %+v", stored)
	}
	if err := repositoryAfterSecondRestart.CommitContext(ctx, taskID, secondLease.Owner,
		secondLease.FencingToken, "attempt-third", "evidence-third", now.Add(16*time.Second)); !errors.Is(err, collector.ErrDuplicateCommit) {
		t.Fatalf("expected exactly-one accepted result after restart, got %v", err)
	}
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
