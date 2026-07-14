//go:build integration

package integration_test

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"network_broker/internal/collector"
	"network_broker/internal/grants"
	"network_broker/internal/keyprovider"
	"network_broker/migrations"
)

func TestExecutionGrantConsumptionSurvivesRestartAndIsConcurrentSingleUse(t *testing.T) {
	database, ctx := openGrantIntegrationDatabase(t)
	tasks, err := collector.NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	taskID := fmt.Sprintf("grant-consumption-%d", now.UnixNano())
	if err := tasks.AddContext(ctx, durableCollectorTask(taskID)); err != nil {
		t.Fatal(err)
	}
	collectorID := "spiffe://example.test/collector/grant-integration"
	lease, err := tasks.AcquireContext(ctx, taskID, collectorID, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := tasks.StartExecutionContext(ctx, taskID, collectorID, lease.FencingToken,
		now.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := keyprovider.NewEd25519Keyring("integration-grant-key", private)
	if err != nil {
		t.Fatal(err)
	}
	consumptions, err := grants.NewPostgresConsumptionRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := grants.NewAuthorityWithProviderAndRepository(
		"integration-credential-broker", "integration-site", keyring, tasks, consumptions)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := issuer.IssueContext(ctx, integrationExecutionGrant(taskID, collectorID,
		lease.FencingToken, now))
	if err != nil {
		t.Fatal(err)
	}
	if err := tasks.RecordExecutionAuthorityContext(ctx, taskID, collectorID,
		lease.FencingToken, "execution-integration", grant.GrantID, now.Add(2*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	request := grants.ExchangeRequest{
		PresentingSPIFFEID: collectorID, TaskID: taskID, TargetID: grant.TargetID,
		RecipeID: grant.RecipeID, RecipeVersion: grant.RecipeVersion,
		FencingToken: lease.FencingToken, Now: time.Now().UTC(),
	}

	// Separate authority instances model credential-broker replicas racing to
	// exchange the same signed grant.
	secondConsumptions, err := grants.NewPostgresConsumptionRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	secondIssuer, err := grants.NewAuthorityWithProviderAndRepository(
		"integration-credential-broker", "integration-site", keyring, tasks, secondConsumptions)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errorsByExchange := make(chan error, 2)
	var waitGroup sync.WaitGroup
	for _, authority := range []*grants.Authority{issuer, secondIssuer} {
		waitGroup.Add(1)
		go func(authority *grants.Authority) {
			defer waitGroup.Done()
			<-start
			_, exchangeErr := authority.ExchangeContext(ctx, grant, request)
			errorsByExchange <- exchangeErr
		}(authority)
	}
	close(start)
	waitGroup.Wait()
	close(errorsByExchange)
	var successes, consumed int
	for exchangeErr := range errorsByExchange {
		switch {
		case exchangeErr == nil:
			successes++
		case errors.Is(exchangeErr, grants.ErrAlreadyConsumed):
			consumed++
		default:
			t.Fatalf("unexpected concurrent exchange error: %v", exchangeErr)
		}
	}
	if successes != 1 || consumed != 1 {
		t.Fatalf("expected one exchange and one rejection, successes=%d consumed=%d", successes, consumed)
	}

	// A third repository and authority model complete process-local state loss.
	afterRestart, err := grants.NewPostgresConsumptionRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	restartedIssuer, err := grants.NewAuthorityWithProviderAndRepository(
		"integration-credential-broker", "integration-site", keyring, tasks, afterRestart)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restartedIssuer.ExchangeContext(ctx, grant, request); !errors.Is(err, grants.ErrAlreadyConsumed) {
		t.Fatalf("expected consumed grant rejection after restart, got %v", err)
	}
	record, err := afterRestart.Get(ctx, grant.TenantID, grant.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	if record.TaskID != taskID || record.FencingToken != lease.FencingToken ||
		record.CollectorSPIFFEID != collectorID || record.NonceDigest == grant.Nonce {
		t.Fatalf("unexpected durable consumption: %+v", record)
	}
	if _, err := database.ExecContext(ctx, `
		UPDATE broker_execution_grant_consumptions SET target_id = 'tampered'
		WHERE grant_id = $1`, grant.GrantID); err == nil {
		t.Fatal("expected execution grant consumption mutation to be rejected")
	}
}

func TestExpiredEvidenceReconciliationAcceptsOnlyUnchangedFence(t *testing.T) {
	database, ctx := openGrantIntegrationDatabase(t)
	tasks, err := collector.NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	collectorID := "spiffe://example.test/collector/reconciler"

	recoverableTaskID := fmt.Sprintf("evidence-recoverable-%d", now.UnixNano())
	if err := tasks.AddContext(ctx, durableCollectorTask(recoverableTaskID)); err != nil {
		t.Fatal(err)
	}
	recoverableLease := prepareReconciliationAttempt(t, ctx, tasks, recoverableTaskID,
		collectorID, "grant-recoverable", now)
	recoverableEnvelope := persistRestartEvidence(t, ctx, database, tasks, recoverableTaskID,
		recoverableLease, now.Add(time.Second))

	// The process disappears after envelope creation. A new repository accepts
	// it after lease expiry without requiring the dead collector's lease owner.
	restartedTasks, err := collector.NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	reconciled, err := restartedTasks.ReconcileExpiredEvidenceContext(ctx,
		recoverableEnvelope.EvidenceID, now.Add(6*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.State != collector.TaskSucceeded ||
		reconciled.AcceptedEvidenceID != recoverableEnvelope.EvidenceID {
		t.Fatalf("unexpected reconciled task: %+v", reconciled)
	}
	if _, err := restartedTasks.ReconcileExpiredEvidenceContext(ctx,
		recoverableEnvelope.EvidenceID, now.Add(7*time.Second)); err != nil {
		t.Fatalf("expected reconciliation to be idempotent, got %v", err)
	}

	staleTaskID := fmt.Sprintf("evidence-stale-%d", now.UnixNano())
	if err := tasks.AddContext(ctx, durableCollectorTask(staleTaskID)); err != nil {
		t.Fatal(err)
	}
	staleNow := time.Now().UTC().Truncate(time.Microsecond)
	staleLease := prepareReconciliationAttempt(t, ctx, tasks, staleTaskID,
		collectorID, "grant-stale", staleNow)
	staleEnvelope := persistRestartEvidence(t, ctx, database, tasks, staleTaskID,
		staleLease, staleNow.Add(time.Second))
	if _, err := tasks.AcquireContext(ctx, staleTaskID, collectorID,
		staleNow.Add(6*time.Second), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := restartedTasks.ReconcileExpiredEvidenceContext(ctx,
		staleEnvelope.EvidenceID, staleNow.Add(7*time.Second)); !errors.Is(err, collector.ErrStaleFence) {
		t.Fatalf("expected old evidence to fail after reacquisition, got %v", err)
	}
}

func openGrantIntegrationDatabase(t *testing.T) (*sql.DB, context.Context) {
	t.Helper()
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	if err := migrations.Apply(ctx, database); err != nil {
		t.Fatal(err)
	}

	return database, ctx
}

func integrationExecutionGrant(taskID, collectorID string, fencingToken int64,
	now time.Time,
) grants.ExecutionGrant {
	return grants.ExecutionGrant{
		GrantID: fmt.Sprintf("grant-%s-%d", taskID, fencingToken),
		Nonce:   fmt.Sprintf("nonce-%s-%d", taskID, fencingToken), TenantID: "tenant-integration",
		CollectorSPIFFEID: collectorID, ResolutionID: "resolution-integration", TaskID: taskID,
		TargetSnapshotID: "snapshot-integration", TargetSnapshotDigest: "snapshot-sha256",
		TargetID: "router-1", RecipeID: "gnmi_interface_get", RecipeVersion: "v1",
		ParameterDigest: "parameters-sha256", FencingToken: fencingToken,
		TriggerDecisionID: "decision-trigger", PlanningDecisionID: "decision-planning",
		ExecutionDecisionID: "execution-integration", NotBefore: now.Add(-time.Second),
		ExpiresAt: now.Add(45 * time.Second), MaximumDuration: 5 * time.Second,
		MaximumResponseBytes: 1024, CredentialClass: "network-read", SingleUse: true,
	}
}

func prepareReconciliationAttempt(t *testing.T, ctx context.Context,
	tasks *collector.PostgresRepository, taskID, collectorID, grantID string,
	now time.Time,
) collector.Lease {
	t.Helper()
	lease, err := tasks.AcquireContext(ctx, taskID, collectorID, now, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := tasks.StartExecutionContext(ctx, taskID, collectorID, lease.FencingToken,
		now.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err := tasks.RecordExecutionAuthorityContext(ctx, taskID, collectorID,
		lease.FencingToken, "decision-"+grantID, grantID, now.Add(2*time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	return lease
}
