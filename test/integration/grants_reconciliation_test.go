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

	"network_broker/internal/authctx"
	"network_broker/internal/collector"
	"network_broker/internal/collectorruntime"
	"network_broker/internal/grants"
	"network_broker/internal/keyprovider"
	"network_broker/internal/parsing"
	"network_broker/internal/planning"
	"network_broker/internal/sanitise"
	"network_broker/internal/transport"
	"network_broker/migrations"
)

func TestProductionCollectorRuntimeUsesOnlyDurableAuthorityStores(t *testing.T) {
	database, ctx := openGrantIntegrationDatabase(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	taskID := fmt.Sprintf("production-runtime-%d", now.UnixNano())
	tasks, err := collector.NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	task := durableCollectorTask(taskID)
	if err := tasks.AddContext(ctx, task); err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := keyprovider.NewEd25519Keyring("runtime-signing-key", private)
	if err != nil {
		t.Fatal(err)
	}
	consumptions, err := grants.NewPostgresConsumptionRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	collectorID := "spiffe://broker.example/tenant/tenant-integration/role/collector/workload/site-1"
	authority, err := grants.NewAuthorityWithProviderAndRepository(
		"runtime-credential-broker", "runtime-site", keyring, tasks, consumptions)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(fmt.Sprintf(
		`{"schema_version":"v1","interface_name":"Ethernet1","operational_state":"up","observed_at":%q}`,
		now.Format(time.RFC3339Nano)))
	runtime, err := collectorruntime.New(collectorruntime.Config{
		Identity: authctx.AuthContext{
			SubjectID: collectorID, SPIFFEID: collectorID, TenantID: task.TenantID,
			Roles: []string{"collector"}, AllowedScopes: []string{"tasks:execute"},
			CredentialClass: "mtls-spiffe", AuthenticatedAt: now, IdentityRevision: "svid-revision-1",
		},
		TransportName: "gnmi", CollectorVersion: "integration-v1",
		AssemblerVersion: "integration-v1", NormaliserVersion: "integration-v1",
		LeaseDuration: 30 * time.Second, GrantTTL: 30 * time.Second,
		MaximumDuration: time.Second, MaximumBytes: 4096, EvidenceValidity: time.Minute,
		Sanitiser: sanitise.Pipeline{ID: "safe-json", Version: "v1", MaximumBytes: 4096},
		Parser:    parsing.InterfaceStateParser{ID: "interface-state", Version: "v1"},
	}, collectorruntime.Dependencies{
		Database: database, Blobs: &integrationBlobStore{objects: make(map[string][]byte)},
		Signing: keyring, Encryption: keyprovider.StaticEncryptionProvider{Reference: "kms://runtime/capture"},
		Transport:  transport.StubAdapter{Payload: payload, MediaType: "application/json"},
		Authorizer: runtimeAllowAuthorizer{}, GrantIssuer: authority, Credentials: authority,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Run(ctx, taskID); err != nil {
		t.Fatal(err)
	}
	stored, err := runtime.Task(ctx, taskID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != collector.TaskSucceeded || stored.AcceptedEvidenceID == "" {
		t.Fatalf("unexpected durable runtime task: %+v", stored)
	}
	if _, err := runtime.Evidence(ctx, stored.AcceptedEvidenceID); err != nil {
		t.Fatalf("read durable runtime evidence: %v", err)
	}
	restartedTasks, err := collector.NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	restartedTask, err := restartedTasks.GetContext(ctx, taskID)
	if err != nil || restartedTask.AcceptedEvidenceID != stored.AcceptedEvidenceID {
		t.Fatalf("runtime authority did not survive reconstruction: task=%+v error=%v", restartedTask, err)
	}
}

type runtimeAllowAuthorizer struct{}

func (runtimeAllowAuthorizer) AuthorizeExecution(_ context.Context,
	_ collector.ExecutionRequest,
) (collector.ExecutionAuthorization, error) {
	return collector.ExecutionAuthorization{
		DecisionID: "runtime-execution-decision", MaximumDuration: time.Second, MaximumBytes: 4096,
	}, nil
}

func TestResolutionTaskFanoutAndEventAreOneConcurrentTransaction(t *testing.T) {
	database, ctx := openGrantIntegrationDatabase(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	resolutionID := fmt.Sprintf("fanout-resolution-%d", now.UnixNano())
	if _, err := database.ExecContext(ctx, `
		INSERT INTO broker_resolutions (
			id, actor_id, tenant_id, idempotency_key, request_digest, state,
			target_count, completed, version, created_at, updated_at
		) VALUES ($1, 'actor-fanout', 'tenant-integration', $2, 'digest-fanout',
			'planning', 0, FALSE, 3, $3, $3)`, resolutionID,
		"idempotency-"+resolutionID, now); err != nil {
		t.Fatal(err)
	}
	tasks := []collector.Task{
		durableCollectorTask("fanout-task-a-" + resolutionID),
		durableCollectorTask("fanout-task-b-" + resolutionID),
	}
	for index := range tasks {
		tasks[index].ResolutionID = resolutionID
		tasks[index].TargetID = fmt.Sprintf("router-%d", index+1)
	}
	firstRepository, err := collector.NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	secondRepository, err := collector.NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	firstService, err := planning.NewService(firstRepository, func() time.Time { return now },
		func(string) (string, error) { return "fanout-event-a-" + resolutionID, nil })
	if err != nil {
		t.Fatal(err)
	}
	secondService, err := planning.NewService(secondRepository, func() time.Time { return now },
		func(string) (string, error) { return "fanout-event-b-" + resolutionID, nil })
	if err != nil {
		t.Fatal(err)
	}
	services := []*planning.Service{firstService, secondService}
	actor := authctx.AuthContext{
		SubjectID: "spiffe://example.test/tenant/tenant-integration/role/planner/workload/control-1",
		TenantID:  "tenant-integration", AllowedScopes: []string{"resolutions:plan"},
		AuthenticatedAt: now,
	}
	request := planning.QueueRequest{
		ResolutionID: resolutionID, ExpectedResolutionVersion: 3, Tasks: tasks,
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var waitGroup sync.WaitGroup
	for index := range services {
		waitGroup.Add(1)
		go func(service *planning.Service) {
			defer waitGroup.Done()
			<-start
			_, queueErr := service.Queue(ctx, actor, request)
			results <- queueErr
		}(services[index])
	}
	close(start)
	waitGroup.Wait()
	close(results)
	var successes, conflicts int
	for fanoutErr := range results {
		switch {
		case fanoutErr == nil:
			successes++
		case errors.Is(fanoutErr, collector.ErrFanoutConflict):
			conflicts++
		default:
			t.Fatalf("unexpected fan-out error: %v", fanoutErr)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("expected one fan-out winner, successes=%d conflicts=%d", successes, conflicts)
	}
	var state string
	var targetCount int
	var version int64
	if err := database.QueryRowContext(ctx, `
		SELECT state, target_count, version FROM broker_resolutions WHERE id = $1`,
		resolutionID).Scan(&state, &targetCount, &version); err != nil {
		t.Fatal(err)
	}
	if state != "queued" || targetCount != len(tasks) || version != 4 {
		t.Fatalf("unexpected queued resolution: state=%q targets=%d version=%d", state, targetCount, version)
	}
	var taskCount, eventCount int
	if err := database.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM broker_collector_tasks WHERE resolution_id = $1`,
		resolutionID).Scan(&taskCount); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM broker_outbox
		WHERE aggregate_id = $1 AND event_type = 'resolution.tasks_queued'`,
		resolutionID).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if taskCount != len(tasks) || eventCount != 1 {
		t.Fatalf("fan-out was not atomic: tasks=%d events=%d", taskCount, eventCount)
	}
}

func TestExecutionGrantConsumptionSurvivesRestartAndIsConcurrentSingleUse(t *testing.T) {
	database, ctx := openGrantIntegrationDatabase(t)
	tasks, err := collector.NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	taskID := fmt.Sprintf("grant-consumption-%d", time.Now().UnixNano())
	if err := tasks.AddContext(ctx, durableCollectorTask(taskID)); err != nil {
		t.Fatal(err)
	}
	now := postgresClock(t, ctx, database)
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
	collectorID := "spiffe://example.test/collector/reconciler"

	recoverableTaskID := fmt.Sprintf("evidence-recoverable-%d", time.Now().UnixNano())
	if err := tasks.AddContext(ctx, durableCollectorTask(recoverableTaskID)); err != nil {
		t.Fatal(err)
	}
	now := postgresClock(t, ctx, database)
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
	metrics := &collector.ReconciliationMetrics{}
	runner := collector.ReconciliationRunner{
		Repository: restartedTasks, BatchSize: 10, PollInterval: time.Second,
		FailureDelay: time.Second, Now: func() time.Time { return now.Add(6 * time.Second) },
		Metrics: metrics,
	}
	count, err := runner.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || metrics.Snapshot().Reconciled != 1 {
		t.Fatalf("expected one runtime reconciliation, count=%d metrics=%+v", count, metrics.Snapshot())
	}
	reconciled, err := restartedTasks.GetContext(ctx, recoverableTaskID)
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

// postgresClock obtains transition time from the same clock that owns the
// task's database-generated created_at timestamp. This prevents a skewed test
// runner clock from attempting to move updated_at before created_at.
func postgresClock(t *testing.T, ctx context.Context, database *sql.DB) time.Time {
	t.Helper()
	var now time.Time
	if err := database.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatalf("read PostgreSQL clock: %v", err)
	}

	return now.UTC().Truncate(time.Microsecond)
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
