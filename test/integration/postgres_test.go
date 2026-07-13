//go:build integration

package integration_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"network_broker/internal/authctx"
	"network_broker/internal/deadletter"
	"network_broker/internal/outbox"
	"network_broker/internal/resolution"
	"network_broker/migrations"
)

func TestPostgresResolutionAndOutboxLifecycle(t *testing.T) {
	databaseURL := os.Getenv("POSTGRES_TEST_DSN")
	if databaseURL == "" {
		t.Skip("POSTGRES_TEST_DSN is not configured")
	}
	natsURL := os.Getenv("NATS_TEST_URL")
	if natsURL == "" {
		t.Skip("NATS_TEST_URL is not configured")
	}
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close postgres: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := migrations.Apply(ctx, database); err != nil {
		t.Fatal(err)
	}
	if err := migrations.Apply(ctx, database); err != nil {
		t.Fatalf("idempotent migration application failed: %v", err)
	}
	if _, err := database.ExecContext(ctx,
		`TRUNCATE broker_dead_letter_actions, broker_outbox, broker_resolution_idempotency, broker_resolutions
		 RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	natsConnection, err := nats.Connect(natsURL, nats.Name("network-broker-integration"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(natsConnection.Close)
	jetStream, err := jetstream.New(natsConnection)
	if err != nil {
		t.Fatal(err)
	}
	streamName := fmt.Sprintf("BROKER_EVENTS_%d", time.Now().UnixNano())
	subject := fmt.Sprintf("network-broker.events.%d", time.Now().UnixNano())
	stream, err := jetStream.CreateStream(ctx, jetstream.StreamConfig{
		Name: streamName, Subjects: []string{subject},
		Storage: jetstream.MemoryStorage, Duplicates: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := jetStream.DeleteStream(cleanupCtx, streamName); err != nil {
			t.Errorf("delete jetstream test stream: %v", err)
		}
	})
	publisher, err := outbox.NewJetStreamPublisher(jetStream, streamName, subject)
	if err != nil {
		t.Fatal(err)
	}

	repository, err := resolution.NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	var sequence atomic.Int64
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	service := resolution.NewServiceWithRepository(repository, func() time.Time { return now }, func(prefix string) (string, error) {
		return fmt.Sprintf("%s-integration-%d", prefix, sequence.Add(1)), nil
	})
	request := resolution.CreateRequest{
		ActorID: "actor-a", TenantID: "tenant-a", IdempotencyKey: "request-1", RequestDigest: "sha256:request-1",
	}
	created, err := service.Create(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := service.Create(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if !created.Created || replayed.Created || created.Resolution.ID != replayed.Resolution.ID {
		t.Fatalf("unexpected idempotency result: created=%+v replayed=%+v", created, replayed)
	}
	transitioned, err := service.Transition(ctx, resolution.TransitionRequest{
		TenantID: created.Resolution.TenantID, ResolutionID: created.Resolution.ID,
		ExpectedVersion: 1, NextState: resolution.ResolutionResolvingTargets,
	})
	if err != nil {
		t.Fatal(err)
	}
	if transitioned.Version != 2 {
		t.Fatalf("expected version 2, got %d", transitioned.Version)
	}

	store, err := outbox.NewPostgresStore(database)
	if err != nil {
		t.Fatal(err)
	}
	records, err := store.Claim(ctx, "worker-a", 10, now.Add(time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected creation and transition events, got %d", len(records))
	}
	contended, err := store.Claim(ctx, "worker-b", 10, now.Add(time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(contended) != 0 {
		t.Fatalf("expected leased events to be unavailable, got %d", len(contended))
	}
	if err := publisher.Publish(ctx, records[0].Event); err != nil {
		t.Fatal(err)
	}
	if err := publisher.Publish(ctx, records[0].Event); err != nil {
		t.Fatal(err)
	}
	streamInfo, err := stream.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if streamInfo.State.Msgs != 1 {
		t.Fatalf("expected JetStream to deduplicate the event ID, got %d messages", streamInfo.State.Msgs)
	}
	if err := store.MarkPublished(ctx, records[0].Sequence, "worker-a", now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := store.Retry(ctx, records[1].Sequence, "worker-a", now.Add(2*time.Second),
		now.Add(2*time.Minute), "temporary failure"); err != nil {
		t.Fatal(err)
	}
	early, err := store.Claim(ctx, "worker-b", 10, now.Add(time.Minute), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(early) != 0 {
		t.Fatalf("expected retry delay to hold event, got %d", len(early))
	}
	retried, err := store.Claim(ctx, "worker-b", 10, now.Add(3*time.Minute), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(retried) != 1 || retried[0].Attempts != 2 {
		t.Fatalf("expected one second-attempt event, got %+v", retried)
	}
	if err := store.MarkPublished(ctx, retried[0].Sequence, "worker-b", now.Add(3*time.Minute+time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Transition(ctx, resolution.TransitionRequest{
		TenantID: created.Resolution.TenantID, ResolutionID: created.Resolution.ID,
		ExpectedVersion: 2, NextState: resolution.ResolutionPlanning,
	}); err != nil {
		t.Fatal(err)
	}
	metrics := &outbox.Metrics{}
	dispatcher := outbox.Dispatcher{
		Store: store, Publisher: publisher, WorkerID: "worker-c", BatchSize: 10,
		MaxAttempts: 3, Lease: time.Minute, RetryDelay: func(int) time.Duration { return time.Minute },
		Now: func() time.Time { return now.Add(4 * time.Minute) }, Metrics: metrics,
	}
	count, err := dispatcher.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || metrics.Snapshot().Published != 1 {
		t.Fatalf("expected one broker-acknowledged dispatch, got count=%d metrics=%+v", count, metrics.Snapshot())
	}
	streamInfo, err = stream.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if streamInfo.State.Msgs != 2 {
		t.Fatalf("expected two unique broker events, got %d", streamInfo.State.Msgs)
	}
	if _, err := service.Transition(ctx, resolution.TransitionRequest{
		TenantID: created.Resolution.TenantID, ResolutionID: created.Resolution.ID,
		ExpectedVersion: 3, NextState: resolution.ResolutionQueued,
	}); err != nil {
		t.Fatal(err)
	}
	failedRecords, err := store.Claim(ctx, "worker-d", 10, now.Add(5*time.Minute), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(failedRecords) != 1 {
		t.Fatalf("expected one event for dead-letter operations, got %d", len(failedRecords))
	}
	if err := store.DeadLetter(ctx, failedRecords[0].Sequence, "worker-d",
		now.Add(5*time.Minute+time.Second), "sensitive broker failure"); err != nil {
		t.Fatal(err)
	}
	deadLetterRepository, err := deadletter.NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	deadLetterService, err := deadletter.NewService(deadLetterRepository,
		func(string) (string, error) { return "dead-letter-action-integration", nil })
	if err != nil {
		t.Fatal(err)
	}
	operator := authctx.AuthContext{
		SubjectID: "spiffe://broker.example/tenant/tenant-a/role/outbox-operator/workload/operator-a",
		SPIFFEID:  "spiffe://broker.example/tenant/tenant-a/role/outbox-operator/workload/operator-a",
		TenantID:  "tenant-a", Roles: []string{deadletter.OperatorRole},
		AllowedScopes:   []string{deadletter.ReadScope, deadletter.ReplayScope},
		AuthenticatedAt: now, IdentityRevision: "revision-1",
	}
	entries, err := deadLetterService.List(ctx, operator, 0, 10)
	if err != nil || len(entries) != 1 || entries[0].EventID != failedRecords[0].ID {
		t.Fatalf("unexpected dead-letter listing: entries=%+v error=%v", entries, err)
	}
	otherTenant := operator
	otherTenant.TenantID = "tenant-b"
	if _, err := deadLetterService.Get(ctx, otherTenant, failedRecords[0].ID); !errors.Is(err, deadletter.ErrNotFound) {
		t.Fatalf("expected cross-tenant lookup to be indistinguishable from missing, got %v", err)
	}
	type replayOutcome struct {
		result deadletter.ReplayResult
		err    error
	}
	replayStart := make(chan struct{})
	replayOutcomes := make(chan replayOutcome, 2)
	for range 2 {
		go func() {
			<-replayStart
			result, replayErr := deadLetterService.Replay(ctx, operator, failedRecords[0].ID,
				"replay-request-1", "broker configuration repaired")
			replayOutcomes <- replayOutcome{result: result, err: replayErr}
		}()
	}
	close(replayStart)
	firstReplay, secondReplay := <-replayOutcomes, <-replayOutcomes
	if firstReplay.err != nil || secondReplay.err != nil {
		t.Fatalf("concurrent replay failed: first=%v second=%v", firstReplay.err, secondReplay.err)
	}
	replay, idempotentReplay := firstReplay.result, secondReplay.result
	if !replay.Replayed {
		replay, idempotentReplay = idempotentReplay, replay
	}
	if !replay.Replayed || idempotentReplay.Replayed || idempotentReplay.ActionID != replay.ActionID {
		t.Fatalf("unexpected concurrent idempotency: applied=%+v idempotent=%+v", replay, idempotentReplay)
	}
	if _, err := deadLetterService.Replay(ctx, operator, failedRecords[0].ID,
		"replay-request-1", "different operator intent"); !errors.Is(err, deadletter.ErrReplayConflict) {
		t.Fatalf("expected changed replay intent to conflict, got %v", err)
	}
	replayedRecords, err := store.Claim(ctx, "worker-e", 10, replay.AvailableAt.Add(time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(replayedRecords) != 1 || replayedRecords[0].Attempts != 1 {
		t.Fatalf("expected reset replay attempt, got %+v", replayedRecords)
	}
	var auditCount int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM broker_dead_letter_actions`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("expected one immutable replay audit row, got %d", auditCount)
	}
	if _, err := database.ExecContext(ctx,
		`UPDATE broker_dead_letter_actions SET reason = 'tampered' WHERE action_id = $1`, replay.ActionID); err == nil {
		t.Fatal("expected append-only audit trigger to reject mutation")
	}
}
