//go:build integration

package integration_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"network_broker/internal/outbox"
	"network_broker/internal/resolution"
	"network_broker/migrations"
)

func TestPostgresResolutionAndOutboxLifecycle(t *testing.T) {
	databaseURL := os.Getenv("POSTGRES_TEST_DSN")
	if databaseURL == "" {
		t.Skip("POSTGRES_TEST_DSN is not configured")
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
		`TRUNCATE broker_outbox, broker_resolution_idempotency, broker_resolutions RESTART IDENTITY CASCADE`); err != nil {
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
}
