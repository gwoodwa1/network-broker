package resolution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestServiceCreatesAndReplaysIdempotentResolution(t *testing.T) {
	repository := NewMemoryRepository()
	service := testService(repository)
	request := validCreateRequest()

	first, err := service.Create(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Create(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Created || second.Created {
		t.Fatalf("expected create then replay, got first=%t second=%t", first.Created, second.Created)
	}
	if first.Resolution.ID != second.Resolution.ID || first.Resolution.Version != 1 {
		t.Fatalf("idempotent replay returned different workflow: first=%+v second=%+v", first, second)
	}
	if events := repository.PendingEvents(10); len(events) != 1 || events[0].Type != "resolution.received" {
		t.Fatalf("expected one creation event, got %+v", events)
	} else if !strings.Contains(string(events[0].Payload), `"request_document":{"claims":["interface.state"]}`) {
		t.Fatalf("creation event omitted canonical request provenance: %s", events[0].Payload)
	}
}

func TestServiceRejectsIdempotencyKeyReusedForDifferentRequest(t *testing.T) {
	service := testService(NewMemoryRepository())
	request := validCreateRequest()
	if _, err := service.Create(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	request.RequestDocument = []byte(`{"claims":["interface.counters"]}`)
	request.RequestDigest = requestDocumentDigest(request.RequestDocument)
	if _, err := service.Create(context.Background(), request); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("expected idempotency conflict, got %v", err)
	}
}

func TestServiceTransitionsWithCompareAndSetAndOutbox(t *testing.T) {
	repository := NewMemoryRepository()
	service := testService(repository)
	created, err := service.Create(context.Background(), validCreateRequest())
	if err != nil {
		t.Fatal(err)
	}
	updated, err := service.Transition(context.Background(), TransitionRequest{
		TenantID: created.Resolution.TenantID, ResolutionID: created.Resolution.ID,
		ExpectedVersion: created.Resolution.Version, NextState: ResolutionResolvingTargets,
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.State != ResolutionResolvingTargets || updated.Version != 2 || updated.Completed {
		t.Fatalf("unexpected transition result: %+v", updated)
	}
	if _, err := service.Transition(context.Background(), TransitionRequest{
		TenantID: updated.TenantID, ResolutionID: updated.ID,
		ExpectedVersion: 1, NextState: ResolutionPlanning,
	}); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("expected stale version rejection, got %v", err)
	}
	if events := repository.PendingEvents(10); len(events) != 2 || events[1].Type != "resolution.state_changed" {
		t.Fatalf("expected atomic transition event, got %+v", events)
	}
}

func TestServiceEnforcesTenantScope(t *testing.T) {
	service := testService(NewMemoryRepository())
	created, err := service.Create(context.Background(), validCreateRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Get(context.Background(), "tenant-other", created.Resolution.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected tenant-scoped not found, got %v", err)
	}
}

func TestMemoryRepositoryListsSafeVersionCursorEvents(t *testing.T) {
	repository := NewMemoryRepository()
	service := testService(repository)
	created, err := service.Create(context.Background(), validCreateRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Transition(context.Background(), TransitionRequest{
		TenantID: created.Resolution.TenantID, ResolutionID: created.Resolution.ID,
		ExpectedVersion: 1, NextState: ResolutionResolvingTargets,
	}); err != nil {
		t.Fatal(err)
	}
	events, err := repository.ListEvents(context.Background(), created.Resolution.TenantID,
		created.Resolution.ID, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Cursor != 1 || events[0].State != ResolutionReceived ||
		events[1].Cursor != 2 || events[1].State != ResolutionResolvingTargets {
		t.Fatalf("unexpected safe event history: %+v", events)
	}
	after, err := repository.ListEvents(context.Background(), created.Resolution.TenantID,
		created.Resolution.ID, 1, 10)
	if err != nil || len(after) != 1 || after[0].Cursor != 2 {
		t.Fatalf("unexpected cursor result: events=%+v error=%v", after, err)
	}
	if _, err := repository.ListEvents(context.Background(), "tenant-other",
		created.Resolution.ID, 0, 10); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected tenant-scoped not found, got %v", err)
	}
}

func TestMemoryRepositoryFailsClosedOnMalformedResolutionEvent(t *testing.T) {
	repository := NewMemoryRepository()
	service := testService(repository)
	created, err := service.Create(context.Background(), validCreateRequest())
	if err != nil {
		t.Fatal(err)
	}
	repository.events[0].Payload = []byte(`{"schema_version":"v1","state":"received","version":"bad"}`)
	if _, err := repository.ListEvents(context.Background(), created.Resolution.TenantID,
		created.Resolution.ID, 0, 10); err == nil {
		t.Fatal("expected malformed durable event to fail closed")
	}
}

func TestServiceConcurrentIdempotentCreationProducesOneWorkflow(t *testing.T) {
	repository := NewMemoryRepository()
	service := testService(repository)
	const callers = 32
	results := make(chan CreateResult, callers)
	errorsFound := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := service.Create(context.Background(), validCreateRequest())
			if err != nil {
				errorsFound <- err
				return
			}
			results <- result
		}()
	}
	wait.Wait()
	close(results)
	close(errorsFound)
	for err := range errorsFound {
		t.Fatalf("concurrent create failed: %v", err)
	}

	createdCount := 0
	resolutionID := ""
	for result := range results {
		if result.Created {
			createdCount++
		}
		if resolutionID == "" {
			resolutionID = result.Resolution.ID
		}
		if result.Resolution.ID != resolutionID {
			t.Fatalf("expected one resolution id, got %q and %q", resolutionID, result.Resolution.ID)
		}
	}
	if createdCount != 1 {
		t.Fatalf("expected exactly one creator, got %d", createdCount)
	}
	if events := repository.PendingEvents(100); len(events) != 1 {
		t.Fatalf("expected one committed event, got %d", len(events))
	}
}

func TestMemoryRepositoryReturnsDetachedOutboxPayloads(t *testing.T) {
	repository := NewMemoryRepository()
	service := testService(repository)
	if _, err := service.Create(context.Background(), validCreateRequest()); err != nil {
		t.Fatal(err)
	}
	first := repository.PendingEvents(1)
	first[0].Payload[0] = 'X'
	second := repository.PendingEvents(1)
	if second[0].Payload[0] == 'X' {
		t.Fatal("caller mutated authoritative outbox payload")
	}
}

func TestMemoryRepositoryReturnsDetachedRequestDocuments(t *testing.T) {
	repository := NewMemoryRepository()
	service := testService(repository)
	created, err := service.Create(context.Background(), validCreateRequest())
	if err != nil {
		t.Fatal(err)
	}
	created.Resolution.RequestDocument[0] = 'X'
	stored, err := service.Get(context.Background(), created.Resolution.TenantID, created.Resolution.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.RequestDocument[0] == 'X' {
		t.Fatal("caller mutated authoritative request document")
	}
}

func TestServiceRejectsInvalidOrMismatchedRequestProvenance(t *testing.T) {
	service := testService(NewMemoryRepository())
	invalidJSON := validCreateRequest()
	invalidJSON.RequestDocument = []byte("not-json")
	invalidJSON.RequestDigest = requestDocumentDigest(invalidJSON.RequestDocument)
	if _, err := service.Create(context.Background(), invalidJSON); err == nil {
		t.Fatal("expected invalid request JSON to fail")
	}
	mismatch := validCreateRequest()
	mismatch.RequestDigest = requestDocumentDigest([]byte(`{"different":true}`))
	if _, err := service.Create(context.Background(), mismatch); err == nil {
		t.Fatal("expected request digest mismatch to fail")
	}
}

func TestMemoryRepositoryRejectsInvalidTransitionWithoutStateOrEventChange(t *testing.T) {
	repository := NewMemoryRepository()
	service := testService(repository)
	created, err := service.Create(context.Background(), validCreateRequest())
	if err != nil {
		t.Fatal(err)
	}
	event := repository.PendingEvents(1)[0]
	_, err = repository.Transition(context.Background(), created.Resolution.TenantID, created.Resolution.ID,
		created.Resolution.Version, ResolutionReceived, ResolutionComplete, created.Resolution.UpdatedAt, event)
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected invalid transition rejection, got %v", err)
	}
	stored, err := repository.Get(context.Background(), created.Resolution.TenantID, created.Resolution.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != ResolutionReceived || stored.Version != 1 || len(repository.PendingEvents(10)) != 1 {
		t.Fatalf("invalid transition changed atomic state: %+v", stored)
	}
}

func TestNewPostgresRepositoryRejectsNilDatabase(t *testing.T) {
	if _, err := NewPostgresRepository(nil); err == nil {
		t.Fatal("expected nil database to be rejected")
	}
}

func validCreateRequest() CreateRequest {
	document := []byte(`{"claims":["interface.state"]}`)
	return CreateRequest{
		ActorID: "actor-a", TenantID: "tenant-a", IdempotencyKey: "request-1",
		RequestDigest: requestDocumentDigest(document), RequestDocument: document,
	}
}

func requestDocumentDigest(document []byte) string {
	digest := sha256.Sum256(document)

	return "sha256:" + hex.EncodeToString(digest[:])
}

func testService(repository Repository) *Service {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	var sequence atomic.Int64

	return NewServiceWithRepository(repository, func() time.Time { return now }, func(prefix string) (string, error) {
		return fmt.Sprintf("%s-%d", prefix, sequence.Add(1)), nil
	})
}
