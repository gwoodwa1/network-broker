package outbox

import (
	"context"
	"errors"
	"testing"
	"time"
)

type dispatcherStore struct {
	records      []Record
	published    []int64
	retried      []int64
	deadLettered []int64
}

func (s *dispatcherStore) Claim(context.Context, string, int, time.Time, time.Duration) ([]Record, error) {
	return append([]Record(nil), s.records...), nil
}

func (s *dispatcherStore) MarkPublished(_ context.Context, sequence int64, _ string, _ time.Time) error {
	s.published = append(s.published, sequence)

	return nil
}

func (s *dispatcherStore) Retry(_ context.Context, sequence int64, _ string, _, _ time.Time, _ string) error {
	s.retried = append(s.retried, sequence)

	return nil
}

func (s *dispatcherStore) DeadLetter(_ context.Context, sequence int64, _ string, _ time.Time, _ string) error {
	s.deadLettered = append(s.deadLettered, sequence)

	return nil
}

type dispatcherPublisher struct {
	fail map[string]error
	seen []string
}

func (p *dispatcherPublisher) Publish(_ context.Context, event Event) error {
	p.seen = append(p.seen, event.ID)

	return p.fail[event.ID]
}

func TestDispatcherPublishesAndAcknowledgesBatch(t *testing.T) {
	store := &dispatcherStore{records: []Record{
		{Event: validEvent("event-1"), Sequence: 1, Attempts: 1},
		{Event: validEvent("event-2"), Sequence: 2, Attempts: 1},
	}}
	publisher := &dispatcherPublisher{}
	count, err := testDispatcher(store, publisher).RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 || len(store.published) != 2 || len(publisher.seen) != 2 {
		t.Fatalf("unexpected dispatch result: count=%d published=%v seen=%v", count, store.published, publisher.seen)
	}
}

func TestDispatcherRetriesThenDeadLettersFailures(t *testing.T) {
	failure := errors.New("broker unavailable")
	store := &dispatcherStore{records: []Record{
		{Event: validEvent("retry"), Sequence: 1, Attempts: 1},
		{Event: validEvent("dead"), Sequence: 2, Attempts: 3},
	}}
	publisher := &dispatcherPublisher{fail: map[string]error{"retry": failure, "dead": failure}}
	count, err := testDispatcher(store, publisher).RunOnce(context.Background())
	if count != 2 || err == nil {
		t.Fatalf("expected two attempted events and an error, got count=%d error=%v", count, err)
	}
	if len(store.retried) != 1 || store.retried[0] != 1 {
		t.Fatalf("expected first event to retry, got %v", store.retried)
	}
	if len(store.deadLettered) != 1 || store.deadLettered[0] != 2 {
		t.Fatalf("expected second event to dead-letter, got %v", store.deadLettered)
	}
}

func TestDispatcherRejectsIncompleteConfiguration(t *testing.T) {
	if _, err := (Dispatcher{}).RunOnce(context.Background()); err == nil {
		t.Fatal("expected invalid dispatcher configuration to fail")
	}
}

func testDispatcher(store Store, publisher Publisher) Dispatcher {
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)

	return Dispatcher{
		Store: store, Publisher: publisher, WorkerID: "dispatcher-1", BatchSize: 10,
		MaxAttempts: 3, Lease: time.Minute, RetryDelay: func(int) time.Duration { return time.Minute },
		Now: func() time.Time { return now },
	}
}

func validEvent(id string) Event {
	return Event{
		ID: id, TenantID: "tenant-a", AggregateType: "resolution", AggregateID: "resolution-1",
		Type: "resolution.received", Payload: []byte(`{"schema_version":"v1"}`),
		OccurredAt: time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC),
	}
}
