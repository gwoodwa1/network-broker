package outbox

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type runnerStore struct {
	dispatcherStore
	mu     sync.Mutex
	claims int
}

func (s *runnerStore) Claim(ctx context.Context, owner string, limit int, now time.Time, lease time.Duration) ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.claims++
	if s.claims == 1 {
		return s.dispatcherStore.Claim(ctx, owner, limit, now, lease)
	}

	return nil, nil
}

func TestRunnerContinuouslyDispatchesUntilCancelled(t *testing.T) {
	store := &runnerStore{dispatcherStore: dispatcherStore{records: []Record{
		{Event: validEvent("event-1"), Sequence: 1, Attempts: 1},
	}}}
	dispatcher := testDispatcher(store, &dispatcherPublisher{})
	dispatcher.BatchSize = 10
	ctx, cancel := context.WithCancel(context.Background())
	runner := Runner{Dispatcher: dispatcher, PollInterval: time.Millisecond, FailureDelay: time.Millisecond}
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()

	deadline := time.After(time.Second)
	for {
		store.mu.Lock()
		claims := store.claims
		store.mu.Unlock()
		if claims >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("runner did not poll again")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestRunnerRejectsInvalidConfiguration(t *testing.T) {
	if err := (Runner{}).Run(context.Background()); err == nil {
		t.Fatal("expected invalid runner configuration to fail")
	}
}
