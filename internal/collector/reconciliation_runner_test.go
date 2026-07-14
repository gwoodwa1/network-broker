package collector

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type reconciliationRepositoryStub struct {
	mu         sync.Mutex
	candidates []string
	errors     map[string]error
	lists      int
}

func (s *reconciliationRepositoryStub) ListExpiredEvidenceCandidatesContext(_ context.Context,
	_ time.Time, limit int,
) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lists++
	if len(s.candidates) > limit {
		return append([]string(nil), s.candidates[:limit]...), nil
	}

	return append([]string(nil), s.candidates...), nil
}

func (s *reconciliationRepositoryStub) ReconcileExpiredEvidenceContext(_ context.Context,
	evidenceID string, _ time.Time,
) (Task, error) {
	if err := s.errors[evidenceID]; err != nil {
		return Task{}, err
	}

	return Task{AcceptedEvidenceID: evidenceID, State: TaskSucceeded}, nil
}

func TestReconciliationRunnerRecordsAcceptedSkippedAndFailedCandidates(t *testing.T) {
	repository := &reconciliationRepositoryStub{
		candidates: []string{"accepted", "stale", "failed"},
		errors: map[string]error{
			"stale":  ErrStaleFence,
			"failed": errors.New("database unavailable"),
		},
	}
	metrics := &ReconciliationMetrics{}
	runner := ReconciliationRunner{
		Repository: repository, BatchSize: 10, PollInterval: time.Second,
		FailureDelay: time.Second, Now: time.Now, Metrics: metrics,
	}
	count, err := runner.RunOnce(context.Background())
	if count != 3 || err == nil {
		t.Fatalf("expected three candidates and one reported failure, count=%d error=%v", count, err)
	}
	snapshot := metrics.Snapshot()
	if snapshot.Candidates != 3 || snapshot.Reconciled != 1 ||
		snapshot.Skipped != 1 || snapshot.Failures != 1 {
		t.Fatalf("unexpected reconciliation metrics: %+v", snapshot)
	}
}

func TestReconciliationRunnerPollsUntilCancellation(t *testing.T) {
	repository := &reconciliationRepositoryStub{}
	ctx, cancel := context.WithCancel(context.Background())
	runner := ReconciliationRunner{
		Repository: repository, BatchSize: 10, PollInterval: time.Millisecond,
		FailureDelay: time.Millisecond, Now: time.Now,
	}
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	deadline := time.After(time.Second)
	for {
		repository.mu.Lock()
		lists := repository.lists
		repository.mu.Unlock()
		if lists >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("reconciliation runner did not poll again")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestReconciliationRunnerRejectsInvalidConfiguration(t *testing.T) {
	if _, err := (ReconciliationRunner{}).RunOnce(context.Background()); err == nil {
		t.Fatal("expected invalid reconciliation runner configuration")
	}
}
