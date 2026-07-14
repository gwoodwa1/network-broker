package collector

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

// EvidenceReconciliationRepository is the narrow authority used by the
// runtime scheduler. Implementations must recheck bindings during acceptance.
type EvidenceReconciliationRepository interface {
	ListExpiredEvidenceCandidatesContext(context.Context, time.Time, int) ([]string, error)
	ReconcileExpiredEvidenceContext(context.Context, string, time.Time) (Task, error)
}

type ReconciliationMetrics struct {
	candidates atomic.Uint64
	reconciled atomic.Uint64
	skipped    atomic.Uint64
	failures   atomic.Uint64
}

type ReconciliationMetricsSnapshot struct {
	Candidates uint64
	Reconciled uint64
	Skipped    uint64
	Failures   uint64
}

func (m *ReconciliationMetrics) Snapshot() ReconciliationMetricsSnapshot {
	if m == nil {
		return ReconciliationMetricsSnapshot{}
	}

	return ReconciliationMetricsSnapshot{
		Candidates: m.candidates.Load(), Reconciled: m.reconciled.Load(),
		Skipped: m.skipped.Load(), Failures: m.failures.Load(),
	}
}

// ReconciliationRunner continuously closes expired evidence/task crash
// windows. Multiple runners may safely inspect the same candidate because the
// repository performs one guarded acceptance update.
type ReconciliationRunner struct {
	Repository   EvidenceReconciliationRepository
	BatchSize    int
	PollInterval time.Duration
	FailureDelay time.Duration
	Now          func() time.Time
	Metrics      *ReconciliationMetrics
	OnError      func(error)
}

func (r ReconciliationRunner) Run(ctx context.Context) error {
	if err := r.validate(); err != nil {
		return err
	}
	for ctx.Err() == nil {
		count, err := r.RunOnce(ctx)
		if err != nil && ctx.Err() == nil && r.OnError != nil {
			r.OnError(err)
		}
		if ctx.Err() != nil {
			break
		}
		if err == nil && count == r.BatchSize {
			continue
		}
		delay := r.PollInterval
		if err != nil {
			delay = r.FailureDelay
		}
		if waitForReconciliationCancellation(ctx, delay) {
			break
		}
	}

	return ctx.Err()
}

func (r ReconciliationRunner) RunOnce(ctx context.Context) (int, error) {
	if err := r.validate(); err != nil {
		return 0, err
	}
	reconciledAt := r.Now().UTC()
	candidates, err := r.Repository.ListExpiredEvidenceCandidatesContext(ctx, reconciledAt, r.BatchSize)
	if err != nil {
		r.recordFailure()
		return 0, err
	}
	if r.Metrics != nil && len(candidates) > 0 {
		r.Metrics.candidates.Add(uint64(len(candidates)))
	}
	var reconciliationErr error
	for _, evidenceID := range candidates {
		if _, err := r.Repository.ReconcileExpiredEvidenceContext(ctx, evidenceID, reconciledAt); err != nil {
			if errors.Is(err, ErrStaleFence) || errors.Is(err, ErrLeaseHeld) ||
				errors.Is(err, ErrDuplicateCommit) || errors.Is(err, ErrInvalidState) {
				if r.Metrics != nil {
					r.Metrics.skipped.Add(1)
				}
				continue
			}
			r.recordFailure()
			reconciliationErr = errors.Join(reconciliationErr,
				fmt.Errorf("reconcile evidence %q: %w", evidenceID, err))
			continue
		}
		if r.Metrics != nil {
			r.Metrics.reconciled.Add(1)
		}
	}

	return len(candidates), reconciliationErr
}

func (r ReconciliationRunner) validate() error {
	if r.Repository == nil || r.BatchSize <= 0 || r.BatchSize > 10_000 ||
		r.PollInterval <= 0 || r.FailureDelay <= 0 || r.Now == nil {
		return fmt.Errorf("reconciliation repository, bounds, intervals and clock are required")
	}

	return nil
}

func (r ReconciliationRunner) recordFailure() {
	if r.Metrics != nil {
		r.Metrics.failures.Add(1)
	}
}

func waitForReconciliationCancellation(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return true
	case <-timer.C:
		return false
	}
}
