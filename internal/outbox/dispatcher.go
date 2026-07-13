package outbox

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Dispatcher publishes leased outbox events and durably records each result.
type Dispatcher struct {
	Store       Store
	Publisher   Publisher
	WorkerID    string
	BatchSize   int
	MaxAttempts int
	Lease       time.Duration
	RetryDelay  func(int) time.Duration
	Now         func() time.Time
}

// RunOnce processes at most one claimed batch. A publication failure is
// recorded durably and returned after the rest of the batch has been handled.
func (d Dispatcher) RunOnce(ctx context.Context) (int, error) {
	if err := d.validate(); err != nil {
		return 0, err
	}
	now := d.Now().UTC()
	records, err := d.Store.Claim(ctx, d.WorkerID, d.BatchSize, now, d.Lease)
	if err != nil {
		return 0, err
	}

	var failures error
	for _, record := range records {
		if err := d.Publisher.Publish(ctx, record.Clone()); err != nil {
			failures = errors.Join(failures, fmt.Errorf("publish outbox event %q: %w", record.ID, err))
			if record.Attempts >= d.MaxAttempts {
				if markErr := d.Store.DeadLetter(ctx, record.Sequence, d.WorkerID, d.Now().UTC(), err.Error()); markErr != nil {
					failures = errors.Join(failures, markErr)
				}
				continue
			}
			failedAt := d.Now().UTC()
			retryAt := failedAt.Add(d.RetryDelay(record.Attempts))
			if retryErr := d.Store.Retry(ctx, record.Sequence, d.WorkerID, failedAt, retryAt, err.Error()); retryErr != nil {
				failures = errors.Join(failures, retryErr)
			}
			continue
		}
		if err := d.Store.MarkPublished(ctx, record.Sequence, d.WorkerID, d.Now().UTC()); err != nil {
			failures = errors.Join(failures, err)
		}
	}

	return len(records), failures
}

func (d Dispatcher) validate() error {
	if d.Store == nil || d.Publisher == nil || d.WorkerID == "" || d.Now == nil || d.RetryDelay == nil {
		return fmt.Errorf("outbox store, publisher, worker id, clock and retry policy are required")
	}
	if d.BatchSize <= 0 || d.MaxAttempts <= 0 || d.Lease <= 0 {
		return fmt.Errorf("outbox batch size, maximum attempts and lease must be positive")
	}

	return nil
}
