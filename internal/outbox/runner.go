package outbox

import (
	"context"
	"fmt"
	"time"
)

// Runner continuously drains the transactional outbox. Transient dispatch
// failures are reported and retried; cancellation returns the context error.
type Runner struct {
	Dispatcher   Dispatcher
	PollInterval time.Duration
	FailureDelay time.Duration
	OnError      func(error)
}

// Run processes ready batches until the context is cancelled.
func (r Runner) Run(ctx context.Context) error {
	if err := r.Dispatcher.validate(); err != nil {
		return err
	}
	if r.PollInterval <= 0 || r.FailureDelay <= 0 {
		return fmt.Errorf("outbox poll interval and failure delay must be positive")
	}

	for ctx.Err() == nil {
		count, err := r.Dispatcher.RunOnce(ctx)
		if err != nil && ctx.Err() == nil && r.OnError != nil {
			r.OnError(err)
		}
		if ctx.Err() != nil {
			break
		}
		if err == nil && count == r.Dispatcher.BatchSize {
			continue
		}
		delay := r.PollInterval
		if err != nil {
			delay = r.FailureDelay
		}
		if waitForCancellation(ctx, delay) {
			break
		}
	}

	return ctx.Err()
}

func waitForCancellation(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return true
	case <-timer.C:
		return false
	}
}
