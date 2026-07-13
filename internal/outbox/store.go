package outbox

import (
	"context"
	"errors"
	"time"
)

var ErrLeaseLost = errors.New("outbox delivery lease was lost")

// Record is a claimed outbox event and its durable delivery metadata.
type Record struct {
	Event
	Sequence int64
	Attempts int
}

// Store owns durable claim, acknowledgement, retry, and dead-letter state.
type Store interface {
	Claim(context.Context, string, int, time.Time, time.Duration) ([]Record, error)
	MarkPublished(context.Context, int64, string, time.Time) error
	Retry(context.Context, int64, string, time.Time, time.Time, string) error
	DeadLetter(context.Context, int64, string, time.Time, string) error
}

// Publisher delivers an event to an external broker or consumer boundary. It
// must tolerate duplicate event IDs because publication is at least once.
type Publisher interface {
	Publish(context.Context, Event) error
}
