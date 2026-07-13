// Package outbox defines durable events written in the same transaction as
// authoritative workflow state.
package outbox

import (
	"fmt"
	"time"
)

// Event is an immutable workflow event awaiting delivery to downstream
// consumers. Payload contains a versioned JSON document.
type Event struct {
	ID            string
	TenantID      string
	AggregateType string
	AggregateID   string
	Type          string
	Payload       []byte
	OccurredAt    time.Time
}

// Clone returns a detached copy safe for delivery outside the repository.
func (e Event) Clone() Event {
	e.Payload = append([]byte(nil), e.Payload...)

	return e
}

// Validate ensures a repository cannot commit state without a deliverable,
// attributable event.
func (e Event) Validate() error {
	if e.ID == "" || e.TenantID == "" || e.AggregateType == "" || e.AggregateID == "" || e.Type == "" {
		return fmt.Errorf("outbox identity, tenant, aggregate and event type are required")
	}
	if len(e.Payload) == 0 || e.OccurredAt.IsZero() {
		return fmt.Errorf("outbox payload and occurrence time are required")
	}

	return nil
}
