package outbox

import (
	"testing"
	"time"
)

func TestEventValidateAndClone(t *testing.T) {
	event := Event{
		ID: "event-1", TenantID: "tenant-a", AggregateType: "resolution", AggregateID: "resolution-1",
		Type: "resolution.received", Payload: []byte(`{"schema_version":"v1"}`), OccurredAt: time.Now(),
	}
	if err := event.Validate(); err != nil {
		t.Fatal(err)
	}
	clone := event.Clone()
	clone.Payload[0] = 'X'
	if event.Payload[0] == 'X' {
		t.Fatal("clone shared the authoritative payload")
	}
}

func TestEventValidateRejectsIncompleteEvent(t *testing.T) {
	if err := (Event{}).Validate(); err == nil {
		t.Fatal("expected incomplete event to be rejected")
	}
}
