package resolution

import (
	"encoding/json"
	"fmt"
	"time"

	"network_broker/internal/outbox"
)

const maximumWatchEvents = 100

// WatchEvent is the safe external projection of a durable resolution event.
// Cursor is the resolution version, not the global outbox sequence, so it does
// not reveal activity in other tenants or resolutions.
type WatchEvent struct {
	Cursor     int64           `json:"cursor"`
	Type       string          `json:"type"`
	State      ResolutionState `json:"state"`
	OccurredAt time.Time       `json:"occurred_at"`
}

type resolutionEventPayload struct {
	SchemaVersion string          `json:"schema_version"`
	State         ResolutionState `json:"state"`
	Version       int64           `json:"version"`
}

func safeWatchEvent(event outbox.Event) (WatchEvent, error) {
	if event.Type != "resolution.received" && event.Type != "resolution.state_changed" &&
		event.Type != "resolution.tasks_queued" {
		return WatchEvent{}, fmt.Errorf("unsupported resolution event type %q", event.Type)
	}
	var payload resolutionEventPayload
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		return WatchEvent{}, fmt.Errorf("decode resolution event payload: %w", err)
	}
	if payload.SchemaVersion != resolutionEventSchemaVersion || payload.Version <= 0 || event.OccurredAt.IsZero() {
		return WatchEvent{}, fmt.Errorf("resolution event schema, version and occurrence time are required")
	}
	if payload.State == "" && event.Type == "resolution.tasks_queued" {
		payload.State = ResolutionQueued
	}
	if !knownResolutionState(payload.State) {
		return WatchEvent{}, fmt.Errorf("resolution event state %q is invalid", payload.State)
	}

	return WatchEvent{
		Cursor: payload.Version, Type: event.Type, State: payload.State,
		OccurredAt: event.OccurredAt.UTC(),
	}, nil
}

func knownResolutionState(state ResolutionState) bool {
	switch state {
	case ResolutionReceived, ResolutionResolvingTargets, ResolutionPlanning, ResolutionQueued,
		ResolutionComplete, ResolutionPartial, ResolutionDenied, ResolutionFailed,
		ResolutionCancelled, ResolutionExpired:
		return true
	default:
		return false
	}
}

func validateWatchRequest(tenantID, resolutionID string, after int64, limit int) error {
	if tenantID == "" || resolutionID == "" || after < 0 || limit <= 0 || limit > maximumWatchEvents {
		return fmt.Errorf("tenant, resolution, non-negative cursor and limit from 1 to %d are required",
			maximumWatchEvents)
	}

	return nil
}
