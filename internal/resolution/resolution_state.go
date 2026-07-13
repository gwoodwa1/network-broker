package resolution

import "fmt"

// ResolutionState models the lifecycle of an evidence resolution.
type ResolutionState string

const (
	ResolutionReceived         ResolutionState = "received"
	ResolutionResolvingTargets ResolutionState = "resolving_targets"
	ResolutionPlanning         ResolutionState = "planning"
	ResolutionQueued           ResolutionState = "queued"
	ResolutionComplete         ResolutionState = "complete"
	ResolutionPartial          ResolutionState = "partial"
	ResolutionDenied           ResolutionState = "denied"
	ResolutionFailed           ResolutionState = "failed"
	ResolutionCancelled        ResolutionState = "cancelled"
	ResolutionExpired          ResolutionState = "expired"
)

// Resolution captures the durable state for an evidence resolution workflow.
type Resolution struct {
	ID          string
	ActorID     string
	TenantID    string
	State       ResolutionState
	TargetCount int
	Completed   bool
}

// Transition validates and applies a state change.
func (r *Resolution) Transition(next ResolutionState) error {
	if r == nil {
		return fmt.Errorf("resolution is nil")
	}
	if r.State == "" {
		r.State = ResolutionReceived
	}
	if next == "" {
		return fmt.Errorf("next state is required")
	}
	r.State = next
	if next == ResolutionComplete || next == ResolutionPartial || next == ResolutionDenied || next == ResolutionFailed || next == ResolutionCancelled || next == ResolutionExpired {
		r.Completed = true
	}
	return nil
}
