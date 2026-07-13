package resolution

import (
	"errors"
	"fmt"
	"time"
)

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

var (
	ErrNotFound            = errors.New("resolution not found")
	ErrVersionConflict     = errors.New("resolution version conflict")
	ErrIdempotencyConflict = errors.New("idempotency key was reused for a different request")
	ErrInvalidTransition   = errors.New("resolution state transition is invalid")
)

var allowedTransitions = map[ResolutionState]map[ResolutionState]struct{}{
	ResolutionReceived: {
		ResolutionResolvingTargets: {}, ResolutionDenied: {}, ResolutionFailed: {}, ResolutionCancelled: {}, ResolutionExpired: {},
	},
	ResolutionResolvingTargets: {
		ResolutionPlanning: {}, ResolutionDenied: {}, ResolutionFailed: {}, ResolutionCancelled: {}, ResolutionExpired: {},
	},
	ResolutionPlanning: {
		ResolutionQueued: {}, ResolutionDenied: {}, ResolutionFailed: {}, ResolutionCancelled: {}, ResolutionExpired: {},
	},
	ResolutionQueued: {
		ResolutionComplete: {}, ResolutionPartial: {}, ResolutionFailed: {}, ResolutionCancelled: {}, ResolutionExpired: {},
	},
}

// Resolution captures durable state for an evidence-resolution workflow.
type Resolution struct {
	ID             string
	ActorID        string
	TenantID       string
	IdempotencyKey string
	RequestDigest  string
	State          ResolutionState
	TargetCount    int
	Completed      bool
	Version        int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// Terminal reports whether no further workflow transition is permitted.
func (s ResolutionState) Terminal() bool {
	switch s {
	case ResolutionComplete, ResolutionPartial, ResolutionDenied, ResolutionFailed,
		ResolutionCancelled, ResolutionExpired:
		return true
	default:
		return false
	}
}

// ValidateTransition enforces the workflow graph before a repository performs
// its compare-and-set update.
func ValidateTransition(current, next ResolutionState) error {
	if next == "" {
		return fmt.Errorf("%w: next state is required", ErrInvalidTransition)
	}
	if current.Terminal() {
		return fmt.Errorf("%w: terminal state %q cannot transition", ErrInvalidTransition, current)
	}

	nextStates, known := allowedTransitions[current]
	if !known {
		return fmt.Errorf("%w: unknown current state %q", ErrInvalidTransition, current)
	}
	if _, allowed := nextStates[next]; !allowed {
		return fmt.Errorf("%w: %q to %q", ErrInvalidTransition, current, next)
	}

	return nil
}
