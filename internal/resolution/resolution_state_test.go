package resolution

import (
	"errors"
	"testing"
)

func TestValidateTransitionAcceptsWorkflowPath(t *testing.T) {
	path := []ResolutionState{
		ResolutionReceived,
		ResolutionResolvingTargets,
		ResolutionPlanning,
		ResolutionQueued,
		ResolutionComplete,
	}
	for index := range len(path) - 1 {
		if err := ValidateTransition(path[index], path[index+1]); err != nil {
			t.Fatalf("expected %q to %q to be allowed: %v", path[index], path[index+1], err)
		}
	}
}

func TestValidateTransitionRejectsSkippedAndTerminalTransitions(t *testing.T) {
	for _, test := range []struct {
		name    string
		current ResolutionState
		next    ResolutionState
	}{
		{name: "skipped stages", current: ResolutionReceived, next: ResolutionComplete},
		{name: "terminal state", current: ResolutionDenied, next: ResolutionPlanning},
		{name: "unknown state", current: "unknown", next: ResolutionPlanning},
		{name: "empty next", current: ResolutionReceived, next: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateTransition(test.current, test.next); !errors.Is(err, ErrInvalidTransition) {
				t.Fatalf("expected invalid transition, got %v", err)
			}
		})
	}
}

func TestResolutionStateTerminal(t *testing.T) {
	if !ResolutionPartial.Terminal() {
		t.Fatal("expected partial to be terminal")
	}
	if ResolutionQueued.Terminal() {
		t.Fatal("expected queued to remain active")
	}
}
