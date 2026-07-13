package resolution

import "testing"

func TestResolutionTransitionMarksCompletion(t *testing.T) {
	r := &Resolution{ID: "res-1", ActorID: "actor-a", TenantID: "tenant-a"}

	if err := r.Transition(ResolutionComplete); err != nil {
		t.Fatalf("expected transition to succeed, got %v", err)
	}

	if r.State != ResolutionComplete {
		t.Fatalf("expected state %q, got %q", ResolutionComplete, r.State)
	}

	if !r.Completed {
		t.Fatal("expected resolution to be marked completed")
	}
}

func TestResolutionTransitionRejectsEmptyState(t *testing.T) {
	r := &Resolution{ID: "res-2", ActorID: "actor-a", TenantID: "tenant-a"}

	if err := r.Transition(""); err == nil {
		t.Fatal("expected empty next state to be rejected")
	}
}
