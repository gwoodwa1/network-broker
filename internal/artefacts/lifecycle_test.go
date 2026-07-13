package artefacts

import (
	"errors"
	"testing"
	"time"
)

func TestLifecycleRulesEnforceRetentionHoldAndDeletionOrder(t *testing.T) {
	now := time.Date(2026, 7, 13, 16, 0, 0, 0, time.UTC)
	current := Lifecycle{
		TenantID: "tenant-a", ArtefactID: "artefact-a", State: LifecycleActive,
		Version: 1, UpdatedAt: now,
	}
	retainedUntil := now.Add(time.Hour)
	retained, err := applyLifecycleAction(current, LifecycleCommand{
		Action: LifecycleRetain, RetainUntil: &retainedUntil,
	}, now)
	if err != nil || retained.RetainUntil == nil {
		t.Fatalf("unexpected retention result: %+v error=%v", retained, err)
	}
	if _, err := applyLifecycleAction(retained, LifecycleCommand{Action: LifecycleRequestDeletion}, now); !errors.Is(err, ErrLifecycleBlocked) {
		t.Fatalf("expected retention to block deletion, got %v", err)
	}
	held, err := applyLifecycleAction(current, LifecycleCommand{Action: LifecyclePlaceHold}, now)
	if err != nil || !held.LegalHold {
		t.Fatalf("unexpected legal hold result: %+v error=%v", held, err)
	}
	if _, err := applyLifecycleAction(held, LifecycleCommand{Action: LifecycleRequestDeletion}, now); !errors.Is(err, ErrLifecycleBlocked) {
		t.Fatalf("expected legal hold to block deletion, got %v", err)
	}
	released, err := applyLifecycleAction(held, LifecycleCommand{Action: LifecycleReleaseHold}, now)
	if err != nil || released.LegalHold {
		t.Fatalf("unexpected legal hold release: %+v error=%v", released, err)
	}
	pending, err := applyLifecycleAction(released, LifecycleCommand{Action: LifecycleRequestDeletion}, now)
	if err != nil || pending.State != LifecyclePendingDeletion {
		t.Fatalf("unexpected deletion request: %+v error=%v", pending, err)
	}
	deleted, err := applyLifecycleAction(pending, LifecycleCommand{Action: LifecycleConfirmDeletion}, now)
	if err != nil || deleted.State != LifecycleDeleted {
		t.Fatalf("unexpected deletion confirmation: %+v error=%v", deleted, err)
	}
}
