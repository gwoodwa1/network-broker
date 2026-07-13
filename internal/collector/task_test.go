package collector

import (
	"errors"
	"testing"
	"time"
)

func TestStoreAcquireRenewAndCommit(t *testing.T) {
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	store := NewStore()
	if err := store.Add(Task{ID: "task-1", TargetID: "target-1", RecipeID: "gnmi_interface_get"}); err != nil {
		t.Fatal(err)
	}
	lease, err := store.Acquire("task-1", "collector-a", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if lease.FencingToken != 1 {
		t.Fatalf("expected fencing token 1, got %d", lease.FencingToken)
	}
	if _, err := store.Renew("task-1", "collector-a", lease.FencingToken, now.Add(30*time.Second), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := store.StartExecution("task-1", "collector-a", lease.FencingToken, now.Add(31*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginCommit("task-1", "collector-a", lease.FencingToken, now.Add(32*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit("task-1", "collector-a", lease.FencingToken, "attempt-1", "evidence-1", now.Add(33*time.Second)); err != nil {
		t.Fatal(err)
	}
	task, err := store.Get("task-1")
	if err != nil {
		t.Fatal(err)
	}
	if task.State != TaskSucceeded || task.AcceptedAttemptID != "attempt-1" || task.AcceptedEvidenceID != "evidence-1" {
		t.Fatalf("unexpected committed task: %+v", task)
	}
}

func TestStoreRejectsStaleAttemptAfterExpiredLeaseIsReacquired(t *testing.T) {
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	store := NewStore()
	if err := store.Add(Task{ID: "task-1", TargetID: "target-1", RecipeID: "gnmi_interface_get"}); err != nil {
		t.Fatal(err)
	}
	stale, err := store.Acquire("task-1", "collector-a", now, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	current, err := store.Acquire("task-1", "collector-b", now.Add(time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if current.FencingToken != stale.FencingToken+1 {
		t.Fatalf("expected incremented fencing token, got %d", current.FencingToken)
	}
	if err := store.StartExecution("task-1", "collector-a", stale.FencingToken, now.Add(time.Second)); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("expected stale fence rejection, got %v", err)
	}
}

func TestStoreRejectsDuplicateAcceptedCommit(t *testing.T) {
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	store := NewStore()
	if err := store.Add(Task{ID: "task-1", TargetID: "target-1", RecipeID: "gnmi_interface_get"}); err != nil {
		t.Fatal(err)
	}
	lease, _ := store.Acquire("task-1", "collector-a", now, time.Minute)
	_ = store.StartExecution("task-1", "collector-a", lease.FencingToken, now)
	_ = store.BeginCommit("task-1", "collector-a", lease.FencingToken, now)
	if err := store.Commit("task-1", "collector-a", lease.FencingToken, "attempt-1", "evidence-1", now); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit("task-1", "collector-a", lease.FencingToken, "attempt-2", "evidence-2", now); !errors.Is(err, ErrDuplicateCommit) {
		t.Fatalf("expected duplicate commit rejection, got %v", err)
	}
}

func TestStoreReportsCurrentFenceForGrantVerification(t *testing.T) {
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	store := NewStore()
	if err := store.Add(Task{ID: "task-1", TargetID: "target-1", RecipeID: "gnmi_interface_get"}); err != nil {
		t.Fatal(err)
	}
	lease, err := store.Acquire("task-1", "collector-a", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	token, err := store.CurrentFence("task-1")
	if err != nil {
		t.Fatal(err)
	}
	if token != lease.FencingToken {
		t.Fatalf("expected current fence %d, got %d", lease.FencingToken, token)
	}
}

func TestStoreVerifiesOnlyCurrentExecutingAttemptForAssembly(t *testing.T) {
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	store := NewStore()
	if err := store.Add(Task{ID: "task-1", TargetID: "target-1", RecipeID: "gnmi_interface_get"}); err != nil {
		t.Fatal(err)
	}
	lease, err := store.Acquire("task-1", "collector-a", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyCurrentAttempt("task-1", "collector-a", lease.FencingToken, now); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("expected leased-only attempt rejection, got %v", err)
	}
	if err := store.StartExecution("task-1", "collector-a", lease.FencingToken, now); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyCurrentAttempt("task-1", "collector-a", lease.FencingToken, now); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyCurrentAttempt("task-1", "collector-b", lease.FencingToken, now); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("expected collector binding rejection, got %v", err)
	}
}
