package collector

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"network_broker/internal/grants"
	"network_broker/internal/transport"
)

func TestWorkerRunsBoundedAttemptAndCommits(t *testing.T) {
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	store := NewStore()
	if err := store.Add(testTask()); err != nil {
		t.Fatal(err)
	}
	authority := testAuthority(t, store)
	worker := Worker{
		ID: "collector-a", Tasks: store, Transport: transport.StubAdapter{Now: func() time.Time { return now }}, Sink: MemorySink{},
		Authorizer: allowAuthorizer{}, GrantIssuer: authority, Credentials: authority,
		LeaseDuration: time.Minute, GrantTTL: time.Minute, MaximumDuration: time.Second, MaximumBytes: 1024,
		Now: func() time.Time { return now },
	}
	if err := worker.Run(context.Background(), "task-1"); err != nil {
		t.Fatal(err)
	}
	task, err := store.Get("task-1")
	if err != nil {
		t.Fatal(err)
	}
	if task.State != TaskSucceeded || task.AcceptedAttemptID == "" || task.AcceptedEvidenceID == "" {
		t.Fatalf("expected an accepted result, got %+v", task)
	}
	if task.ExecutionDecisionID == "" || task.ExecutionGrantID == "" {
		t.Fatalf("expected execution authority lineage, got %+v", task)
	}
}

func TestWorkerReturnsFailedTransportTaskToRetryWait(t *testing.T) {
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	store := NewStore()
	task := testTask()
	if err := store.Add(task); err != nil {
		t.Fatal(err)
	}
	authority := testAuthority(t, store)
	worker := Worker{
		ID: "collector-a", Tasks: store, Transport: failingAdapter{}, Sink: MemorySink{},
		Authorizer: allowAuthorizer{}, GrantIssuer: authority, Credentials: authority,
		LeaseDuration: time.Minute, GrantTTL: time.Minute, MaximumDuration: time.Second, MaximumBytes: 1024,
		Now: func() time.Time { return now },
	}
	if err := worker.Run(context.Background(), "task-1"); err == nil {
		t.Fatal("expected transport failure")
	}
	task, _ = store.Get("task-1")
	if task.State != TaskRetryWait || task.LastError == "" {
		t.Fatalf("expected retry_wait with failure detail, got %+v", task)
	}
}

func TestWorkerDoesNotContactTargetWhenExecutionIsDenied(t *testing.T) {
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	store := NewStore()
	if err := store.Add(testTask()); err != nil {
		t.Fatal(err)
	}
	authority := testAuthority(t, store)
	adapter := &countingAdapter{}
	worker := Worker{
		ID: "collector-a", Tasks: store, Transport: adapter, Sink: MemorySink{},
		Authorizer: denyAuthorizer{}, GrantIssuer: authority, Credentials: authority,
		LeaseDuration: time.Minute, GrantTTL: time.Minute, MaximumDuration: time.Second, MaximumBytes: 1024,
		Now: func() time.Time { return now },
	}
	if err := worker.Run(context.Background(), "task-1"); err == nil {
		t.Fatal("expected execution authorization denial")
	}
	if adapter.calls != 0 {
		t.Fatalf("expected no target contact, got %d calls", adapter.calls)
	}
	task, _ := store.Get("task-1")
	if task.State != TaskRetryWait {
		t.Fatalf("expected denied attempt to return to retry wait, got %s", task.State)
	}
}

type allowAuthorizer struct{}

func (allowAuthorizer) AuthorizeExecution(context.Context, ExecutionRequest) (ExecutionAuthorization, error) {
	return ExecutionAuthorization{DecisionID: "execution-1", MaximumDuration: time.Second, MaximumBytes: 1024}, nil
}

type denyAuthorizer struct{}

func (denyAuthorizer) AuthorizeExecution(context.Context, ExecutionRequest) (ExecutionAuthorization, error) {
	return ExecutionAuthorization{}, errors.New("current policy denies target")
}

type countingAdapter struct{ calls int }

func (a *countingAdapter) Execute(context.Context, transport.TargetConnection, transport.BoundedOperation) (transport.CapturedBytes, error) {
	a.calls++
	return transport.CapturedBytes{}, nil
}

func testTask() Task {
	return Task{
		ID: "task-1", TenantID: "tenant-1", ResolutionID: "resolution-1",
		TargetSnapshotID: "snapshot-1", TargetSnapshotHash: "sha256:snapshot",
		TargetID: "target-1", RecipeID: "gnmi_interface_get", RecipeVersion: "v1",
		TriggerDecisionID: "trigger-1", PlanningDecisionID: "planning-1",
	}
}

func testAuthority(t *testing.T, store *Store) *grants.Authority {
	t.Helper()
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := grants.NewAuthority("test-issuer", "test-audience", private, store)
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

type failingAdapter struct{}

func (failingAdapter) Execute(context.Context, transport.TargetConnection, transport.BoundedOperation) (transport.CapturedBytes, error) {
	return transport.CapturedBytes{}, errors.New("device unavailable")
}
