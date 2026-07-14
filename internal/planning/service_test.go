package planning

import (
	"context"
	"errors"
	"testing"
	"time"

	"network_broker/internal/authctx"
	"network_broker/internal/collector"
)

type fanoutRepositoryStub struct {
	request collector.FanoutRequest
	err     error
}

func (r *fanoutRepositoryStub) CreateFanoutContext(_ context.Context,
	request collector.FanoutRequest,
) error {
	r.request = request

	return r.err
}

func TestQueueBindsTenantStateAndEventToAuthenticatedPlanner(t *testing.T) {
	repository := &fanoutRepositoryStub{}
	now := time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC)
	service, err := NewService(repository, func() time.Time { return now },
		func(prefix string) (string, error) { return prefix + "-planning", nil })
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Queue(context.Background(), planningActor(), QueueRequest{
		ResolutionID: "resolution-1", ExpectedResolutionVersion: 3,
		Tasks: []collector.Task{plannedTask()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Version != 4 || result.TaskCount != 1 ||
		repository.request.TenantID != "tenant-a" ||
		repository.request.Tasks[0].TenantID != "tenant-a" ||
		repository.request.Tasks[0].ResolutionID != "resolution-1" ||
		repository.request.Tasks[0].State != collector.TaskQueued ||
		repository.request.Event.ID != "evt-planning" ||
		repository.request.Event.TenantID != "tenant-a" ||
		!repository.request.Event.OccurredAt.Equal(now) {
		t.Fatalf("unexpected queue authority: result=%+v request=%+v", result, repository.request)
	}
}

func TestQueueRejectsMissingScopeAndTenantOverride(t *testing.T) {
	service, err := NewService(&fanoutRepositoryStub{}, time.Now,
		func(string) (string, error) { return "event-1", nil })
	if err != nil {
		t.Fatal(err)
	}
	actor := planningActor()
	actor.AllowedScopes = nil
	if _, err := service.Queue(context.Background(), actor, QueueRequest{
		ResolutionID: "resolution-1", ExpectedResolutionVersion: 1,
		Tasks: []collector.Task{plannedTask()},
	}); !errors.Is(err, ErrDenied) {
		t.Fatalf("expected denied planner, got %v", err)
	}
	actor = planningActor()
	task := plannedTask()
	task.TenantID = "tenant-b"
	if _, err := service.Queue(context.Background(), actor, QueueRequest{
		ResolutionID: "resolution-1", ExpectedResolutionVersion: 1,
		Tasks: []collector.Task{task},
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected tenant override rejection, got %v", err)
	}
}

func TestQueuePropagatesAtomicFanoutConflict(t *testing.T) {
	repository := &fanoutRepositoryStub{err: collector.ErrFanoutConflict}
	service, err := NewService(repository, time.Now,
		func(string) (string, error) { return "event-1", nil })
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Queue(context.Background(), planningActor(), QueueRequest{
		ResolutionID: "resolution-1", ExpectedResolutionVersion: 1,
		Tasks: []collector.Task{plannedTask()},
	})
	if !errors.Is(err, collector.ErrFanoutConflict) {
		t.Fatalf("expected fan-out conflict, got %v", err)
	}
}

func planningActor() authctx.AuthContext {
	return authctx.AuthContext{
		SubjectID: "spiffe://broker.example/tenant/tenant-a/role/planner/workload/control-1",
		TenantID:  "tenant-a", AllowedScopes: []string{queueScope}, AuthenticatedAt: time.Now(),
	}
}

func plannedTask() collector.Task {
	return collector.Task{
		ID: "task-1", ClaimFingerprint: "claim-sha256", TargetSnapshotID: "snapshot-1",
		TargetSnapshotHash: "snapshot-sha256", TargetID: "router-1",
		TargetEndpoint: "router-1.example:57400", RecipeID: "gnmi_interface_get",
		RecipeVersion: "v1", TriggerDecisionID: "trigger-1",
		PlanningDecisionID: "planning-1", CompatibilityHash: "compatibility-sha256",
	}
}
