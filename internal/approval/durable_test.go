package approval

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBoundApprovalConsumptionIsIdempotentAndTenantScoped(t *testing.T) {
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	service, err := NewServiceWithRepository(NewMemoryRepository())
	if err != nil {
		t.Fatal(err)
	}
	grant, err := service.CreateContext(context.Background(), CreateRequest{
		GrantID: "approval-1", TenantID: "tenant-a", RecipeID: "gnmi_interface_get",
		TargetSubsetHash: "sha256:targets", MaxUses: 1, ExpiresAt: now.Add(time.Hour),
		CreatedBy: "operator-a", PolicyDecisionID: "decision-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	request := ConsumeRequest{
		ConsumptionID: "use-1", GrantID: grant.GrantID, TenantID: grant.TenantID,
		RecipeID: grant.RecipeID, TargetSubsetHash: grant.TargetSubsetHash,
		TaskID: "task-1", ActorID: "collector-a", Now: now,
	}
	consumed, err := service.ConsumeContext(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	retried, err := service.ConsumeContext(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if consumed.Used != 1 || retried.Used != 1 || consumed.Version != 2 {
		t.Fatalf("unexpected idempotent approval state: consumed=%+v retried=%+v", consumed, retried)
	}
	request.ConsumptionID = "use-2"
	request.TaskID = "task-2"
	if _, err := service.ConsumeContext(context.Background(), request); !errors.Is(err, ErrExhausted) {
		t.Fatalf("expected exhausted grant, got %v", err)
	}
	request.TenantID = "tenant-b"
	if _, err := service.ConsumeContext(context.Background(), request); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected opaque tenant isolation, got %v", err)
	}
}
