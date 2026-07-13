package disclosure

import (
	"testing"
	"time"
)

func TestEvaluateDecisionAndRecordDelivery(t *testing.T) {
	service := NewService()
	decision, err := service.EvaluateDecision("actor-a", "evidence-1", "normalised", []string{"interface_state"})
	if err != nil {
		t.Fatalf("expected evaluate to succeed, got %v", err)
	}
	receipt, err := service.RecordDelivery(decision, "normalised", []string{"interface_state"})
	if err != nil {
		t.Fatalf("expected delivery to succeed, got %v", err)
	}
	if receipt.ActorID != "actor-a" {
		t.Fatalf("expected actor id actor-a, got %s", receipt.ActorID)
	}
}

func TestRecordDeliveryRejectsExpiredDecision(t *testing.T) {
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	service := NewServiceWithClock(func() time.Time { return now })
	decision, err := service.Evaluate(DecisionRequest{ActorID: "actor-a", TenantID: "tenant-a", EvidenceID: "evidence-2",
		Representation: "normalised", PolicyBundleDigest: "policy-1", InputDigest: "input-1", PermittedFields: []string{"interface_state"}, TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	_, err = service.RecordDelivery(decision, "normalised", []string{"interface_state"})
	if err == nil {
		t.Fatal("expected expired decision to be rejected")
	}
}

func TestDeliverEnforcesFieldsRepresentationAndRedactions(t *testing.T) {
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	service := NewServiceWithClock(func() time.Time { return now })
	decision, err := service.Evaluate(DecisionRequest{ActorID: "actor-a", TenantID: "tenant-a", EvidenceID: "evidence-1",
		Representation: "normalised", PolicyBundleDigest: "policy-1", InputDigest: "input-1",
		PermittedFields: []string{"interface_name", "operational_state"}, RequiredRedactions: []string{"device_address"}, TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.Deliver(decision.DecisionID, "actor-a", "tenant-a", "evidence-1", "request-1", "captured", map[string]string{"operational_state": "up"}, []string{"device_address"}); err == nil {
		t.Fatal("expected representation escalation to be rejected")
	}
	if _, _, err := service.Deliver(decision.DecisionID, "actor-a", "tenant-a", "evidence-1", "request-1", "normalised", map[string]string{"password": "secret"}, []string{"device_address"}); err == nil {
		t.Fatal("expected field escalation to be rejected")
	}
	if _, _, err := service.Deliver(decision.DecisionID, "actor-a", "tenant-a", "evidence-1", "request-1", "normalised", map[string]string{"operational_state": "up"}, nil); err == nil {
		t.Fatal("expected missing redaction to be rejected")
	}
	delivered, receipt, err := service.Deliver(decision.DecisionID, "actor-a", "tenant-a", "evidence-1", "request-1", "normalised",
		map[string]string{"operational_state": "up"}, []string{"device_address"})
	if err != nil {
		t.Fatal(err)
	}
	if delivered["operational_state"] != "up" || receipt.DeliveredPayloadDigest == "" || receipt.RequestID != "request-1" {
		t.Fatalf("unexpected delivery: payload=%v receipt=%+v", delivered, receipt)
	}
}

func TestDeliverRejectsDecisionUsedByAnotherActor(t *testing.T) {
	service := NewService()
	decision, err := service.Evaluate(DecisionRequest{ActorID: "actor-a", TenantID: "tenant-a", EvidenceID: "evidence-1",
		Representation: "normalised", PolicyBundleDigest: "policy-1", InputDigest: "input-1",
		PermittedFields: []string{"operational_state"}, TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.Deliver(decision.DecisionID, "actor-b", "tenant-a", "evidence-1", "request-1", "normalised",
		map[string]string{"operational_state": "up"}, nil); err == nil {
		t.Fatal("expected cross-actor decision reuse to be rejected")
	}
}
