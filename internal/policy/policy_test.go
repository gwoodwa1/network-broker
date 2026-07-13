package policy

import "testing"

func TestEvaluatorAllowsSimpleRecipe(t *testing.T) {
	evaluator := Evaluator{}
	decision, err := evaluator.Evaluate("cached_openconfig_interfaces", "access_edge")
	if err != nil {
		t.Fatalf("expected evaluate to succeed, got %v", err)
	}
	if !decision.Allow {
		t.Fatal("expected cached recipe to be allowed")
	}
	if decision.RequiresApproval {
		t.Fatal("expected no approval requirement")
	}
}

func TestEvaluatorRequiresApprovalForCoreRecipe(t *testing.T) {
	evaluator := Evaluator{}
	decision, err := evaluator.Evaluate("gnmi_interface_get", "production_core")
	if err != nil {
		t.Fatalf("expected evaluate to succeed, got %v", err)
	}
	if decision.Allow {
		t.Fatal("expected production_core target to require approval or be denied")
	}
	if !decision.RequiresApproval {
		t.Fatal("expected approval to be required")
	}
}
