package contextstore

import (
	"testing"
	"time"

	"network_broker/internal/authctx"
	"network_broker/internal/inventory"
)

func TestStoreQueryReturnsObservations(t *testing.T) {
	auth := authctx.AuthContext{SubjectID: "sub-1", TenantID: "tenant-a", AuthenticatedAt: time.Now()}
	store := Store{Observations: map[string][]Observation{
		"interface.operational_state": {{ClaimType: "interface.operational_state", Value: "up"}},
	}}
	result, err := store.Query(auth, "interface.operational_state", inventory.ResolvedTargetSnapshot{TenantID: "tenant-a"})
	if err != nil {
		t.Fatalf("expected query to succeed, got %v", err)
	}
	if !result.Complete {
		t.Fatal("expected query result to be complete")
	}
	if len(result.Observations) != 1 {
		t.Fatalf("expected one observation, got %d", len(result.Observations))
	}
}

func TestStoreQueryRejectsScopeMismatch(t *testing.T) {
	auth := authctx.AuthContext{SubjectID: "sub-1", TenantID: "tenant-a", AuthenticatedAt: time.Now()}
	store := Store{}
	_, err := store.Query(auth, "interface.operational_state", inventory.ResolvedTargetSnapshot{TenantID: "tenant-b"})
	if err == nil {
		t.Fatal("expected tenant scope mismatch to be rejected")
	}
}
