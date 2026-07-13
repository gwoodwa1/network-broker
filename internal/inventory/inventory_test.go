package inventory

import (
	"testing"
	"time"

	"network_broker/internal/authctx"
)

func TestResolverResolve(t *testing.T) {
	auth := authctx.AuthContext{SubjectID: "sub-1", TenantID: "tenant-a", AuthenticatedAt: time.Now()}
	resolver := Resolver{Catalog: map[string]ResolvedTarget{
		"t-1": {TargetID: "t-1", TenantID: "tenant-a", SiteID: "site-1", Platform: "ios-xr", SoftwareFamily: "ios_xr", DeviceClass: "production_core"},
		"t-2": {TargetID: "t-2", TenantID: "tenant-a", SiteID: "site-2", Platform: "junos", SoftwareFamily: "junos", DeviceClass: "access_edge"},
	}}

	snapshot, err := resolver.Resolve(auth, Selector{TargetIDs: []string{"t-1", "t-2"}})
	if err != nil {
		t.Fatalf("expected resolve to succeed, got %v", err)
	}

	if snapshot.TenantID != auth.TenantID {
		t.Fatalf("expected tenant %q, got %q", auth.TenantID, snapshot.TenantID)
	}
	if len(snapshot.Targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(snapshot.Targets))
	}
}

func TestResolverRejectsCrossTenantTarget(t *testing.T) {
	auth := authctx.AuthContext{SubjectID: "sub-1", TenantID: "tenant-a", AuthenticatedAt: time.Now()}
	resolver := Resolver{Catalog: map[string]ResolvedTarget{
		"t-1": {TargetID: "t-1", TenantID: "tenant-b", SiteID: "site-1", Platform: "ios-xr", SoftwareFamily: "ios_xr", DeviceClass: "production_core"},
	}}

	_, err := resolver.Resolve(auth, Selector{TargetIDs: []string{"t-1"}})
	if err == nil {
		t.Fatal("expected cross-tenant target to be rejected")
	}
}
