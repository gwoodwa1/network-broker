package transport

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func TestStubAdapterExecute(t *testing.T) {
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	adapter := StubAdapter{Now: func() time.Time { return now }}
	result, err := adapter.Execute(context.Background(), TargetConnection{
		TargetID: "target-1", CredentialToken: "opaque", CredentialExpiry: now.Add(time.Minute),
	}, BoundedOperation{
		RecipeID: "gnmi_interface_get", MaximumDuration: time.Second, MaximumBytes: 16,
	})
	if err != nil {
		t.Fatalf("expected execute to succeed, got %v", err)
	}
	if result.TargetID != "target-1" || string(result.Payload) != "ok" {
		t.Fatalf("unexpected captured result: %+v", result)
	}
	if result.Digest != sha256.Sum256([]byte("ok")) || !result.CapturedAt.Equal(now) {
		t.Fatal("expected capture digest and timestamp to be populated")
	}
}

func TestStubAdapterEnforcesResponseLimit(t *testing.T) {
	adapter := StubAdapter{Payload: []byte("too-large")}
	_, err := adapter.Execute(context.Background(), TargetConnection{
		TargetID: "target-1", CredentialToken: "opaque", CredentialExpiry: time.Now().Add(time.Minute),
	}, BoundedOperation{
		RecipeID: "gnmi_interface_get", MaximumDuration: time.Second, MaximumBytes: 3,
	})
	if err == nil {
		t.Fatal("expected oversized output to be rejected")
	}
}

func TestStubAdapterHonoursCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (StubAdapter{}).Execute(ctx, TargetConnection{
		TargetID: "target-1", CredentialToken: "opaque", CredentialExpiry: time.Now().Add(time.Minute),
	}, BoundedOperation{
		RecipeID: "gnmi_interface_get", MaximumDuration: time.Second, MaximumBytes: 16,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}

func TestStubAdapterRejectsMissingCredential(t *testing.T) {
	_, err := (StubAdapter{}).Execute(context.Background(), TargetConnection{TargetID: "target-1"}, BoundedOperation{
		RecipeID: "gnmi_interface_get", MaximumDuration: time.Second, MaximumBytes: 16,
	})
	if err == nil {
		t.Fatal("expected missing credential to be rejected")
	}
}

func TestStubAdapterRejectsExpiredCredential(t *testing.T) {
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	_, err := (StubAdapter{Now: func() time.Time { return now }}).Execute(context.Background(), TargetConnection{
		TargetID: "target-1", CredentialToken: "opaque", CredentialExpiry: now,
	}, BoundedOperation{RecipeID: "gnmi_interface_get", MaximumDuration: time.Second, MaximumBytes: 16})
	if err == nil {
		t.Fatal("expected expired credential to be rejected")
	}
}
