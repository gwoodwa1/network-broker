package grants

import (
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"
)

type fenceStore struct {
	mu     sync.Mutex
	tokens map[string]int64
}

func (s *fenceStore) CurrentFence(taskID string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokens[taskID], nil
}

func TestExchangeBindsPresentingCollectorAndConsumesGrant(t *testing.T) {
	authority, grant, request, _ := fixture(t)
	credential, err := authority.Exchange(grant, request)
	if err != nil {
		t.Fatal(err)
	}
	if credential.Token == "" || credential.TargetID != grant.TargetID || credential.GrantID != grant.GrantID {
		t.Fatalf("unexpected credential: %+v", credential)
	}
	if _, err := authority.Exchange(grant, request); !errors.Is(err, ErrAlreadyConsumed) {
		t.Fatalf("expected consumed grant rejection, got %v", err)
	}
}

func TestExchangeRejectsDifferentPresentingCollector(t *testing.T) {
	authority, grant, request, _ := fixture(t)
	request.PresentingSPIFFEID = "spiffe://example.test/collector/b"
	if _, err := authority.Exchange(grant, request); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("expected collector binding rejection, got %v", err)
	}
}

func TestExchangeRejectsStaleFence(t *testing.T) {
	authority, grant, request, fences := fixture(t)
	fences.tokens[grant.TaskID]++
	if _, err := authority.Exchange(grant, request); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("expected stale fence rejection, got %v", err)
	}
}

func TestExchangeRejectsTamperedGrantAndExpiry(t *testing.T) {
	authority, grant, request, _ := fixture(t)
	tampered := grant
	tampered.TargetID = "target-2"
	if _, err := authority.Exchange(tampered, request); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected signature rejection, got %v", err)
	}
	request.Now = grant.ExpiresAt
	if _, err := authority.Exchange(grant, request); !errors.Is(err, ErrNotCurrent) {
		t.Fatalf("expected expiry rejection, got %v", err)
	}
}

func fixture(t *testing.T) (*Authority, ExecutionGrant, ExchangeRequest, *fenceStore) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	fences := &fenceStore{tokens: map[string]int64{"task-1": 7}}
	authority, err := NewAuthority("credential-broker", "site-a", private, fences)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := authority.Issue(ExecutionGrant{
		GrantID: "grant-1", Nonce: "nonce-1", TenantID: "tenant-1",
		CollectorSPIFFEID: "spiffe://example.test/collector/a", ResolutionID: "resolution-1",
		TaskID: "task-1", TargetSnapshotID: "snapshot-1", TargetSnapshotDigest: "sha256:snapshot",
		TargetID: "target-1", RecipeID: "gnmi_interface_get", RecipeVersion: "v1",
		ParameterDigest: "sha256:parameters", FencingToken: 7,
		TriggerDecisionID: "trigger-1", PlanningDecisionID: "planning-1", ExecutionDecisionID: "execution-1",
		NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
		MaximumDuration: 10 * time.Second, MaximumResponseBytes: 1024,
		CredentialClass: "network-read", SingleUse: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := ExchangeRequest{
		PresentingSPIFFEID: grant.CollectorSPIFFEID, TaskID: grant.TaskID, TargetID: grant.TargetID,
		RecipeID: grant.RecipeID, RecipeVersion: grant.RecipeVersion, FencingToken: grant.FencingToken, Now: now,
	}
	return authority, grant, request, fences
}
