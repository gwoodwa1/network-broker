package grants

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"

	"network_broker/internal/keyprovider"
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

func TestAuthorityVerifiesGrantsIssuedBeforeSigningKeyRotation(t *testing.T) {
	_, firstPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := keyprovider.NewEd25519Keyring("grant-key-v1", firstPrivate)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	fences := &fenceStore{tokens: map[string]int64{"task-1": 7, "task-2": 9}}
	authority, err := NewAuthorityWithProvider("credential-broker", "site-a", keyring, fences)
	if err != nil {
		t.Fatal(err)
	}
	first, err := authority.IssueContext(context.Background(), validGrant(now))
	if err != nil {
		t.Fatal(err)
	}
	_, secondPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyring.Rotate("grant-key-v2", secondPrivate); err != nil {
		t.Fatal(err)
	}
	secondInput := validGrant(now)
	secondInput.GrantID = "grant-2"
	secondInput.Nonce = "nonce-2"
	secondInput.TaskID = "task-2"
	secondInput.FencingToken = 9
	second, err := authority.Issue(secondInput)
	if err != nil {
		t.Fatal(err)
	}
	if first.SigningKeyRef != "grant-key-v1" || second.SigningKeyRef != "grant-key-v2" {
		t.Fatalf("unexpected signing references: first=%q second=%q", first.SigningKeyRef, second.SigningKeyRef)
	}
	request := ExchangeRequest{
		PresentingSPIFFEID: first.CollectorSPIFFEID, TaskID: first.TaskID, TargetID: first.TargetID,
		RecipeID: first.RecipeID, RecipeVersion: first.RecipeVersion,
		FencingToken: first.FencingToken, Now: now,
	}
	if _, err := authority.ExchangeContext(context.Background(), first, request); err != nil {
		t.Fatalf("grant signed before rotation no longer verifies: %v", err)
	}
}

func TestSharedConsumptionRepositorySurvivesAuthorityRecreation(t *testing.T) {
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := keyprovider.NewEd25519Keyring("grant-key-v1", private)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC)
	fences := &fenceStore{tokens: map[string]int64{"task-1": 7}}
	consumptions := NewMemoryConsumptionRepository()
	firstAuthority, err := NewAuthorityWithProviderAndRepository(
		"credential-broker", "site-a", keyring, fences, consumptions)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := firstAuthority.Issue(validGrant(now))
	if err != nil {
		t.Fatal(err)
	}
	request := ExchangeRequest{
		PresentingSPIFFEID: grant.CollectorSPIFFEID, TaskID: grant.TaskID,
		TargetID: grant.TargetID, RecipeID: grant.RecipeID,
		RecipeVersion: grant.RecipeVersion, FencingToken: grant.FencingToken, Now: now,
	}
	if _, err := firstAuthority.Exchange(grant, request); err != nil {
		t.Fatal(err)
	}
	secondAuthority, err := NewAuthorityWithProviderAndRepository(
		"credential-broker", "site-a", keyring, fences, consumptions)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secondAuthority.Exchange(grant, request); !errors.Is(err, ErrAlreadyConsumed) {
		t.Fatalf("expected recreated authority to reject consumed grant, got %v", err)
	}
	record, err := consumptions.Get(context.Background(), grant.TenantID, grant.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	if record.NonceDigest == grant.Nonce || len(record.NonceDigest) != 64 {
		t.Fatalf("raw grant nonce crossed persistence boundary: %+v", record)
	}
}

func TestIssueRejectsReusableExecutionGrant(t *testing.T) {
	authority, grant, _, _ := fixture(t)
	grant.SingleUse = false
	if _, err := authority.Issue(grant); err == nil {
		t.Fatal("expected reusable execution grant to be rejected")
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
	grant, err := authority.Issue(validGrant(now))
	if err != nil {
		t.Fatal(err)
	}
	request := ExchangeRequest{
		PresentingSPIFFEID: grant.CollectorSPIFFEID, TaskID: grant.TaskID, TargetID: grant.TargetID,
		RecipeID: grant.RecipeID, RecipeVersion: grant.RecipeVersion, FencingToken: grant.FencingToken, Now: now,
	}
	return authority, grant, request, fences
}

func validGrant(now time.Time) ExecutionGrant {
	return ExecutionGrant{
		GrantID: "grant-1", Nonce: "nonce-1", TenantID: "tenant-1",
		CollectorSPIFFEID: "spiffe://example.test/collector/a", ResolutionID: "resolution-1",
		TaskID: "task-1", TargetSnapshotID: "snapshot-1", TargetSnapshotDigest: "sha256:snapshot",
		TargetID: "target-1", RecipeID: "gnmi_interface_get", RecipeVersion: "v1",
		ParameterDigest: "sha256:parameters", FencingToken: 7,
		TriggerDecisionID: "trigger-1", PlanningDecisionID: "planning-1", ExecutionDecisionID: "execution-1",
		NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
		MaximumDuration: 10 * time.Second, MaximumResponseBytes: 1024,
		CredentialClass: "network-read", SingleUse: true,
	}
}
