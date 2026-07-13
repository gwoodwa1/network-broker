package collector

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"network_broker/internal/grants"
)

func TestStoreAcquireRenewAndCommit(t *testing.T) {
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	store := NewStore()
	if err := store.Add(Task{ID: "task-1", TargetID: "target-1", RecipeID: "gnmi_interface_get"}); err != nil {
		t.Fatal(err)
	}
	lease, err := store.Acquire("task-1", "collector-a", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if lease.FencingToken != 1 {
		t.Fatalf("expected fencing token 1, got %d", lease.FencingToken)
	}
	if _, err := store.Renew("task-1", "collector-a", lease.FencingToken, now.Add(30*time.Second), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := store.StartExecution("task-1", "collector-a", lease.FencingToken, now.Add(31*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginCommit("task-1", "collector-a", lease.FencingToken, now.Add(32*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit("task-1", "collector-a", lease.FencingToken, "attempt-1", "evidence-1", now.Add(33*time.Second)); err != nil {
		t.Fatal(err)
	}
	task, err := store.Get("task-1")
	if err != nil {
		t.Fatal(err)
	}
	if task.State != TaskSucceeded || task.AcceptedAttemptID != "attempt-1" || task.AcceptedEvidenceID != "evidence-1" {
		t.Fatalf("unexpected committed task: %+v", task)
	}
}

func TestSameCollectorIdentityRestartCannotReuseLeaseOrExecutionGrant(t *testing.T) {
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	const collectorID = "spiffe://example.test/collector/site-a"
	store := NewStore()
	if err := store.Add(Task{ID: "task-1", TargetID: "target-1", RecipeID: "gnmi_interface_get"}); err != nil {
		t.Fatal(err)
	}
	staleLease, err := store.Acquire("task-1", collectorID, now, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.StartExecution("task-1", collectorID, staleLease.FencingToken, now); err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := grants.NewAuthority("credential-broker", "site-a", private, store)
	if err != nil {
		t.Fatal(err)
	}
	staleGrant, err := authority.Issue(restartGrant("grant-old", "nonce-old", collectorID,
		staleLease.FencingToken, now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Acquire("task-1", collectorID, now.Add(500*time.Millisecond), time.Minute); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("restarted collector reacquired an unexpired lease: %v", err)
	}
	currentLease, err := store.Acquire("task-1", collectorID, now.Add(time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if currentLease.FencingToken != staleLease.FencingToken+1 {
		t.Fatalf("restart did not advance the fencing epoch: stale=%d current=%d",
			staleLease.FencingToken, currentLease.FencingToken)
	}
	staleRequest := restartExchangeRequest(staleGrant, now.Add(time.Second))
	if _, err := authority.Exchange(staleGrant, staleRequest); !errors.Is(err, grants.ErrStaleFence) {
		t.Fatalf("old execution grant survived collector restart: %v", err)
	}
	if err := store.VerifyCurrentAttempt("task-1", collectorID, staleLease.FencingToken, now.Add(time.Second)); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("old attempt remained eligible for evidence assembly: %v", err)
	}
	if err := store.BeginCommit("task-1", collectorID, staleLease.FencingToken, now.Add(time.Second)); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("old attempt remained eligible to commit: %v", err)
	}
	if err := store.StartExecution("task-1", collectorID, currentLease.FencingToken, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	currentGrant, err := authority.Issue(restartGrant("grant-new", "nonce-new", collectorID,
		currentLease.FencingToken, now.Add(time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	credential, err := authority.Exchange(currentGrant, restartExchangeRequest(currentGrant, now.Add(time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	if credential.FencingToken != currentLease.FencingToken || credential.CollectorID != collectorID {
		t.Fatalf("credential was not bound to the restarted collector epoch: %+v", credential)
	}
}

func restartGrant(grantID, nonce, collectorID string, fencingToken int64, now time.Time) grants.ExecutionGrant {
	return grants.ExecutionGrant{
		GrantID: grantID, Nonce: nonce, TenantID: "tenant-1", CollectorSPIFFEID: collectorID,
		TaskID: "task-1", TargetID: "target-1", RecipeID: "gnmi_interface_get", RecipeVersion: "v1",
		FencingToken: fencingToken, NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute),
		MaximumDuration: time.Second, MaximumResponseBytes: 4096, CredentialClass: "network-read", SingleUse: true,
	}
}

func restartExchangeRequest(grant grants.ExecutionGrant, now time.Time) grants.ExchangeRequest {
	return grants.ExchangeRequest{
		PresentingSPIFFEID: grant.CollectorSPIFFEID, TaskID: grant.TaskID, TargetID: grant.TargetID,
		RecipeID: grant.RecipeID, RecipeVersion: grant.RecipeVersion, FencingToken: grant.FencingToken, Now: now,
	}
}

func TestStoreRejectsStaleAttemptAfterExpiredLeaseIsReacquired(t *testing.T) {
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	store := NewStore()
	if err := store.Add(Task{ID: "task-1", TargetID: "target-1", RecipeID: "gnmi_interface_get"}); err != nil {
		t.Fatal(err)
	}
	stale, err := store.Acquire("task-1", "collector-a", now, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	current, err := store.Acquire("task-1", "collector-b", now.Add(time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if current.FencingToken != stale.FencingToken+1 {
		t.Fatalf("expected incremented fencing token, got %d", current.FencingToken)
	}
	if err := store.StartExecution("task-1", "collector-a", stale.FencingToken, now.Add(time.Second)); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("expected stale fence rejection, got %v", err)
	}
}

func TestStoreRejectsDuplicateAcceptedCommit(t *testing.T) {
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	store := NewStore()
	if err := store.Add(Task{ID: "task-1", TargetID: "target-1", RecipeID: "gnmi_interface_get"}); err != nil {
		t.Fatal(err)
	}
	lease, err := store.Acquire("task-1", "collector-a", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.StartExecution("task-1", "collector-a", lease.FencingToken, now); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginCommit("task-1", "collector-a", lease.FencingToken, now); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit("task-1", "collector-a", lease.FencingToken, "attempt-1", "evidence-1", now); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit("task-1", "collector-a", lease.FencingToken, "attempt-2", "evidence-2", now); !errors.Is(err, ErrDuplicateCommit) {
		t.Fatalf("expected duplicate commit rejection, got %v", err)
	}
}

func TestStoreReportsCurrentFenceForGrantVerification(t *testing.T) {
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	store := NewStore()
	if err := store.Add(Task{ID: "task-1", TargetID: "target-1", RecipeID: "gnmi_interface_get"}); err != nil {
		t.Fatal(err)
	}
	lease, err := store.Acquire("task-1", "collector-a", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	token, err := store.CurrentFence("task-1")
	if err != nil {
		t.Fatal(err)
	}
	if token != lease.FencingToken {
		t.Fatalf("expected current fence %d, got %d", lease.FencingToken, token)
	}
}

func TestStoreVerifiesOnlyCurrentExecutingAttemptForAssembly(t *testing.T) {
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	store := NewStore()
	if err := store.Add(Task{ID: "task-1", TargetID: "target-1", RecipeID: "gnmi_interface_get"}); err != nil {
		t.Fatal(err)
	}
	lease, err := store.Acquire("task-1", "collector-a", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyCurrentAttempt("task-1", "collector-a", lease.FencingToken, now); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("expected leased-only attempt rejection, got %v", err)
	}
	if err := store.StartExecution("task-1", "collector-a", lease.FencingToken, now); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyCurrentAttempt("task-1", "collector-a", lease.FencingToken, now); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyCurrentAttempt("task-1", "collector-b", lease.FencingToken, now); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("expected collector binding rejection, got %v", err)
	}
}
