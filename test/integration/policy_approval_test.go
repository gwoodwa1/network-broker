//go:build integration

package integration_test

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"network_broker/internal/approval"
	"network_broker/internal/keyprovider"
	"network_broker/internal/policy"
	"network_broker/migrations"
)

func TestDurablePolicyAndApprovalProvenance(t *testing.T) {
	databaseURL := os.Getenv("POSTGRES_TEST_DSN")
	if databaseURL == "" {
		t.Skip("POSTGRES_TEST_DSN is not configured")
	}
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close postgres: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := migrations.Apply(ctx, database); err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := keyprovider.NewEd25519Keyring("policy-integration-v1", private)
	if err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scope := "integration-" + suffix
	issuedAt := time.Now().UTC().Add(-time.Minute)
	bundle, err := policy.SignBundle(ctx, keyring, policy.Bundle{
		BundleID: "bundle-" + suffix, Version: 1, Scope: scope, IssuedAt: issuedAt,
		Rules: []policy.Rule{{
			RecipeID: "gnmi_interface_get", TargetClass: "lab", Allow: true,
			RequiresApproval: true, Obligations: map[string]string{"max_response_bytes": "4096"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	policyRepository, err := policy.NewPostgresBundleRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policyRepository.StoreBundle(ctx, bundle); err != nil {
		t.Fatal(err)
	}
	if err := policyRepository.ActivateBundle(ctx, scope, bundle.BundleID, bundle.Version, "policy-admin"); err != nil {
		t.Fatal(err)
	}
	engine, err := policy.NewBundleEngine(policyRepository, keyring, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := engine.Evaluate(ctx, policy.EvaluationRequest{
		TenantID: "tenant-policy", ActorID: "actor-policy", Phase: policy.PhaseExecution,
		Scope: scope, RecipeID: "gnmi_interface_get", TargetClass: "lab",
		Attributes: map[string]string{"target_snapshot_digest": "sha256:snapshot"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allow || !decision.RequiresApproval || decision.BundleDigest == "" || decision.InputDigest == "" {
		t.Fatalf("incomplete durable decision: %+v", decision)
	}
	approvalRepository, err := approval.NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	approvalService, err := approval.NewServiceWithRepository(approvalRepository)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := approvalService.CreateContext(ctx, approval.CreateRequest{
		GrantID: "approval-" + suffix, TenantID: decision.TenantID, RecipeID: decision.RecipeID,
		TargetSubsetHash: "sha256:targets", MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour),
		CreatedBy: "approver-a", PolicyDecisionID: decision.DecisionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	consumption := approval.ConsumeRequest{
		ConsumptionID: "consumption-" + suffix, GrantID: grant.GrantID, TenantID: grant.TenantID,
		RecipeID: grant.RecipeID, TargetSubsetHash: grant.TargetSubsetHash,
		TaskID: "task-" + suffix, ActorID: "collector-a", Now: time.Now(),
	}
	consumed, err := approvalService.ConsumeContext(ctx, consumption)
	if err != nil {
		t.Fatal(err)
	}
	retried, err := approvalService.ConsumeContext(ctx, consumption)
	if err != nil || consumed.Used != 1 || retried.Used != 1 {
		t.Fatalf("approval consumption was not idempotent: consumed=%+v retried=%+v error=%v", consumed, retried, err)
	}
	consumption.TenantID = "other-tenant"
	if _, err := approvalService.ConsumeContext(ctx, consumption); !errors.Is(err, approval.ErrNotFound) {
		t.Fatalf("expected tenant-isolated approval lookup, got %v", err)
	}
	if _, err := database.ExecContext(ctx, `
		UPDATE broker_policy_decisions SET actor_id = 'tampered' WHERE decision_id = $1`,
		decision.DecisionID); err == nil {
		t.Fatal("expected append-only policy decision trigger to reject mutation")
	}
}
