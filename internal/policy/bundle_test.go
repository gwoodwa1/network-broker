package policy

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"network_broker/internal/keyprovider"
)

type bundleRepositoryFixture struct {
	bundle   Bundle
	digest   string
	recorded DecisionRecord
}

func (r *bundleRepositoryFixture) LoadActiveBundle(context.Context, string) (Bundle, string, error) {
	return r.bundle, r.digest, nil
}

func (r *bundleRepositoryFixture) RecordDecision(_ context.Context, record DecisionRecord) error {
	r.recorded = record

	return nil
}

func TestBundleEngineVerifiesSignedBundleAndRecordsCompleteProvenance(t *testing.T) {
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := keyprovider.NewEd25519Keyring("policy-v1", private)
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	bundle, err := SignBundle(context.Background(), keyring, Bundle{
		BundleID: "network-read", Version: 1, Scope: "tenant-default", IssuedAt: issuedAt,
		Rules: []Rule{{
			RecipeID: "gnmi_interface_get", TargetClass: "lab", Allow: true,
			Obligations: map[string]string{"max_response_bytes": "1048576"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := bundleSigningPayload(bundle)
	if err != nil {
		t.Fatal(err)
	}
	repository := &bundleRepositoryFixture{bundle: bundle, digest: sha256Hex(payload)}
	engine, err := NewBundleEngine(repository, keyring, func() time.Time { return issuedAt.Add(time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	decision, err := engine.Evaluate(context.Background(), EvaluationRequest{
		TenantID: "tenant-a", ActorID: "spiffe://broker.example/collector/a",
		Phase: PhaseExecution, Scope: "tenant-default", RecipeID: "gnmi_interface_get",
		TargetClass: "lab", Attributes: map[string]string{"fence": "7"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allow || decision.BundleID != bundle.BundleID || decision.BundleDigest == "" ||
		decision.InputDigest == "" || repository.recorded.DecisionID != decision.DecisionID {
		t.Fatalf("incomplete decision provenance: %+v", decision)
	}
}

func TestBundleEngineRejectsTamperedBundleAndMissingRule(t *testing.T) {
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := keyprovider.NewEd25519Keyring("policy-v1", private)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := SignBundle(context.Background(), keyring, Bundle{
		BundleID: "network-read", Version: 1, Scope: "default", IssuedAt: time.Now().UTC(),
		Rules: []Rule{{RecipeID: "gnmi_interface_get", TargetClass: "lab", Allow: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := bundleSigningPayload(bundle)
	if err != nil {
		t.Fatal(err)
	}
	repository := &bundleRepositoryFixture{bundle: bundle, digest: sha256Hex(payload)}
	engine, err := NewBundleEngine(repository, keyring, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	repository.bundle.Rules[0].Allow = false
	request := EvaluationRequest{
		TenantID: "tenant-a", ActorID: "actor-a", Phase: PhaseExecution,
		Scope: "default", RecipeID: "gnmi_interface_get", TargetClass: "lab",
	}
	if _, err := engine.Evaluate(context.Background(), request); err == nil {
		t.Fatal("expected tampered policy bundle rejection")
	}
	bundle.Rules[0].Allow = true
	repository.bundle = bundle
	request.RecipeID = "unsupported"
	if _, err := engine.Evaluate(context.Background(), request); !errors.Is(err, ErrNoMatchingRule) {
		t.Fatalf("expected missing rule rejection, got %v", err)
	}
}

func sha256Hex(payload []byte) string {
	digest := sha256.Sum256(payload)

	return hex.EncodeToString(digest[:])
}
