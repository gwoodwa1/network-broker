package disclosure

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"network_broker/internal/cryptosign"
	"network_broker/internal/keyprovider"
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
	decision, err := service.Evaluate(DecisionRequest{
		ActorID: "actor-a", TenantID: "tenant-a", EvidenceID: "evidence-2",
		Representation: "normalised", PolicyBundleDigest: "policy-1", InputDigest: "input-1", PermittedFields: []string{"interface_state"}, TTL: time.Minute,
	})
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
	decision, err := service.Evaluate(DecisionRequest{
		ActorID: "actor-a", TenantID: "tenant-a", EvidenceID: "evidence-1",
		Representation: "normalised", PolicyBundleDigest: "policy-1", InputDigest: "input-1",
		PermittedFields: []string{"interface_name", "operational_state"}, RequiredRedactions: []string{"device_address"}, TTL: time.Minute,
	})
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
	if err := service.VerifyReceipt(context.Background(), *receipt); err != nil {
		t.Fatalf("verify signed delivery receipt: %v", err)
	}
}

func TestDeliverRejectsDecisionUsedByAnotherActor(t *testing.T) {
	service := NewService()
	decision, err := service.Evaluate(DecisionRequest{
		ActorID: "actor-a", TenantID: "tenant-a", EvidenceID: "evidence-1",
		Representation: "normalised", PolicyBundleDigest: "policy-1", InputDigest: "input-1",
		PermittedFields: []string{"operational_state"}, TTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.Deliver(decision.DecisionID, "actor-b", "tenant-a", "evidence-1", "request-1", "normalised",
		map[string]string{"operational_state": "up"}, nil); err == nil {
		t.Fatal("expected cross-actor decision reuse to be rejected")
	}
}

func TestReceiptRejectsTamperingAndSignatureStripping(t *testing.T) {
	service := NewService()
	decision, err := service.Evaluate(DecisionRequest{
		ActorID: "actor-a", TenantID: "tenant-a", EvidenceID: "evidence-1",
		Representation: "normalised", PolicyBundleDigest: "policy-1", InputDigest: "input-1",
		PermittedFields: []string{"operational_state"}, AllowTaintedFields: true, TTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, receipt, err := service.DeliverContextWithTaint(context.Background(), decision.DecisionID, "actor-a",
		"tenant-a", "evidence-1", "request-1", "normalised", map[string]string{"operational_state": "up"}, nil,
		[]string{"operational_state"})
	if err != nil {
		t.Fatal(err)
	}
	tampered := *receipt
	tampered.ActorID = "actor-b"
	if err := service.VerifyReceipt(context.Background(), tampered); err == nil {
		t.Fatal("expected tampered actor to invalidate receipt")
	}
	stripped := *receipt
	stripped.SignatureSet.Signatures = nil
	if err := service.VerifyReceipt(context.Background(), stripped); err == nil {
		t.Fatal("expected stripped signature set to be rejected")
	}
	taintTampered := *receipt
	taintTampered.TaintedFields = nil
	if err := service.VerifyReceipt(context.Background(), taintTampered); err == nil {
		t.Fatal("expected removed taint metadata to invalidate receipt")
	}
}

func TestDisclosureRejectsTaintedFieldsByDefaultAndWarnsWhenAllowed(t *testing.T) {
	service := NewService()
	request := DecisionRequest{
		ActorID: "actor-a", TenantID: "tenant-a", EvidenceID: "evidence-1", Representation: "normalised",
		PolicyBundleDigest: "policy-1", InputDigest: "input-1", PermittedFields: []string{"interface_name"},
		TTL: time.Minute,
	}
	decision, err := service.Evaluate(request)
	if err != nil {
		t.Fatal(err)
	}
	deliver := func(decisionID string) (*Receipt, error) {
		_, receipt, deliverErr := service.DeliverContextWithTaint(context.Background(), decisionID, "actor-a",
			"tenant-a", "evidence-1", "request-1", "normalised", map[string]string{"interface_name": "Ethernet1"},
			nil, []string{"interface_name"})
		return receipt, deliverErr
	}
	if _, err := deliver(decision.DecisionID); err == nil {
		t.Fatal("expected tainted disclosure to fail closed by default")
	}
	request.AllowTaintedFields = true
	decision, err = service.Evaluate(request)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := deliver(decision.DecisionID)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.TaintWarning != taintedDataWarning {
		t.Fatalf("mandatory taint warning missing from receipt: %+v", receipt)
	}
	if receipt.SanitisationSummary != "tainted: 1 device-controlled field(s) delivered" {
		t.Fatalf("sanitisation summary missing from receipt: %+v", receipt)
	}
	if err := service.VerifyReceipt(context.Background(), *receipt); err != nil {
		t.Fatal(err)
	}
	tampered := *receipt
	tampered.SanitisationSummary = "clean: no tainted fields delivered"
	if err := service.VerifyReceipt(context.Background(), tampered); err == nil {
		t.Fatal("expected a changed sanitisation summary to invalidate the receipt")
	}
}

func TestDeliverRejectsTaintForUndeliveredField(t *testing.T) {
	service := NewService()
	decision, err := service.Evaluate(DecisionRequest{
		ActorID: "actor-a", TenantID: "tenant-a", EvidenceID: "evidence-1",
		Representation: "normalised", PolicyBundleDigest: "policy-1", InputDigest: "input-1",
		PermittedFields: []string{"operational_state"}, TTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = service.DeliverContextWithTaint(context.Background(), decision.DecisionID, "actor-a", "tenant-a",
		"evidence-1", "request-1", "normalised", map[string]string{"operational_state": "up"}, nil,
		[]string{"interface_name"})
	if err == nil {
		t.Fatal("expected taint metadata for an undelivered field to fail closed")
	}
}

func TestReceiptV1RemainsVerifiable(t *testing.T) {
	service := NewService()
	receipt := Receipt{
		SchemaVersion: receiptSchemaVersionV1, ReceiptID: "receipt-legacy", TenantID: "tenant-a",
		EvidenceID: "evidence-1", ActorID: "actor-a", DisclosureDecisionID: "decision-1",
		PolicyBundleDigest: "policy-1", PolicyInputDigest: "input-1", Representation: "normalised",
		FieldsDelivered: []string{"operational_state"}, DeliveredPayloadDigest: "digest-1",
		RequestID: "request-1", DeliveredAt: time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC),
	}
	canonical, err := canonicalReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.SignatureSet, err = service.signing.Sign(context.Background(), receiptSigningPurpose,
		receiptSigningDomainV1, canonical)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.VerifyReceipt(context.Background(), receipt); err != nil {
		t.Fatalf("legacy receipt no longer verifies: %v", err)
	}
}

func TestReceiptV2RemainsVerifiable(t *testing.T) {
	service := NewService()
	receipt := Receipt{
		SchemaVersion: receiptSchemaVersionV2, ReceiptID: "receipt-v2", TenantID: "tenant-a",
		EvidenceID: "evidence-1", ActorID: "actor-a", DisclosureDecisionID: "decision-1",
		PolicyBundleDigest: "policy-1", PolicyInputDigest: "input-1", Representation: "normalised",
		FieldsDelivered: []string{"interface_name"}, TaintedFields: []string{"interface_name"},
		DeliveredPayloadDigest: "digest-1", RequestID: "request-1",
		DeliveredAt: time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC),
	}
	canonical, err := canonicalReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.SignatureSet, err = service.signing.Sign(context.Background(), receiptSigningPurpose,
		receiptSigningDomainV2, canonical)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.VerifyReceipt(context.Background(), receipt); err != nil {
		t.Fatalf("v2 receipt no longer verifies: %v", err)
	}
}

func TestReceiptSupportsDualSignaturePolicy(t *testing.T) {
	first := disclosureKeyring(t, "receipt-key-1")
	second := disclosureKeyring(t, "receipt-key-2")
	manager, err := cryptosign.NewManager([]keyprovider.SigningProvider{first, second}, cryptosign.Policy{
		MinimumValidSignatures: 2, RequiredAlgorithms: []string{keyprovider.Ed25519Algorithm},
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewServiceWithSigning(time.Now, manager)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := service.Evaluate(DecisionRequest{
		ActorID: "actor-a", TenantID: "tenant-a", EvidenceID: "evidence-1",
		Representation: "normalised", PolicyBundleDigest: "policy-1", InputDigest: "input-1",
		PermittedFields: []string{"operational_state"}, TTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, receipt, err := service.Deliver(decision.DecisionID, "actor-a", "tenant-a", "evidence-1", "request-1", "normalised",
		map[string]string{"operational_state": "up"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(receipt.SignatureSet.Signatures) != 2 {
		t.Fatalf("expected two signatures, got %d", len(receipt.SignatureSet.Signatures))
	}
	if err := service.VerifyReceipt(context.Background(), *receipt); err != nil {
		t.Fatal(err)
	}
}

func disclosureKeyring(t *testing.T, reference string) *keyprovider.Ed25519Keyring {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := keyprovider.NewEd25519Keyring(reference, private)
	if err != nil {
		t.Fatal(err)
	}
	return keyring
}
