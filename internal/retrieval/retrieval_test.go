package retrieval

import (
	"context"
	"testing"
	"time"

	"network_broker/internal/disclosure"
	"network_broker/internal/evidence"
	"network_broker/internal/parsing"
)

type evidenceReader struct{ envelope evidence.EvidenceEnvelope }

func (r evidenceReader) Get(string) (evidence.EvidenceEnvelope, error) { return r.envelope, nil }

func TestRetrieveNormalisedIsActorSpecificAndReceipted(t *testing.T) {
	disclosures := disclosure.NewService()
	decision, err := disclosures.Evaluate(disclosure.DecisionRequest{
		ActorID: "actor-a", TenantID: "tenant-a", EvidenceID: "evidence-1",
		Representation: "normalised", PolicyBundleDigest: "policy-1", InputDigest: "input-1",
		PermittedFields: []string{"interface_name", "operational_state"}, AllowTaintedFields: true, TTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	service := Service{Evidence: evidenceReader{envelope: evidence.EvidenceEnvelope{
		EvidenceID: "evidence-1", TenantID: "tenant-a",
		InterfaceState: parsing.InterfaceOperationalState{
			SchemaVersion: "v1", InterfaceName: "Ethernet1", OperationalState: "up",
			ObservedAt: time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC), TaintedFields: []string{"interface_name"},
		},
	}}, Disclosure: disclosures}
	result, err := service.RetrieveNormalised(context.Background(), Request{
		ActorID: "actor-a", TenantID: "tenant-a",
		EvidenceID: "evidence-1", DecisionID: decision.DecisionID, RequestID: "request-1",
		Fields: []string{"interface_name", "operational_state"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Fields["operational_state"] != "up" || result.Receipt.DeliveredPayloadDigest == "" || result.Receipt.ActorID != "actor-a" {
		t.Fatalf("unexpected retrieval result: %+v", result)
	}
	if len(result.TaintedFields) != 1 || result.TaintedFields[0] != "interface_name" ||
		len(result.Receipt.TaintedFields) != 1 || result.Receipt.TaintedFields[0] != "interface_name" {
		t.Fatalf("taint metadata was not propagated: %+v", result)
	}
	if err := disclosures.VerifyReceipt(context.Background(), result.Receipt); err != nil {
		t.Fatalf("taint-bound receipt did not verify: %v", err)
	}
	_, err = service.RetrieveNormalised(context.Background(), Request{
		ActorID: "actor-b", TenantID: "tenant-a",
		EvidenceID: "evidence-1", DecisionID: decision.DecisionID, RequestID: "request-2", Fields: []string{"operational_state"},
	})
	if err == nil {
		t.Fatal("expected another actor to be unable to reuse the decision")
	}
}
