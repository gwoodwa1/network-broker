// Package retrieval releases signed evidence through current disclosure decisions.
package retrieval

import (
	"context"
	"fmt"

	"network_broker/internal/disclosure"
	"network_broker/internal/evidence"
)

type EvidenceReader interface {
	Get(evidenceID string) (evidence.EvidenceEnvelope, error)
}

type Request struct {
	ActorID, TenantID, EvidenceID, DecisionID, RequestID string
	Fields                                               []string
	Redactions                                           []string
}

type Result struct {
	EvidenceID string
	Fields     map[string]string
	Receipt    disclosure.Receipt
}

type Service struct {
	Evidence   EvidenceReader
	Disclosure *disclosure.Service
}

func (s Service) RetrieveNormalised(ctx context.Context, request Request) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if s.Evidence == nil || s.Disclosure == nil || request.ActorID == "" || request.TenantID == "" ||
		request.EvidenceID == "" || request.DecisionID == "" || request.RequestID == "" || len(request.Fields) == 0 {
		return Result{}, fmt.Errorf("retrieval dependencies, identity, evidence, decision, request and fields are required")
	}
	envelope, err := s.Evidence.Get(request.EvidenceID)
	if err != nil {
		return Result{}, err
	}
	if envelope.TenantID != request.TenantID {
		return Result{}, fmt.Errorf("evidence tenant does not match caller scope")
	}
	available := map[string]string{
		"schema_version":    envelope.InterfaceState.SchemaVersion,
		"interface_name":    envelope.InterfaceState.InterfaceName,
		"operational_state": envelope.InterfaceState.OperationalState,
		"observed_at":       envelope.InterfaceState.ObservedAt.Format("2006-01-02T15:04:05.999999999Z07:00"),
	}
	selected := make(map[string]string, len(request.Fields))
	for _, field := range request.Fields {
		value, ok := available[field]
		if !ok {
			return Result{}, fmt.Errorf("normalised field %q does not exist", field)
		}
		selected[field] = value
	}
	delivered, receipt, err := s.Disclosure.DeliverContext(ctx, request.DecisionID, request.ActorID, request.TenantID,
		request.EvidenceID, request.RequestID, "normalised", selected, request.Redactions)
	if err != nil {
		return Result{}, err
	}
	return Result{EvidenceID: request.EvidenceID, Fields: delivered, Receipt: *receipt}, nil
}
