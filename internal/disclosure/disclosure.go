package disclosure

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
)

type Decision struct {
	DecisionID              string
	ActorID                 string
	TenantID                string
	EvidenceID              string
	PolicyBundleDigest      string
	PolicyInputDigest       string
	PermittedFields         []string
	PermittedRepresentation string
	RequiredRedactions      []string
	EvaluatedAt             time.Time
	ExpiresAt               time.Time
}

type Receipt struct {
	ReceiptID              string
	EvidenceID             string
	ActorID                string
	DisclosureDecisionID   string
	Representation         string
	FieldsDelivered        []string
	RedactionsApplied      []string
	DeliveredPayloadDigest string
	RequestID              string
	DeliveredAt            time.Time
}

type DecisionRequest struct {
	ActorID, TenantID, EvidenceID                   string
	Representation, PolicyBundleDigest, InputDigest string
	PermittedFields, RequiredRedactions             []string
	TTL                                             time.Duration
}

type Service struct {
	mu        sync.Mutex
	decisions map[string]*Decision
	receipts  map[string]*Receipt
	now       func() time.Time
	sequence  uint64
}

func NewService() *Service { return NewServiceWithClock(time.Now) }

func NewServiceWithClock(now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{decisions: make(map[string]*Decision), receipts: make(map[string]*Receipt), now: now}
}

// Evaluate stores a fresh actor- and evidence-specific disclosure decision.
func (s *Service) Evaluate(request DecisionRequest) (*Decision, error) {
	if request.ActorID == "" || request.TenantID == "" || request.EvidenceID == "" || request.Representation == "" ||
		request.PolicyBundleDigest == "" || request.InputDigest == "" || request.TTL <= 0 {
		return nil, fmt.Errorf("actor, tenant, evidence, representation, policy lineage and positive ttl are required")
	}
	if len(request.PermittedFields) == 0 {
		return nil, fmt.Errorf("at least one permitted field is required")
	}
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sequence++
	decision := &Decision{
		DecisionID: fmt.Sprintf("disclosure-%s-%d", request.EvidenceID, s.sequence), ActorID: request.ActorID,
		TenantID: request.TenantID, EvidenceID: request.EvidenceID, PolicyBundleDigest: request.PolicyBundleDigest,
		PolicyInputDigest: request.InputDigest, PermittedFields: uniqueSorted(request.PermittedFields),
		PermittedRepresentation: request.Representation, RequiredRedactions: uniqueSorted(request.RequiredRedactions),
		EvaluatedAt: now, ExpiresAt: now.Add(request.TTL),
	}
	s.decisions[decision.DecisionID] = decision
	copy := *decision
	copy.PermittedFields = append([]string(nil), decision.PermittedFields...)
	copy.RequiredRedactions = append([]string(nil), decision.RequiredRedactions...)
	return &copy, nil
}

// EvaluateDecision is retained as a local-scaffold convenience.
func (s *Service) EvaluateDecision(actorID, evidenceID, representation string, permittedFields []string) (*Decision, error) {
	return s.Evaluate(DecisionRequest{ActorID: actorID, TenantID: "tenant-local", EvidenceID: evidenceID,
		Representation: representation, PolicyBundleDigest: "policy-local", InputDigest: "input-local",
		PermittedFields: permittedFields, TTL: 15 * time.Minute})
}

// Deliver enforces the stored decision and records the exact released payload.
func (s *Service) Deliver(decisionID, actorID, tenantID, evidenceID, requestID, representation string, fields map[string]string, redactions []string) (map[string]string, *Receipt, error) {
	if decisionID == "" || actorID == "" || tenantID == "" || evidenceID == "" || requestID == "" || representation == "" || len(fields) == 0 {
		return nil, nil, fmt.Errorf("decision, actor, tenant, evidence, request, representation and fields are required")
	}
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	decision, ok := s.decisions[decisionID]
	if !ok {
		return nil, nil, fmt.Errorf("disclosure decision %q not found", decisionID)
	}
	if !now.Before(decision.ExpiresAt) {
		return nil, nil, fmt.Errorf("disclosure decision is expired")
	}
	if actorID != decision.ActorID || tenantID != decision.TenantID || evidenceID != decision.EvidenceID {
		return nil, nil, fmt.Errorf("disclosure decision identity binding does not match")
	}
	if representation != decision.PermittedRepresentation {
		return nil, nil, fmt.Errorf("representation is not permitted")
	}
	permitted := stringSet(decision.PermittedFields)
	delivered := make(map[string]string, len(fields))
	fieldNames := make([]string, 0, len(fields))
	for field, value := range fields {
		if _, ok := permitted[field]; !ok {
			return nil, nil, fmt.Errorf("field %q is not permitted", field)
		}
		delivered[field] = value
		fieldNames = append(fieldNames, field)
	}
	applied := stringSet(redactions)
	for _, required := range decision.RequiredRedactions {
		if _, ok := applied[required]; !ok {
			return nil, nil, fmt.Errorf("required redaction %q was not applied", required)
		}
	}
	sort.Strings(fieldNames)
	payload, err := json.Marshal(delivered)
	if err != nil {
		return nil, nil, fmt.Errorf("encode delivered payload: %w", err)
	}
	digest := sha256.Sum256(payload)
	s.sequence++
	receipt := &Receipt{ReceiptID: fmt.Sprintf("receipt-%s-%d", decision.EvidenceID, s.sequence), EvidenceID: decision.EvidenceID,
		ActorID: decision.ActorID, DisclosureDecisionID: decision.DecisionID, Representation: representation,
		FieldsDelivered: fieldNames, RedactionsApplied: uniqueSorted(redactions), DeliveredPayloadDigest: hex.EncodeToString(digest[:]),
		RequestID: requestID, DeliveredAt: now}
	s.receipts[receipt.ReceiptID] = receipt
	copy := *receipt
	copy.FieldsDelivered = append([]string(nil), receipt.FieldsDelivered...)
	copy.RedactionsApplied = append([]string(nil), receipt.RedactionsApplied...)
	return delivered, &copy, nil
}

// RecordDelivery validates the legacy field-only delivery shape.
func (s *Service) RecordDelivery(decision *Decision, representation string, fields []string) (*Receipt, error) {
	if decision == nil {
		return nil, fmt.Errorf("decision is required")
	}
	payload := make(map[string]string, len(fields))
	for _, field := range fields {
		payload[field] = "delivered"
	}
	_, receipt, err := s.Deliver(decision.DecisionID, decision.ActorID, decision.TenantID, decision.EvidenceID,
		"request-local", representation, payload, decision.RequiredRedactions)
	return receipt, err
}

func uniqueSorted(values []string) []string {
	set := stringSet(values)
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func stringSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			set[value] = struct{}{}
		}
	}
	return set
}
