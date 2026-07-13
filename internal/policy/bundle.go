package policy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"network_broker/internal/keyprovider"
)

var (
	ErrNoActiveBundle = errors.New("no active policy bundle")
	ErrNoMatchingRule = errors.New("policy bundle has no matching rule")
)

type Phase string

const (
	PhaseTrigger    Phase = "trigger"
	PhaseCandidate  Phase = "candidate"
	PhaseExecution  Phase = "execution"
	PhaseDisclosure Phase = "disclosure"
)

type Rule struct {
	RecipeID         string            `json:"recipe_id"`
	TargetClass      string            `json:"target_class"`
	Allow            bool              `json:"allow"`
	RequiresApproval bool              `json:"requires_approval"`
	Denials          []string          `json:"denials,omitempty"`
	Obligations      map[string]string `json:"obligations,omitempty"`
}

type Bundle struct {
	BundleID           string    `json:"bundle_id"`
	Version            int64     `json:"version"`
	Scope              string    `json:"scope"`
	IssuedAt           time.Time `json:"issued_at"`
	Rules              []Rule    `json:"rules"`
	SigningKeyRef      string    `json:"signing_key_ref"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	Signature          []byte    `json:"signature"`
}

type EvaluationRequest struct {
	TenantID    string
	ActorID     string
	Phase       Phase
	Scope       string
	RecipeID    string
	TargetClass string
	Attributes  map[string]string
}

type DecisionRecord struct {
	DecisionID       string
	TenantID         string
	ActorID          string
	Phase            Phase
	Scope            string
	RecipeID         string
	TargetClass      string
	InputDigest      string
	BundleID         string
	BundleVersion    int64
	BundleDigest     string
	Allow            bool
	RequiresApproval bool
	Denials          []string
	Obligations      map[string]string
	EvaluatedAt      time.Time
}

type BundleRepository interface {
	LoadActiveBundle(context.Context, string) (Bundle, string, error)
	RecordDecision(context.Context, DecisionRecord) error
}

type BundleEngine struct {
	repository BundleRepository
	verifier   keyprovider.SigningProvider
	now        func() time.Time
}

func NewBundleEngine(repository BundleRepository, verifier keyprovider.SigningProvider,
	now func() time.Time,
) (*BundleEngine, error) {
	if repository == nil || verifier == nil || now == nil {
		return nil, fmt.Errorf("policy repository, signing verifier and clock are required")
	}

	return &BundleEngine{repository: repository, verifier: verifier, now: now}, nil
}

func SignBundle(ctx context.Context, signing keyprovider.SigningProvider, bundle Bundle) (Bundle, error) {
	if signing == nil {
		return Bundle{}, fmt.Errorf("policy signing provider is required")
	}
	if err := validateUnsignedBundle(bundle); err != nil {
		return Bundle{}, err
	}
	key, err := signing.CurrentSigningKey(ctx, "policy-bundle")
	if err != nil {
		return Bundle{}, fmt.Errorf("resolve policy signing key: %w", err)
	}
	bundle.SigningKeyRef = key.Reference
	bundle.SignatureAlgorithm = key.Algorithm
	payload, err := bundleSigningPayload(bundle)
	if err != nil {
		return Bundle{}, err
	}
	bundle.Signature, err = signing.Sign(ctx, key.Reference, payload)
	if err != nil {
		return Bundle{}, fmt.Errorf("sign policy bundle: %w", err)
	}

	return bundle, nil
}

func (e *BundleEngine) Evaluate(ctx context.Context, request EvaluationRequest) (DecisionRecord, error) {
	if err := validateEvaluationRequest(request); err != nil {
		return DecisionRecord{}, err
	}
	bundle, storedDigest, err := e.repository.LoadActiveBundle(ctx, request.Scope)
	if err != nil {
		return DecisionRecord{}, err
	}
	if err := validateSignedBundle(bundle); err != nil {
		return DecisionRecord{}, err
	}
	payload, err := bundleSigningPayload(bundle)
	if err != nil {
		return DecisionRecord{}, err
	}
	digest := sha256.Sum256(payload)
	bundleDigest := hex.EncodeToString(digest[:])
	if bundleDigest != storedDigest {
		return DecisionRecord{}, fmt.Errorf("policy bundle digest does not match stored provenance")
	}
	if err := e.verifier.Verify(ctx, bundle.SigningKeyRef, bundle.SignatureAlgorithm,
		payload, bundle.Signature); err != nil {
		return DecisionRecord{}, fmt.Errorf("verify policy bundle: %w", err)
	}
	rule, err := matchingRule(bundle.Rules, request.RecipeID, request.TargetClass)
	if err != nil {
		return DecisionRecord{}, err
	}
	inputDigest, err := evaluationDigest(request)
	if err != nil {
		return DecisionRecord{}, err
	}
	evaluatedAt := e.now().UTC()
	decisionID, err := newDecisionID()
	if err != nil {
		return DecisionRecord{}, err
	}
	record := DecisionRecord{
		DecisionID: decisionID, TenantID: request.TenantID,
		ActorID: request.ActorID, Phase: request.Phase, Scope: request.Scope,
		RecipeID: request.RecipeID, TargetClass: request.TargetClass, InputDigest: inputDigest,
		BundleID: bundle.BundleID, BundleVersion: bundle.Version, BundleDigest: bundleDigest,
		Allow: rule.Allow, RequiresApproval: rule.RequiresApproval,
		Denials: append([]string(nil), rule.Denials...), Obligations: cloneMap(rule.Obligations),
		EvaluatedAt: evaluatedAt,
	}
	if err := e.repository.RecordDecision(ctx, record); err != nil {
		return DecisionRecord{}, fmt.Errorf("record policy decision: %w", err)
	}

	return record, nil
}

func validateUnsignedBundle(bundle Bundle) error {
	return validateBundleContents(bundle)
}

func validateSignedBundle(bundle Bundle) error {
	if err := validateBundleContents(bundle); err != nil {
		return err
	}
	if bundle.SigningKeyRef == "" || bundle.SignatureAlgorithm == "" || len(bundle.Signature) == 0 {
		return fmt.Errorf("signed policy bundle provenance is required")
	}

	return nil
}

func validateBundleContents(bundle Bundle) error {
	if bundle.BundleID == "" || bundle.Version <= 0 || bundle.Scope == "" || bundle.IssuedAt.IsZero() || len(bundle.Rules) == 0 {
		return fmt.Errorf("complete policy bundle identity, scope, issue time and rules are required")
	}
	for _, rule := range bundle.Rules {
		if rule.RecipeID == "" || rule.TargetClass == "" || (!rule.Allow && len(rule.Denials) == 0) {
			return fmt.Errorf("policy rules require recipe, target class and denial reasons")
		}
	}

	return nil
}

func validateEvaluationRequest(request EvaluationRequest) error {
	if request.TenantID == "" || request.ActorID == "" || request.Scope == "" ||
		request.RecipeID == "" || request.TargetClass == "" {
		return fmt.Errorf("complete policy evaluation identity and target are required")
	}
	switch request.Phase {
	case PhaseTrigger, PhaseCandidate, PhaseExecution, PhaseDisclosure:
		return nil
	default:
		return fmt.Errorf("policy evaluation phase is invalid")
	}
}

func matchingRule(rules []Rule, recipeID, targetClass string) (Rule, error) {
	for _, rule := range rules {
		if rule.RecipeID == recipeID && rule.TargetClass == targetClass {
			return rule, nil
		}
	}

	return Rule{}, ErrNoMatchingRule
}

func bundleSigningPayload(bundle Bundle) ([]byte, error) {
	bundle.Signature = nil
	payload, err := json.Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("encode policy bundle: %w", err)
	}

	return payload, nil
}

func evaluationDigest(request EvaluationRequest) (string, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("encode policy input: %w", err)
	}
	digest := sha256.Sum256(payload)

	return hex.EncodeToString(digest[:]), nil
}

func cloneMap(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}

	return result
}

func newDecisionID() (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate policy decision id: %w", err)
	}

	return "decision-" + hex.EncodeToString(random), nil
}
