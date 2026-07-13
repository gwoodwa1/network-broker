// Package grants issues and exchanges collector execution grants.
package grants

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrInvalidSignature = errors.New("execution grant signature is invalid")
	ErrNotCurrent       = errors.New("execution grant is not currently valid")
	ErrBindingMismatch  = errors.New("execution grant binding does not match")
	ErrStaleFence       = errors.New("execution grant fencing token is stale")
	ErrAlreadyConsumed  = errors.New("execution grant has already been consumed")
)

// ExecutionGrant contains immutable authority to contact exactly one target
// with one catalogue recipe. It intentionally contains no rendered command or
// target credential.
type ExecutionGrant struct {
	GrantID              string
	Nonce                string
	TenantID             string
	CollectorSPIFFEID    string
	ResolutionID         string
	TaskID               string
	TargetSnapshotID     string
	TargetSnapshotDigest string
	TargetID             string
	RecipeID             string
	RecipeVersion        string
	ParameterDigest      string
	FencingToken         int64
	TriggerDecisionID    string
	PlanningDecisionID   string
	ExecutionDecisionID  string
	ApprovalGrantID      string
	Audience             string
	NotBefore            time.Time
	ExpiresAt            time.Time
	MaximumDuration      time.Duration
	MaximumResponseBytes int64
	CredentialClass      string
	SingleUse            bool
	Issuer               string
	Signature            []byte
}

// ExchangeRequest is independently populated by the credential broker from
// the authenticated connection and requested task, not copied from the grant.
type ExchangeRequest struct {
	PresentingSPIFFEID string
	TaskID             string
	TargetID           string
	RecipeID           string
	RecipeVersion      string
	FencingToken       int64
	Now                time.Time
}

// SessionCredential is an opaque, short-lived credential scoped to the
// verified grant. Token must not be persisted in task or evidence records.
type SessionCredential struct {
	Token           string
	GrantID         string
	CollectorID     string
	TargetID        string
	RecipeID        string
	RecipeVersion   string
	FencingToken    int64
	ExpiresAt       time.Time
	CredentialClass string
}

// FenceReader returns the current fencing token for a task.
type FenceReader interface {
	CurrentFence(taskID string) (int64, error)
}

// Authority signs grants and atomically exchanges valid grants for credentials.
type Authority struct {
	issuer   string
	audience string
	private  ed25519.PrivateKey
	public   ed25519.PublicKey
	fences   FenceReader

	mu       sync.Mutex
	consumed map[string]struct{}
}

func NewAuthority(issuer, audience string, private ed25519.PrivateKey, fences FenceReader) (*Authority, error) {
	if issuer == "" || audience == "" || len(private) != ed25519.PrivateKeySize || fences == nil {
		return nil, fmt.Errorf("issuer, audience, private key and fence reader are required")
	}
	public, ok := private.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("derive ed25519 public key")
	}
	return &Authority{issuer: issuer, audience: audience, private: private, public: public, fences: fences, consumed: make(map[string]struct{})}, nil
}

// Issue validates and signs a grant. Server-owned issuer and audience values
// replace any caller-provided values.
func (a *Authority) Issue(grant ExecutionGrant) (ExecutionGrant, error) {
	grant.Issuer = a.issuer
	grant.Audience = a.audience
	grant.Signature = nil
	if err := validateGrant(grant); err != nil {
		return ExecutionGrant{}, err
	}
	payload, err := signingPayload(grant)
	if err != nil {
		return ExecutionGrant{}, err
	}
	grant.Signature = ed25519.Sign(a.private, payload)
	return grant, nil
}

// Exchange verifies all bindings and consumes a single-use grant atomically.
func (a *Authority) Exchange(grant ExecutionGrant, request ExchangeRequest) (SessionCredential, error) {
	if request.Now.IsZero() {
		return SessionCredential{}, fmt.Errorf("exchange time is required")
	}
	payload, err := signingPayload(grant)
	if err != nil || !ed25519.Verify(a.public, payload, grant.Signature) {
		return SessionCredential{}, ErrInvalidSignature
	}
	if grant.Issuer != a.issuer || grant.Audience != a.audience || request.Now.Before(grant.NotBefore) || !request.Now.Before(grant.ExpiresAt) {
		return SessionCredential{}, ErrNotCurrent
	}
	if request.PresentingSPIFFEID != grant.CollectorSPIFFEID || request.TaskID != grant.TaskID ||
		request.TargetID != grant.TargetID || request.RecipeID != grant.RecipeID ||
		request.RecipeVersion != grant.RecipeVersion || request.FencingToken != grant.FencingToken {
		return SessionCredential{}, ErrBindingMismatch
	}
	currentFence, err := a.fences.CurrentFence(grant.TaskID)
	if err != nil {
		return SessionCredential{}, fmt.Errorf("read current fence: %w", err)
	}
	if currentFence != grant.FencingToken {
		return SessionCredential{}, ErrStaleFence
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.consumed[grant.Nonce]; grant.SingleUse && exists {
		return SessionCredential{}, ErrAlreadyConsumed
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return SessionCredential{}, fmt.Errorf("mint session credential: %w", err)
	}
	if grant.SingleUse {
		a.consumed[grant.Nonce] = struct{}{}
	}
	return SessionCredential{
		Token: hex.EncodeToString(tokenBytes), GrantID: grant.GrantID,
		CollectorID: grant.CollectorSPIFFEID, TargetID: grant.TargetID,
		RecipeID: grant.RecipeID, RecipeVersion: grant.RecipeVersion,
		FencingToken: grant.FencingToken, ExpiresAt: grant.ExpiresAt,
		CredentialClass: grant.CredentialClass,
	}, nil
}

func validateGrant(grant ExecutionGrant) error {
	if grant.GrantID == "" || grant.Nonce == "" || grant.TenantID == "" || grant.CollectorSPIFFEID == "" ||
		grant.TaskID == "" || grant.TargetID == "" || grant.RecipeID == "" || grant.RecipeVersion == "" ||
		grant.Issuer == "" || grant.Audience == "" {
		return fmt.Errorf("grant identity and binding fields are required")
	}
	if grant.FencingToken <= 0 || grant.MaximumDuration <= 0 || grant.MaximumResponseBytes <= 0 {
		return fmt.Errorf("positive fence, duration and response byte limit are required")
	}
	if grant.NotBefore.IsZero() || !grant.ExpiresAt.After(grant.NotBefore) {
		return fmt.Errorf("grant validity window is invalid")
	}
	return nil
}

func signingPayload(grant ExecutionGrant) ([]byte, error) {
	grantCopy := grant
	grantCopy.Signature = nil
	payload, err := json.Marshal(grantCopy)
	if err != nil {
		return nil, fmt.Errorf("encode execution grant: %w", err)
	}
	return payload, nil
}
