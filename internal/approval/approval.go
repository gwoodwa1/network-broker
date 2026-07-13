package approval

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrNotFound        = errors.New("approval grant was not found")
	ErrExhausted       = errors.New("approval grant is exhausted")
	ErrExpired         = errors.New("approval grant has expired")
	ErrBindingMismatch = errors.New("approval grant binding does not match")
)

// Grant models a durable, scoped approval for bounded use of a recipe.
type Grant struct {
	GrantID          string
	TenantID         string
	RecipeID         string
	TargetSubsetHash string
	MaxUses          int
	Used             int
	ExpiresAt        time.Time
	CreatedBy        string
	PolicyDecisionID string
	Version          int64
	CreatedAt        time.Time
}

type CreateRequest struct {
	GrantID          string
	TenantID         string
	RecipeID         string
	TargetSubsetHash string
	MaxUses          int
	ExpiresAt        time.Time
	CreatedBy        string
	PolicyDecisionID string
}

type ConsumeRequest struct {
	ConsumptionID    string
	GrantID          string
	TenantID         string
	RecipeID         string
	TargetSubsetHash string
	TaskID           string
	ActorID          string
	Now              time.Time
}

type Repository interface {
	Create(context.Context, CreateRequest) (Grant, error)
	Get(context.Context, string, string) (Grant, error)
	Consume(context.Context, ConsumeRequest) (Grant, error)
}

type Service struct {
	repository Repository
	legacy     *MemoryRepository
}

// NewService retains the deterministic local scaffold API.
func NewService() *Service {
	repository := NewMemoryRepository()

	return &Service{repository: repository, legacy: repository}
}

func NewServiceWithRepository(repository Repository) (*Service, error) {
	if repository == nil {
		return nil, fmt.Errorf("approval repository is required")
	}

	return &Service{repository: repository}, nil
}

// Create is retained for local scaffolds. Production callers use CreateContext
// and provide expiry, actor and policy provenance.
func (s *Service) Create(grantID, tenantID, recipeID, targetSubsetHash string, maxUses int) (*Grant, error) {
	grant, err := s.CreateContext(context.Background(), CreateRequest{
		GrantID: grantID, TenantID: tenantID, RecipeID: recipeID,
		TargetSubsetHash: targetSubsetHash, MaxUses: maxUses,
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour), CreatedBy: "local-scaffold",
		PolicyDecisionID: "local-scaffold",
	})
	if err != nil {
		return nil, err
	}

	return &grant, nil
}

func (s *Service) CreateContext(ctx context.Context, request CreateRequest) (Grant, error) {
	if err := validateCreate(request); err != nil {
		return Grant{}, err
	}

	return s.repository.Create(ctx, request)
}

// Consume is retained for local tests that predate bound consumption records.
func (s *Service) Consume(grantID string) error {
	if s.legacy == nil {
		return fmt.Errorf("legacy approval consumption is unavailable for durable repositories")
	}

	return s.legacy.ConsumeLegacy(grantID)
}

func (s *Service) ConsumeContext(ctx context.Context, request ConsumeRequest) (Grant, error) {
	if err := validateConsume(request); err != nil {
		return Grant{}, err
	}

	return s.repository.Consume(ctx, request)
}

type MemoryRepository struct {
	mu     sync.Mutex
	grants map[string]Grant
	uses   map[string]string
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{grants: make(map[string]Grant), uses: make(map[string]string)}
}

func (r *MemoryRepository) Create(_ context.Context, request CreateRequest) (Grant, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.grants[request.GrantID]; exists {
		return Grant{}, fmt.Errorf("approval grant already exists")
	}
	grant := Grant{
		GrantID: request.GrantID, TenantID: request.TenantID, RecipeID: request.RecipeID,
		TargetSubsetHash: request.TargetSubsetHash, MaxUses: request.MaxUses,
		ExpiresAt: request.ExpiresAt.UTC(), CreatedBy: request.CreatedBy,
		PolicyDecisionID: request.PolicyDecisionID, Version: 1, CreatedAt: time.Now().UTC(),
	}
	r.grants[grant.GrantID] = grant

	return grant, nil
}

func (r *MemoryRepository) Get(_ context.Context, tenantID, grantID string) (Grant, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	grant, ok := r.grants[grantID]
	if !ok || grant.TenantID != tenantID {
		return Grant{}, ErrNotFound
	}

	return grant, nil
}

func (r *MemoryRepository) Consume(_ context.Context, request ConsumeRequest) (Grant, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	grant, ok := r.grants[request.GrantID]
	if !ok || grant.TenantID != request.TenantID {
		return Grant{}, ErrNotFound
	}
	if existingGrant, exists := r.uses[request.ConsumptionID]; exists {
		if existingGrant == request.GrantID {
			return grant, nil
		}
		return Grant{}, ErrBindingMismatch
	}
	if grant.RecipeID != request.RecipeID || grant.TargetSubsetHash != request.TargetSubsetHash {
		return Grant{}, ErrBindingMismatch
	}
	if !request.Now.Before(grant.ExpiresAt) {
		return Grant{}, ErrExpired
	}
	if grant.Used >= grant.MaxUses {
		return Grant{}, ErrExhausted
	}
	grant.Used++
	grant.Version++
	r.grants[grant.GrantID] = grant
	r.uses[request.ConsumptionID] = request.GrantID

	return grant, nil
}

func (r *MemoryRepository) ConsumeLegacy(grantID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	grant, ok := r.grants[grantID]
	if !ok {
		return fmt.Errorf("approval grant %q not found", grantID)
	}
	if grant.Used >= grant.MaxUses {
		return fmt.Errorf("approval grant %q is exhausted", grantID)
	}
	grant.Used++
	grant.Version++
	r.grants[grantID] = grant

	return nil
}

func validateCreate(request CreateRequest) error {
	if request.GrantID == "" || request.TenantID == "" || request.RecipeID == "" ||
		request.TargetSubsetHash == "" || request.MaxUses <= 0 || request.ExpiresAt.IsZero() ||
		request.CreatedBy == "" || request.PolicyDecisionID == "" {
		return fmt.Errorf("complete approval identity, bounds, expiry, actor and policy provenance are required")
	}

	return nil
}

func validateConsume(request ConsumeRequest) error {
	if request.ConsumptionID == "" || request.GrantID == "" || request.TenantID == "" ||
		request.RecipeID == "" || request.TargetSubsetHash == "" || request.TaskID == "" ||
		request.ActorID == "" || request.Now.IsZero() {
		return fmt.Errorf("complete approval consumption identity and bindings are required")
	}

	return nil
}
