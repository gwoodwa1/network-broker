package approval

import "fmt"

// Grant models a scoped approval for a bounded use of a recipe.
type Grant struct {
	GrantID          string
	TenantID         string
	RecipeID         string
	TargetSubsetHash string
	MaxUses          int
	Used             int
}

// Service tracks approval grants.
type Service struct {
	grants map[string]*Grant
}

// NewService constructs a new approval service.
func NewService() *Service {
	return &Service{grants: make(map[string]*Grant)}
}

// Create creates and stores a grant.
func (s *Service) Create(grantID, tenantID, recipeID, targetSubsetHash string, maxUses int) (*Grant, error) {
	if grantID == "" || tenantID == "" || recipeID == "" || targetSubsetHash == "" {
		return nil, fmt.Errorf("grant id, tenant id, recipe id and target subset hash are required")
	}
	if maxUses <= 0 {
		return nil, fmt.Errorf("max uses must be positive")
	}
	grant := &Grant{GrantID: grantID, TenantID: tenantID, RecipeID: recipeID, TargetSubsetHash: targetSubsetHash, MaxUses: maxUses}
	s.grants[grantID] = grant
	return grant, nil
}

// Consume decrements the remaining uses if available.
func (s *Service) Consume(grantID string) error {
	grant, ok := s.grants[grantID]
	if !ok {
		return fmt.Errorf("approval grant %q not found", grantID)
	}
	if grant.Used >= grant.MaxUses {
		return fmt.Errorf("approval grant %q is exhausted", grantID)
	}
	grant.Used++
	return nil
}
