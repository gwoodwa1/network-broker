package resolution

import (
	"fmt"
	"time"
)

// Service manages the lifecycle of evidence resolutions.
type Service struct {
	resolutions map[string]*Resolution
}

// NewService constructs a new resolution service.
func NewService() *Service {
	return &Service{resolutions: make(map[string]*Resolution)}
}

// Create stores a new resolution and returns it.
func (s *Service) Create(actorID, tenantID string) (*Resolution, error) {
	if actorID == "" || tenantID == "" {
		return nil, fmt.Errorf("actor id and tenant id are required")
	}
	res := &Resolution{ID: fmt.Sprintf("res-%d", time.Now().UnixNano()), ActorID: actorID, TenantID: tenantID, State: ResolutionReceived}
	s.resolutions[res.ID] = res
	return res, nil
}

// Get retrieves a resolution by id.
func (s *Service) Get(id string) (*Resolution, error) {
	res, ok := s.resolutions[id]
	if !ok {
		return nil, fmt.Errorf("resolution %q not found", id)
	}
	return res, nil
}

// Update transitions a resolution to a new state.
func (s *Service) Update(id string, next ResolutionState) error {
	res, err := s.Get(id)
	if err != nil {
		return err
	}
	return res.Transition(next)
}
