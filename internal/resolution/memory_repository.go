package resolution

import (
	"context"
	"fmt"
	"sync"
	"time"

	"network_broker/internal/outbox"
)

type idempotencyRecord struct {
	requestDigest string
	resolutionID  string
}

// MemoryRepository is a concurrency-safe reference implementation of the
// transactional repository contract. Production deployments should use a
// durable adapter.
type MemoryRepository struct {
	mu          sync.Mutex
	resolutions map[string]Resolution
	idempotency map[string]idempotencyRecord
	events      []outbox.Event
}

// NewMemoryRepository constructs an empty repository.
func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{
		resolutions: make(map[string]Resolution),
		idempotency: make(map[string]idempotencyRecord),
	}
}

// Create atomically stores a workflow, idempotency record, and outbox event.
func (r *MemoryRepository) Create(_ context.Context, resolution Resolution, event outbox.Event) (Resolution, bool, error) {
	if r == nil {
		return Resolution{}, false, fmt.Errorf("resolution repository is nil")
	}
	if err := validateNewResolution(resolution, event); err != nil {
		return Resolution{}, false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	key := idempotencyMapKey(resolution.TenantID, resolution.ActorID, resolution.IdempotencyKey)
	if record, exists := r.idempotency[key]; exists {
		if record.requestDigest != resolution.RequestDigest {
			return Resolution{}, false, ErrIdempotencyConflict
		}

		return cloneResolution(r.resolutions[record.resolutionID]), false, nil
	}
	if _, exists := r.resolutions[resolution.ID]; exists {
		return Resolution{}, false, fmt.Errorf("%w: duplicate resolution id", ErrVersionConflict)
	}

	resolution = cloneResolution(resolution)
	r.resolutions[resolution.ID] = resolution
	r.idempotency[key] = idempotencyRecord{requestDigest: resolution.RequestDigest, resolutionID: resolution.ID}
	r.events = append(r.events, event.Clone())

	return cloneResolution(resolution), true, nil
}

// Get returns a tenant-scoped resolution snapshot.
func (r *MemoryRepository) Get(_ context.Context, tenantID, resolutionID string) (Resolution, error) {
	if r == nil {
		return Resolution{}, fmt.Errorf("resolution repository is nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	resolution, exists := r.resolutions[resolutionID]
	if !exists || resolution.TenantID != tenantID {
		return Resolution{}, fmt.Errorf("%w: %q", ErrNotFound, resolutionID)
	}

	return cloneResolution(resolution), nil
}

// Transition performs a compare-and-set update and outbox append atomically.
func (r *MemoryRepository) Transition(_ context.Context, tenantID, resolutionID string, expectedVersion int64,
	expectedState, next ResolutionState, updatedAt time.Time, event outbox.Event,
) (Resolution, error) {
	if r == nil {
		return Resolution{}, fmt.Errorf("resolution repository is nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	resolution, exists := r.resolutions[resolutionID]
	if !exists || resolution.TenantID != tenantID {
		return Resolution{}, fmt.Errorf("%w: %q", ErrNotFound, resolutionID)
	}
	if resolution.Version != expectedVersion || resolution.State != expectedState {
		return Resolution{}, ErrVersionConflict
	}
	if err := ValidateTransition(expectedState, next); err != nil {
		return Resolution{}, err
	}
	if updatedAt.IsZero() || updatedAt.Before(resolution.UpdatedAt) {
		return Resolution{}, fmt.Errorf("resolution update time must not move backwards")
	}
	if err := validateEventBinding(event, tenantID, resolutionID); err != nil {
		return Resolution{}, err
	}
	resolution.State = next
	resolution.Completed = next.Terminal()
	resolution.Version++
	resolution.UpdatedAt = updatedAt
	r.resolutions[resolutionID] = resolution
	r.events = append(r.events, event.Clone())

	return cloneResolution(resolution), nil
}

// PendingEvents returns detached events in commit order. It is intended for
// local dispatchers and repository contract tests.
func (r *MemoryRepository) PendingEvents(limit int) []outbox.Event {
	if r == nil || limit <= 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if limit > len(r.events) {
		limit = len(r.events)
	}
	events := make([]outbox.Event, limit)
	for index := range events {
		events[index] = r.events[index].Clone()
	}

	return events
}

func idempotencyMapKey(tenantID, actorID, key string) string {
	return tenantID + "\x00" + actorID + "\x00" + key
}

func cloneResolution(value Resolution) Resolution {
	value.RequestDocument = append([]byte(nil), value.RequestDocument...)

	return value
}
