package resolution

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"network_broker/internal/outbox"
)

const (
	resolutionEventSchemaVersion = "v1"
	maximumRequestDocumentSize   = 64 * 1024
)

// Repository provides the atomic operations required by the resolution
// workflow. Create and Transition must commit their outbox event in the same
// transaction as authoritative state.
type Repository interface {
	Create(context.Context, Resolution, outbox.Event) (Resolution, bool, error)
	Get(context.Context, string, string) (Resolution, error)
	Transition(context.Context, string, string, int64, ResolutionState, ResolutionState, time.Time, outbox.Event) (Resolution, error)
}

// CreateRequest is the server-validated input used to establish an idempotent
// asynchronous workflow.
type CreateRequest struct {
	ActorID         string
	TenantID        string
	IdempotencyKey  string
	RequestDigest   string
	RequestDocument []byte
}

// CreateResult distinguishes a new workflow from an idempotent replay.
type CreateResult struct {
	Resolution Resolution
	Created    bool
}

// TransitionRequest carries the compare-and-set version supplied by a worker
// that previously read the resolution.
type TransitionRequest struct {
	TenantID        string
	ResolutionID    string
	ExpectedVersion int64
	NextState       ResolutionState
}

// Service manages the lifecycle of evidence resolutions.
type Service struct {
	repository Repository
	now        func() time.Time
	newID      func(string) (string, error)
}

// NewService constructs a concurrency-safe in-memory service for local use.
func NewService() *Service {
	return NewServiceWithRepository(NewMemoryRepository(), time.Now, randomID)
}

// NewServiceWithRepository constructs a service over a durable repository.
func NewServiceWithRepository(repository Repository, now func() time.Time, newID func(string) (string, error)) *Service {
	return &Service{repository: repository, now: now, newID: newID}
}

// Create establishes or replays an idempotent resolution.
func (s *Service) Create(ctx context.Context, request CreateRequest) (CreateResult, error) {
	if err := validateCreateRequest(request); err != nil {
		return CreateResult{}, err
	}
	if err := s.validateDependencies(); err != nil {
		return CreateResult{}, err
	}

	now := s.now().UTC()
	resolutionID, err := s.newID("res")
	if err != nil {
		return CreateResult{}, fmt.Errorf("generate resolution id: %w", err)
	}
	eventID, err := s.newID("evt")
	if err != nil {
		return CreateResult{}, fmt.Errorf("generate resolution event id: %w", err)
	}
	created := Resolution{
		ID: resolutionID, ActorID: request.ActorID, TenantID: request.TenantID,
		IdempotencyKey: request.IdempotencyKey, RequestDigest: request.RequestDigest,
		RequestDocument: append([]byte(nil), request.RequestDocument...),
		State:           ResolutionReceived, Version: 1, CreatedAt: now, UpdatedAt: now,
	}
	event, err := resolutionEvent(eventID, "resolution.received", created, now)
	if err != nil {
		return CreateResult{}, err
	}
	stored, wasCreated, err := s.repository.Create(ctx, created, event)
	if err != nil {
		return CreateResult{}, err
	}

	return CreateResult{Resolution: stored, Created: wasCreated}, nil
}

// Get retrieves a tenant-scoped detached resolution snapshot.
func (s *Service) Get(ctx context.Context, tenantID, resolutionID string) (Resolution, error) {
	if tenantID == "" || resolutionID == "" {
		return Resolution{}, fmt.Errorf("tenant id and resolution id are required")
	}
	if err := s.validateDependencies(); err != nil {
		return Resolution{}, err
	}

	return s.repository.Get(ctx, tenantID, resolutionID)
}

// Transition validates and atomically applies a versioned state change.
func (s *Service) Transition(ctx context.Context, request TransitionRequest) (Resolution, error) {
	if request.TenantID == "" || request.ResolutionID == "" || request.ExpectedVersion <= 0 {
		return Resolution{}, fmt.Errorf("tenant id, resolution id and positive expected version are required")
	}
	if err := s.validateDependencies(); err != nil {
		return Resolution{}, err
	}
	current, err := s.repository.Get(ctx, request.TenantID, request.ResolutionID)
	if err != nil {
		return Resolution{}, err
	}
	if current.Version != request.ExpectedVersion {
		return Resolution{}, ErrVersionConflict
	}
	if err := ValidateTransition(current.State, request.NextState); err != nil {
		return Resolution{}, err
	}

	now := s.now().UTC()
	eventID, err := s.newID("evt")
	if err != nil {
		return Resolution{}, fmt.Errorf("generate transition event id: %w", err)
	}
	next := current
	next.State = request.NextState
	next.Completed = request.NextState.Terminal()
	next.Version++
	next.UpdatedAt = now
	event, err := resolutionEvent(eventID, "resolution.state_changed", next, now)
	if err != nil {
		return Resolution{}, err
	}

	return s.repository.Transition(ctx, request.TenantID, request.ResolutionID,
		request.ExpectedVersion, current.State, request.NextState, now, event)
}

func (s *Service) validateDependencies() error {
	if s == nil || s.repository == nil || s.now == nil || s.newID == nil {
		return fmt.Errorf("resolution service dependencies are required")
	}

	return nil
}

func validateCreateRequest(request CreateRequest) error {
	if request.ActorID == "" || request.TenantID == "" || request.IdempotencyKey == "" || request.RequestDigest == "" ||
		len(request.RequestDocument) == 0 {
		return fmt.Errorf("actor id, tenant id, idempotency key, request digest and request document are required")
	}
	if len(request.IdempotencyKey) > 128 || len(request.RequestDigest) > 128 {
		return fmt.Errorf("idempotency key and request digest must not exceed 128 bytes")
	}
	if len(request.RequestDocument) > maximumRequestDocumentSize || !json.Valid(request.RequestDocument) {
		return fmt.Errorf("request document must be valid JSON and not exceed %d bytes", maximumRequestDocumentSize)
	}
	digest := sha256.Sum256(request.RequestDocument)
	if request.RequestDigest != "sha256:"+hex.EncodeToString(digest[:]) {
		return fmt.Errorf("request digest does not match request document")
	}

	return nil
}

func validateNewResolution(resolution Resolution, event outbox.Event) error {
	if resolution.ID == "" {
		return fmt.Errorf("resolution id is required")
	}
	if err := validateCreateRequest(CreateRequest{
		ActorID: resolution.ActorID, TenantID: resolution.TenantID,
		IdempotencyKey: resolution.IdempotencyKey, RequestDigest: resolution.RequestDigest,
		RequestDocument: resolution.RequestDocument,
	}); err != nil {
		return err
	}
	if resolution.State != ResolutionReceived || resolution.Version != 1 || resolution.Completed {
		return fmt.Errorf("new resolution must be active in received state at version 1")
	}
	if resolution.CreatedAt.IsZero() || resolution.UpdatedAt.Before(resolution.CreatedAt) {
		return fmt.Errorf("valid resolution creation and update times are required")
	}

	return validateEventBinding(event, resolution.TenantID, resolution.ID)
}

func validateEventBinding(event outbox.Event, tenantID, resolutionID string) error {
	if err := event.Validate(); err != nil {
		return err
	}
	if event.TenantID != tenantID || event.AggregateType != "resolution" || event.AggregateID != resolutionID {
		return fmt.Errorf("outbox event does not match resolution tenant and aggregate")
	}

	return nil
}

func resolutionEvent(eventID, eventType string, resolution Resolution, occurredAt time.Time) (outbox.Event, error) {
	eventPayload := struct {
		SchemaVersion   string          `json:"schema_version"`
		ResolutionID    string          `json:"resolution_id"`
		State           ResolutionState `json:"state"`
		Version         int64           `json:"version"`
		RequestDigest   string          `json:"request_digest,omitempty"`
		RequestDocument json.RawMessage `json:"request_document,omitempty"`
	}{
		SchemaVersion: resolutionEventSchemaVersion, ResolutionID: resolution.ID,
		State: resolution.State, Version: resolution.Version,
	}
	if eventType == "resolution.received" {
		eventPayload.RequestDigest = resolution.RequestDigest
		eventPayload.RequestDocument = append(json.RawMessage(nil), resolution.RequestDocument...)
	}
	payload, err := json.Marshal(eventPayload)
	if err != nil {
		return outbox.Event{}, fmt.Errorf("encode resolution event: %w", err)
	}

	return outbox.Event{
		ID: eventID, TenantID: resolution.TenantID, AggregateType: "resolution",
		AggregateID: resolution.ID, Type: eventType, Payload: payload, OccurredAt: occurredAt,
	}, nil
}

func randomID(prefix string) (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}

	return prefix + "-" + hex.EncodeToString(value), nil
}
