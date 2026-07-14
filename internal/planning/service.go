// Package planning connects an authenticated planning workload to atomic
// collector-task fan-out without allowing it to choose tenant or event
// authority.
package planning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"network_broker/internal/authctx"
	"network_broker/internal/collector"
	"network_broker/internal/outbox"
)

const (
	queueScope              = "resolutions:plan"
	queueEventSchemaVersion = "v1"
	maximumTasksPerRequest  = 1_000
)

var (
	// ErrDenied means the authenticated workload lacks planning authority.
	ErrDenied = errors.New("planning authority denied")
	// ErrInvalidRequest means the planning request is incomplete or unbounded.
	ErrInvalidRequest = errors.New("invalid planning request")
)

// FanoutRepository is the atomic durable boundary used to queue a complete
// plan and its event.
type FanoutRepository interface {
	CreateFanoutContext(context.Context, collector.FanoutRequest) error
}

// QueueRequest contains a server-validated plan for one resolution. Tenant,
// resolution and initial task state are assigned by the service.
type QueueRequest struct {
	ResolutionID              string
	ExpectedResolutionVersion int64
	Tasks                     []collector.Task
}

// QueueResult is the stable acknowledgement returned to a planner.
type QueueResult struct {
	ResolutionID string `json:"resolution_id"`
	Version      int64  `json:"version"`
	TaskCount    int    `json:"task_count"`
}

// Service authorizes and submits complete planned task sets.
type Service struct {
	repository FanoutRepository
	now        func() time.Time
	newID      func(string) (string, error)
}

// NewService constructs a planning service with explicit durable authority,
// clock and identifier dependencies.
func NewService(repository FanoutRepository, now func() time.Time,
	newID func(string) (string, error),
) (*Service, error) {
	if repository == nil || now == nil || newID == nil {
		return nil, fmt.Errorf("planning repository, clock and identifier generator are required")
	}

	return &Service{repository: repository, now: now, newID: newID}, nil
}

// Queue binds the plan to the authenticated tenant and atomically makes it
// available to collectors.
func (s *Service) Queue(ctx context.Context, actor authctx.AuthContext,
	request QueueRequest,
) (QueueResult, error) {
	if err := actor.Validate(); err != nil {
		return QueueResult{}, fmt.Errorf("%w: %w", ErrDenied, err)
	}
	if !slices.Contains(actor.AllowedScopes, queueScope) {
		return QueueResult{}, ErrDenied
	}
	if request.ResolutionID == "" || request.ExpectedResolutionVersion <= 0 ||
		len(request.Tasks) == 0 || len(request.Tasks) > maximumTasksPerRequest {
		return QueueResult{}, ErrInvalidRequest
	}

	tasks := make([]collector.Task, len(request.Tasks))
	copy(tasks, request.Tasks)
	for index := range tasks {
		if (tasks[index].TenantID != "" && tasks[index].TenantID != actor.TenantID) ||
			(tasks[index].ResolutionID != "" && tasks[index].ResolutionID != request.ResolutionID) {
			return QueueResult{}, fmt.Errorf("%w: task authority override", ErrInvalidRequest)
		}
		tasks[index].TenantID = actor.TenantID
		tasks[index].ResolutionID = request.ResolutionID
		tasks[index].State = collector.TaskQueued
	}

	queuedAt := s.now().UTC()
	if queuedAt.IsZero() {
		return QueueResult{}, fmt.Errorf("planning clock returned zero time")
	}
	eventID, err := s.newID("evt")
	if err != nil {
		return QueueResult{}, fmt.Errorf("generate planning event id: %w", err)
	}
	eventPayload := struct {
		SchemaVersion string `json:"schema_version"`
		ResolutionID  string `json:"resolution_id"`
		Version       int64  `json:"version"`
		TaskCount     int    `json:"task_count"`
	}{
		SchemaVersion: queueEventSchemaVersion,
		ResolutionID:  request.ResolutionID,
		Version:       request.ExpectedResolutionVersion + 1,
		TaskCount:     len(tasks),
	}
	payload, err := json.Marshal(eventPayload)
	if err != nil {
		return QueueResult{}, fmt.Errorf("encode planning event: %w", err)
	}
	err = s.repository.CreateFanoutContext(ctx, collector.FanoutRequest{
		TenantID: actor.TenantID, ResolutionID: request.ResolutionID,
		ExpectedResolutionVersion: request.ExpectedResolutionVersion,
		Tasks:                     tasks, QueuedAt: queuedAt,
		Event: outbox.Event{
			ID: eventID, TenantID: actor.TenantID, AggregateType: "resolution",
			AggregateID: request.ResolutionID, Type: "resolution.tasks_queued",
			Payload: payload, OccurredAt: queuedAt,
		},
	})
	if err != nil {
		return QueueResult{}, err
	}

	return QueueResult{
		ResolutionID: request.ResolutionID,
		Version:      request.ExpectedResolutionVersion + 1, TaskCount: len(tasks),
	}, nil
}
