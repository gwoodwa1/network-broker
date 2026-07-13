package artefacts

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var (
	ErrLifecycleConflict = errors.New("artefact lifecycle version conflict")
	ErrLifecycleBlocked  = errors.New("artefact lifecycle transition is blocked")
)

type LifecycleState string

const (
	LifecycleActive          LifecycleState = "active"
	LifecyclePendingDeletion LifecycleState = "pending_deletion"
	LifecycleDeleted         LifecycleState = "deleted"
)

type LifecycleAction string

const (
	LifecycleRetain          LifecycleAction = "retain"
	LifecyclePlaceHold       LifecycleAction = "place_hold"
	LifecycleReleaseHold     LifecycleAction = "release_hold"
	LifecycleRequestDeletion LifecycleAction = "request_deletion"
	LifecycleConfirmDeletion LifecycleAction = "confirm_deletion"
)

type Lifecycle struct {
	TenantID    string
	ArtefactID  string
	State       LifecycleState
	RetainUntil *time.Time
	LegalHold   bool
	Version     int64
	UpdatedAt   time.Time
}

type LifecycleCommand struct {
	TenantID        string
	ArtefactID      string
	ExpectedVersion int64
	Action          LifecycleAction
	RetainUntil     *time.Time
	ActorID         string
	Reason          string
}

type LifecycleRepository interface {
	GetLifecycle(context.Context, string, string) (Lifecycle, error)
	ApplyLifecycle(context.Context, LifecycleCommand) (Lifecycle, error)
}

type LifecycleService struct {
	repository LifecycleRepository
}

func NewLifecycleService(repository LifecycleRepository) (*LifecycleService, error) {
	if repository == nil {
		return nil, fmt.Errorf("artefact lifecycle repository is required")
	}

	return &LifecycleService{repository: repository}, nil
}

func (s *LifecycleService) Get(ctx context.Context, tenantID, artefactID string) (Lifecycle, error) {
	if invalidSegment(tenantID) || artefactID == "" {
		return Lifecycle{}, fmt.Errorf("tenant and artefact are required")
	}

	return s.repository.GetLifecycle(ctx, tenantID, artefactID)
}

func (s *LifecycleService) Apply(ctx context.Context, command LifecycleCommand) (Lifecycle, error) {
	if invalidSegment(command.TenantID) || command.ArtefactID == "" || command.ExpectedVersion <= 0 ||
		command.ActorID == "" || command.Reason == "" || len(command.Reason) > 512 {
		return Lifecycle{}, fmt.Errorf("complete lifecycle identity, version, actor and bounded reason are required")
	}
	switch command.Action {
	case LifecycleRetain:
		if command.RetainUntil == nil || command.RetainUntil.IsZero() {
			return Lifecycle{}, fmt.Errorf("retention deadline is required")
		}
	case LifecyclePlaceHold, LifecycleReleaseHold, LifecycleRequestDeletion, LifecycleConfirmDeletion:
		if command.RetainUntil != nil {
			return Lifecycle{}, fmt.Errorf("retention deadline is valid only for retain actions")
		}
	default:
		return Lifecycle{}, fmt.Errorf("lifecycle action is invalid")
	}

	return s.repository.ApplyLifecycle(ctx, command)
}
