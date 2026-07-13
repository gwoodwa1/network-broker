// Package deadletter provides tenant-scoped inspection and audited replay of
// terminal outbox delivery failures.
package deadletter

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"network_broker/internal/authctx"
)

const (
	OperatorRole                = "outbox-operator"
	ReadScope                   = "outbox:dead-letter:read"
	ReplayScope                 = "outbox:dead-letter:replay"
	maximumReplayReasonLength   = 512
	maximumIdempotencyKeyLength = 128
	maximumEventIDLength        = 256
)

var (
	ErrNotFound       = errors.New("dead-lettered outbox event was not found")
	ErrReplayConflict = errors.New("dead-letter replay idempotency conflict")
	ErrDenied         = errors.New("dead-letter operator authorization denied")
	ErrInvalidInput   = errors.New("dead-letter operator input is invalid")
)

// Entry is secret-safe dead-letter metadata. Event payload and raw broker
// errors are deliberately excluded from operator responses.
type Entry struct {
	Sequence       int64     `json:"sequence"`
	EventID        string    `json:"event_id"`
	AggregateType  string    `json:"aggregate_type"`
	AggregateID    string    `json:"aggregate_id"`
	EventType      string    `json:"event_type"`
	OccurredAt     time.Time `json:"occurred_at"`
	Attempts       int       `json:"attempts"`
	DeadLetteredAt time.Time `json:"dead_lettered_at"`
}

// ReplayCommand contains only server-derived identity and validated operator
// intent. The repository obtains timestamps from the database transaction.
type ReplayCommand struct {
	ActionID         string
	TenantID         string
	EventID          string
	ActorID          string
	SPIFFEID         string
	IdentityRevision string
	IdempotencyKey   string
	Reason           string
}

// ReplayResult identifies the immutable action and whether this call applied
// the replay or returned an existing idempotent result.
type ReplayResult struct {
	ActionID    string    `json:"action_id"`
	EventID     string    `json:"event_id"`
	RequestedAt time.Time `json:"requested_at"`
	AvailableAt time.Time `json:"available_at"`
	Replayed    bool      `json:"replayed"`
}

// Repository is separate from the delivery Store so dispatcher credentials
// and operational credentials can be least-privileged independently.
type Repository interface {
	List(context.Context, string, int64, int) ([]Entry, error)
	Get(context.Context, string, string) (Entry, error)
	Replay(context.Context, ReplayCommand) (ReplayResult, error)
}

// Service authorizes operator actions before accessing durable state.
type Service struct {
	repository Repository
	newID      func(string) (string, error)
}

func NewService(repository Repository, newID func(string) (string, error)) (*Service, error) {
	if repository == nil || newID == nil {
		return nil, fmt.Errorf("dead-letter repository and id generator are required")
	}

	return &Service{repository: repository, newID: newID}, nil
}

func (s *Service) List(ctx context.Context, actor authctx.AuthContext, beforeSequence int64, limit int) ([]Entry, error) {
	if err := authorize(actor, ReadScope); err != nil {
		return nil, err
	}
	if beforeSequence < 0 || limit <= 0 || limit > 100 {
		return nil, fmt.Errorf("%w: cursor must be nonnegative and limit must be between 1 and 100", ErrInvalidInput)
	}

	return s.repository.List(ctx, actor.TenantID, beforeSequence, limit)
}

func (s *Service) Get(ctx context.Context, actor authctx.AuthContext, eventID string) (Entry, error) {
	if err := authorize(actor, ReadScope); err != nil {
		return Entry{}, err
	}
	if err := validateEventID(eventID); err != nil {
		return Entry{}, err
	}

	return s.repository.Get(ctx, actor.TenantID, eventID)
}

func (s *Service) Replay(ctx context.Context, actor authctx.AuthContext, eventID,
	idempotencyKey, reason string,
) (ReplayResult, error) {
	if err := authorize(actor, ReplayScope); err != nil {
		return ReplayResult{}, err
	}
	if err := validateEventID(eventID); err != nil {
		return ReplayResult{}, err
	}
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	reason = strings.TrimSpace(reason)
	if idempotencyKey == "" || len(idempotencyKey) > maximumIdempotencyKeyLength ||
		reason == "" || len(reason) > maximumReplayReasonLength {
		return ReplayResult{}, fmt.Errorf("%w: idempotency key up to 128 bytes and reason up to 512 bytes are required", ErrInvalidInput)
	}
	actionID, err := s.newID("dead-letter-action")
	if err != nil {
		return ReplayResult{}, fmt.Errorf("generate dead-letter action id: %w", err)
	}

	return s.repository.Replay(ctx, ReplayCommand{
		ActionID: actionID, TenantID: actor.TenantID, EventID: eventID,
		ActorID: actor.SubjectID, SPIFFEID: actor.SPIFFEID, IdentityRevision: actor.IdentityRevision,
		IdempotencyKey: idempotencyKey, Reason: reason,
	})
}

func authorize(actor authctx.AuthContext, scope string) error {
	if err := actor.Validate(); err != nil || actor.SPIFFEID == "" || actor.IdentityRevision == "" ||
		!containsExact(actor.Roles, OperatorRole) || !containsExact(actor.AllowedScopes, scope) {
		return ErrDenied
	}

	return nil
}

func validateEventID(eventID string) error {
	if eventID == "" || len(eventID) > maximumEventIDLength || strings.TrimSpace(eventID) != eventID ||
		strings.ContainsAny(eventID, "/\\\x00\r\n\t") {
		return fmt.Errorf("%w: event id is invalid", ErrInvalidInput)
	}

	return nil
}

func containsExact(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}

	return false
}
