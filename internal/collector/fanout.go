package collector

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"network_broker/internal/outbox"
)

var ErrFanoutConflict = errors.New("collector task fan-out authority changed")

// FanoutRequest atomically advances one planned resolution to queued, creates
// its complete task set and records the corresponding outbox event.
type FanoutRequest struct {
	TenantID                  string
	ResolutionID              string
	ExpectedResolutionVersion int64
	Tasks                     []Task
	Event                     outbox.Event
	QueuedAt                  time.Time
}

// CreateFanoutContext prevents a resolution from becoming queued without all
// of its tasks and delivery event. A losing concurrent planner receives
// ErrFanoutConflict and cannot create a partial or duplicate task set.
func (r *PostgresRepository) CreateFanoutContext(ctx context.Context,
	request FanoutRequest,
) (err error) {
	if err := validateFanoutRequest(r, request); err != nil {
		return err
	}
	transaction, err := r.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin collector task fan-out: %w", err)
	}
	defer func() {
		if rollbackErr := transaction.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("rollback collector task fan-out: %w", rollbackErr))
		}
	}()

	var version int64
	var state string
	if err := transaction.QueryRowContext(ctx, `
		SELECT version, state FROM broker_resolutions
		WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, request.TenantID,
		request.ResolutionID).Scan(&version, &state); errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: resolution was not found", ErrFanoutConflict)
	} else if err != nil {
		return fmt.Errorf("lock resolution for task fan-out: %w", err)
	}
	if version != request.ExpectedResolutionVersion || state != "planning" {
		return ErrFanoutConflict
	}
	for index := range request.Tasks {
		if err := insertTaskTx(ctx, transaction, request.Tasks[index]); err != nil {
			return err
		}
	}
	result, err := transaction.ExecContext(ctx, `
		UPDATE broker_resolutions
		SET state = 'queued', target_count = $3, version = version + 1, updated_at = $4
		WHERE tenant_id = $1 AND id = $2 AND version = $5 AND state = 'planning'`,
		request.TenantID, request.ResolutionID, len(request.Tasks),
		normaliseTime(request.QueuedAt), request.ExpectedResolutionVersion)
	if err != nil {
		return fmt.Errorf("queue resolution after task fan-out: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect resolution task fan-out: %w", err)
	}
	if rows != 1 {
		return ErrFanoutConflict
	}
	if err := insertFanoutEvent(ctx, transaction, request.Event); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit collector task fan-out: %w", err)
	}

	return nil
}

func validateFanoutRequest(repository *PostgresRepository, request FanoutRequest) error {
	if repository == nil || repository.database == nil || request.TenantID == "" ||
		request.ResolutionID == "" || request.ExpectedResolutionVersion <= 0 ||
		len(request.Tasks) == 0 || len(request.Tasks) > 10_000 || request.QueuedAt.IsZero() {
		return fmt.Errorf("database, resolution authority, bounded tasks and queue time are required")
	}
	if err := validateFanoutTasks(request); err != nil {
		return err
	}

	return validateFanoutEvent(request)
}

func validateFanoutTasks(request FanoutRequest) error {
	seen := make(map[string]struct{}, len(request.Tasks))
	for index := range request.Tasks {
		task := request.Tasks[index]
		if err := validateDurableTask(task); err != nil {
			return fmt.Errorf("validate fan-out task %d: %w", index, err)
		}
		if task.TenantID != request.TenantID || task.ResolutionID != request.ResolutionID ||
			(task.State != "" && task.State != TaskQueued) {
			return fmt.Errorf("fan-out task does not match resolution authority")
		}
		if _, exists := seen[task.ID]; exists {
			return fmt.Errorf("fan-out contains duplicate task id")
		}
		seen[task.ID] = struct{}{}
	}

	return nil
}

func validateFanoutEvent(request FanoutRequest) error {
	if err := request.Event.Validate(); err != nil {
		return err
	}
	if request.Event.TenantID != request.TenantID || request.Event.AggregateType != "resolution" ||
		request.Event.AggregateID != request.ResolutionID ||
		request.Event.Type != "resolution.tasks_queued" ||
		!request.Event.OccurredAt.Equal(request.QueuedAt) {
		return fmt.Errorf("fan-out event does not match resolution authority")
	}

	return nil
}

func insertTaskTx(ctx context.Context, transaction *sql.Tx, task Task) error {
	state := task.State
	if state == "" {
		state = TaskQueued
	}
	_, err := transaction.ExecContext(ctx, `
		INSERT INTO broker_collector_tasks (
			id, tenant_id, resolution_id, claim_fingerprint, target_snapshot_id,
			target_snapshot_hash, target_id, target_endpoint, recipe_id, recipe_version,
			trigger_decision_id, planning_decision_id, approval_grant_id,
			compatibility_hash, state
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), $9, $10, $11,
			$12, NULLIF($13, ''), $14, $15)`,
		task.ID, task.TenantID, task.ResolutionID, task.ClaimFingerprint,
		task.TargetSnapshotID, task.TargetSnapshotHash, task.TargetID, task.TargetEndpoint,
		task.RecipeID, task.RecipeVersion, task.TriggerDecisionID, task.PlanningDecisionID,
		task.ApprovalGrantID, task.CompatibilityHash, state)
	if err != nil {
		return fmt.Errorf("insert fan-out collector task: %w", err)
	}

	return nil
}

func insertFanoutEvent(ctx context.Context, transaction *sql.Tx, event outbox.Event) error {
	result, err := transaction.ExecContext(ctx, `
		INSERT INTO broker_outbox (
			id, tenant_id, aggregate_type, aggregate_id, event_type, payload,
			occurred_at, available_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
		ON CONFLICT (id) DO NOTHING`, event.ID, event.TenantID, event.AggregateType,
		event.AggregateID, event.Type, string(event.Payload), event.OccurredAt)
	if err != nil {
		return fmt.Errorf("insert task fan-out outbox event: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect task fan-out event insert: %w", err)
	}
	if rows == 1 {
		return nil
	}

	return ErrFanoutConflict
}
