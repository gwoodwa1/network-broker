package collector

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// PostgresRepository persists the collector's authoritative lease, fencing
// and accepted-result state. Every state change is a single guarded UPDATE so
// a process restart cannot revive stale ownership.
type PostgresRepository struct {
	database *sql.DB
}

func NewPostgresRepository(database *sql.DB) (*PostgresRepository, error) {
	if database == nil {
		return nil, fmt.Errorf("collector task database is required")
	}

	return &PostgresRepository{database: database}, nil
}

func (r *PostgresRepository) AddContext(ctx context.Context, task Task) error {
	if r == nil || r.database == nil {
		return fmt.Errorf("collector task database is required")
	}
	if err := validateDurableTask(task); err != nil {
		return err
	}
	if task.State == "" {
		task.State = TaskQueued
	}
	if task.State != TaskQueued {
		return fmt.Errorf("%w: new task must be queued", ErrInvalidState)
	}
	_, err := r.database.ExecContext(ctx, `
		INSERT INTO broker_collector_tasks (
			id, tenant_id, resolution_id, claim_fingerprint, target_snapshot_id,
			target_snapshot_hash, target_id, target_endpoint, recipe_id, recipe_version,
			trigger_decision_id, planning_decision_id, approval_grant_id, compatibility_hash, state
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), $9, $10, $11, $12,
			NULLIF($13, ''), $14, $15)`,
		task.ID, task.TenantID, task.ResolutionID, task.ClaimFingerprint, task.TargetSnapshotID,
		task.TargetSnapshotHash, task.TargetID, task.TargetEndpoint, task.RecipeID, task.RecipeVersion,
		task.TriggerDecisionID, task.PlanningDecisionID, task.ApprovalGrantID, task.CompatibilityHash,
		task.State,
	)
	if err != nil {
		return fmt.Errorf("insert collector task: %w", err)
	}

	return nil
}

func (r *PostgresRepository) AcquireContext(ctx context.Context, taskID, owner string, now time.Time,
	duration time.Duration,
) (Lease, error) {
	if r == nil || r.database == nil {
		return Lease{}, fmt.Errorf("collector task database is required")
	}
	if err := validateLeaseInput(taskID, owner, now, duration); err != nil {
		return Lease{}, err
	}
	task, err := scanTask(r.database.QueryRowContext(ctx, `
		UPDATE broker_collector_tasks
		SET state = 'leased', lease_owner = $2,
			lease_expiry = $3 + ($4 * INTERVAL '1 microsecond'),
			fencing_token = fencing_token + 1, attempt_count = attempt_count + 1,
			execution_decision_id = NULL, execution_grant_id = NULL, last_error = NULL,
			updated_at = $3
		WHERE id = $1 AND (
			state IN ('queued', 'retry_wait') OR
			(state IN ('leased', 'executing', 'committing') AND lease_expiry <= $3)
		)
		RETURNING `+taskColumns,
		taskID, owner, normaliseTime(now), duration.Microseconds()))
	if errors.Is(err, sql.ErrNoRows) {
		return Lease{}, r.classifyAcquire(ctx, taskID, now)
	}
	if err != nil {
		return Lease{}, fmt.Errorf("acquire collector task: %w", err)
	}

	return leaseFor(&task), nil
}

func (r *PostgresRepository) RenewContext(ctx context.Context, taskID, owner string, token int64,
	now time.Time, duration time.Duration,
) (Lease, error) {
	if r == nil || r.database == nil {
		return Lease{}, fmt.Errorf("collector task database is required")
	}
	if err := validateLeaseInput(taskID, owner, now, duration); err != nil || token <= 0 {
		if err != nil {
			return Lease{}, err
		}
		return Lease{}, fmt.Errorf("positive fencing token is required")
	}
	task, err := scanTask(r.database.QueryRowContext(ctx, `
		UPDATE broker_collector_tasks
		SET lease_expiry = $4 + ($5 * INTERVAL '1 microsecond'), updated_at = $4
		WHERE id = $1 AND lease_owner = $2 AND fencing_token = $3
			AND state IN ('leased', 'executing') AND lease_expiry > $4
		RETURNING `+taskColumns,
		taskID, owner, token, normaliseTime(now), duration.Microseconds()))
	if errors.Is(err, sql.ErrNoRows) {
		return r.classifyOwned(ctx, taskID, owner, token, now, TaskLeased, TaskExecuting)
	}
	if err != nil {
		return Lease{}, fmt.Errorf("renew collector task: %w", err)
	}

	return leaseFor(&task), nil
}

func (r *PostgresRepository) StartExecutionContext(ctx context.Context, taskID, owner string, token int64,
	now time.Time,
) error {
	return r.transitionOwned(ctx, taskID, owner, token, now, TaskLeased, TaskExecuting)
}

func (r *PostgresRepository) RecordExecutionAuthorityContext(ctx context.Context, taskID, owner string,
	token int64, decisionID, grantID string, now time.Time,
) error {
	if r == nil || r.database == nil {
		return fmt.Errorf("collector task database is required")
	}
	if decisionID == "" || grantID == "" {
		return fmt.Errorf("execution decision id and grant id are required")
	}
	result, err := r.database.ExecContext(ctx, `
		UPDATE broker_collector_tasks
		SET execution_decision_id = $4, execution_grant_id = $5, updated_at = $6
		WHERE id = $1 AND lease_owner = $2 AND fencing_token = $3
			AND state = 'executing' AND lease_expiry > $6`,
		taskID, owner, token, decisionID, grantID, normaliseTime(now))
	if err != nil {
		return fmt.Errorf("record collector execution authority: %w", err)
	}
	return r.requireChanged(ctx, result, taskID, owner, token, now, TaskExecuting)
}

func (r *PostgresRepository) BeginCommitContext(ctx context.Context, taskID, owner string, token int64,
	now time.Time,
) error {
	return r.transitionOwned(ctx, taskID, owner, token, now, TaskExecuting, TaskCommitting)
}

func (r *PostgresRepository) CommitContext(ctx context.Context, taskID, owner string, token int64,
	attemptID, evidenceID string, now time.Time,
) error {
	if r == nil || r.database == nil {
		return fmt.Errorf("collector task database is required")
	}
	if attemptID == "" || evidenceID == "" {
		return fmt.Errorf("attempt id and evidence id are required")
	}
	result, err := r.database.ExecContext(ctx, `
		UPDATE broker_collector_tasks
		SET accepted_attempt_id = $4, accepted_evidence_id = $5, state = 'succeeded', updated_at = $6
		WHERE id = $1 AND lease_owner = $2 AND fencing_token = $3
			AND state = 'committing' AND lease_expiry > $6
			AND accepted_attempt_id IS NULL AND accepted_evidence_id IS NULL`,
		taskID, owner, token, attemptID, evidenceID, normaliseTime(now))
	if err != nil {
		return fmt.Errorf("commit collector task result: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect collector task commit: %w", err)
	}
	if rows == 1 {
		return nil
	}
	task, err := r.GetContext(ctx, taskID)
	if err != nil {
		return err
	}
	if task.AcceptedAttemptID != "" {
		return ErrDuplicateCommit
	}
	if err := requireLease(&task, owner, token, now); err != nil {
		return err
	}

	return fmt.Errorf("%w: cannot commit task in state %q", ErrInvalidState, task.State)
}

func (r *PostgresRepository) RetryContext(ctx context.Context, taskID, owner string, token int64,
	now time.Time, cause error,
) error {
	if r == nil || r.database == nil {
		return fmt.Errorf("collector task database is required")
	}
	lastError := ""
	if cause != nil {
		lastError = boundedError(cause.Error())
	}
	result, err := r.database.ExecContext(ctx, `
		UPDATE broker_collector_tasks
		SET state = 'retry_wait', lease_owner = NULL, lease_expiry = NULL,
			last_error = NULLIF($4, ''), updated_at = $5
		WHERE id = $1 AND lease_owner = $2 AND fencing_token = $3
			AND state IN ('leased', 'executing', 'committing') AND lease_expiry > $5`,
		taskID, owner, token, lastError, normaliseTime(now))
	if err != nil {
		return fmt.Errorf("return collector task to retry: %w", err)
	}
	return r.requireChanged(ctx, result, taskID, owner, token, now,
		TaskLeased, TaskExecuting, TaskCommitting)
}

func (r *PostgresRepository) GetContext(ctx context.Context, taskID string) (Task, error) {
	if r == nil || r.database == nil || taskID == "" {
		return Task{}, fmt.Errorf("collector task database and id are required")
	}
	task, err := scanTask(r.database.QueryRowContext(ctx, `
		SELECT `+taskColumns+` FROM broker_collector_tasks WHERE id = $1`, taskID))
	if errors.Is(err, sql.ErrNoRows) {
		return Task{}, fmt.Errorf("%w: %q", ErrTaskNotFound, taskID)
	}
	if err != nil {
		return Task{}, fmt.Errorf("get collector task: %w", err)
	}

	return task, nil
}

func (r *PostgresRepository) CurrentFence(taskID string) (int64, error) {
	if r == nil || r.database == nil || taskID == "" {
		return 0, fmt.Errorf("collector task database and id are required")
	}
	var token int64
	err := r.database.QueryRowContext(context.Background(), `
		SELECT fencing_token FROM broker_collector_tasks WHERE id = $1`, taskID).Scan(&token)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("%w: %q", ErrTaskNotFound, taskID)
	}
	if err != nil {
		return 0, fmt.Errorf("get collector task fence: %w", err)
	}

	return token, nil
}

func (r *PostgresRepository) VerifyCurrentAttempt(taskID, collectorID string, fencingToken int64,
	at time.Time,
) error {
	task, err := r.GetContext(context.Background(), taskID)
	if err != nil {
		return err
	}
	if err := requireLease(&task, collectorID, fencingToken, at); err != nil {
		return err
	}
	if task.State != TaskExecuting && task.State != TaskCommitting {
		return fmt.Errorf("%w: cannot assemble evidence in state %q", ErrInvalidState, task.State)
	}

	return nil
}

func (r *PostgresRepository) transitionOwned(ctx context.Context, taskID, owner string, token int64,
	now time.Time, from, to TaskState,
) error {
	if r == nil || r.database == nil {
		return fmt.Errorf("collector task database is required")
	}
	result, err := r.database.ExecContext(ctx, `
		UPDATE broker_collector_tasks SET state = $4, updated_at = $5
		WHERE id = $1 AND lease_owner = $2 AND fencing_token = $3
			AND state = $6 AND lease_expiry > $5`,
		taskID, owner, token, to, normaliseTime(now), from)
	if err != nil {
		return fmt.Errorf("transition collector task: %w", err)
	}
	return r.requireChanged(ctx, result, taskID, owner, token, now, from)
}

func (r *PostgresRepository) requireChanged(ctx context.Context, result sql.Result, taskID, owner string,
	token int64, now time.Time, states ...TaskState,
) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect collector task update: %w", err)
	}
	if rows == 1 {
		return nil
	}
	_, err = r.classifyOwned(ctx, taskID, owner, token, now, states...)

	return err
}

func (r *PostgresRepository) classifyAcquire(ctx context.Context, taskID string, now time.Time) error {
	task, err := r.GetContext(ctx, taskID)
	if err != nil {
		return err
	}
	if (task.State == TaskLeased || task.State == TaskExecuting || task.State == TaskCommitting) &&
		now.Before(task.LeaseExpiry) {
		return ErrLeaseHeld
	}

	return fmt.Errorf("%w: cannot lease task in state %q", ErrInvalidState, task.State)
}

func (r *PostgresRepository) classifyOwned(ctx context.Context, taskID, owner string, token int64,
	now time.Time, states ...TaskState,
) (Lease, error) {
	task, err := r.GetContext(ctx, taskID)
	if err != nil {
		return Lease{}, err
	}
	if err := requireLease(&task, owner, token, now); err != nil {
		return Lease{}, err
	}
	for _, state := range states {
		if task.State == state {
			return Lease{}, ErrStaleFence
		}
	}

	return Lease{}, fmt.Errorf("%w: task is in state %q", ErrInvalidState, task.State)
}

const taskColumns = `id, tenant_id, resolution_id, claim_fingerprint, target_snapshot_id,
	target_snapshot_hash, target_id, COALESCE(target_endpoint, ''), recipe_id, recipe_version,
	trigger_decision_id, planning_decision_id, COALESCE(execution_decision_id, ''),
	COALESCE(execution_grant_id, ''), COALESCE(approval_grant_id, ''), compatibility_hash,
	state, attempt_count, COALESCE(lease_owner, ''), lease_expiry, fencing_token,
	COALESCE(accepted_attempt_id, ''), COALESCE(accepted_evidence_id, ''), COALESCE(last_error, '')`

type taskRowScanner interface {
	Scan(...any) error
}

func scanTask(row taskRowScanner) (Task, error) {
	var task Task
	var leaseExpiry sql.NullTime
	err := row.Scan(
		&task.ID, &task.TenantID, &task.ResolutionID, &task.ClaimFingerprint,
		&task.TargetSnapshotID, &task.TargetSnapshotHash, &task.TargetID, &task.TargetEndpoint,
		&task.RecipeID, &task.RecipeVersion, &task.TriggerDecisionID, &task.PlanningDecisionID,
		&task.ExecutionDecisionID, &task.ExecutionGrantID, &task.ApprovalGrantID,
		&task.CompatibilityHash, &task.State, &task.AttemptCount, &task.LeaseOwner,
		&leaseExpiry, &task.FencingToken, &task.AcceptedAttemptID, &task.AcceptedEvidenceID,
		&task.LastError,
	)
	if leaseExpiry.Valid {
		task.LeaseExpiry = leaseExpiry.Time
	}

	return task, err
}

func validateDurableTask(task Task) error {
	required := []string{
		task.ID, task.TenantID, task.ResolutionID, task.ClaimFingerprint, task.TargetSnapshotID,
		task.TargetSnapshotHash, task.TargetID, task.RecipeID, task.RecipeVersion,
		task.TriggerDecisionID, task.PlanningDecisionID, task.CompatibilityHash,
	}
	for _, value := range required {
		if value == "" || len(value) > 512 {
			return fmt.Errorf("complete bounded collector task authority is required")
		}
	}

	return nil
}

func validateLeaseInput(taskID, owner string, now time.Time, duration time.Duration) error {
	if taskID == "" || owner == "" {
		return fmt.Errorf("task id and lease owner are required")
	}
	if now.IsZero() || duration.Microseconds() <= 0 {
		return fmt.Errorf("lease time and positive microsecond duration are required")
	}

	return nil
}

func normaliseTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Microsecond)
}

func boundedError(value string) string {
	runes := []rune(value)
	if len(runes) > 2048 {
		return string(runes[:2048])
	}

	return value
}

var _ TaskRepository = (*PostgresRepository)(nil)
