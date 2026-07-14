package collector

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ReconcileExpiredEvidenceContext closes the deliberate crash window between
// immutable evidence creation and task commit. It can accept evidence only
// after the owning lease has expired and only while the task still carries the
// same tenant, task, fencing token and execution-grant binding. A concurrent
// reacquisition increments the fence and makes the old envelope ineligible.
func (r *PostgresRepository) ReconcileExpiredEvidenceContext(ctx context.Context,
	evidenceID string, reconciledAt time.Time,
) (Task, error) {
	if r == nil || r.database == nil || evidenceID == "" || reconciledAt.IsZero() {
		return Task{}, fmt.Errorf("collector task database, evidence id and reconciliation time are required")
	}
	var taskID string
	err := r.database.QueryRowContext(ctx, `
		WITH candidate AS (
			SELECT tenant_id, task_id, accepted_attempt_id, fencing_token,
				execution_grant_id, evidence_id
			FROM broker_evidence_envelopes WHERE evidence_id = $1
		)
		UPDATE broker_collector_tasks AS task
		SET accepted_attempt_id = candidate.accepted_attempt_id,
			accepted_evidence_id = candidate.evidence_id,
			state = 'succeeded', updated_at = $2
		FROM candidate
		WHERE task.id = candidate.task_id
			AND task.tenant_id = candidate.tenant_id
			AND task.fencing_token = candidate.fencing_token
			AND task.execution_grant_id = candidate.execution_grant_id
			AND task.state IN ('executing', 'committing')
			AND task.lease_expiry <= $2
			AND task.accepted_attempt_id IS NULL
			AND task.accepted_evidence_id IS NULL
		RETURNING task.id`, evidenceID, normaliseTime(reconciledAt)).Scan(&taskID)
	if err == nil {
		return r.GetContext(ctx, taskID)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Task{}, fmt.Errorf("reconcile expired collector evidence: %w", err)
	}

	return r.classifyEvidenceReconciliation(ctx, evidenceID, reconciledAt)
}

func (r *PostgresRepository) classifyEvidenceReconciliation(ctx context.Context,
	evidenceID string, reconciledAt time.Time,
) (Task, error) {
	var tenantID, taskID, attemptID, grantID string
	var fencingToken int64
	err := r.database.QueryRowContext(ctx, `
		SELECT tenant_id, task_id, accepted_attempt_id, fencing_token, execution_grant_id
		FROM broker_evidence_envelopes WHERE evidence_id = $1`, evidenceID).Scan(
		&tenantID, &taskID, &attemptID, &fencingToken, &grantID)
	if errors.Is(err, sql.ErrNoRows) {
		return Task{}, ErrEvidenceNotFound
	}
	if err != nil {
		return Task{}, fmt.Errorf("classify evidence reconciliation: %w", err)
	}
	task, err := r.GetContext(ctx, taskID)
	if err != nil {
		return Task{}, err
	}
	if task.TenantID != tenantID || task.FencingToken != fencingToken ||
		task.ExecutionGrantID != grantID {
		return Task{}, ErrStaleFence
	}
	if task.AcceptedEvidenceID == evidenceID && task.AcceptedAttemptID == attemptID &&
		task.State == TaskSucceeded {
		return task, nil
	}
	if task.AcceptedEvidenceID != "" || task.AcceptedAttemptID != "" {
		return Task{}, ErrDuplicateCommit
	}
	if reconciledAt.Before(task.LeaseExpiry) {
		return Task{}, ErrLeaseHeld
	}

	return Task{}, fmt.Errorf("%w: cannot reconcile evidence in state %q", ErrInvalidState, task.State)
}
