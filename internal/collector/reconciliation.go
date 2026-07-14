package collector

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ListExpiredEvidenceCandidatesContext returns a bounded deterministic batch
// whose indexed envelope bindings still match an expired active task. The
// guarded reconciliation update remains the authority check because a task
// may be reacquired after this read.
func (r *PostgresRepository) ListExpiredEvidenceCandidatesContext(ctx context.Context,
	expiredAt time.Time, limit int,
) (candidates []string, err error) {
	if r == nil || r.database == nil || expiredAt.IsZero() || limit <= 0 || limit > 10_000 {
		return nil, fmt.Errorf("collector task database, expiry time and bounded limit are required")
	}
	rows, err := r.database.QueryContext(ctx, `
		SELECT evidence.evidence_id
		FROM broker_evidence_envelopes AS evidence
		JOIN broker_collector_tasks AS task
		  ON task.tenant_id = evidence.tenant_id
		 AND task.id = evidence.task_id
		 AND task.fencing_token = evidence.fencing_token
		 AND task.execution_grant_id = evidence.execution_grant_id
		WHERE task.state IN ('executing', 'committing')
		  AND task.lease_expiry <= $1
		  AND task.accepted_attempt_id IS NULL
		  AND task.accepted_evidence_id IS NULL
		ORDER BY task.lease_expiry, evidence.recorded_at, evidence.evidence_id
		LIMIT $2`, normaliseTime(expiredAt), limit)
	if err != nil {
		return nil, fmt.Errorf("list expired evidence reconciliation candidates: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close evidence reconciliation candidates: %w", closeErr))
		}
	}()
	for rows.Next() {
		var evidenceID string
		if err := rows.Scan(&evidenceID); err != nil {
			return nil, fmt.Errorf("scan evidence reconciliation candidate: %w", err)
		}
		candidates = append(candidates, evidenceID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate evidence reconciliation candidates: %w", err)
	}

	return candidates, nil
}

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
