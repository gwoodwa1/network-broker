package artefacts

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

func (r *PostgresRepository) GetLifecycle(ctx context.Context, tenantID, artefactID string) (Lifecycle, error) {
	if r == nil || r.database == nil || invalidSegment(tenantID) || artefactID == "" {
		return Lifecycle{}, fmt.Errorf("artefact database, tenant and artefact are required")
	}

	return scanLifecycle(r.database.QueryRowContext(ctx, `
		SELECT tenant_id, artefact_id, state, retain_until, legal_hold, version, updated_at
		FROM broker_artefact_lifecycle
		WHERE tenant_id = $1 AND artefact_id = $2`, tenantID, artefactID))
}

func (r *PostgresRepository) ApplyLifecycle(ctx context.Context, command LifecycleCommand) (result Lifecycle, err error) {
	if r == nil || r.database == nil {
		return Lifecycle{}, fmt.Errorf("artefact lifecycle database is required")
	}
	transaction, err := r.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return Lifecycle{}, fmt.Errorf("begin artefact lifecycle transition: %w", err)
	}
	defer func() {
		if rollbackErr := transaction.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("rollback artefact lifecycle transition: %w", rollbackErr))
		}
	}()
	current, now, err := lockLifecycle(ctx, transaction, command.TenantID, command.ArtefactID)
	if err != nil {
		return Lifecycle{}, err
	}
	if current.Version != command.ExpectedVersion {
		return Lifecycle{}, ErrLifecycleConflict
	}
	next, err := applyLifecycleAction(current, command, now)
	if err != nil {
		return Lifecycle{}, err
	}
	next.Version++
	next.UpdatedAt = now
	update, err := transaction.ExecContext(ctx, `
		UPDATE broker_artefact_lifecycle
		SET state = $4, retain_until = $5, legal_hold = $6, version = $7, updated_at = $8
		WHERE tenant_id = $1 AND artefact_id = $2 AND version = $3`,
		command.TenantID, command.ArtefactID, command.ExpectedVersion, next.State,
		next.RetainUntil, next.LegalHold, next.Version, next.UpdatedAt)
	if err != nil {
		return Lifecycle{}, fmt.Errorf("update artefact lifecycle: %w", err)
	}
	rows, err := update.RowsAffected()
	if err != nil {
		return Lifecycle{}, fmt.Errorf("inspect artefact lifecycle update: %w", err)
	}
	if rows != 1 {
		return Lifecycle{}, ErrLifecycleConflict
	}
	if _, err := transaction.ExecContext(ctx, `
		INSERT INTO broker_artefact_lifecycle_events (
			tenant_id, artefact_id, version, action, previous_state, next_state,
			previous_retain_until, next_retain_until, previous_legal_hold,
			next_legal_hold, actor_id, reason, occurred_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		command.TenantID, command.ArtefactID, next.Version, command.Action, current.State, next.State,
		current.RetainUntil, next.RetainUntil, current.LegalHold, next.LegalHold,
		command.ActorID, command.Reason, now); err != nil {
		return Lifecycle{}, fmt.Errorf("append artefact lifecycle event: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return Lifecycle{}, fmt.Errorf("commit artefact lifecycle transition: %w", err)
	}

	return next, nil
}

type rowScanner interface {
	Scan(...any) error
}

func scanLifecycle(row rowScanner) (Lifecycle, error) {
	var lifecycle Lifecycle
	var state string
	var retainUntil sql.NullTime
	if err := row.Scan(&lifecycle.TenantID, &lifecycle.ArtefactID, &state, &retainUntil,
		&lifecycle.LegalHold, &lifecycle.Version, &lifecycle.UpdatedAt); errors.Is(err, sql.ErrNoRows) {
		return Lifecycle{}, ErrArtefactNotFound
	} else if err != nil {
		return Lifecycle{}, fmt.Errorf("scan artefact lifecycle: %w", err)
	}
	lifecycle.State = LifecycleState(state)
	if retainUntil.Valid {
		value := retainUntil.Time
		lifecycle.RetainUntil = &value
	}

	return lifecycle, nil
}

func lockLifecycle(ctx context.Context, transaction *sql.Tx, tenantID, artefactID string) (Lifecycle, time.Time, error) {
	row := transaction.QueryRowContext(ctx, `
		SELECT tenant_id, artefact_id, state, retain_until, legal_hold, version, updated_at,
		       CURRENT_TIMESTAMP
		FROM broker_artefact_lifecycle
		WHERE tenant_id = $1 AND artefact_id = $2
		FOR UPDATE`, tenantID, artefactID)
	var lifecycle Lifecycle
	var state string
	var retainUntil sql.NullTime
	var now time.Time
	if err := row.Scan(&lifecycle.TenantID, &lifecycle.ArtefactID, &state, &retainUntil,
		&lifecycle.LegalHold, &lifecycle.Version, &lifecycle.UpdatedAt, &now); errors.Is(err, sql.ErrNoRows) {
		return Lifecycle{}, time.Time{}, ErrArtefactNotFound
	} else if err != nil {
		return Lifecycle{}, time.Time{}, fmt.Errorf("lock artefact lifecycle: %w", err)
	}
	lifecycle.State = LifecycleState(state)
	if retainUntil.Valid {
		value := retainUntil.Time
		lifecycle.RetainUntil = &value
	}

	return lifecycle, now, nil
}

func applyLifecycleAction(current Lifecycle, command LifecycleCommand, now time.Time) (Lifecycle, error) {
	switch command.Action {
	case LifecycleRetain:
		return applyRetention(current, command.RetainUntil, now)
	case LifecyclePlaceHold:
		return placeLegalHold(current)
	case LifecycleReleaseHold:
		return releaseLegalHold(current)
	case LifecycleRequestDeletion:
		return applyDeletionRequest(current, now)
	case LifecycleConfirmDeletion:
		return applyDeletionConfirmation(current)
	default:
		return Lifecycle{}, fmt.Errorf("lifecycle action is invalid")
	}
}

func applyRetention(current Lifecycle, retainUntil *time.Time, now time.Time) (Lifecycle, error) {
	if current.State != LifecycleActive || retainUntil == nil || !retainUntil.After(now) ||
		(current.RetainUntil != nil && !retainUntil.After(*current.RetainUntil)) {
		return Lifecycle{}, ErrLifecycleBlocked
	}
	next := current
	value := retainUntil.UTC().Truncate(time.Microsecond)
	next.RetainUntil = &value

	return next, nil
}

func placeLegalHold(current Lifecycle) (Lifecycle, error) {
	if current.State == LifecycleDeleted || current.LegalHold {
		return Lifecycle{}, ErrLifecycleBlocked
	}
	next := current
	next.LegalHold = true

	return next, nil
}

func releaseLegalHold(current Lifecycle) (Lifecycle, error) {
	if current.State == LifecycleDeleted || !current.LegalHold {
		return Lifecycle{}, ErrLifecycleBlocked
	}
	next := current
	next.LegalHold = false

	return next, nil
}

func applyDeletionRequest(current Lifecycle, now time.Time) (Lifecycle, error) {
	if current.State != LifecycleActive || current.LegalHold ||
		(current.RetainUntil != nil && current.RetainUntil.After(now)) {
		return Lifecycle{}, ErrLifecycleBlocked
	}
	next := current
	next.State = LifecyclePendingDeletion

	return next, nil
}

func applyDeletionConfirmation(current Lifecycle) (Lifecycle, error) {
	if current.State != LifecyclePendingDeletion || current.LegalHold {
		return Lifecycle{}, ErrLifecycleBlocked
	}
	next := current
	next.State = LifecycleDeleted

	return next, nil
}
