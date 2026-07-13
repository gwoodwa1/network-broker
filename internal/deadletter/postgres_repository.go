package deadletter

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// PostgresRepository implements tenant-scoped inspection and transactional,
// append-only replay auditing.
type PostgresRepository struct {
	database *sql.DB
}

func NewPostgresRepository(database *sql.DB) (*PostgresRepository, error) {
	if database == nil {
		return nil, fmt.Errorf("dead-letter database is required")
	}

	return &PostgresRepository{database: database}, nil
}

func (r *PostgresRepository) List(ctx context.Context, tenantID string, beforeSequence int64, limit int) (
	entries []Entry, err error,
) {
	if r == nil || r.database == nil || tenantID == "" || beforeSequence < 0 || limit <= 0 || limit > 100 {
		return nil, fmt.Errorf("dead-letter database, tenant, cursor and bounded limit are required")
	}
	rows, err := r.database.QueryContext(ctx, `
		SELECT sequence, id, aggregate_type, aggregate_id, event_type, occurred_at, attempts, dead_lettered_at
		FROM broker_outbox
		WHERE tenant_id = $1 AND published_at IS NULL AND dead_lettered_at IS NOT NULL
		  AND ($2 = 0 OR sequence < $2)
		ORDER BY sequence DESC
		LIMIT $3`, tenantID, beforeSequence, limit)
	if err != nil {
		return nil, fmt.Errorf("list dead-lettered events: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close dead-letter rows: %w", closeErr))
		}
	}()
	for rows.Next() {
		var entry Entry
		if err := rows.Scan(
			&entry.Sequence, &entry.EventID, &entry.AggregateType, &entry.AggregateID,
			&entry.EventType, &entry.OccurredAt, &entry.Attempts, &entry.DeadLetteredAt,
		); err != nil {
			return nil, fmt.Errorf("scan dead-lettered event: %w", err)
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate dead-lettered events: %w", err)
	}

	return entries, nil
}

func (r *PostgresRepository) Get(ctx context.Context, tenantID, eventID string) (Entry, error) {
	if r == nil || r.database == nil || tenantID == "" || eventID == "" {
		return Entry{}, fmt.Errorf("dead-letter database, tenant and event id are required")
	}
	var entry Entry
	err := r.database.QueryRowContext(ctx, `
		SELECT sequence, id, aggregate_type, aggregate_id, event_type, occurred_at, attempts, dead_lettered_at
		FROM broker_outbox
		WHERE tenant_id = $1 AND id = $2 AND published_at IS NULL AND dead_lettered_at IS NOT NULL`,
		tenantID, eventID,
	).Scan(
		&entry.Sequence, &entry.EventID, &entry.AggregateType, &entry.AggregateID,
		&entry.EventType, &entry.OccurredAt, &entry.Attempts, &entry.DeadLetteredAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Entry{}, ErrNotFound
	}
	if err != nil {
		return Entry{}, fmt.Errorf("get dead-lettered event: %w", err)
	}

	return entry, nil
}

func (r *PostgresRepository) Replay(ctx context.Context, command ReplayCommand) (result ReplayResult, err error) {
	if err := validateReplayCommand(r, command); err != nil {
		return ReplayResult{}, err
	}
	transaction, err := r.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return ReplayResult{}, fmt.Errorf("begin dead-letter replay: %w", err)
	}
	defer func() {
		if rollbackErr := transaction.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("rollback dead-letter replay: %w", rollbackErr))
		}
	}()

	lockKey := fmt.Sprintf("%d:%s%d:%s%d:%s", len(command.TenantID), command.TenantID,
		len(command.ActorID), command.ActorID, len(command.IdempotencyKey), command.IdempotencyKey)
	if _, err := transaction.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		return ReplayResult{}, fmt.Errorf("lock dead-letter replay idempotency key: %w", err)
	}
	existing, found, err := findReplay(ctx, transaction, command)
	if err != nil {
		return ReplayResult{}, err
	}
	if found {
		if err := transaction.Commit(); err != nil {
			return ReplayResult{}, fmt.Errorf("commit idempotent dead-letter replay: %w", err)
		}

		return existing, nil
	}

	var sequence int64
	var eventID, lastError string
	var attempts int
	var priorDeadLetteredAt time.Time
	if err := transaction.QueryRowContext(ctx, `
		SELECT sequence, id, dead_lettered_at, attempts, COALESCE(last_error, '')
		FROM broker_outbox
		WHERE tenant_id = $1 AND id = $2 AND published_at IS NULL AND dead_lettered_at IS NOT NULL
		FOR UPDATE`, command.TenantID, command.EventID,
	).Scan(&sequence, &eventID, &priorDeadLetteredAt, &attempts, &lastError); errors.Is(err, sql.ErrNoRows) {
		return ReplayResult{}, ErrNotFound
	} else if err != nil {
		return ReplayResult{}, fmt.Errorf("lock dead-lettered event: %w", err)
	}

	result = ReplayResult{ActionID: command.ActionID, EventID: eventID, Replayed: true}
	if err := transaction.QueryRowContext(ctx, `
		INSERT INTO broker_dead_letter_actions (
			action_id, tenant_id, outbox_sequence, event_id, actor_id, spiffe_id,
			identity_revision, action, idempotency_key, reason, prior_dead_lettered_at,
			attempts_at_action, last_error_at_action, available_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, 'replay', $8, $9, $10, $11, $12, CURRENT_TIMESTAMP)
		RETURNING requested_at, available_at`,
		command.ActionID, command.TenantID, sequence, eventID, command.ActorID, command.SPIFFEID,
		command.IdentityRevision, command.IdempotencyKey, command.Reason, priorDeadLetteredAt,
		attempts, lastError,
	).Scan(&result.RequestedAt, &result.AvailableAt); err != nil {
		return ReplayResult{}, fmt.Errorf("insert dead-letter replay audit: %w", err)
	}
	update, err := transaction.ExecContext(ctx, `
		UPDATE broker_outbox
		SET dead_lettered_at = NULL, lease_owner = NULL, lease_expires_at = NULL,
		    attempts = 0, available_at = $2
		WHERE sequence = $1 AND published_at IS NULL AND dead_lettered_at IS NOT NULL`,
		sequence, result.AvailableAt)
	if err != nil {
		return ReplayResult{}, fmt.Errorf("requeue dead-lettered event: %w", err)
	}
	rows, err := update.RowsAffected()
	if err != nil {
		return ReplayResult{}, fmt.Errorf("inspect dead-letter replay update: %w", err)
	}
	if rows != 1 {
		return ReplayResult{}, ErrNotFound
	}
	if err := transaction.Commit(); err != nil {
		return ReplayResult{}, fmt.Errorf("commit dead-letter replay: %w", err)
	}

	return result, nil
}

func findReplay(ctx context.Context, transaction *sql.Tx, command ReplayCommand) (ReplayResult, bool, error) {
	var result ReplayResult
	var reason string
	err := transaction.QueryRowContext(ctx, `
		SELECT action_id, event_id, reason, requested_at, available_at
		FROM broker_dead_letter_actions
		WHERE tenant_id = $1 AND actor_id = $2 AND idempotency_key = $3`,
		command.TenantID, command.ActorID, command.IdempotencyKey,
	).Scan(&result.ActionID, &result.EventID, &reason, &result.RequestedAt, &result.AvailableAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ReplayResult{}, false, nil
	}
	if err != nil {
		return ReplayResult{}, false, fmt.Errorf("read dead-letter replay idempotency: %w", err)
	}
	if result.EventID != command.EventID || reason != command.Reason {
		return ReplayResult{}, false, ErrReplayConflict
	}
	result.Replayed = false

	return result, true, nil
}

func validateReplayCommand(repository *PostgresRepository, command ReplayCommand) error {
	if repository == nil || repository.database == nil || command.ActionID == "" || command.TenantID == "" ||
		command.EventID == "" || command.ActorID == "" || command.SPIFFEID == "" ||
		command.IdentityRevision == "" || command.IdempotencyKey == "" || command.Reason == "" {
		return fmt.Errorf("complete dead-letter replay command and database are required")
	}

	return nil
}
