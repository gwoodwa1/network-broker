package resolution

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"network_broker/internal/outbox"
)

// PostgresRepository persists resolution state, idempotency records, and
// outbox events in one serializable transaction. The caller owns the database
// pool and driver configuration.
type PostgresRepository struct {
	database *sql.DB
}

// NewPostgresRepository constructs a PostgreSQL-backed repository.
func NewPostgresRepository(database *sql.DB) (*PostgresRepository, error) {
	if database == nil {
		return nil, fmt.Errorf("resolution database is required")
	}

	return &PostgresRepository{database: database}, nil
}

// Create atomically inserts a new workflow or returns the matching idempotent
// workflow. A key reused with a different digest fails closed.
func (r *PostgresRepository) Create(ctx context.Context, resolution Resolution, event outbox.Event) (
	stored Resolution, created bool, err error,
) {
	if err := validateNewResolution(resolution, event); err != nil {
		return Resolution{}, false, err
	}
	transaction, err := r.begin(ctx)
	if err != nil {
		return Resolution{}, false, err
	}
	defer func() {
		if rollbackErr := transaction.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("rollback resolution creation: %w", rollbackErr))
		}
	}()

	if _, err := transaction.ExecContext(ctx, `
		INSERT INTO broker_resolutions (
			id, actor_id, tenant_id, idempotency_key, request_digest, state,
			target_count, completed, version, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		resolution.ID, resolution.ActorID, resolution.TenantID, resolution.IdempotencyKey,
		resolution.RequestDigest, resolution.State, resolution.TargetCount, resolution.Completed,
		resolution.Version, resolution.CreatedAt, resolution.UpdatedAt,
	); err != nil {
		return Resolution{}, false, fmt.Errorf("insert resolution: %w", err)
	}

	result, err := transaction.ExecContext(ctx, `
		INSERT INTO broker_resolution_idempotency (
			tenant_id, actor_id, idempotency_key, request_digest, resolution_id, created_at
		) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (tenant_id, actor_id, idempotency_key) DO NOTHING`,
		resolution.TenantID, resolution.ActorID, resolution.IdempotencyKey,
		resolution.RequestDigest, resolution.ID, resolution.CreatedAt,
	)
	if err != nil {
		return Resolution{}, false, fmt.Errorf("insert resolution idempotency record: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return Resolution{}, false, fmt.Errorf("inspect idempotency insert: %w", err)
	}
	if rows == 0 {
		existing, digest, getErr := getIdempotentResolution(ctx, transaction,
			resolution.TenantID, resolution.ActorID, resolution.IdempotencyKey)
		if getErr != nil {
			return Resolution{}, false, getErr
		}
		if digest != resolution.RequestDigest {
			return Resolution{}, false, ErrIdempotencyConflict
		}

		return existing, false, nil
	}
	if err := insertOutboxEvent(ctx, transaction, event); err != nil {
		return Resolution{}, false, err
	}
	if err := transaction.Commit(); err != nil {
		return Resolution{}, false, fmt.Errorf("commit resolution creation: %w", err)
	}

	return resolution, true, nil
}

// Get returns a tenant-scoped resolution snapshot.
func (r *PostgresRepository) Get(ctx context.Context, tenantID, resolutionID string) (Resolution, error) {
	if r == nil || r.database == nil {
		return Resolution{}, fmt.Errorf("resolution database is required")
	}
	resolution, err := scanResolution(r.database.QueryRowContext(ctx, `
		SELECT id, actor_id, tenant_id, idempotency_key, request_digest, state,
		       target_count, completed, version, created_at, updated_at
		FROM broker_resolutions
		WHERE tenant_id = $1 AND id = $2`, tenantID, resolutionID))
	if errors.Is(err, sql.ErrNoRows) {
		return Resolution{}, fmt.Errorf("%w: %q", ErrNotFound, resolutionID)
	}
	if err != nil {
		return Resolution{}, fmt.Errorf("get resolution: %w", err)
	}

	return resolution, nil
}

// Transition performs a tenant-scoped compare-and-set update and writes its
// event before committing the transaction.
func (r *PostgresRepository) Transition(ctx context.Context, tenantID, resolutionID string, expectedVersion int64,
	expectedState, next ResolutionState, updatedAt time.Time, event outbox.Event,
) (updated Resolution, err error) {
	if err := ValidateTransition(expectedState, next); err != nil {
		return Resolution{}, err
	}
	if updatedAt.IsZero() {
		return Resolution{}, fmt.Errorf("resolution update time is required")
	}
	if err := validateEventBinding(event, tenantID, resolutionID); err != nil {
		return Resolution{}, err
	}
	transaction, err := r.begin(ctx)
	if err != nil {
		return Resolution{}, err
	}
	defer func() {
		if rollbackErr := transaction.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("rollback resolution transition: %w", rollbackErr))
		}
	}()

	resolution, err := scanResolution(transaction.QueryRowContext(ctx, `
		UPDATE broker_resolutions
		SET state = $1, completed = $2, version = version + 1, updated_at = $3
		WHERE tenant_id = $4 AND id = $5 AND version = $6 AND state = $7 AND updated_at <= $3
		RETURNING id, actor_id, tenant_id, idempotency_key, request_digest, state,
		          target_count, completed, version, created_at, updated_at`,
		next, next.Terminal(), updatedAt, tenantID, resolutionID, expectedVersion, expectedState,
	))
	if errors.Is(err, sql.ErrNoRows) {
		if _, getErr := getResolutionTx(ctx, transaction, tenantID, resolutionID); errors.Is(getErr, sql.ErrNoRows) {
			return Resolution{}, fmt.Errorf("%w: %q", ErrNotFound, resolutionID)
		}

		return Resolution{}, ErrVersionConflict
	}
	if err != nil {
		return Resolution{}, fmt.Errorf("transition resolution: %w", err)
	}
	if err := insertOutboxEvent(ctx, transaction, event); err != nil {
		return Resolution{}, err
	}
	if err := transaction.Commit(); err != nil {
		return Resolution{}, fmt.Errorf("commit resolution transition: %w", err)
	}

	return resolution, nil
}

func (r *PostgresRepository) begin(ctx context.Context) (*sql.Tx, error) {
	if r == nil || r.database == nil {
		return nil, fmt.Errorf("resolution database is required")
	}
	transaction, err := r.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin resolution transaction: %w", err)
	}

	return transaction, nil
}

type rowScanner interface {
	Scan(...any) error
}

func scanResolution(row rowScanner) (Resolution, error) {
	var resolution Resolution
	err := row.Scan(
		&resolution.ID, &resolution.ActorID, &resolution.TenantID, &resolution.IdempotencyKey,
		&resolution.RequestDigest, &resolution.State, &resolution.TargetCount, &resolution.Completed,
		&resolution.Version, &resolution.CreatedAt, &resolution.UpdatedAt,
	)

	return resolution, err
}

func getResolutionTx(ctx context.Context, transaction *sql.Tx, tenantID, resolutionID string) (Resolution, error) {
	return scanResolution(transaction.QueryRowContext(ctx, `
		SELECT id, actor_id, tenant_id, idempotency_key, request_digest, state,
		       target_count, completed, version, created_at, updated_at
		FROM broker_resolutions
		WHERE tenant_id = $1 AND id = $2`, tenantID, resolutionID))
}

func getIdempotentResolution(ctx context.Context, transaction *sql.Tx, tenantID, actorID, key string) (Resolution, string, error) {
	var digest, resolutionID string
	if err := transaction.QueryRowContext(ctx, `
		SELECT request_digest, resolution_id
		FROM broker_resolution_idempotency
		WHERE tenant_id = $1 AND actor_id = $2 AND idempotency_key = $3`,
		tenantID, actorID, key,
	).Scan(&digest, &resolutionID); err != nil {
		return Resolution{}, "", fmt.Errorf("get resolution idempotency record: %w", err)
	}
	resolution, err := getResolutionTx(ctx, transaction, tenantID, resolutionID)
	if err != nil {
		return Resolution{}, "", fmt.Errorf("get idempotent resolution: %w", err)
	}

	return resolution, digest, nil
}

func insertOutboxEvent(ctx context.Context, transaction *sql.Tx, event outbox.Event) error {
	if _, err := transaction.ExecContext(ctx, `
		INSERT INTO broker_outbox (
			id, tenant_id, aggregate_type, aggregate_id, event_type, payload, occurred_at, available_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $7)`,
		event.ID, event.TenantID, event.AggregateType, event.AggregateID,
		event.Type, string(event.Payload), event.OccurredAt,
	); err != nil {
		return fmt.Errorf("insert resolution outbox event: %w", err)
	}

	return nil
}
