package outbox

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const maximumStoredErrorBytes = 2048

// PostgresStore coordinates multiple dispatchers with short leases and
// SKIP LOCKED claims.
type PostgresStore struct {
	database *sql.DB
}

// NewPostgresStore constructs a durable outbox store.
func NewPostgresStore(database *sql.DB) (*PostgresStore, error) {
	if database == nil {
		return nil, fmt.Errorf("outbox database is required")
	}

	return &PostgresStore{database: database}, nil
}

// Claim leases currently available events in commit order.
func (s *PostgresStore) Claim(ctx context.Context, owner string, limit int, now time.Time, lease time.Duration) (
	records []Record, err error,
) {
	if s == nil || s.database == nil || owner == "" || limit <= 0 || now.IsZero() || lease <= 0 {
		return nil, fmt.Errorf("outbox database, owner, positive limit, time and lease are required")
	}
	transaction, err := s.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin outbox claim: %w", err)
	}
	defer func() {
		if rollbackErr := transaction.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("rollback outbox claim: %w", rollbackErr))
		}
	}()

	rows, err := transaction.QueryContext(ctx, `
		WITH claimable AS (
			SELECT sequence
			FROM broker_outbox
			WHERE published_at IS NULL
			  AND dead_lettered_at IS NULL
			  AND available_at <= $1
			  AND (lease_expires_at IS NULL OR lease_expires_at <= $1)
			ORDER BY sequence
			FOR UPDATE SKIP LOCKED
			LIMIT $2
		)
		UPDATE broker_outbox AS event
		SET lease_owner = $3, lease_expires_at = $4, attempts = event.attempts + 1
		FROM claimable
		WHERE event.sequence = claimable.sequence
		RETURNING event.sequence, event.id, event.tenant_id, event.aggregate_type,
		          event.aggregate_id, event.event_type, event.payload, event.occurred_at, event.attempts`,
		now, limit, owner, now.Add(lease),
	)
	if err != nil {
		return nil, fmt.Errorf("claim outbox events: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close outbox claim rows: %w", closeErr))
		}
	}()
	for rows.Next() {
		var record Record
		if err := rows.Scan(
			&record.Sequence, &record.ID, &record.TenantID, &record.AggregateType,
			&record.AggregateID, &record.Type, &record.Payload, &record.OccurredAt, &record.Attempts,
		); err != nil {
			return nil, fmt.Errorf("scan claimed outbox event: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate claimed outbox events: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return nil, fmt.Errorf("commit outbox claim: %w", err)
	}

	return records, nil
}

// MarkPublished acknowledges a currently leased event.
func (s *PostgresStore) MarkPublished(ctx context.Context, sequence int64, owner string, publishedAt time.Time) error {
	return s.updateLease(ctx, sequence, owner, `
		UPDATE broker_outbox
		SET published_at = $3, lease_owner = NULL, lease_expires_at = NULL, last_error = NULL
		WHERE sequence = $1 AND lease_owner = $2 AND lease_expires_at > $3
		  AND published_at IS NULL AND dead_lettered_at IS NULL`,
		publishedAt, "mark outbox event published")
}

// Retry releases a failed event for a later attempt.
func (s *PostgresStore) Retry(ctx context.Context, sequence int64, owner string,
	failedAt, availableAt time.Time, failure string,
) error {
	if err := validateLeaseUpdate(s, sequence, owner, failedAt); err != nil {
		return err
	}
	if availableAt.Before(failedAt) {
		return fmt.Errorf("outbox retry availability must not precede failure time")
	}
	result, err := s.database.ExecContext(ctx, `
		UPDATE broker_outbox
		SET available_at = $4, last_error = $5, lease_owner = NULL, lease_expires_at = NULL
		WHERE sequence = $1 AND lease_owner = $2 AND lease_expires_at > $3
		  AND published_at IS NULL AND dead_lettered_at IS NULL`,
		sequence, owner, failedAt, availableAt, boundedError(failure))
	if err != nil {
		return fmt.Errorf("schedule outbox retry: %w", err)
	}

	return requireUpdatedLease(result)
}

// DeadLetter permanently removes a repeatedly failing event from dispatch.
func (s *PostgresStore) DeadLetter(ctx context.Context, sequence int64, owner string, failedAt time.Time, failure string) error {
	return s.updateLeaseWithError(ctx, sequence, owner, `
		UPDATE broker_outbox
		SET dead_lettered_at = $3, last_error = $4, lease_owner = NULL, lease_expires_at = NULL
		WHERE sequence = $1 AND lease_owner = $2 AND lease_expires_at > $3
		  AND published_at IS NULL AND dead_lettered_at IS NULL`,
		failedAt, failure, "dead-letter outbox event")
}

func (s *PostgresStore) updateLease(ctx context.Context, sequence int64, owner, query string, at time.Time, operation string) error {
	if err := validateLeaseUpdate(s, sequence, owner, at); err != nil {
		return err
	}
	result, err := s.database.ExecContext(ctx, query, sequence, owner, at)
	if err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}

	return requireUpdatedLease(result)
}

func (s *PostgresStore) updateLeaseWithError(ctx context.Context, sequence int64, owner, query string,
	at time.Time, failure, operation string,
) error {
	if err := validateLeaseUpdate(s, sequence, owner, at); err != nil {
		return err
	}
	result, err := s.database.ExecContext(ctx, query, sequence, owner, at, boundedError(failure))
	if err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}

	return requireUpdatedLease(result)
}

func validateLeaseUpdate(store *PostgresStore, sequence int64, owner string, at time.Time) error {
	if store == nil || store.database == nil || sequence <= 0 || owner == "" || at.IsZero() {
		return fmt.Errorf("outbox database, positive sequence, owner and time are required")
	}

	return nil
}

func requireUpdatedLease(result sql.Result) error {
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect outbox lease update: %w", err)
	}
	if count != 1 {
		return ErrLeaseLost
	}

	return nil
}

func boundedError(failure string) string {
	failure = strings.ToValidUTF8(failure, "�")
	if len(failure) <= maximumStoredErrorBytes {
		return failure
	}
	failure = failure[:maximumStoredErrorBytes]
	for !utf8.ValidString(failure) {
		failure = failure[:len(failure)-1]
	}

	return failure
}
