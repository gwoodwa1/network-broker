package grants

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Consumption is the complete, non-secret authority binding recorded when a
// credential broker exchanges a signed execution grant. The nonce itself is
// never persisted; only its one-way digest crosses this boundary.
type Consumption struct {
	GrantID           string
	NonceDigest       string
	GrantDigest       string
	TenantID          string
	TaskID            string
	CollectorSPIFFEID string
	TargetID          string
	RecipeID          string
	RecipeVersion     string
	FencingToken      int64
	GrantExpiresAt    time.Time
	RequestedAt       time.Time
}

// ConsumptionRecord is immutable proof that one grant and nonce were
// consumed. It intentionally contains no target credential or raw nonce.
type ConsumptionRecord struct {
	Consumption
	ConsumedAt time.Time
}

// ConsumptionRepository atomically consumes signed execution grants.
type ConsumptionRepository interface {
	Consume(context.Context, Consumption) (ConsumptionRecord, error)
	Get(context.Context, string, string) (ConsumptionRecord, error)
}

// MemoryConsumptionRepository preserves the production conflict semantics for
// local execution. It is not restart-safe and must not be used as production
// authority.
type MemoryConsumptionRepository struct {
	mu      sync.RWMutex
	byGrant map[string]ConsumptionRecord
	byNonce map[string]string
}

func NewMemoryConsumptionRepository() *MemoryConsumptionRepository {
	return &MemoryConsumptionRepository{
		byGrant: make(map[string]ConsumptionRecord),
		byNonce: make(map[string]string),
	}
}

func (r *MemoryConsumptionRepository) Consume(_ context.Context,
	consumption Consumption,
) (ConsumptionRecord, error) {
	if err := validateConsumption(consumption); err != nil {
		return ConsumptionRecord{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.byGrant[consumption.GrantID]; exists {
		return ConsumptionRecord{}, ErrAlreadyConsumed
	}
	if _, exists := r.byNonce[consumption.NonceDigest]; exists {
		return ConsumptionRecord{}, ErrAlreadyConsumed
	}
	if !consumption.RequestedAt.Before(consumption.GrantExpiresAt) {
		return ConsumptionRecord{}, ErrNotCurrent
	}
	record := ConsumptionRecord{Consumption: consumption, ConsumedAt: consumption.RequestedAt.UTC()}
	r.byGrant[consumption.GrantID] = record
	r.byNonce[consumption.NonceDigest] = consumption.GrantID

	return record, nil
}

func (r *MemoryConsumptionRepository) Get(_ context.Context, tenantID,
	grantID string,
) (ConsumptionRecord, error) {
	r.mu.RLock()
	record, exists := r.byGrant[grantID]
	r.mu.RUnlock()
	if !exists || record.TenantID != tenantID {
		return ConsumptionRecord{}, ErrConsumptionNotFound
	}

	return record, nil
}

// PostgresConsumptionRepository binds consumption to the authoritative task
// row in the same row-locked transaction as the append-only ledger insert.
type PostgresConsumptionRepository struct {
	database *sql.DB
}

func NewPostgresConsumptionRepository(database *sql.DB) (*PostgresConsumptionRepository, error) {
	if database == nil {
		return nil, fmt.Errorf("execution grant consumption database is required")
	}

	return &PostgresConsumptionRepository{database: database}, nil
}

func (r *PostgresConsumptionRepository) Consume(ctx context.Context,
	consumption Consumption,
) (record ConsumptionRecord, err error) {
	if r == nil || r.database == nil {
		return ConsumptionRecord{}, fmt.Errorf("execution grant consumption database is required")
	}
	if err := validateConsumption(consumption); err != nil {
		return ConsumptionRecord{}, err
	}
	transaction, err := r.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return ConsumptionRecord{}, fmt.Errorf("begin execution grant consumption: %w", err)
	}
	defer func() {
		if rollbackErr := transaction.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("rollback execution grant consumption: %w", rollbackErr))
		}
	}()

	var alreadyConsumed bool
	if err := transaction.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM broker_execution_grant_consumptions
			WHERE grant_id = $1 OR nonce_digest = $2
		)`, consumption.GrantID, consumption.NonceDigest).Scan(&alreadyConsumed); err != nil {
		return ConsumptionRecord{}, fmt.Errorf("check execution grant consumption: %w", err)
	}
	if alreadyConsumed {
		return ConsumptionRecord{}, ErrAlreadyConsumed
	}
	if err := lockAndValidateTask(ctx, transaction, consumption); err != nil {
		return ConsumptionRecord{}, err
	}
	result, err := transaction.ExecContext(ctx, `
		INSERT INTO broker_execution_grant_consumptions (
			grant_id, nonce_digest, grant_digest, tenant_id, task_id,
			collector_spiffe_id, target_id, recipe_id, recipe_version,
			fencing_token, grant_expires_at, requested_at, consumed_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, clock_timestamp())
		ON CONFLICT DO NOTHING`,
		consumption.GrantID, consumption.NonceDigest, consumption.GrantDigest,
		consumption.TenantID, consumption.TaskID, consumption.CollectorSPIFFEID,
		consumption.TargetID, consumption.RecipeID, consumption.RecipeVersion,
		consumption.FencingToken, consumption.GrantExpiresAt.UTC(), consumption.RequestedAt.UTC())
	if err != nil {
		return ConsumptionRecord{}, fmt.Errorf("record execution grant consumption: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return ConsumptionRecord{}, fmt.Errorf("inspect execution grant consumption: %w", err)
	}
	if rows != 1 {
		return ConsumptionRecord{}, ErrAlreadyConsumed
	}
	if err := transaction.QueryRowContext(ctx, `
		SELECT consumed_at FROM broker_execution_grant_consumptions
		WHERE tenant_id = $1 AND grant_id = $2`, consumption.TenantID,
		consumption.GrantID).Scan(&record.ConsumedAt); err != nil {
		return ConsumptionRecord{}, fmt.Errorf("read execution grant consumption time: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return ConsumptionRecord{}, fmt.Errorf("commit execution grant consumption: %w", err)
	}
	record.Consumption = consumption

	return record, nil
}

func (r *PostgresConsumptionRepository) Get(ctx context.Context, tenantID,
	grantID string,
) (ConsumptionRecord, error) {
	if r == nil || r.database == nil || tenantID == "" || grantID == "" {
		return ConsumptionRecord{}, fmt.Errorf("execution grant consumption database and identity are required")
	}
	var record ConsumptionRecord
	err := r.database.QueryRowContext(ctx, `
		SELECT grant_id, nonce_digest, grant_digest, tenant_id, task_id,
			collector_spiffe_id, target_id, recipe_id, recipe_version,
			fencing_token, grant_expires_at, requested_at, consumed_at
		FROM broker_execution_grant_consumptions
		WHERE tenant_id = $1 AND grant_id = $2`, tenantID, grantID).Scan(
		&record.GrantID, &record.NonceDigest, &record.GrantDigest, &record.TenantID,
		&record.TaskID, &record.CollectorSPIFFEID, &record.TargetID, &record.RecipeID,
		&record.RecipeVersion, &record.FencingToken, &record.GrantExpiresAt,
		&record.RequestedAt, &record.ConsumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ConsumptionRecord{}, ErrConsumptionNotFound
	}
	if err != nil {
		return ConsumptionRecord{}, fmt.Errorf("get execution grant consumption: %w", err)
	}
	if err := validateConsumption(record.Consumption); err != nil {
		return ConsumptionRecord{}, errors.Join(ErrConsumptionIntegrity, err)
	}
	if record.ConsumedAt.IsZero() || !record.ConsumedAt.Before(record.GrantExpiresAt) {
		return ConsumptionRecord{}, ErrConsumptionIntegrity
	}

	return record, nil
}

func lockAndValidateTask(ctx context.Context, transaction *sql.Tx,
	consumption Consumption,
) error {
	var tenantID, collectorID, targetID, recipeID, recipeVersion, grantID, state string
	var fencingToken int64
	var leaseExpiry, databaseNow time.Time
	err := transaction.QueryRowContext(ctx, `
		SELECT tenant_id, COALESCE(lease_owner, ''), target_id, recipe_id,
			recipe_version, COALESCE(execution_grant_id, ''), fencing_token,
			state, lease_expiry, clock_timestamp()
		FROM broker_collector_tasks WHERE id = $1 FOR UPDATE`, consumption.TaskID).Scan(
		&tenantID, &collectorID, &targetID, &recipeID, &recipeVersion, &grantID,
		&fencingToken, &state, &leaseExpiry, &databaseNow)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrBindingMismatch
	}
	if err != nil {
		return fmt.Errorf("lock execution grant task: %w", err)
	}
	if tenantID != consumption.TenantID || collectorID != consumption.CollectorSPIFFEID ||
		targetID != consumption.TargetID || recipeID != consumption.RecipeID ||
		recipeVersion != consumption.RecipeVersion || grantID != consumption.GrantID {
		return ErrBindingMismatch
	}
	if fencingToken != consumption.FencingToken {
		return ErrStaleFence
	}
	if state != "executing" || !databaseNow.Before(leaseExpiry) ||
		!databaseNow.Before(consumption.GrantExpiresAt) {
		return ErrNotCurrent
	}

	return nil
}

func validateConsumption(consumption Consumption) error {
	required := []string{
		consumption.GrantID, consumption.NonceDigest, consumption.GrantDigest,
		consumption.TenantID, consumption.TaskID, consumption.CollectorSPIFFEID,
		consumption.TargetID, consumption.RecipeID, consumption.RecipeVersion,
	}
	for _, value := range required {
		if value == "" || len(value) > 512 {
			return fmt.Errorf("complete bounded execution grant consumption is required")
		}
	}
	if len(consumption.NonceDigest) != sha256.Size*2 ||
		len(consumption.GrantDigest) != sha256.Size*2 {
		return fmt.Errorf("execution grant consumption digests must be SHA-256")
	}
	if _, err := hex.DecodeString(consumption.NonceDigest); err != nil {
		return fmt.Errorf("decode execution grant nonce digest: %w", err)
	}
	if _, err := hex.DecodeString(consumption.GrantDigest); err != nil {
		return fmt.Errorf("decode execution grant document digest: %w", err)
	}
	if consumption.FencingToken <= 0 || consumption.GrantExpiresAt.IsZero() ||
		consumption.RequestedAt.IsZero() {
		return fmt.Errorf("execution grant consumption fence and times are required")
	}

	return nil
}
