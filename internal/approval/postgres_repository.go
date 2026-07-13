package approval

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type PostgresRepository struct {
	database *sql.DB
}

func NewPostgresRepository(database *sql.DB) (*PostgresRepository, error) {
	if database == nil {
		return nil, fmt.Errorf("approval database is required")
	}

	return &PostgresRepository{database: database}, nil
}

func (r *PostgresRepository) Create(ctx context.Context, request CreateRequest) (Grant, error) {
	var grant Grant
	err := r.database.QueryRowContext(ctx, `
		INSERT INTO broker_approval_grants (
			grant_id, tenant_id, recipe_id, target_subset_hash, max_uses,
			expires_at, created_by, policy_decision_id
		) SELECT $1, $2, $3, $4, $5, $6, $7, $8
		WHERE $6 > CURRENT_TIMESTAMP
		RETURNING grant_id, tenant_id, recipe_id, target_subset_hash, max_uses,
			used, expires_at, created_by, policy_decision_id, version, created_at`,
		request.GrantID, request.TenantID, request.RecipeID, request.TargetSubsetHash,
		request.MaxUses, request.ExpiresAt.UTC(), request.CreatedBy, request.PolicyDecisionID).Scan(
		&grant.GrantID, &grant.TenantID, &grant.RecipeID, &grant.TargetSubsetHash,
		&grant.MaxUses, &grant.Used, &grant.ExpiresAt, &grant.CreatedBy,
		&grant.PolicyDecisionID, &grant.Version, &grant.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Grant{}, ErrExpired
	}
	if err != nil {
		return Grant{}, fmt.Errorf("create approval grant: %w", err)
	}

	return grant, nil
}

func (r *PostgresRepository) Get(ctx context.Context, tenantID, grantID string) (Grant, error) {
	var grant Grant
	err := r.database.QueryRowContext(ctx, `
		SELECT grant_id, tenant_id, recipe_id, target_subset_hash, max_uses,
			used, expires_at, created_by, policy_decision_id, version, created_at
		FROM broker_approval_grants WHERE tenant_id = $1 AND grant_id = $2`,
		tenantID, grantID).Scan(
		&grant.GrantID, &grant.TenantID, &grant.RecipeID, &grant.TargetSubsetHash,
		&grant.MaxUses, &grant.Used, &grant.ExpiresAt, &grant.CreatedBy,
		&grant.PolicyDecisionID, &grant.Version, &grant.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Grant{}, ErrNotFound
	}
	if err != nil {
		return Grant{}, fmt.Errorf("get approval grant: %w", err)
	}

	return grant, nil
}

func (r *PostgresRepository) Consume(ctx context.Context, request ConsumeRequest) (grant Grant, err error) {
	transaction, err := r.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Grant{}, fmt.Errorf("begin approval consumption: %w", err)
	}
	defer func() {
		if rollbackErr := transaction.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("rollback approval consumption: %w", rollbackErr))
		}
	}()
	var databaseNow time.Time
	err = transaction.QueryRowContext(ctx, `
		SELECT grant_id, tenant_id, recipe_id, target_subset_hash, max_uses,
			used, expires_at, created_by, policy_decision_id, version, created_at,
			CURRENT_TIMESTAMP
		FROM broker_approval_grants WHERE tenant_id = $1 AND grant_id = $2 FOR UPDATE`,
		request.TenantID, request.GrantID).Scan(
		&grant.GrantID, &grant.TenantID, &grant.RecipeID, &grant.TargetSubsetHash,
		&grant.MaxUses, &grant.Used, &grant.ExpiresAt, &grant.CreatedBy,
		&grant.PolicyDecisionID, &grant.Version, &grant.CreatedAt, &databaseNow)
	if errors.Is(err, sql.ErrNoRows) {
		return Grant{}, ErrNotFound
	}
	if err != nil {
		return Grant{}, fmt.Errorf("lock approval grant: %w", err)
	}
	idempotent, err := existingConsumption(ctx, transaction, request)
	if err != nil {
		return Grant{}, err
	}
	if idempotent {
		if err := transaction.Commit(); err != nil {
			return Grant{}, fmt.Errorf("commit idempotent approval consumption: %w", err)
		}

		return grant, nil
	}
	if grant.RecipeID != request.RecipeID || grant.TargetSubsetHash != request.TargetSubsetHash {
		return Grant{}, ErrBindingMismatch
	}
	if !databaseNow.Before(grant.ExpiresAt) {
		return Grant{}, ErrExpired
	}
	if grant.Used >= grant.MaxUses {
		return Grant{}, ErrExhausted
	}
	grant.Used++
	grant.Version++
	if _, err := transaction.ExecContext(ctx, `
		UPDATE broker_approval_grants SET used = $3, version = $4
		WHERE tenant_id = $1 AND grant_id = $2`, request.TenantID, request.GrantID,
		grant.Used, grant.Version); err != nil {
		return Grant{}, fmt.Errorf("update approval grant consumption: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
		INSERT INTO broker_approval_consumptions (
			consumption_id, grant_id, tenant_id, task_id, actor_id, grant_version
		) VALUES ($1, $2, $3, $4, $5, $6)`, request.ConsumptionID, request.GrantID,
		request.TenantID, request.TaskID, request.ActorID, grant.Version); err != nil {
		return Grant{}, fmt.Errorf("record approval consumption: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return Grant{}, fmt.Errorf("commit approval consumption: %w", err)
	}

	return grant, nil
}

func existingConsumption(ctx context.Context, transaction *sql.Tx, request ConsumeRequest) (bool, error) {
	var consumptionID, grantID, tenantID, taskID string
	err := transaction.QueryRowContext(ctx, `
		SELECT consumption_id, grant_id, tenant_id, task_id
		FROM broker_approval_consumptions
		WHERE consumption_id = $1 OR (grant_id = $2 AND task_id = $3)
		LIMIT 1`, request.ConsumptionID, request.GrantID, request.TaskID).Scan(
		&consumptionID, &grantID, &tenantID, &taskID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check approval consumption idempotency: %w", err)
	}
	if consumptionID != request.ConsumptionID || grantID != request.GrantID ||
		tenantID != request.TenantID || taskID != request.TaskID {
		return false, ErrBindingMismatch
	}

	return true, nil
}
