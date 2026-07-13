package policy

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

type PostgresBundleRepository struct {
	database *sql.DB
}

func NewPostgresBundleRepository(database *sql.DB) (*PostgresBundleRepository, error) {
	if database == nil {
		return nil, fmt.Errorf("policy database is required")
	}

	return &PostgresBundleRepository{database: database}, nil
}

func (r *PostgresBundleRepository) StoreBundle(ctx context.Context, bundle Bundle) (string, error) {
	if err := validateSignedBundle(bundle); err != nil {
		return "", err
	}
	document, err := json.Marshal(bundle)
	if err != nil {
		return "", fmt.Errorf("encode stored policy bundle: %w", err)
	}
	payload, err := bundleSigningPayload(bundle)
	if err != nil {
		return "", err
	}
	digestBytes := sha256.Sum256(payload)
	digest := hex.EncodeToString(digestBytes[:])
	result, err := r.database.ExecContext(ctx, `
		INSERT INTO broker_policy_bundles (
			bundle_id, version, scope, issued_at, document, document_digest,
			signing_key_ref, signature_algorithm, signature
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (bundle_id, version) DO NOTHING`,
		bundle.BundleID, bundle.Version, bundle.Scope, bundle.IssuedAt.UTC(), document, digest,
		bundle.SigningKeyRef, bundle.SignatureAlgorithm, bundle.Signature)
	if err != nil {
		return "", fmt.Errorf("store policy bundle: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return "", fmt.Errorf("inspect policy bundle insert: %w", err)
	}
	if rows != 1 {
		return "", fmt.Errorf("policy bundle version already exists")
	}

	return digest, nil
}

func (r *PostgresBundleRepository) ActivateBundle(ctx context.Context, scope, bundleID string,
	version int64, actorID string,
) (err error) {
	if scope == "" || bundleID == "" || version <= 0 || actorID == "" {
		return fmt.Errorf("policy activation scope, bundle, version and actor are required")
	}
	transaction, err := r.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("begin policy activation: %w", err)
	}
	defer func() {
		if rollbackErr := transaction.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("rollback policy activation: %w", rollbackErr))
		}
	}()
	var bundleScope string
	if err := transaction.QueryRowContext(ctx, `
		SELECT scope FROM broker_policy_bundles WHERE bundle_id = $1 AND version = $2`,
		bundleID, version).Scan(&bundleScope); errors.Is(err, sql.ErrNoRows) {
		return ErrNoActiveBundle
	} else if err != nil {
		return fmt.Errorf("load policy bundle for activation: %w", err)
	}
	if bundleScope != scope {
		return fmt.Errorf("policy bundle scope does not match activation scope")
	}
	if _, err := transaction.ExecContext(ctx, `
		INSERT INTO broker_policy_activations (scope, bundle_id, version, activated_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (scope) DO UPDATE SET
			bundle_id = EXCLUDED.bundle_id, version = EXCLUDED.version,
			activated_at = CURRENT_TIMESTAMP, activated_by = EXCLUDED.activated_by`,
		scope, bundleID, version, actorID); err != nil {
		return fmt.Errorf("activate policy bundle: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
		INSERT INTO broker_policy_activation_events (scope, bundle_id, version, actor_id)
		VALUES ($1, $2, $3, $4)`, scope, bundleID, version, actorID); err != nil {
		return fmt.Errorf("record policy activation: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit policy activation: %w", err)
	}

	return nil
}

func (r *PostgresBundleRepository) LoadActiveBundle(ctx context.Context, scope string) (Bundle, string, error) {
	if scope == "" {
		return Bundle{}, "", fmt.Errorf("policy scope is required")
	}
	var document []byte
	var digest string
	err := r.database.QueryRowContext(ctx, `
		SELECT b.document, b.document_digest
		FROM broker_policy_activations a
		JOIN broker_policy_bundles b ON b.bundle_id = a.bundle_id AND b.version = a.version
		WHERE a.scope = $1`, scope).Scan(&document, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		return Bundle{}, "", ErrNoActiveBundle
	}
	if err != nil {
		return Bundle{}, "", fmt.Errorf("load active policy bundle: %w", err)
	}
	var bundle Bundle
	if err := json.Unmarshal(document, &bundle); err != nil {
		return Bundle{}, "", fmt.Errorf("decode active policy bundle: %w", err)
	}

	return bundle, digest, nil
}

func (r *PostgresBundleRepository) RecordDecision(ctx context.Context, record DecisionRecord) error {
	denials, err := json.Marshal(record.Denials)
	if err != nil {
		return fmt.Errorf("encode policy denials: %w", err)
	}
	obligations, err := json.Marshal(record.Obligations)
	if err != nil {
		return fmt.Errorf("encode policy obligations: %w", err)
	}
	_, err = r.database.ExecContext(ctx, `
		INSERT INTO broker_policy_decisions (
			decision_id, tenant_id, actor_id, phase, scope, recipe_id, target_class,
			input_digest, bundle_id, bundle_version, bundle_digest, allow,
			requires_approval, denials, obligations, evaluated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
		record.DecisionID, record.TenantID, record.ActorID, record.Phase, record.Scope,
		record.RecipeID, record.TargetClass, record.InputDigest, record.BundleID,
		record.BundleVersion, record.BundleDigest, record.Allow, record.RequiresApproval,
		denials, obligations, record.EvaluatedAt)
	if err != nil {
		return fmt.Errorf("insert policy decision: %w", err)
	}

	return nil
}
