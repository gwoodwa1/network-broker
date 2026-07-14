package evidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrEnvelopeNotFound  = errors.New("evidence envelope was not found")
	ErrEnvelopeConflict  = errors.New("immutable evidence envelope conflicts with an existing record")
	ErrEnvelopeIntegrity = errors.New("evidence envelope integrity verification failed")
)

// Repository is the immutable tenant-aware persistence boundary for signed
// evidence envelopes.
type Repository interface {
	Create(context.Context, EvidenceEnvelope) error
	GetForTenant(context.Context, string, string) (EvidenceEnvelope, error)
	GetByID(context.Context, string) (EvidenceEnvelope, error)
}

type MemoryRepository struct {
	mu        sync.RWMutex
	envelopes map[string][]byte
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{envelopes: make(map[string][]byte)}
}

func (r *MemoryRepository) Create(_ context.Context, envelope EvidenceEnvelope) error {
	document, err := encodeEnvelope(envelope)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.envelopes[envelope.EvidenceID]; ok {
		if bytes.Equal(existing, document) {
			return nil
		}
		return ErrEnvelopeConflict
	}
	r.envelopes[envelope.EvidenceID] = append([]byte(nil), document...)

	return nil
}

func (r *MemoryRepository) GetForTenant(ctx context.Context, tenantID, evidenceID string) (EvidenceEnvelope, error) {
	envelope, err := r.GetByID(ctx, evidenceID)
	if err != nil || envelope.TenantID != tenantID {
		return EvidenceEnvelope{}, ErrEnvelopeNotFound
	}

	return envelope, nil
}

func (r *MemoryRepository) GetByID(_ context.Context, evidenceID string) (EvidenceEnvelope, error) {
	r.mu.RLock()
	document, ok := r.envelopes[evidenceID]
	document = append([]byte(nil), document...)
	r.mu.RUnlock()
	if !ok {
		return EvidenceEnvelope{}, ErrEnvelopeNotFound
	}

	return decodeEnvelope(document)
}

type PostgresRepository struct {
	database *sql.DB
}

func NewPostgresRepository(database *sql.DB) (*PostgresRepository, error) {
	if database == nil {
		return nil, fmt.Errorf("evidence envelope database is required")
	}

	return &PostgresRepository{database: database}, nil
}

func (r *PostgresRepository) Create(ctx context.Context, envelope EvidenceEnvelope) error {
	if r == nil || r.database == nil {
		return fmt.Errorf("evidence envelope database is required")
	}
	document, err := encodeEnvelope(envelope)
	if err != nil {
		return err
	}
	digest := digestDocument(document)
	result, err := r.database.ExecContext(ctx, `
		INSERT INTO broker_evidence_envelopes (
			evidence_id, tenant_id, task_id, accepted_attempt_id, fencing_token,
			target_id, recipe_id, observed_at, valid_until, document, document_digest
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (evidence_id) DO NOTHING`,
		envelope.EvidenceID, envelope.TenantID, envelope.TaskID, envelope.AcceptedAttemptID,
		envelope.FencingToken, envelope.TargetID, envelope.RecipeID, envelope.ObservedAt,
		envelope.ValidUntil, document, digest)
	if err != nil {
		return fmt.Errorf("insert evidence envelope: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect evidence envelope insert: %w", err)
	}
	if rows == 1 {
		return nil
	}
	existing, err := r.GetForTenant(ctx, envelope.TenantID, envelope.EvidenceID)
	if err != nil {
		return err
	}
	existingDocument, err := encodeEnvelope(existing)
	if err != nil {
		return err
	}
	if existing.EvidenceID != envelope.EvidenceID || !bytes.Equal(existingDocument, document) {
		return ErrEnvelopeConflict
	}

	return nil
}

func (r *PostgresRepository) GetForTenant(ctx context.Context, tenantID, evidenceID string) (EvidenceEnvelope, error) {
	if r == nil || r.database == nil || tenantID == "" || evidenceID == "" {
		return EvidenceEnvelope{}, fmt.Errorf("evidence database and identity are required")
	}

	return scanStoredEnvelope(r.database.QueryRowContext(ctx, `
		SELECT tenant_id, task_id, accepted_attempt_id, fencing_token, target_id,
			recipe_id, observed_at, valid_until, document, document_digest
		FROM broker_evidence_envelopes WHERE evidence_id = $1 AND tenant_id = $2`, evidenceID, tenantID), evidenceID)
}

func (r *PostgresRepository) GetByID(ctx context.Context, evidenceID string) (EvidenceEnvelope, error) {
	if r == nil || r.database == nil || evidenceID == "" {
		return EvidenceEnvelope{}, fmt.Errorf("evidence database and identity are required")
	}

	return scanStoredEnvelope(r.database.QueryRowContext(ctx, `
		SELECT tenant_id, task_id, accepted_attempt_id, fencing_token, target_id,
			recipe_id, observed_at, valid_until, document, document_digest
		FROM broker_evidence_envelopes WHERE evidence_id = $1`, evidenceID), evidenceID)
}

type storedEnvelopeRow interface {
	Scan(...any) error
}

func scanStoredEnvelope(row storedEnvelopeRow, evidenceID string) (EvidenceEnvelope, error) {
	var storedTenant, taskID, attemptID, targetID, recipeID, digest string
	var fencingToken int64
	var observedAt, validUntil sql.NullTime
	var document []byte
	err := row.Scan(
		&storedTenant, &taskID, &attemptID, &fencingToken, &targetID, &recipeID,
		&observedAt, &validUntil, &document, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		return EvidenceEnvelope{}, ErrEnvelopeNotFound
	}
	if err != nil {
		return EvidenceEnvelope{}, fmt.Errorf("get evidence envelope: %w", err)
	}
	if digestDocument(document) != digest {
		return EvidenceEnvelope{}, ErrEnvelopeIntegrity
	}
	envelope, err := decodeEnvelope(document)
	if err != nil {
		return EvidenceEnvelope{}, err
	}
	if envelope.EvidenceID != evidenceID || envelope.TenantID != storedTenant || envelope.TaskID != taskID ||
		envelope.AcceptedAttemptID != attemptID || envelope.FencingToken != fencingToken ||
		envelope.TargetID != targetID || envelope.RecipeID != recipeID || !observedAt.Valid || !validUntil.Valid ||
		!envelope.ObservedAt.UTC().Truncate(time.Microsecond).Equal(observedAt.Time) ||
		!envelope.ValidUntil.UTC().Truncate(time.Microsecond).Equal(validUntil.Time) {
		return EvidenceEnvelope{}, ErrEnvelopeIntegrity
	}

	return envelope, nil
}

func encodeEnvelope(envelope EvidenceEnvelope) ([]byte, error) {
	if err := validatePersistedEnvelope(envelope); err != nil {
		return nil, err
	}
	document, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("encode evidence envelope document: %w", err)
	}
	if len(document) == 0 || len(document) > 16<<20 {
		return nil, fmt.Errorf("evidence envelope document exceeds its bound")
	}

	return document, nil
}

func decodeEnvelope(document []byte) (EvidenceEnvelope, error) {
	var envelope EvidenceEnvelope
	if err := json.Unmarshal(document, &envelope); err != nil {
		return EvidenceEnvelope{}, fmt.Errorf("decode evidence envelope document: %w", err)
	}
	if err := validatePersistedEnvelope(envelope); err != nil {
		return EvidenceEnvelope{}, errors.Join(ErrEnvelopeIntegrity, err)
	}

	return envelope, nil
}

func validatePersistedEnvelope(envelope EvidenceEnvelope) error {
	required := []string{
		envelope.EvidenceID, envelope.TenantID, envelope.TaskID, envelope.TargetID,
		envelope.RecipeID, envelope.AcceptedAttemptID, envelope.Captured.URI,
		envelope.Captured.SHA256Digest, envelope.Sanitised.URI, envelope.Sanitised.SHA256Digest,
		envelope.Sanitised.TransformationManifestDigest, envelope.Attribution.CollectorIdentity,
		envelope.Attribution.SignatureAlgorithm, envelope.Attribution.SigningKeyRef,
	}
	for _, value := range required {
		if value == "" || len(value) > 2048 {
			return fmt.Errorf("complete bounded evidence envelope identity and lineage are required")
		}
	}
	if envelope.FencingToken <= 0 || envelope.ObservedAt.IsZero() ||
		!envelope.ValidUntil.After(envelope.ObservedAt) || len(envelope.Attribution.Signature) == 0 {
		return fmt.Errorf("evidence envelope validity, fence and signature are required")
	}

	return nil
}

func digestDocument(document []byte) string {
	digest := sha256.Sum256(document)

	return hex.EncodeToString(digest[:])
}

var (
	_ Repository = (*MemoryRepository)(nil)
	_ Repository = (*PostgresRepository)(nil)
)
