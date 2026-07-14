package disclosure

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

var (
	ErrDecisionNotFound = errors.New("disclosure decision was not found")
	ErrDecisionConflict = errors.New("immutable disclosure decision conflicts with an existing record")
	ErrReceiptNotFound  = errors.New("disclosure receipt was not found")
	ErrReceiptConflict  = errors.New("disclosure request conflicts with an existing receipt")
	ErrRecordIntegrity  = errors.New("disclosure record integrity verification failed")
)

type Repository interface {
	CreateDecision(context.Context, Decision) error
	GetDecision(context.Context, string, string) (Decision, error)
	CreateReceipt(context.Context, Receipt) (Receipt, error)
	GetReceipt(context.Context, string, string) (Receipt, error)
	GetReceiptByRequest(context.Context, string, string, string) (Receipt, error)
}

type MemoryRepository struct {
	mu        sync.RWMutex
	decisions map[string][]byte
	receipts  map[string][]byte
	requests  map[string]string
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{
		decisions: make(map[string][]byte), receipts: make(map[string][]byte), requests: make(map[string]string),
	}
}

func (r *MemoryRepository) CreateDecision(_ context.Context, decision Decision) error {
	document, err := encodeDecision(decision)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.decisions[decision.DecisionID]; ok {
		if bytes.Equal(existing, document) {
			return nil
		}
		return ErrDecisionConflict
	}
	r.decisions[decision.DecisionID] = append([]byte(nil), document...)

	return nil
}

func (r *MemoryRepository) GetDecision(_ context.Context, tenantID, decisionID string) (Decision, error) {
	r.mu.RLock()
	document, ok := r.decisions[decisionID]
	document = append([]byte(nil), document...)
	r.mu.RUnlock()
	if !ok {
		return Decision{}, ErrDecisionNotFound
	}
	decision, err := decodeDecision(document)
	if err != nil || decision.TenantID != tenantID {
		return Decision{}, ErrDecisionNotFound
	}

	return decision, nil
}

func (r *MemoryRepository) CreateReceipt(_ context.Context, receipt Receipt) (Receipt, error) {
	document, err := encodeReceipt(receipt)
	if err != nil {
		return Receipt{}, err
	}
	requestKey := receiptRequestKey(receipt.TenantID, receipt.ActorID, receipt.RequestID)
	r.mu.Lock()
	defer r.mu.Unlock()
	if existingID, ok := r.requests[requestKey]; ok {
		existing, decodeErr := decodeReceipt(r.receipts[existingID])
		if decodeErr != nil {
			return Receipt{}, decodeErr
		}
		if sameDelivery(existing, receipt) {
			return existing, nil
		}
		return Receipt{}, ErrReceiptConflict
	}
	if existing, ok := r.receipts[receipt.ReceiptID]; ok {
		if bytes.Equal(existing, document) {
			return receipt, nil
		}
		return Receipt{}, ErrReceiptConflict
	}
	r.receipts[receipt.ReceiptID] = append([]byte(nil), document...)
	r.requests[requestKey] = receipt.ReceiptID

	return cloneReceipt(&receipt), nil
}

func (r *MemoryRepository) GetReceipt(_ context.Context, tenantID, receiptID string) (Receipt, error) {
	r.mu.RLock()
	document, ok := r.receipts[receiptID]
	document = append([]byte(nil), document...)
	r.mu.RUnlock()
	if !ok {
		return Receipt{}, ErrReceiptNotFound
	}
	receipt, err := decodeReceipt(document)
	if err != nil || receipt.TenantID != tenantID {
		return Receipt{}, ErrReceiptNotFound
	}

	return receipt, nil
}

func (r *MemoryRepository) GetReceiptByRequest(ctx context.Context, tenantID, actorID,
	requestID string,
) (Receipt, error) {
	r.mu.RLock()
	receiptID, ok := r.requests[receiptRequestKey(tenantID, actorID, requestID)]
	r.mu.RUnlock()
	if !ok {
		return Receipt{}, ErrReceiptNotFound
	}

	return r.GetReceipt(ctx, tenantID, receiptID)
}

type PostgresRepository struct {
	database *sql.DB
}

func NewPostgresRepository(database *sql.DB) (*PostgresRepository, error) {
	if database == nil {
		return nil, fmt.Errorf("disclosure database is required")
	}

	return &PostgresRepository{database: database}, nil
}

func (r *PostgresRepository) CreateDecision(ctx context.Context, decision Decision) error {
	if r == nil || r.database == nil {
		return fmt.Errorf("disclosure database is required")
	}
	document, err := encodeDecision(decision)
	if err != nil {
		return err
	}
	result, err := r.database.ExecContext(ctx, `
		INSERT INTO broker_disclosure_decisions (
			decision_id, tenant_id, actor_id, evidence_id, evaluated_at, expires_at,
			document, document_digest
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (decision_id) DO NOTHING`,
		decision.DecisionID, decision.TenantID, decision.ActorID, decision.EvidenceID,
		decision.EvaluatedAt, decision.ExpiresAt, document, disclosureDocumentDigest(document))
	if err != nil {
		return fmt.Errorf("insert disclosure decision: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect disclosure decision insert: %w", err)
	}
	if rows == 1 {
		return nil
	}
	existing, existingDocument, err := r.getDecision(ctx, decision.TenantID, decision.DecisionID)
	if err != nil {
		return err
	}
	if existing.DecisionID != decision.DecisionID || !bytes.Equal(existingDocument, document) {
		return ErrDecisionConflict
	}

	return nil
}

func (r *PostgresRepository) GetDecision(ctx context.Context, tenantID, decisionID string) (Decision, error) {
	decision, _, err := r.getDecision(ctx, tenantID, decisionID)

	return decision, err
}

func (r *PostgresRepository) CreateReceipt(ctx context.Context, receipt Receipt) (Receipt, error) {
	if r == nil || r.database == nil {
		return Receipt{}, fmt.Errorf("disclosure database is required")
	}
	document, err := encodeReceipt(receipt)
	if err != nil {
		return Receipt{}, err
	}
	result, err := r.database.ExecContext(ctx, `
		INSERT INTO broker_disclosure_receipts (
			receipt_id, tenant_id, evidence_id, actor_id, disclosure_decision_id,
			request_id, delivered_payload_digest, delivered_at, schema_version,
			document, document_digest
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT DO NOTHING`,
		receipt.ReceiptID, receipt.TenantID, receipt.EvidenceID, receipt.ActorID,
		receipt.DisclosureDecisionID, receipt.RequestID, receipt.DeliveredPayloadDigest,
		receipt.DeliveredAt, receipt.SchemaVersion, document, disclosureDocumentDigest(document))
	if err != nil {
		return Receipt{}, fmt.Errorf("insert disclosure receipt: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return Receipt{}, fmt.Errorf("inspect disclosure receipt insert: %w", err)
	}
	if rows == 1 {
		return cloneReceipt(&receipt), nil
	}
	existing, err := r.GetReceiptByRequest(ctx, receipt.TenantID, receipt.ActorID, receipt.RequestID)
	if errors.Is(err, ErrReceiptNotFound) {
		return Receipt{}, ErrReceiptConflict
	}
	if err != nil {
		return Receipt{}, err
	}
	if !sameDelivery(existing, receipt) {
		return Receipt{}, ErrReceiptConflict
	}

	return existing, nil
}

func (r *PostgresRepository) GetReceipt(ctx context.Context, tenantID, receiptID string) (Receipt, error) {
	return r.getReceipt(ctx, `receipt_id = $2`, tenantID, receiptID)
}

func (r *PostgresRepository) GetReceiptByRequest(ctx context.Context, tenantID, actorID,
	requestID string,
) (Receipt, error) {
	return r.getReceipt(ctx, `actor_id = $2 AND request_id = $3`, tenantID, actorID, requestID)
}

func (r *PostgresRepository) getDecision(ctx context.Context, tenantID,
	decisionID string,
) (Decision, []byte, error) {
	if r == nil || r.database == nil || tenantID == "" || decisionID == "" {
		return Decision{}, nil, fmt.Errorf("disclosure database, tenant and decision are required")
	}
	var storedTenant, actorID, evidenceID, digest string
	var evaluatedAt, expiresAt time.Time
	var document []byte
	err := r.database.QueryRowContext(ctx, `
		SELECT tenant_id, actor_id, evidence_id, evaluated_at, expires_at, document, document_digest
		FROM broker_disclosure_decisions WHERE tenant_id = $1 AND decision_id = $2`,
		tenantID, decisionID).Scan(
		&storedTenant, &actorID, &evidenceID, &evaluatedAt, &expiresAt, &document, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		return Decision{}, nil, ErrDecisionNotFound
	}
	if err != nil {
		return Decision{}, nil, fmt.Errorf("get disclosure decision: %w", err)
	}
	if disclosureDocumentDigest(document) != digest {
		return Decision{}, nil, ErrRecordIntegrity
	}
	decision, err := decodeDecision(document)
	if err != nil {
		return Decision{}, nil, err
	}
	if decision.DecisionID != decisionID || decision.TenantID != storedTenant || decision.ActorID != actorID ||
		decision.EvidenceID != evidenceID ||
		!decision.EvaluatedAt.UTC().Truncate(time.Microsecond).Equal(evaluatedAt) ||
		!decision.ExpiresAt.UTC().Truncate(time.Microsecond).Equal(expiresAt) {
		return Decision{}, nil, ErrRecordIntegrity
	}

	return decision, document, nil
}

func (r *PostgresRepository) getReceipt(ctx context.Context, predicate string,
	arguments ...any,
) (Receipt, error) {
	if r == nil || r.database == nil || len(arguments) < 2 {
		return Receipt{}, fmt.Errorf("disclosure database and receipt identity are required")
	}
	query := `SELECT receipt_id, tenant_id, evidence_id, actor_id, disclosure_decision_id,
		request_id, delivered_payload_digest, delivered_at, schema_version, document, document_digest
		FROM broker_disclosure_receipts WHERE tenant_id = $1 AND ` + predicate
	var receiptID, tenantID, evidenceID, actorID, decisionID, requestID, payloadDigest, schemaVersion, digest string
	var deliveredAt time.Time
	var document []byte
	err := r.database.QueryRowContext(ctx, query, arguments...).Scan(
		&receiptID, &tenantID, &evidenceID, &actorID, &decisionID, &requestID,
		&payloadDigest, &deliveredAt, &schemaVersion, &document, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		return Receipt{}, ErrReceiptNotFound
	}
	if err != nil {
		return Receipt{}, fmt.Errorf("get disclosure receipt: %w", err)
	}
	if disclosureDocumentDigest(document) != digest {
		return Receipt{}, ErrRecordIntegrity
	}
	receipt, err := decodeReceipt(document)
	if err != nil {
		return Receipt{}, err
	}
	if receipt.ReceiptID != receiptID || receipt.TenantID != tenantID || receipt.EvidenceID != evidenceID ||
		receipt.ActorID != actorID || receipt.DisclosureDecisionID != decisionID || receipt.RequestID != requestID ||
		receipt.DeliveredPayloadDigest != payloadDigest || receipt.SchemaVersion != schemaVersion ||
		!receipt.DeliveredAt.UTC().Truncate(time.Microsecond).Equal(deliveredAt) {
		return Receipt{}, ErrRecordIntegrity
	}

	return receipt, nil
}

func encodeDecision(decision Decision) ([]byte, error) {
	if err := validatePersistedDecision(decision); err != nil {
		return nil, err
	}
	document, err := json.Marshal(decision)
	if err != nil {
		return nil, fmt.Errorf("encode disclosure decision: %w", err)
	}

	return document, nil
}

func decodeDecision(document []byte) (Decision, error) {
	var decision Decision
	if err := json.Unmarshal(document, &decision); err != nil {
		return Decision{}, fmt.Errorf("decode disclosure decision: %w", err)
	}
	if err := validatePersistedDecision(decision); err != nil {
		return Decision{}, errors.Join(ErrRecordIntegrity, err)
	}

	return decision, nil
}

func encodeReceipt(receipt Receipt) ([]byte, error) {
	if err := validateReceipt(receipt); err != nil {
		return nil, err
	}
	if receipt.SignatureSet.Version == "" || len(receipt.SignatureSet.Signatures) == 0 {
		return nil, fmt.Errorf("signed disclosure receipt is required")
	}
	document, err := json.Marshal(receipt)
	if err != nil {
		return nil, fmt.Errorf("encode disclosure receipt: %w", err)
	}

	return document, nil
}

func decodeReceipt(document []byte) (Receipt, error) {
	var receipt Receipt
	if err := json.Unmarshal(document, &receipt); err != nil {
		return Receipt{}, fmt.Errorf("decode disclosure receipt: %w", err)
	}
	if _, err := encodeReceipt(receipt); err != nil {
		return Receipt{}, errors.Join(ErrRecordIntegrity, err)
	}

	return cloneReceipt(&receipt), nil
}

func validatePersistedDecision(decision Decision) error {
	if decision.DecisionID == "" || decision.ActorID == "" || decision.TenantID == "" ||
		decision.EvidenceID == "" || decision.PolicyBundleDigest == "" || decision.PolicyInputDigest == "" ||
		decision.PermittedRepresentation == "" || len(decision.PermittedFields) == 0 ||
		decision.EvaluatedAt.IsZero() || !decision.ExpiresAt.After(decision.EvaluatedAt) {
		return fmt.Errorf("complete disclosure decision identity, policy and validity are required")
	}

	return nil
}

func sameDelivery(left, right Receipt) bool {
	return left.TenantID == right.TenantID && left.EvidenceID == right.EvidenceID &&
		left.ActorID == right.ActorID && left.DisclosureDecisionID == right.DisclosureDecisionID &&
		left.PolicyBundleDigest == right.PolicyBundleDigest && left.PolicyInputDigest == right.PolicyInputDigest &&
		left.Representation == right.Representation && left.DeliveredPayloadDigest == right.DeliveredPayloadDigest &&
		left.RequestID == right.RequestID && left.TaintWarning == right.TaintWarning &&
		left.SanitisationSummary == right.SanitisationSummary &&
		slices.Equal(left.FieldsDelivered, right.FieldsDelivered) &&
		slices.Equal(left.TaintedFields, right.TaintedFields) &&
		slices.Equal(left.RedactionsApplied, right.RedactionsApplied)
}

func receiptRequestKey(tenantID, actorID, requestID string) string {
	return tenantID + "\x00" + actorID + "\x00" + requestID
}

func disclosureDocumentDigest(document []byte) string {
	digest := sha256.Sum256(document)

	return hex.EncodeToString(digest[:])
}

var (
	_ Repository = (*MemoryRepository)(nil)
	_ Repository = (*PostgresRepository)(nil)
)
