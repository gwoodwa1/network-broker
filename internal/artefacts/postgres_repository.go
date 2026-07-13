package artefacts

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

type PostgresRepository struct {
	database *sql.DB
}

func NewPostgresRepository(database *sql.DB) (*PostgresRepository, error) {
	if database == nil {
		return nil, fmt.Errorf("artefact metadata database is required")
	}

	return &PostgresRepository{database: database}, nil
}

func (r *PostgresRepository) Create(ctx context.Context, metadata Metadata) error {
	if err := validateMetadata(r, metadata); err != nil {
		return err
	}
	manifest, err := encodeManifest(metadata.Manifest)
	if err != nil {
		return err
	}
	result, err := r.database.ExecContext(ctx, `
		INSERT INTO broker_artefacts (
			artefact_id, tenant_id, class, uri, object_key, sha256_digest, byte_count,
			media_type, transport, attempt_id, encryption_key_ref, parent_artefact_id,
			parent_digest, transformation_manifest, manifest_digest, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''), NULLIF($10, ''),
			NULLIF($11, ''), NULLIF($12, ''), NULLIF($13, ''), $14, NULLIF($15, ''), $16)
		ON CONFLICT (artefact_id) DO NOTHING`,
		metadata.ArtefactID, metadata.TenantID, metadata.Class, metadata.URI, metadata.ObjectKey,
		metadata.SHA256Digest, metadata.ByteCount, metadata.MediaType, metadata.Transport,
		metadata.AttemptID, metadata.EncryptionKeyRef, metadata.ParentArtefactID,
		metadata.ParentDigest, manifest, metadata.ManifestDigest, metadata.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert artefact metadata: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect artefact metadata insert: %w", err)
	}
	if rows == 1 {
		return nil
	}
	existing, err := r.Get(ctx, metadata.TenantID, metadata.URI)
	if err != nil {
		if errors.Is(err, ErrArtefactNotFound) {
			return ErrMetadataConflict
		}
		return fmt.Errorf("read idempotent artefact metadata: %w", err)
	}
	if !metadataEqual(existing, metadata) {
		return ErrMetadataConflict
	}

	return nil
}

func metadataEqual(left, right Metadata) bool {
	return left.ArtefactID == right.ArtefactID && left.TenantID == right.TenantID &&
		left.Class == right.Class && left.URI == right.URI && left.ObjectKey == right.ObjectKey &&
		left.SHA256Digest == right.SHA256Digest && left.ByteCount == right.ByteCount &&
		left.MediaType == right.MediaType && left.Transport == right.Transport &&
		left.AttemptID == right.AttemptID && left.EncryptionKeyRef == right.EncryptionKeyRef &&
		left.ParentArtefactID == right.ParentArtefactID && left.ParentDigest == right.ParentDigest &&
		left.ManifestDigest == right.ManifestDigest && left.CreatedAt.Equal(right.CreatedAt) &&
		reflect.DeepEqual(left.Manifest, right.Manifest)
}

func (r *PostgresRepository) Get(ctx context.Context, tenantID, uri string) (Metadata, error) {
	if r == nil || r.database == nil || invalidSegment(tenantID) || uri == "" {
		return Metadata{}, fmt.Errorf("artefact database, tenant and URI are required")
	}
	var metadata Metadata
	var class string
	var transport, attemptID, encryptionKeyRef, parentArtefactID, parentDigest, manifestDigest sql.NullString
	var manifest []byte
	err := r.database.QueryRowContext(ctx, `
		SELECT artefact_id, tenant_id, class, uri, object_key, sha256_digest, byte_count,
		       media_type, transport, attempt_id, encryption_key_ref, parent_artefact_id,
		       parent_digest, transformation_manifest, manifest_digest, created_at
		FROM broker_artefacts
		WHERE tenant_id = $1 AND uri = $2`, tenantID, uri,
	).Scan(
		&metadata.ArtefactID, &metadata.TenantID, &class, &metadata.URI, &metadata.ObjectKey,
		&metadata.SHA256Digest, &metadata.ByteCount, &metadata.MediaType, &transport, &attemptID,
		&encryptionKeyRef, &parentArtefactID, &parentDigest, &manifest, &manifestDigest, &metadata.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Metadata{}, ErrArtefactNotFound
	}
	if err != nil {
		return Metadata{}, fmt.Errorf("get artefact metadata: %w", err)
	}
	metadata.Class = Class(class)
	metadata.Transport = transport.String
	metadata.AttemptID = attemptID.String
	metadata.EncryptionKeyRef = encryptionKeyRef.String
	metadata.ParentArtefactID = parentArtefactID.String
	metadata.ParentDigest = parentDigest.String
	metadata.ManifestDigest = manifestDigest.String
	if len(manifest) > 0 {
		metadata.Manifest = &TransformationManifest{}
		if err := json.Unmarshal(manifest, metadata.Manifest); err != nil {
			return Metadata{}, fmt.Errorf("decode transformation manifest: %w", err)
		}
	}

	return metadata, nil
}

func validateMetadata(repository *PostgresRepository, metadata Metadata) error {
	if repository == nil || repository.database == nil || metadata.ArtefactID == "" ||
		invalidSegment(metadata.TenantID) || metadata.URI != "artefact://"+metadata.ArtefactID ||
		metadata.ObjectKey == "" || !validDigest(metadata.SHA256Digest) || metadata.ByteCount == 0 ||
		metadata.ByteCount > MaximumArtefactBytes || metadata.MediaType == "" || metadata.CreatedAt.IsZero() {
		return fmt.Errorf("complete bounded artefact metadata and database are required")
	}
	if metadata.ObjectKey != objectKey(metadata.TenantID, metadata.Class, metadata.SHA256Digest) {
		return fmt.Errorf("artefact object key does not match tenant, class and digest")
	}
	switch metadata.Class {
	case ClassCaptured:
		return validateCapturedMetadata(metadata)
	case ClassSanitised:
		return validateSanitisedMetadata(metadata)
	default:
		return fmt.Errorf("artefact class is invalid")
	}
}

func validateCapturedMetadata(metadata Metadata) error {
	if metadata.Transport == "" || metadata.AttemptID == "" || metadata.EncryptionKeyRef == "" ||
		metadata.ParentArtefactID != "" || metadata.ParentDigest != "" || metadata.Manifest != nil ||
		metadata.ManifestDigest != "" {
		return fmt.Errorf("captured artefact metadata is invalid")
	}

	return nil
}

func validateSanitisedMetadata(metadata Metadata) error {
	if metadata.Transport != "" || metadata.AttemptID != "" || metadata.EncryptionKeyRef != "" ||
		metadata.ParentArtefactID == "" || !validDigest(metadata.ParentDigest) || metadata.Manifest == nil ||
		!validDigest(metadata.ManifestDigest) {
		return fmt.Errorf("sanitised artefact metadata is invalid")
	}

	return nil
}

func encodeManifest(manifest *TransformationManifest) ([]byte, error) {
	if manifest == nil {
		return nil, nil
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("encode transformation manifest: %w", err)
	}

	return payload, nil
}
