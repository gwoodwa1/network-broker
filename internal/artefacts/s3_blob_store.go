package artefacts

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const digestMetadataKey = "network-broker-sha256"

type s3API interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
}

type S3BlobOptions struct {
	Bucket      string
	Prefix      string
	SSEKMSKeyID string
}

// S3BlobStore uses conditional writes to preserve content-addressed
// immutability. Compatible providers must support If-None-Match on PutObject.
type S3BlobStore struct {
	client      s3API
	bucket      string
	prefix      string
	sseKMSKeyID string
}

func NewS3BlobStore(client s3API, options S3BlobOptions) (*S3BlobStore, error) {
	prefix := strings.Trim(options.Prefix, "/")
	if client == nil || options.Bucket == "" || strings.Contains(options.Bucket, "/") ||
		strings.Contains(prefix, "..") {
		return nil, fmt.Errorf("S3 client, bucket and safe optional prefix are required")
	}

	return &S3BlobStore{
		client: client, bucket: options.Bucket, prefix: prefix, sseKMSKeyID: options.SSEKMSKeyID,
	}, nil
}

func (s *S3BlobStore) PutIfAbsent(ctx context.Context, key string, payload []byte,
	digest, mediaType string,
) error {
	if err := validateBlobWrite(key, payload, digest, mediaType); err != nil {
		return err
	}
	objectKey := s.objectKey(key)
	input := &s3.PutObjectInput{
		Bucket: aws.String(s.bucket), Key: aws.String(objectKey), Body: bytes.NewReader(payload),
		ContentLength: aws.Int64(int64(len(payload))), ContentType: aws.String(mediaType),
		IfNoneMatch: aws.String("*"), Metadata: map[string]string{digestMetadataKey: digest},
	}
	if s.sseKMSKeyID != "" {
		input.ServerSideEncryption = types.ServerSideEncryptionAwsKms
		input.SSEKMSKeyId = aws.String(s.sseKMSKeyID)
	}
	if _, err := s.client.PutObject(ctx, input); err != nil {
		existing, headErr := s.client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(s.bucket), Key: aws.String(objectKey),
		})
		if headErr == nil && existing.ContentLength != nil && *existing.ContentLength == int64(len(payload)) &&
			existing.Metadata[digestMetadataKey] == digest {
			return nil
		}

		return fmt.Errorf("conditionally put S3 artefact object: %w", err)
	}

	return nil
}

func (s *S3BlobStore) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	if err := validateBlobKey(key); err != nil {
		return nil, err
	}
	result, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket), Key: aws.String(s.objectKey(key)),
	})
	if err != nil {
		return nil, fmt.Errorf("get S3 artefact object: %w", err)
	}
	if result.Body == nil {
		return nil, fmt.Errorf("S3 artefact object has no response body")
	}

	return result.Body, nil
}

func (s *S3BlobStore) objectKey(key string) string {
	if s.prefix == "" {
		return key
	}

	return path.Join(s.prefix, key)
}

func validateBlobWrite(key string, payload []byte, digest, mediaType string) error {
	if err := validateBlobKey(key); err != nil {
		return err
	}
	if len(payload) == 0 || len(payload) > MaximumArtefactBytes || len(digest) != 64 ||
		digestBytes(payload) != digest || mediaType == "" {
		return fmt.Errorf("bounded payload, matching SHA-256 digest and media type are required")
	}

	return nil
}

func validateBlobKey(key string) error {
	if !strings.HasPrefix(key, "tenants/") || strings.HasPrefix(key, "/") || strings.Contains(key, "..") ||
		path.Clean(key) != key {
		return fmt.Errorf("tenant-scoped canonical object key is required")
	}
	parts := strings.Split(key, "/")
	if len(parts) != 6 || parts[0] != "tenants" || parts[1] == "" ||
		(parts[2] != string(ClassCaptured) && parts[2] != string(ClassSanitised)) || parts[3] != "sha256" ||
		!validDigest(parts[5]) || parts[4] != parts[5][:2] {
		return fmt.Errorf("tenant-scoped canonical object key is required")
	}
	tenant, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || invalidSegment(string(tenant)) {
		return fmt.Errorf("tenant-scoped canonical object key is required")
	}

	return nil
}

func validDigest(value string) bool {
	if len(value) != sha256DigestHexLength {
		return false
	}
	_, err := hex.DecodeString(value)

	return err == nil
}
