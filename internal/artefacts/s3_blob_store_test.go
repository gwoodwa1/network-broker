package artefacts

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type staticS3Credentials struct{}

func (staticS3Credentials) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{AccessKeyID: "test-access", SecretAccessKey: "test-secret", Source: "test"}, nil
}

type protocolObject struct {
	payload []byte
	digest  string
}

type s3ProtocolFixture struct {
	mu      sync.Mutex
	objects map[string]protocolObject
}

func (f *s3ProtocolFixture) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.TrimPrefix(request.URL.Path, "/evidence/")
	switch request.Method {
	case http.MethodPut:
		f.put(response, request, key)
	case http.MethodHead:
		f.head(response, key)
	case http.MethodGet:
		f.get(response, key)
	default:
		response.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (f *s3ProtocolFixture) put(response http.ResponseWriter, request *http.Request, key string) {
	if _, exists := f.objects[key]; exists {
		response.WriteHeader(http.StatusPreconditionFailed)
		return
	}
	payload, err := io.ReadAll(request.Body)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	f.objects[key] = protocolObject{
		payload: payload, digest: request.Header.Get("X-Amz-Meta-Network-Broker-Sha256"),
	}
	response.WriteHeader(http.StatusOK)
}

func (f *s3ProtocolFixture) head(response http.ResponseWriter, key string) {
	stored, exists := f.objects[key]
	if !exists {
		response.WriteHeader(http.StatusNotFound)
		return
	}
	response.Header().Set("Content-Length", fmt.Sprint(len(stored.payload)))
	response.Header().Set("X-Amz-Meta-Network-Broker-Sha256", stored.digest)
	response.WriteHeader(http.StatusOK)
}

func (f *s3ProtocolFixture) get(response http.ResponseWriter, key string) {
	stored, exists := f.objects[key]
	if !exists {
		response.WriteHeader(http.StatusNotFound)
		return
	}
	if _, err := response.Write(stored.payload); err != nil {
		return
	}
}

type s3Stub struct {
	putInput  *s3.PutObjectInput
	putErr    error
	head      *s3.HeadObjectOutput
	headErr   error
	getOutput *s3.GetObjectOutput
}

func (s *s3Stub) PutObject(_ context.Context, input *s3.PutObjectInput,
	_ ...func(*s3.Options),
) (*s3.PutObjectOutput, error) {
	s.putInput = input

	return &s3.PutObjectOutput{}, s.putErr
}

func (s *s3Stub) HeadObject(context.Context, *s3.HeadObjectInput,
	...func(*s3.Options),
) (*s3.HeadObjectOutput, error) {
	return s.head, s.headErr
}

func (s *s3Stub) GetObject(context.Context, *s3.GetObjectInput,
	...func(*s3.Options),
) (*s3.GetObjectOutput, error) {
	return s.getOutput, nil
}

func TestS3BlobStoreUsesConditionalTenantScopedWrites(t *testing.T) {
	client := &s3Stub{}
	store, err := NewS3BlobStore(client, S3BlobOptions{Bucket: "evidence", Prefix: "broker"})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("captured")
	digest := digestBytes(payload)
	key := objectKey("tenant-a", ClassCaptured, digest)
	if err := store.PutIfAbsent(context.Background(), key, payload, digest, "application/octet-stream"); err != nil {
		t.Fatal(err)
	}
	if aws.ToString(client.putInput.IfNoneMatch) != "*" ||
		aws.ToString(client.putInput.Key) != "broker/"+key ||
		client.putInput.Metadata[digestMetadataKey] != digest {
		t.Fatalf("unexpected conditional S3 input: %+v", client.putInput)
	}
}

func TestS3BlobStoreAcceptsOnlyMatchingExistingObject(t *testing.T) {
	payload := []byte("captured")
	digest := digestBytes(payload)
	key := objectKey("tenant-a", ClassCaptured, digest)
	client := &s3Stub{
		putErr: errors.New("precondition failed"),
		head: &s3.HeadObjectOutput{
			ContentLength: aws.Int64(int64(len(payload))),
			Metadata:      map[string]string{digestMetadataKey: digest},
		},
	}
	store, err := NewS3BlobStore(client, S3BlobOptions{Bucket: "evidence"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutIfAbsent(context.Background(), key, payload, digest, "text/plain"); err != nil {
		t.Fatalf("expected matching immutable object to be idempotent: %v", err)
	}
	client.head.Metadata[digestMetadataKey] = strings.Repeat("0", 64)
	if err := store.PutIfAbsent(context.Background(), key, payload, digest, "text/plain"); err == nil {
		t.Fatal("expected conflicting existing object to fail")
	}
}

func TestS3BlobStoreReturnsObjectBody(t *testing.T) {
	client := &s3Stub{getOutput: &s3.GetObjectOutput{Body: io.NopCloser(strings.NewReader("captured"))}}
	store, err := NewS3BlobStore(client, S3BlobOptions{Bucket: "evidence"})
	if err != nil {
		t.Fatal(err)
	}
	digest := digestBytes([]byte("captured"))
	reader, err := store.Get(context.Background(), objectKey("tenant-a", ClassCaptured, digest))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Errorf("close object body: %v", err)
		}
	})
	got, err := io.ReadAll(reader)
	if err != nil || string(got) != "captured" {
		t.Fatalf("unexpected object body %q: %v", got, err)
	}
}

func TestS3BlobStoreProtocolCompatibility(t *testing.T) {
	fixture := &s3ProtocolFixture{objects: make(map[string]protocolObject)}
	server := httptest.NewServer(fixture)
	t.Cleanup(server.Close)
	client := s3.New(s3.Options{
		BaseEndpoint: aws.String(server.URL), Region: "us-east-1", UsePathStyle: true,
		Credentials: aws.NewCredentialsCache(staticS3Credentials{}),
	})
	store, err := NewS3BlobStore(client, S3BlobOptions{Bucket: "evidence", Prefix: "broker"})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("protocol-tested")
	digest := digestBytes(payload)
	key := objectKey("tenant-a", ClassCaptured, digest)
	if err := store.PutIfAbsent(context.Background(), key, payload, digest, "text/plain"); err != nil {
		t.Fatal(err)
	}
	if err := store.PutIfAbsent(context.Background(), key, payload, digest, "text/plain"); err != nil {
		t.Fatalf("conditional retry was not idempotent: %v", err)
	}
	reader, err := store.Get(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if closeErr := reader.Close(); closeErr != nil {
		t.Errorf("close protocol object body: %v", closeErr)
	}
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("unexpected protocol object body %q: %v", got, err)
	}
}
