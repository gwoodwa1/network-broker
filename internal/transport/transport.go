package transport

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"
)

// TargetConnection is resolved from a trusted target snapshot. It deliberately
// contains no credential material.
type TargetConnection struct {
	TargetID         string
	Endpoint         string
	CredentialToken  string
	CredentialExpiry time.Time
	CredentialClass  string
}

// BoundedOperation identifies a catalogue-owned recipe and its hard limits.
// Clients never supply a protocol command or path through this contract.
type BoundedOperation struct {
	RecipeID        string
	RecipeVersion   string
	MaximumDuration time.Duration
	MaximumBytes    int64
}

// CapturedBytes is the exact bounded payload returned by a transport plus its
// capture metadata.
type CapturedBytes struct {
	TargetID   string
	Payload    []byte
	Digest     [sha256.Size]byte
	MediaType  string
	CapturedAt time.Time
}

// Adapter is the narrow boundary implemented by gNMI, NETCONF and SSH drivers.
type Adapter interface {
	Execute(context.Context, TargetConnection, BoundedOperation) (CapturedBytes, error)
}

// StubAdapter is deterministic and supports local end-to-end collector tests.
type StubAdapter struct {
	Now       func() time.Time
	Payload   []byte
	MediaType string
}

func (a StubAdapter) Execute(ctx context.Context, target TargetConnection, operation BoundedOperation) (CapturedBytes, error) {
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	executedAt := now()
	if target.TargetID == "" {
		return CapturedBytes{}, fmt.Errorf("target id is required")
	}
	if target.CredentialToken == "" || target.CredentialExpiry.IsZero() {
		return CapturedBytes{}, fmt.Errorf("bounded target credential is required")
	}
	if !executedAt.Before(target.CredentialExpiry) {
		return CapturedBytes{}, fmt.Errorf("bounded target credential has expired")
	}
	if operation.RecipeID == "" {
		return CapturedBytes{}, fmt.Errorf("recipe id is required")
	}
	if operation.MaximumDuration <= 0 || operation.MaximumBytes <= 0 {
		return CapturedBytes{}, fmt.Errorf("positive duration and response byte limits are required")
	}
	select {
	case <-ctx.Done():
		return CapturedBytes{}, ctx.Err()
	default:
	}
	payload := a.Payload
	if payload == nil {
		payload = []byte("ok")
	}
	if int64(len(payload)) > operation.MaximumBytes {
		return CapturedBytes{}, fmt.Errorf("transport response exceeds %d byte limit", operation.MaximumBytes)
	}
	mediaType := a.MediaType
	if mediaType == "" {
		mediaType = "application/octet-stream"
	}
	copyPayload := append([]byte(nil), payload...)
	return CapturedBytes{
		TargetID:   target.TargetID,
		Payload:    copyPayload,
		Digest:     sha256.Sum256(copyPayload),
		MediaType:  mediaType,
		CapturedAt: executedAt.UTC(),
	}, nil
}
