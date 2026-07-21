package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"slices"
	"sort"
	"strings"
	"unicode"

	"network_broker/internal/authctx"
	"network_broker/internal/resolution"
)

const (
	resolutionCreateScope              = "resolutions:create"
	maximumResolutionCreateBodySize    = 64 * 1024
	maximumResolutionCreateRequests    = 32
	maximumClaimsPerResolution         = 32
	maximumTargetsPerResolution        = 1_000
	maximumClaimTypeLength             = 128
	maximumIdempotencyKeyLength        = 128
	maximumRequestedFreshnessInSeconds = 7 * 24 * 60 * 60
)

type resolutionCreateAuthenticator interface {
	Authenticate(*tls.ConnectionState) (authctx.AuthContext, error)
}

type resolutionCreator interface {
	Create(context.Context, resolution.CreateRequest) (resolution.CreateResult, error)
}

type resolutionCreateAPI struct {
	service       resolutionCreator
	authenticator resolutionCreateAuthenticator
	logger        *slog.Logger
	concurrency   chan struct{}
}

type createResolutionBody struct {
	SchemaVersion     string   `json:"schema_version"`
	Claims            []string `json:"claims"`
	TargetIDs         []string `json:"target_ids"`
	MaximumAgeSeconds int64    `json:"maximum_age_seconds"`
}

type createResolutionResponse struct {
	SchemaVersion string                     `json:"schema_version"`
	ResolutionID  string                     `json:"resolution_id"`
	State         resolution.ResolutionState `json:"state"`
	Version       int64                      `json:"version"`
	Created       bool                       `json:"created"`
}

type resolutionCreateErrorDetail struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

type resolutionCreateErrorResponse struct {
	Error resolutionCreateErrorDetail `json:"error"`
}

func newResolutionCreateAPI(service resolutionCreator,
	authenticator resolutionCreateAuthenticator, logger *slog.Logger,
) (*resolutionCreateAPI, error) {
	if service == nil || authenticator == nil || logger == nil {
		return nil, fmt.Errorf("resolution service, authenticator and logger are required")
	}

	return &resolutionCreateAPI{
		service: service, authenticator: authenticator, logger: logger,
		concurrency: make(chan struct{}, maximumResolutionCreateRequests),
	}, nil
}

func (a *resolutionCreateAPI) register(mux *http.ServeMux) {
	mux.Handle("POST /v1/resolutions", a.limit(http.HandlerFunc(a.create)))
}

func (a *resolutionCreateAPI) limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		select {
		case a.concurrency <- struct{}{}:
			defer func() { <-a.concurrency }()
			next.ServeHTTP(response, request)
		default:
			writeResolutionCreateError(response, http.StatusTooManyRequests,
				"RESOLUTION_CREATE_BUSY", "resolution creation capacity is exhausted", true)
		}
	})
}

func (a *resolutionCreateAPI) create(response http.ResponseWriter, request *http.Request) {
	actor, err := a.authenticator.Authenticate(request.TLS)
	if err != nil || actor.Validate() != nil {
		response.Header().Set("WWW-Authenticate", "Mutual")
		writeResolutionCreateError(response, http.StatusUnauthorized,
			"AUTHENTICATION_REQUIRED", "a verified workload identity is required", false)
		return
	}
	if !slices.Contains(actor.AllowedScopes, resolutionCreateScope) {
		writeResolutionCreateError(response, http.StatusForbidden,
			"RESOLUTION_CREATE_DENIED", "resolution creation is not permitted", false)
		return
	}
	idempotencyKey := request.Header.Get("Idempotency-Key")
	if !validIdempotencyKey(idempotencyKey) {
		writeResolutionCreateError(response, http.StatusBadRequest,
			"INVALID_IDEMPOTENCY_KEY", "a valid Idempotency-Key header is required", false)
		return
	}
	document, err := decodeCanonicalResolutionRequest(response, request)
	if err != nil {
		writeResolutionCreateError(response, http.StatusBadRequest,
			"INVALID_REQUEST", "the resolution request is invalid", false)
		return
	}
	digest := sha256.Sum256(document)
	result, err := a.service.Create(request.Context(), resolution.CreateRequest{
		ActorID: actor.SubjectID, TenantID: actor.TenantID, IdempotencyKey: idempotencyKey,
		RequestDigest: "sha256:" + hex.EncodeToString(digest[:]), RequestDocument: document,
	})
	if err != nil {
		if errors.Is(err, resolution.ErrIdempotencyConflict) {
			writeResolutionCreateError(response, http.StatusConflict,
				resolution.IdempotencyConflictCode,
				"idempotency key was reused for different request content", false)
			return
		}
		a.logger.ErrorContext(request.Context(), "create resolution failed", "error", err)
		writeResolutionCreateError(response, http.StatusInternalServerError,
			"RESOLUTION_CREATE_FAILED", "resolution creation failed", true)
		return
	}

	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Location", "/v1/resolutions/"+result.Resolution.ID)
	response.WriteHeader(http.StatusAccepted)
	if err := json.NewEncoder(response).Encode(createResolutionResponse{
		SchemaVersion: resolutionStatusSchemaVersion, ResolutionID: result.Resolution.ID,
		State: result.Resolution.State, Version: result.Resolution.Version, Created: result.Created,
	}); err != nil {
		a.logger.ErrorContext(request.Context(), "encode resolution creation response failed", "error", err)
	}
}

func decodeCanonicalResolutionRequest(response http.ResponseWriter, request *http.Request) ([]byte, error) {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, fmt.Errorf("content type must be application/json")
	}
	request.Body = http.MaxBytesReader(response, request.Body, maximumResolutionCreateBodySize)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var body createResolutionBody
	if err := decoder.Decode(&body); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("request body must contain one JSON document")
	}
	if err := validateResolutionRequestBody(body); err != nil {
		return nil, err
	}
	claims := append([]string(nil), body.Claims...)
	targetIDs := append([]string(nil), body.TargetIDs...)
	sort.Strings(claims)
	sort.Strings(targetIDs)

	return json.Marshal(createResolutionBody{
		SchemaVersion: resolutionStatusSchemaVersion, Claims: claims, TargetIDs: targetIDs,
		MaximumAgeSeconds: body.MaximumAgeSeconds,
	})
}

func validateResolutionRequestBody(body createResolutionBody) error {
	if body.SchemaVersion != resolutionStatusSchemaVersion || len(body.Claims) == 0 ||
		len(body.Claims) > maximumClaimsPerResolution || len(body.TargetIDs) == 0 ||
		len(body.TargetIDs) > maximumTargetsPerResolution || body.MaximumAgeSeconds <= 0 ||
		body.MaximumAgeSeconds > maximumRequestedFreshnessInSeconds {
		return fmt.Errorf("resolution request bounds are invalid")
	}
	if hasDuplicate(body.Claims) || hasDuplicate(body.TargetIDs) {
		return fmt.Errorf("claims and target ids must be unique")
	}
	for _, claim := range body.Claims {
		if !validClaimType(claim) {
			return fmt.Errorf("claim type is invalid")
		}
	}
	for _, targetID := range body.TargetIDs {
		if !validResolutionID(targetID) {
			return fmt.Errorf("target id is invalid")
		}
	}

	return nil
}

func validClaimType(value string) bool {
	if value == "" || len(value) > maximumClaimTypeLength || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, char := range value[1:] {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') &&
			char != '.' && char != '_' && char != '-' {
			return false
		}
	}

	return true
}

func validIdempotencyKey(value string) bool {
	return value != "" && len(value) <= maximumIdempotencyKeyLength &&
		strings.IndexFunc(value, func(char rune) bool {
			return unicode.IsSpace(char) || unicode.IsControl(char)
		}) < 0
}

func hasDuplicate(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			return true
		}
		seen[value] = struct{}{}
	}

	return false
}

func writeResolutionCreateError(response http.ResponseWriter, status int, code, message string, retryable bool) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	if err := json.NewEncoder(response).Encode(resolutionCreateErrorResponse{
		Error: resolutionCreateErrorDetail{Code: code, Message: message, Retryable: retryable},
	}); err != nil {
		return
	}
}
