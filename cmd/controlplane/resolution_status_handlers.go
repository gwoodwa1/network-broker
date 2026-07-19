package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"

	"network_broker/internal/authctx"
	"network_broker/internal/resolution"
)

const (
	resolutionStatusSchemaVersion = "v1"
	resolutionReadScope           = "resolutions:read"
	maximumResolutionStatusReads  = 64
	maximumResolutionIDLength     = 128
)

type resolutionStatusAuthenticator interface {
	Authenticate(*tls.ConnectionState) (authctx.AuthContext, error)
}

type resolutionStatusReader interface {
	Get(context.Context, string, string) (resolution.Resolution, error)
}

type resolutionStatusAPI struct {
	reader        resolutionStatusReader
	authenticator resolutionStatusAuthenticator
	logger        *slog.Logger
	concurrency   chan struct{}
}

type resolutionStatusResponse struct {
	SchemaVersion string                     `json:"schema_version"`
	ResolutionID  string                     `json:"resolution_id"`
	State         resolution.ResolutionState `json:"state"`
	TargetCount   int                        `json:"target_count"`
	Completed     bool                       `json:"completed"`
	Version       int64                      `json:"version"`
	CreatedAt     time.Time                  `json:"created_at"`
	UpdatedAt     time.Time                  `json:"updated_at"`
}

func newResolutionStatusAPI(reader resolutionStatusReader,
	authenticator resolutionStatusAuthenticator, logger *slog.Logger,
) (*resolutionStatusAPI, error) {
	if reader == nil || authenticator == nil || logger == nil {
		return nil, fmt.Errorf("resolution reader, authenticator and logger are required")
	}

	return &resolutionStatusAPI{
		reader: reader, authenticator: authenticator, logger: logger,
		concurrency: make(chan struct{}, maximumResolutionStatusReads),
	}, nil
}

func (a *resolutionStatusAPI) register(mux *http.ServeMux) {
	mux.Handle("GET /v1/resolutions/{resolution_id}", a.limit(http.HandlerFunc(a.get)))
}

func (a *resolutionStatusAPI) limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		select {
		case a.concurrency <- struct{}{}:
			defer func() { <-a.concurrency }()
			next.ServeHTTP(response, request)
		default:
			writeResolutionStatusError(response, http.StatusTooManyRequests, "RESOLUTION_STATUS_BUSY")
		}
	})
}

func (a *resolutionStatusAPI) get(response http.ResponseWriter, request *http.Request) {
	actor, err := a.authenticator.Authenticate(request.TLS)
	if err != nil || actor.Validate() != nil {
		response.Header().Set("WWW-Authenticate", "Mutual")
		writeResolutionStatusError(response, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
		return
	}
	if !slices.Contains(actor.AllowedScopes, resolutionReadScope) {
		writeResolutionStatusError(response, http.StatusForbidden, "RESOLUTION_READ_DENIED")
		return
	}
	resolutionID := request.PathValue("resolution_id")
	if !validResolutionID(resolutionID) {
		writeResolutionStatusError(response, http.StatusBadRequest, "INVALID_RESOLUTION_ID")
		return
	}
	status, err := a.reader.Get(request.Context(), actor.TenantID, resolutionID)
	if err != nil {
		if errors.Is(err, resolution.ErrNotFound) {
			writeResolutionStatusError(response, http.StatusNotFound, "RESOLUTION_NOT_FOUND")
			return
		}
		a.logger.ErrorContext(request.Context(), "read resolution status failed", "error", err)
		writeResolutionStatusError(response, http.StatusInternalServerError, "RESOLUTION_STATUS_FAILED")
		return
	}

	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(response).Encode(resolutionStatusResponse{
		SchemaVersion: resolutionStatusSchemaVersion,
		ResolutionID:  status.ID,
		State:         status.State,
		TargetCount:   status.TargetCount,
		Completed:     status.Completed,
		Version:       status.Version,
		CreatedAt:     status.CreatedAt.UTC(),
		UpdatedAt:     status.UpdatedAt.UTC(),
	}); err != nil {
		a.logger.ErrorContext(request.Context(), "encode resolution status failed", "error", err)
	}
}

func validResolutionID(identifier string) bool {
	return identifier != "" && len(identifier) <= maximumResolutionIDLength &&
		!strings.ContainsAny(identifier, "/\\") && strings.IndexFunc(identifier, func(char rune) bool {
		return unicode.IsSpace(char) || unicode.IsControl(char)
	}) < 0
}

func writeResolutionStatusError(response http.ResponseWriter, status int, code string) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	if err := json.NewEncoder(response).Encode(struct {
		Code string `json:"code"`
	}{Code: code}); err != nil {
		return
	}
}
