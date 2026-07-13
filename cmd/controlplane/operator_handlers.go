package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"sync/atomic"

	"network_broker/internal/authctx"
	"network_broker/internal/deadletter"
)

const (
	defaultDeadLetterLimit  = 50
	maximumOperatorBodySize = 4096
	maximumOperatorRequests = 8
)

type operatorAuthenticator interface {
	Authenticate(*http.Request) (authctx.AuthContext, error)
}

type operatorMetrics struct {
	replayApplied    atomic.Uint64
	replayIdempotent atomic.Uint64
	denied           atomic.Uint64
}

type deadLetterAPI struct {
	service       *deadletter.Service
	authenticator operatorAuthenticator
	logger        *slog.Logger
	metrics       *operatorMetrics
	concurrency   chan struct{}
}

func newDeadLetterAPI(service *deadletter.Service, authenticator operatorAuthenticator,
	logger *slog.Logger,
) (*deadLetterAPI, error) {
	if service == nil || authenticator == nil || logger == nil {
		return nil, fmt.Errorf("dead-letter service, authenticator and logger are required")
	}

	return &deadLetterAPI{
		service: service, authenticator: authenticator, logger: logger,
		metrics: &operatorMetrics{}, concurrency: make(chan struct{}, maximumOperatorRequests),
	}, nil
}

func (a *deadLetterAPI) register(mux *http.ServeMux) {
	mux.Handle("GET /v1/operations/dead-letters", a.limit(http.HandlerFunc(a.list)))
	mux.Handle("GET /v1/operations/dead-letters/{event_id}", a.limit(http.HandlerFunc(a.get)))
	mux.Handle("POST /v1/operations/dead-letters/{event_id}/replay", a.limit(http.HandlerFunc(a.replay)))
}

func (a *deadLetterAPI) limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		select {
		case a.concurrency <- struct{}{}:
			defer func() { <-a.concurrency }()
			next.ServeHTTP(response, request)
		default:
			http.Error(response, "operator API is busy", http.StatusTooManyRequests)
		}
	})
}

func (a *deadLetterAPI) list(response http.ResponseWriter, request *http.Request) {
	actor, ok := a.authenticate(response, request)
	if !ok {
		return
	}
	before, limit, err := parsePagination(request)
	if err != nil {
		http.Error(response, "invalid pagination", http.StatusBadRequest)
		return
	}
	entries, err := a.service.List(request.Context(), actor, before, limit)
	if err != nil {
		a.writeServiceError(response, err)
		return
	}
	if entries == nil {
		entries = make([]deadletter.Entry, 0)
	}
	nextCursor := ""
	if len(entries) == limit {
		nextCursor = encodeCursor(entries[len(entries)-1].Sequence)
	}
	a.writeJSON(request.Context(), response, http.StatusOK, struct {
		Entries    []deadletter.Entry `json:"entries"`
		NextCursor string             `json:"next_cursor,omitempty"`
	}{Entries: entries, NextCursor: nextCursor})
}

func (a *deadLetterAPI) get(response http.ResponseWriter, request *http.Request) {
	actor, ok := a.authenticate(response, request)
	if !ok {
		return
	}
	entry, err := a.service.Get(request.Context(), actor, request.PathValue("event_id"))
	if err != nil {
		a.writeServiceError(response, err)
		return
	}
	a.writeJSON(request.Context(), response, http.StatusOK, entry)
}

func (a *deadLetterAPI) replay(response http.ResponseWriter, request *http.Request) {
	actor, ok := a.authenticate(response, request)
	if !ok {
		return
	}
	reason, err := decodeReplayBody(response, request)
	if err != nil {
		http.Error(response, "invalid replay request", http.StatusBadRequest)
		return
	}
	result, err := a.service.Replay(request.Context(), actor, request.PathValue("event_id"),
		request.Header.Get("Idempotency-Key"), reason)
	if err != nil {
		a.writeServiceError(response, err)
		return
	}
	if result.Replayed {
		a.metrics.replayApplied.Add(1)
	} else {
		a.metrics.replayIdempotent.Add(1)
	}
	a.logger.InfoContext(request.Context(), "dead-letter replay accepted",
		"action_id", result.ActionID, "event_id", result.EventID, "actor_id", actor.SubjectID)
	a.writeJSON(request.Context(), response, http.StatusAccepted, result)
}

func (a *deadLetterAPI) authenticate(response http.ResponseWriter, request *http.Request) (authctx.AuthContext, bool) {
	actor, err := a.authenticator.Authenticate(request)
	if err != nil {
		a.metrics.denied.Add(1)
		response.Header().Set("WWW-Authenticate", "Mutual")
		http.Error(response, "authentication required", http.StatusUnauthorized)
		return authctx.AuthContext{}, false
	}

	return actor, true
}

func (a *deadLetterAPI) writeServiceError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, deadletter.ErrDenied):
		a.metrics.denied.Add(1)
		http.Error(response, "forbidden", http.StatusForbidden)
	case errors.Is(err, deadletter.ErrNotFound):
		http.Error(response, "not found", http.StatusNotFound)
	case errors.Is(err, deadletter.ErrReplayConflict):
		http.Error(response, "idempotency conflict", http.StatusConflict)
	case errors.Is(err, deadletter.ErrInvalidInput):
		http.Error(response, "invalid request", http.StatusBadRequest)
	default:
		http.Error(response, "operation failed", http.StatusInternalServerError)
	}
}

func parsePagination(request *http.Request) (cursor int64, limit int, err error) {
	query := request.URL.Query()
	for key, values := range query {
		if (key != "cursor" && key != "limit") || len(values) != 1 {
			return 0, 0, deadletter.ErrInvalidInput
		}
	}
	limit = defaultDeadLetterLimit
	if raw := query.Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 || parsed > 100 {
			return 0, 0, deadletter.ErrInvalidInput
		}
		limit = parsed
	}
	cursor = 0
	if raw := query.Get("cursor"); raw != "" {
		if len(raw) > 64 {
			return 0, 0, deadletter.ErrInvalidInput
		}
		decoded, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil {
			return 0, 0, deadletter.ErrInvalidInput
		}
		cursor, err = strconv.ParseInt(string(decoded), 10, 64)
		if err != nil || cursor <= 0 || encodeCursor(cursor) != raw {
			return 0, 0, deadletter.ErrInvalidInput
		}
	}

	return cursor, limit, nil
}

func encodeCursor(sequence int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(sequence, 10)))
}

func decodeReplayBody(response http.ResponseWriter, request *http.Request) (string, error) {
	request.Body = http.MaxBytesReader(response, request.Body, maximumOperatorBodySize)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var body struct {
		Reason string `json:"reason"`
	}
	if err := decoder.Decode(&body); err != nil {
		return "", err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("replay body must contain one JSON document")
	}

	return body.Reason, nil
}

func (a *deadLetterAPI) writeJSON(ctx context.Context, response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	if err := json.NewEncoder(response).Encode(value); err != nil {
		a.logger.ErrorContext(ctx, "encode operator API response failed", "error", err)
	}
}

func randomIdentifier(prefix string) (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("read random identifier bytes: %w", err)
	}

	return prefix + "-" + hex.EncodeToString(value), nil
}
