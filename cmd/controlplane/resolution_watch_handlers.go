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
	"strconv"
	"time"

	"network_broker/internal/authctx"
	"network_broker/internal/resolution"
)

const (
	resolutionWatchScope           = "resolutions:watch"
	maximumResolutionWatchRequests = 32
	resolutionWatchBatchSize       = 100
	defaultResolutionWatchDuration = 15 * time.Second
	maximumResolutionWatchDuration = 30 * time.Second
	resolutionWatchPollInterval    = 250 * time.Millisecond
)

type resolutionWatchAuthenticator interface {
	Authenticate(*tls.ConnectionState) (authctx.AuthContext, error)
}

type resolutionEventReader interface {
	ListEvents(context.Context, string, string, int64, int) ([]resolution.WatchEvent, error)
}

type resolutionWatchAPI struct {
	reader        resolutionEventReader
	authenticator resolutionWatchAuthenticator
	logger        *slog.Logger
	concurrency   chan struct{}
}

func newResolutionWatchAPI(reader resolutionEventReader,
	authenticator resolutionWatchAuthenticator, logger *slog.Logger,
) (*resolutionWatchAPI, error) {
	if reader == nil || authenticator == nil || logger == nil {
		return nil, fmt.Errorf("resolution event reader, authenticator and logger are required")
	}

	return &resolutionWatchAPI{
		reader: reader, authenticator: authenticator, logger: logger,
		concurrency: make(chan struct{}, maximumResolutionWatchRequests),
	}, nil
}

func (a *resolutionWatchAPI) register(mux *http.ServeMux) {
	mux.Handle("GET /v1/resolutions/{resolution_id}/events", a.limit(http.HandlerFunc(a.watch)))
}

func (a *resolutionWatchAPI) limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		select {
		case a.concurrency <- struct{}{}:
			defer func() { <-a.concurrency }()
			next.ServeHTTP(response, request)
		default:
			writeResolutionWatchError(response, http.StatusTooManyRequests, "RESOLUTION_WATCH_BUSY")
		}
	})
}

func (a *resolutionWatchAPI) watch(response http.ResponseWriter, request *http.Request) {
	actor, err := a.authenticator.Authenticate(request.TLS)
	if err != nil || actor.Validate() != nil {
		response.Header().Set("WWW-Authenticate", "Mutual")
		writeResolutionWatchError(response, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
		return
	}
	if !slices.Contains(actor.AllowedScopes, resolutionWatchScope) {
		writeResolutionWatchError(response, http.StatusForbidden, "RESOLUTION_WATCH_DENIED")
		return
	}
	resolutionID := request.PathValue("resolution_id")
	if !validResolutionID(resolutionID) {
		writeResolutionWatchError(response, http.StatusBadRequest, "INVALID_RESOLUTION_ID")
		return
	}
	cursor, duration, err := parseResolutionWatchParameters(request)
	if err != nil {
		writeResolutionWatchError(response, http.StatusBadRequest, "INVALID_WATCH_CURSOR")
		return
	}
	events, err := a.reader.ListEvents(request.Context(), actor.TenantID, resolutionID,
		cursor, resolutionWatchBatchSize)
	if err != nil {
		a.writeInitialWatchFailure(response, request, err)
		return
	}
	flusher, ok := response.(http.Flusher)
	if !ok {
		writeResolutionWatchError(response, http.StatusInternalServerError, "WATCH_STREAM_UNAVAILABLE")
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "text/event-stream")
	response.Header().Set("X-Accel-Buffering", "no")
	if _, err := fmt.Fprint(response, "retry: 1000\n\n"); err != nil {
		return
	}
	flusher.Flush()
	nextCursor, terminal, ok := writeResolutionWatchEvents(response, flusher, cursor, events)
	if !ok || terminal {
		return
	}
	a.continueWatch(response, request, flusher, actor.TenantID, resolutionID, nextCursor, duration)
}

func (a *resolutionWatchAPI) continueWatch(response http.ResponseWriter, request *http.Request,
	flusher http.Flusher, tenantID, resolutionID string, cursor int64, duration time.Duration,
) {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	ticker := time.NewTicker(resolutionWatchPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-request.Context().Done():
			return
		case <-timer.C:
			if _, err := fmt.Fprint(response, ": timeout\n\n"); err != nil {
				return
			}
			flusher.Flush()
			return
		case <-ticker.C:
			events, err := a.reader.ListEvents(request.Context(), tenantID, resolutionID,
				cursor, resolutionWatchBatchSize)
			if err != nil {
				a.logger.ErrorContext(request.Context(), "continue resolution watch failed", "error", err)
				return
			}
			next, terminal, ok := writeResolutionWatchEvents(response, flusher, cursor, events)
			if !ok || terminal {
				return
			}
			cursor = next
		}
	}
}

func writeResolutionWatchEvents(response http.ResponseWriter, flusher http.Flusher,
	cursor int64, events []resolution.WatchEvent,
) (nextCursor int64, terminal, ok bool) {
	for _, event := range events {
		if event.Cursor <= cursor {
			return cursor, false, false
		}
		if _, err := fmt.Fprintf(response, "id: %d\nevent: %s\ndata: ", event.Cursor, event.Type); err != nil {
			return cursor, false, false
		}
		if err := json.NewEncoder(response).Encode(event); err != nil {
			return cursor, false, false
		}
		if _, err := fmt.Fprint(response, "\n"); err != nil {
			return cursor, false, false
		}
		flusher.Flush()
		cursor = event.Cursor
		if event.State.Terminal() {
			return cursor, true, true
		}
	}

	return cursor, false, true
}

func (a *resolutionWatchAPI) writeInitialWatchFailure(response http.ResponseWriter,
	request *http.Request, err error,
) {
	if errors.Is(err, resolution.ErrNotFound) {
		writeResolutionWatchError(response, http.StatusNotFound, "RESOLUTION_NOT_FOUND")
		return
	}
	a.logger.ErrorContext(request.Context(), "start resolution watch failed", "error", err)
	writeResolutionWatchError(response, http.StatusInternalServerError, "RESOLUTION_WATCH_FAILED")
}

func parseResolutionWatchParameters(request *http.Request) (int64, time.Duration, error) {
	query := request.URL.Query()
	for key, values := range query {
		if (key != "after" && key != "wait_seconds") || len(values) != 1 {
			return 0, 0, fmt.Errorf("watch query parameters are invalid")
		}
	}
	if len(request.Header.Values("Last-Event-ID")) > 1 {
		return 0, 0, fmt.Errorf("only one Last-Event-ID may be supplied")
	}
	headerCursor := request.Header.Get("Last-Event-ID")
	queryCursor := query.Get("after")
	if headerCursor != "" && queryCursor != "" {
		return 0, 0, fmt.Errorf("only one watch cursor may be supplied")
	}
	rawCursor := headerCursor
	if rawCursor == "" {
		rawCursor = queryCursor
	}
	cursor := int64(0)
	if rawCursor != "" {
		parsed, err := strconv.ParseInt(rawCursor, 10, 64)
		if err != nil || parsed < 0 {
			return 0, 0, fmt.Errorf("watch cursor must be a non-negative integer")
		}
		cursor = parsed
	}
	duration := defaultResolutionWatchDuration
	if rawSeconds := query.Get("wait_seconds"); rawSeconds != "" {
		seconds, err := strconv.ParseInt(rawSeconds, 10, 32)
		if err != nil || seconds <= 0 || time.Duration(seconds)*time.Second > maximumResolutionWatchDuration {
			return 0, 0, fmt.Errorf("watch duration is invalid")
		}
		duration = time.Duration(seconds) * time.Second
	}

	return cursor, duration, nil
}

func writeResolutionWatchError(response http.ResponseWriter, status int, code string) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	if err := json.NewEncoder(response).Encode(struct {
		Code string `json:"code"`
	}{Code: code}); err != nil {
		return
	}
}
