package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"network_broker/internal/authctx"
	"network_broker/internal/resolution"
)

type resolutionWatchAuthenticatorStub struct {
	actor authctx.AuthContext
	err   error
}

func (a resolutionWatchAuthenticatorStub) Authenticate(*tls.ConnectionState) (authctx.AuthContext, error) {
	return a.actor, a.err
}

type resolutionEventReaderStub struct {
	tenantID     string
	resolutionID string
	after        int64
	limit        int
	events       []resolution.WatchEvent
	err          error
	calls        int
}

func (r *resolutionEventReaderStub) ListEvents(_ context.Context, tenantID, resolutionID string,
	after int64, limit int,
) ([]resolution.WatchEvent, error) {
	r.calls++
	r.tenantID = tenantID
	r.resolutionID = resolutionID
	r.after = after
	r.limit = limit

	return append([]resolution.WatchEvent(nil), r.events...), r.err
}

func TestResolutionWatchAPIStreamsSafeTenantScopedEvents(t *testing.T) {
	reader := &resolutionEventReaderStub{events: []resolution.WatchEvent{{
		Cursor: 2, Type: "resolution.state_changed", State: resolution.ResolutionComplete,
		OccurredAt: time.Date(2026, 7, 21, 9, 0, 0, 0, time.UTC),
	}}}
	api := testResolutionWatchAPI(t, reader,
		resolutionWatchAuthenticatorStub{actor: testResolutionWatcherActor()})
	request := newResolutionWatchRequest("/v1/resolutions/resolution-1/events?after=1")
	response := performResolutionWatchRequest(api, request)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "text/event-stream" ||
		response.Header().Get("Cache-Control") != "no-store" || reader.tenantID != "tenant-a" ||
		reader.resolutionID != "resolution-1" || reader.after != 1 || reader.limit != resolutionWatchBatchSize {
		t.Fatalf("unexpected watch response: status=%d headers=%v reader=%+v body=%q",
			response.Code, response.Header(), reader, response.Body.String())
	}
	for _, expected := range []string{
		"retry: 1000", "id: 2", "event: resolution.state_changed",
		`"cursor":2`, `"state":"complete"`,
	} {
		if !strings.Contains(response.Body.String(), expected) {
			t.Errorf("watch body omitted %q: %q", expected, response.Body.String())
		}
	}
	for _, forbidden := range []string{"request_document", "request_digest", "task_count", "tenant-a"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Errorf("watch body exposed internal field %q: %q", forbidden, response.Body.String())
		}
	}
}

func TestResolutionWatchAPIResumesFromLastEventID(t *testing.T) {
	reader := &resolutionEventReaderStub{events: []resolution.WatchEvent{{
		Cursor: 4, Type: "resolution.state_changed", State: resolution.ResolutionFailed,
		OccurredAt: time.Now(),
	}}}
	api := testResolutionWatchAPI(t, reader,
		resolutionWatchAuthenticatorStub{actor: testResolutionWatcherActor()})
	request := newResolutionWatchRequest("/v1/resolutions/resolution-1/events")
	request.Header.Set("Last-Event-ID", "3")
	response := performResolutionWatchRequest(api, request)
	if response.Code != http.StatusOK || reader.after != 3 || !strings.Contains(response.Body.String(), "id: 4") {
		t.Fatalf("unexpected resumed watch: status=%d after=%d body=%q",
			response.Code, reader.after, response.Body.String())
	}
}

func TestResolutionWatchAPIRejectsAuthorityAndCursorBeforeRead(t *testing.T) {
	tests := []struct {
		name          string
		authenticator resolutionWatchAuthenticatorStub
		path          string
		lastEventID   string
		status        int
		code          string
	}{
		{
			name: "missing identity", authenticator: resolutionWatchAuthenticatorStub{err: errors.New("missing")},
			path: "/v1/resolutions/resolution-1/events", status: http.StatusUnauthorized,
			code: "AUTHENTICATION_REQUIRED",
		},
		{
			name: "missing scope", authenticator: resolutionWatchAuthenticatorStub{actor: authctx.AuthContext{
				SubjectID: "agent-a", TenantID: "tenant-a", AuthenticatedAt: time.Now(),
			}}, path: "/v1/resolutions/resolution-1/events", status: http.StatusForbidden,
			code: "RESOLUTION_WATCH_DENIED",
		},
		{
			name: "invalid cursor", authenticator: resolutionWatchAuthenticatorStub{actor: testResolutionWatcherActor()},
			path: "/v1/resolutions/resolution-1/events?after=-1", status: http.StatusBadRequest,
			code: "INVALID_WATCH_CURSOR",
		},
		{
			name: "conflicting cursors", authenticator: resolutionWatchAuthenticatorStub{actor: testResolutionWatcherActor()},
			path: "/v1/resolutions/resolution-1/events?after=1", lastEventID: "1",
			status: http.StatusBadRequest, code: "INVALID_WATCH_CURSOR",
		},
		{
			name: "unknown query", authenticator: resolutionWatchAuthenticatorStub{actor: testResolutionWatcherActor()},
			path: "/v1/resolutions/resolution-1/events?cursor=1", status: http.StatusBadRequest,
			code: "INVALID_WATCH_CURSOR",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := &resolutionEventReaderStub{}
			api := testResolutionWatchAPI(t, reader, test.authenticator)
			request := newResolutionWatchRequest(test.path)
			if test.lastEventID != "" {
				request.Header.Set("Last-Event-ID", test.lastEventID)
			}
			response := performResolutionWatchRequest(api, request)
			if response.Code != test.status || !strings.Contains(response.Body.String(), test.code) ||
				reader.calls != 0 {
				t.Fatalf("unexpected rejected watch: status=%d body=%q calls=%d",
					response.Code, response.Body.String(), reader.calls)
			}
		})
	}
}

func TestResolutionWatchAPIUsesGenericNotFound(t *testing.T) {
	reader := &resolutionEventReaderStub{err: resolution.ErrNotFound}
	api := testResolutionWatchAPI(t, reader,
		resolutionWatchAuthenticatorStub{actor: testResolutionWatcherActor()})
	response := performResolutionWatchRequest(api,
		newResolutionWatchRequest("/v1/resolutions/resolution-1/events"))
	if response.Code != http.StatusNotFound ||
		response.Body.String() != "{\"code\":\"RESOLUTION_NOT_FOUND\"}\n" {
		t.Fatalf("unexpected missing watch response: status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestResolutionWatchAPIBoundsConcurrentStreams(t *testing.T) {
	reader := &resolutionEventReaderStub{}
	api := testResolutionWatchAPI(t, reader,
		resolutionWatchAuthenticatorStub{actor: testResolutionWatcherActor()})
	for range maximumResolutionWatchRequests {
		api.concurrency <- struct{}{}
	}
	response := performResolutionWatchRequest(api,
		newResolutionWatchRequest("/v1/resolutions/resolution-1/events"))
	if response.Code != http.StatusTooManyRequests ||
		!strings.Contains(response.Body.String(), "RESOLUTION_WATCH_BUSY") || reader.calls != 0 {
		t.Fatalf("unexpected busy response: status=%d body=%q calls=%d",
			response.Code, response.Body.String(), reader.calls)
	}
}

func testResolutionWatchAPI(t *testing.T, reader resolutionEventReader,
	authenticator resolutionWatchAuthenticator,
) *resolutionWatchAPI {
	t.Helper()
	api, err := newResolutionWatchAPI(reader, authenticator, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}

	return api
}

func newResolutionWatchRequest(path string) *http.Request {
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, http.NoBody)
	request.TLS = &tls.ConnectionState{}

	return request
}

func performResolutionWatchRequest(api *resolutionWatchAPI, request *http.Request) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	mux := http.NewServeMux()
	api.register(mux)
	mux.ServeHTTP(response, request)

	return response
}

func testResolutionWatcherActor() authctx.AuthContext {
	return authctx.AuthContext{
		SubjectID: "spiffe://broker.example/tenant/tenant-a/role/agent/workload/client-1",
		TenantID:  "tenant-a", AllowedScopes: []string{resolutionWatchScope}, AuthenticatedAt: time.Now(),
	}
}
