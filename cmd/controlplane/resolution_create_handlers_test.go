package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"network_broker/internal/authctx"
	"network_broker/internal/resolution"
)

type resolutionCreateAuthenticatorStub struct {
	actor authctx.AuthContext
	err   error
}

func (a resolutionCreateAuthenticatorStub) Authenticate(*tls.ConnectionState) (authctx.AuthContext, error) {
	return a.actor, a.err
}

type resolutionCreatorStub struct {
	request resolution.CreateRequest
	result  resolution.CreateResult
	err     error
	calls   int
}

func (s *resolutionCreatorStub) Create(_ context.Context, request resolution.CreateRequest) (
	resolution.CreateResult, error,
) {
	s.calls++
	s.request = request

	return s.result, s.err
}

func TestResolutionCreateAPICanonicalisesAndPersistsAuthenticatedRequest(t *testing.T) {
	service := &resolutionCreatorStub{result: resolution.CreateResult{
		Resolution: resolution.Resolution{
			ID: "resolution-1", State: resolution.ResolutionReceived, Version: 1,
		},
		Created: true,
	}}
	api := testResolutionCreateAPI(t, service,
		resolutionCreateAuthenticatorStub{actor: testResolutionCreatorActor()})
	response := performResolutionCreateRequest(api, validResolutionCreateBody(), "request-1", "application/json")
	wantDocument := `{"schema_version":"v1","claims":["interface.name","interface.operational_state"],` +
		`"target_ids":["router-1","router-2"],"maximum_age_seconds":300}`
	digest := sha256.Sum256([]byte(wantDocument))
	if response.Code != http.StatusAccepted || service.calls != 1 ||
		service.request.ActorID != testResolutionCreatorActor().SubjectID ||
		service.request.TenantID != "tenant-a" || service.request.IdempotencyKey != "request-1" ||
		string(service.request.RequestDocument) != wantDocument ||
		service.request.RequestDigest != "sha256:"+hex.EncodeToString(digest[:]) {
		t.Fatalf("unexpected creation: status=%d body=%q request=%+v",
			response.Code, response.Body.String(), service.request)
	}
	if response.Header().Get("Location") != "/v1/resolutions/resolution-1" ||
		response.Header().Get("Cache-Control") != "no-store" ||
		!strings.Contains(response.Body.String(), `"created":true`) {
		t.Fatalf("unexpected response headers or body: headers=%v body=%q", response.Header(), response.Body.String())
	}
}

func TestResolutionCreateAPIMapsIdempotencyConflict(t *testing.T) {
	service := &resolutionCreatorStub{err: resolution.ErrIdempotencyConflict}
	api := testResolutionCreateAPI(t, service,
		resolutionCreateAuthenticatorStub{actor: testResolutionCreatorActor()})
	response := performResolutionCreateRequest(api, validResolutionCreateBody(), "request-1", "application/json")
	if response.Code != http.StatusConflict ||
		!strings.Contains(response.Body.String(), resolution.IdempotencyConflictCode) ||
		!strings.Contains(response.Body.String(), `"retryable":false`) {
		t.Fatalf("unexpected conflict response: status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestResolutionCreateAPIRejectsAuthorityFailuresBeforeBodyRead(t *testing.T) {
	tests := []struct {
		name          string
		authenticator resolutionCreateAuthenticatorStub
		status        int
		code          string
	}{
		{
			name: "missing identity", authenticator: resolutionCreateAuthenticatorStub{err: errors.New("missing")},
			status: http.StatusUnauthorized, code: "AUTHENTICATION_REQUIRED",
		},
		{
			name: "missing scope", authenticator: resolutionCreateAuthenticatorStub{actor: authctx.AuthContext{
				SubjectID: "agent-a", TenantID: "tenant-a", AuthenticatedAt: time.Now(),
			}},
			status: http.StatusForbidden, code: "RESOLUTION_CREATE_DENIED",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &resolutionCreatorStub{}
			api := testResolutionCreateAPI(t, service, test.authenticator)
			body := &trackingReader{Reader: strings.NewReader(validResolutionCreateBody())}
			response := performResolutionCreateRequestWithReader(api, body, "request-1", "application/json")
			if response.Code != test.status || !strings.Contains(response.Body.String(), test.code) ||
				service.calls != 0 || body.read {
				t.Fatalf("unexpected denied request: status=%d body=%q calls=%d body_read=%t",
					response.Code, response.Body.String(), service.calls, body.read)
			}
		})
	}
}

func TestResolutionCreateAPIRejectsInvalidInputsBeforeService(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		key         string
		contentType string
		code        string
	}{
		{name: "missing key", body: validResolutionCreateBody(), contentType: "application/json", code: "INVALID_IDEMPOTENCY_KEY"},
		{name: "wrong media type", body: validResolutionCreateBody(), key: "request-1", contentType: "text/plain", code: "INVALID_REQUEST"},
		{name: "unknown field", body: `{"schema_version":"v1","claims":["interface.name"],"target_ids":["r1"],"maximum_age_seconds":1,"extra":true}`, key: "request-1", contentType: "application/json", code: "INVALID_REQUEST"},
		{name: "trailing document", body: validResolutionCreateBody() + `{}`, key: "request-1", contentType: "application/json", code: "INVALID_REQUEST"},
		{name: "duplicate claim", body: `{"schema_version":"v1","claims":["interface.name","interface.name"],"target_ids":["r1"],"maximum_age_seconds":1}`, key: "request-1", contentType: "application/json", code: "INVALID_REQUEST"},
		{name: "unbounded age", body: `{"schema_version":"v1","claims":["interface.name"],"target_ids":["r1"],"maximum_age_seconds":9999999}`, key: "request-1", contentType: "application/json", code: "INVALID_REQUEST"},
		{name: "invalid claim", body: `{"schema_version":"v1","claims":["Interface Name"],"target_ids":["r1"],"maximum_age_seconds":1}`, key: "request-1", contentType: "application/json", code: "INVALID_REQUEST"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &resolutionCreatorStub{}
			api := testResolutionCreateAPI(t, service,
				resolutionCreateAuthenticatorStub{actor: testResolutionCreatorActor()})
			response := performResolutionCreateRequest(api, test.body, test.key, test.contentType)
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), test.code) ||
				service.calls != 0 {
				t.Fatalf("unexpected invalid request: status=%d body=%q calls=%d",
					response.Code, response.Body.String(), service.calls)
			}
		})
	}
}

func TestResolutionCreateAPIBoundsConcurrentRequests(t *testing.T) {
	service := &resolutionCreatorStub{}
	api := testResolutionCreateAPI(t, service,
		resolutionCreateAuthenticatorStub{actor: testResolutionCreatorActor()})
	for range maximumResolutionCreateRequests {
		api.concurrency <- struct{}{}
	}
	response := performResolutionCreateRequest(api, validResolutionCreateBody(), "request-1", "application/json")
	if response.Code != http.StatusTooManyRequests ||
		!strings.Contains(response.Body.String(), "RESOLUTION_CREATE_BUSY") || service.calls != 0 {
		t.Fatalf("unexpected busy response: status=%d body=%q calls=%d",
			response.Code, response.Body.String(), service.calls)
	}
}

type trackingReader struct {
	io.Reader
	read bool
}

func (r *trackingReader) Read(buffer []byte) (int, error) {
	r.read = true

	return r.Reader.Read(buffer)
}

func testResolutionCreateAPI(t *testing.T, service resolutionCreator,
	authenticator resolutionCreateAuthenticator,
) *resolutionCreateAPI {
	t.Helper()
	api, err := newResolutionCreateAPI(service, authenticator, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}

	return api
}

func performResolutionCreateRequest(api *resolutionCreateAPI, body, key, contentType string) *httptest.ResponseRecorder {
	return performResolutionCreateRequestWithReader(api, strings.NewReader(body), key, contentType)
}

func performResolutionCreateRequestWithReader(api *resolutionCreateAPI, body io.Reader,
	key, contentType string,
) *httptest.ResponseRecorder {
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/resolutions", body)
	request.TLS = &tls.ConnectionState{}
	if key != "" {
		request.Header.Set("Idempotency-Key", key)
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response := httptest.NewRecorder()
	mux := http.NewServeMux()
	api.register(mux)
	mux.ServeHTTP(response, request)

	return response
}

func testResolutionCreatorActor() authctx.AuthContext {
	return authctx.AuthContext{
		SubjectID: "spiffe://broker.example/tenant/tenant-a/role/agent/workload/client-1",
		TenantID:  "tenant-a", AllowedScopes: []string{resolutionCreateScope}, AuthenticatedAt: time.Now(),
	}
}

func validResolutionCreateBody() string {
	return `{"schema_version":"v1","claims":["interface.operational_state","interface.name"],` +
		`"target_ids":["router-2","router-1"],"maximum_age_seconds":300}`
}
