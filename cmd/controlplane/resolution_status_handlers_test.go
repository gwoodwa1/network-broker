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

type resolutionStatusAuthenticatorStub struct {
	actor authctx.AuthContext
	err   error
}

func (a resolutionStatusAuthenticatorStub) Authenticate(*tls.ConnectionState) (authctx.AuthContext, error) {
	return a.actor, a.err
}

type resolutionStatusReaderStub struct {
	wantTenantID string
	status       resolution.Resolution
	err          error
	reads        int
}

func (r *resolutionStatusReaderStub) Get(_ context.Context, tenantID, resolutionID string) (
	resolution.Resolution, error,
) {
	r.reads++
	if r.wantTenantID != "" && tenantID != r.wantTenantID {
		return resolution.Resolution{}, resolution.ErrNotFound
	}
	if r.status.ID != resolutionID {
		return resolution.Resolution{}, resolution.ErrNotFound
	}

	return r.status, r.err
}

func TestResolutionStatusAPIReturnsSafeTenantScopedStatus(t *testing.T) {
	now := time.Date(2026, 7, 19, 10, 30, 0, 0, time.UTC)
	reader := &resolutionStatusReaderStub{
		wantTenantID: "tenant-a",
		status: resolution.Resolution{
			ID: "resolution-1", ActorID: "sensitive-actor", TenantID: "tenant-a",
			IdempotencyKey: "sensitive-key", RequestDigest: "sensitive-digest",
			State: resolution.ResolutionQueued, TargetCount: 3, Version: 4,
			CreatedAt: now.Add(-time.Minute), UpdatedAt: now,
		},
	}
	api := testResolutionStatusAPI(t, reader, resolutionStatusAuthenticatorStub{actor: testResolutionReaderActor()})
	response := performResolutionStatusRequest(api, "/v1/resolutions/resolution-1")
	if response.Code != http.StatusOK || reader.reads != 1 ||
		!strings.Contains(response.Body.String(), `"resolution_id":"resolution-1"`) ||
		!strings.Contains(response.Body.String(), `"target_count":3`) ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected status response: status=%d headers=%v body=%q",
			response.Code, response.Header(), response.Body.String())
	}
	for _, secret := range []string{"sensitive-actor", "sensitive-key", "sensitive-digest", "tenant-a"} {
		if strings.Contains(response.Body.String(), secret) {
			t.Errorf("response exposed internal field %q: %q", secret, response.Body.String())
		}
	}
}

func TestResolutionStatusAPIRejectsMissingIdentityAndScopeBeforeRead(t *testing.T) {
	tests := []struct {
		name          string
		authenticator resolutionStatusAuthenticatorStub
		status        int
		code          string
	}{
		{
			name: "missing identity", authenticator: resolutionStatusAuthenticatorStub{err: errors.New("no identity")},
			status: http.StatusUnauthorized, code: "AUTHENTICATION_REQUIRED",
		},
		{
			name: "missing scope", authenticator: resolutionStatusAuthenticatorStub{actor: authctx.AuthContext{
				SubjectID: "agent-a", TenantID: "tenant-a", AuthenticatedAt: time.Now(),
			}},
			status: http.StatusForbidden, code: "RESOLUTION_READ_DENIED",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := &resolutionStatusReaderStub{}
			api := testResolutionStatusAPI(t, reader, test.authenticator)
			response := performResolutionStatusRequest(api, "/v1/resolutions/resolution-1")
			if response.Code != test.status || !strings.Contains(response.Body.String(), test.code) || reader.reads != 0 {
				t.Fatalf("unexpected denied response: status=%d body=%q reads=%d",
					response.Code, response.Body.String(), reader.reads)
			}
		})
	}
}

func TestResolutionStatusAPIUsesSameNotFoundResponseAcrossTenantBoundary(t *testing.T) {
	reader := &resolutionStatusReaderStub{
		wantTenantID: "tenant-b",
		status:       resolution.Resolution{ID: "resolution-1", TenantID: "tenant-b"},
	}
	api := testResolutionStatusAPI(t, reader, resolutionStatusAuthenticatorStub{actor: testResolutionReaderActor()})
	response := performResolutionStatusRequest(api, "/v1/resolutions/resolution-1")
	if response.Code != http.StatusNotFound ||
		response.Body.String() != "{\"code\":\"RESOLUTION_NOT_FOUND\"}\n" {
		t.Fatalf("unexpected cross-tenant response: status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestResolutionStatusAPIRejectsInvalidIdentifierBeforeRead(t *testing.T) {
	reader := &resolutionStatusReaderStub{}
	api := testResolutionStatusAPI(t, reader, resolutionStatusAuthenticatorStub{actor: testResolutionReaderActor()})
	response := performResolutionStatusRequest(api, "/v1/resolutions/%20")
	if response.Code != http.StatusBadRequest ||
		!strings.Contains(response.Body.String(), "INVALID_RESOLUTION_ID") || reader.reads != 0 {
		t.Fatalf("unexpected invalid-id response: status=%d body=%q reads=%d",
			response.Code, response.Body.String(), reader.reads)
	}
}

func TestResolutionStatusAPIFailsClosedOnRepositoryFailure(t *testing.T) {
	reader := &resolutionStatusReaderStub{
		status: resolution.Resolution{ID: "resolution-1"}, err: errors.New("sensitive database detail"),
	}
	api := testResolutionStatusAPI(t, reader, resolutionStatusAuthenticatorStub{actor: testResolutionReaderActor()})
	response := performResolutionStatusRequest(api, "/v1/resolutions/resolution-1")
	if response.Code != http.StatusInternalServerError ||
		response.Body.String() != "{\"code\":\"RESOLUTION_STATUS_FAILED\"}\n" ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected repository failure response: status=%d body=%q",
			response.Code, response.Body.String())
	}
}

func TestResolutionStatusAPIBoundsConcurrentReads(t *testing.T) {
	reader := &resolutionStatusReaderStub{}
	api := testResolutionStatusAPI(t, reader, resolutionStatusAuthenticatorStub{actor: testResolutionReaderActor()})
	for range maximumResolutionStatusReads {
		api.concurrency <- struct{}{}
	}
	response := performResolutionStatusRequest(api, "/v1/resolutions/resolution-1")
	if response.Code != http.StatusTooManyRequests ||
		!strings.Contains(response.Body.String(), "RESOLUTION_STATUS_BUSY") || reader.reads != 0 {
		t.Fatalf("unexpected busy response: status=%d body=%q reads=%d",
			response.Code, response.Body.String(), reader.reads)
	}
}

func testResolutionStatusAPI(t *testing.T, reader resolutionStatusReader,
	authenticator resolutionStatusAuthenticator,
) *resolutionStatusAPI {
	t.Helper()
	api, err := newResolutionStatusAPI(reader, authenticator, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}

	return api
}

func performResolutionStatusRequest(api *resolutionStatusAPI, path string) *httptest.ResponseRecorder {
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, http.NoBody)
	request.TLS = &tls.ConnectionState{}
	response := httptest.NewRecorder()
	mux := http.NewServeMux()
	api.register(mux)
	mux.ServeHTTP(response, request)

	return response
}

func testResolutionReaderActor() authctx.AuthContext {
	return authctx.AuthContext{
		SubjectID: "spiffe://broker.example/tenant/tenant-a/role/agent/workload/client-1",
		TenantID:  "tenant-a", AllowedScopes: []string{resolutionReadScope}, AuthenticatedAt: time.Now(),
	}
}
