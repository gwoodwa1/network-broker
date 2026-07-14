package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"network_broker/internal/authctx"
	"network_broker/internal/collector"
	"network_broker/internal/planning"
)

type planningAuthenticatorStub struct {
	actor authctx.AuthContext
	err   error
}

func (a planningAuthenticatorStub) Authenticate(*tls.ConnectionState) (authctx.AuthContext, error) {
	return a.actor, a.err
}

type planningFanoutStub struct {
	request collector.FanoutRequest
	err     error
}

func (r *planningFanoutStub) CreateFanoutContext(_ context.Context,
	request collector.FanoutRequest,
) error {
	r.request = request

	return r.err
}

func TestPlanningAPIQueuesTenantBoundPlan(t *testing.T) {
	repository := &planningFanoutStub{}
	api := testPlanningAPI(t, repository, planningAuthenticatorStub{actor: testPlanningActor()})
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/resolutions/resolution-1/tasks:queue", planningRequestBody(t))
	request.TLS = &tls.ConnectionState{}
	response := httptest.NewRecorder()
	mux := http.NewServeMux()
	api.register(mux)
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || repository.request.TenantID != "tenant-a" ||
		repository.request.ResolutionID != "resolution-1" ||
		repository.request.Tasks[0].TenantID != "tenant-a" {
		t.Fatalf("unexpected response or fan-out: status=%d body=%q request=%+v",
			response.Code, response.Body.String(), repository.request)
	}
}

func TestPlanningAPIRejectsUnauthenticatedUnknownAndConflictingRequests(t *testing.T) {
	tests := []struct {
		name          string
		authenticator planningAuthenticatorStub
		repositoryErr error
		body          io.Reader
		status        int
		code          string
	}{
		{
			name: "unauthenticated", authenticator: planningAuthenticatorStub{err: errors.New("no identity")},
			body: planningRequestBody(t), status: http.StatusUnauthorized, code: "AUTHENTICATION_REQUIRED",
		},
		{
			name: "unknown field", authenticator: planningAuthenticatorStub{actor: testPlanningActor()},
			body:   strings.NewReader(`{"schema_version":"v1","unexpected":true}`),
			status: http.StatusBadRequest, code: "INVALID_REQUEST",
		},
		{
			name: "conflict", authenticator: planningAuthenticatorStub{actor: testPlanningActor()},
			repositoryErr: collector.ErrFanoutConflict, body: planningRequestBody(t),
			status: http.StatusConflict, code: "RESOLUTION_AUTHORITY_CHANGED",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &planningFanoutStub{err: test.repositoryErr}
			api := testPlanningAPI(t, repository, test.authenticator)
			request := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
				"/v1/resolutions/resolution-1/tasks:queue", test.body)
			response := httptest.NewRecorder()
			mux := http.NewServeMux()
			api.register(mux)
			mux.ServeHTTP(response, request)
			if response.Code != test.status || !strings.Contains(response.Body.String(), test.code) {
				t.Fatalf("unexpected response: status=%d body=%q", response.Code, response.Body.String())
			}
		})
	}
}

func testPlanningAPI(t *testing.T, repository *planningFanoutStub,
	authenticator planningAuthenticatorStub,
) *planningAPI {
	t.Helper()
	service, err := planning.NewService(repository, time.Now,
		func(string) (string, error) { return "event-1", nil })
	if err != nil {
		t.Fatal(err)
	}
	api, err := newPlanningAPI(service, authenticator, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}

	return api
}

func testPlanningActor() authctx.AuthContext {
	return authctx.AuthContext{
		SubjectID: "spiffe://broker.example/tenant/tenant-a/role/planner/workload/control-1",
		TenantID:  "tenant-a", AllowedScopes: []string{"resolutions:plan"},
		AuthenticatedAt: time.Now(),
	}
}

func planningRequestBody(t *testing.T) io.Reader {
	t.Helper()
	body := queuePlanBody{
		SchemaVersion: planningAPISchemaVersion, ExpectedResolutionVersion: 3,
		Tasks: []plannedTaskBody{{
			TaskID: "task-1", ClaimFingerprint: "claim-sha256",
			TargetSnapshotID: "snapshot-1", TargetSnapshotHash: "snapshot-sha256",
			TargetID: "router-1", TargetEndpoint: "router-1.example:57400",
			RecipeID: "gnmi_interface_get", RecipeVersion: "v1",
			TriggerDecisionID: "trigger-1", PlanningDecisionID: "planning-1",
			CompatibilityHash: "compatibility-sha256",
		}},
	}
	document, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	return bytes.NewReader(document)
}
