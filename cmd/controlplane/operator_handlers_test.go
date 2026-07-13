package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"network_broker/internal/authctx"
	"network_broker/internal/deadletter"
)

type operatorAuthenticatorStub struct {
	actor authctx.AuthContext
	err   error
}

func (a operatorAuthenticatorStub) Authenticate(*http.Request) (authctx.AuthContext, error) {
	return a.actor, a.err
}

type deadLetterRepositoryStub struct {
	entries []deadletter.Entry
	replay  deadletter.ReplayResult
}

func (r *deadLetterRepositoryStub) List(context.Context, string, int64, int) ([]deadletter.Entry, error) {
	return append([]deadletter.Entry(nil), r.entries...), nil
}

func (r *deadLetterRepositoryStub) Get(_ context.Context, _, eventID string) (deadletter.Entry, error) {
	for _, entry := range r.entries {
		if entry.EventID == eventID {
			return entry, nil
		}
	}

	return deadletter.Entry{}, deadletter.ErrNotFound
}

func (r *deadLetterRepositoryStub) Replay(context.Context, deadletter.ReplayCommand) (deadletter.ReplayResult, error) {
	return r.replay, nil
}

func TestDeadLetterAPIFailsClosedWithoutVerifiedIdentity(t *testing.T) {
	api := testDeadLetterAPI(t, &deadLetterRepositoryStub{}, operatorAuthenticatorStub{err: errors.New("unverified")})
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/v1/operations/dead-letters", http.NoBody)
	response := httptest.NewRecorder()
	mux := http.NewServeMux()
	api.register(mux)
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || response.Header().Get("WWW-Authenticate") != "Mutual" {
		t.Fatalf("unexpected authentication response: status=%d headers=%v", response.Code, response.Header())
	}
}

func TestDeadLetterAPIListsSecretSafeMetadata(t *testing.T) {
	repository := &deadLetterRepositoryStub{entries: []deadletter.Entry{{
		Sequence: 7, EventID: "evt-1", AggregateType: "resolution", AggregateID: "res-1",
		EventType: "resolution.received", Attempts: 10, DeadLetteredAt: time.Now(),
	}}}
	api := testDeadLetterAPI(t, repository, operatorAuthenticatorStub{actor: testOperatorActor()})
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/v1/operations/dead-letters?limit=1", http.NoBody)
	response := httptest.NewRecorder()
	mux := http.NewServeMux()
	api.register(mux)
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"event_id":"evt-1"`) ||
		strings.Contains(response.Body.String(), "payload") || strings.Contains(response.Body.String(), "last_error") {
		t.Fatalf("unexpected list response: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestDeadLetterAPIReplaysWithStrictBodyAndIdempotency(t *testing.T) {
	repository := &deadLetterRepositoryStub{replay: deadletter.ReplayResult{
		ActionID: "action-1", EventID: "evt-1", Replayed: true,
	}}
	api := testDeadLetterAPI(t, repository, operatorAuthenticatorStub{actor: testOperatorActor()})
	mux := http.NewServeMux()
	api.register(mux)
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/operations/dead-letters/evt-1/replay",
		strings.NewReader(`{"reason":"broker configuration repaired"}`))
	request.Header.Set("Idempotency-Key", "request-1")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || api.metrics.replayApplied.Load() != 1 {
		t.Fatalf("unexpected replay response: status=%d body=%s", response.Code, response.Body.String())
	}

	badRequest := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/operations/dead-letters/evt-1/replay",
		strings.NewReader(`{"reason":"valid","unknown":true}`))
	badRequest.Header.Set("Idempotency-Key", "request-2")
	badResponse := httptest.NewRecorder()
	mux.ServeHTTP(badResponse, badRequest)
	if badResponse.Code != http.StatusBadRequest {
		t.Fatalf("expected strict JSON rejection, got %d", badResponse.Code)
	}
}

func testDeadLetterAPI(t *testing.T, repository deadletter.Repository,
	authenticator operatorAuthenticator,
) *deadLetterAPI {
	t.Helper()
	service, err := deadletter.NewService(repository, func(string) (string, error) { return "action-1", nil })
	if err != nil {
		t.Fatal(err)
	}
	api, err := newDeadLetterAPI(service, authenticator, slog.New(slog.NewTextHandler(&strings.Builder{}, nil)))
	if err != nil {
		t.Fatal(err)
	}

	return api
}

func testOperatorActor() authctx.AuthContext {
	return authctx.AuthContext{
		SubjectID: "spiffe://broker.example/tenant/tenant-a/role/outbox-operator/workload/operator-a",
		SPIFFEID:  "spiffe://broker.example/tenant/tenant-a/role/outbox-operator/workload/operator-a",
		TenantID:  "tenant-a", Roles: []string{deadletter.OperatorRole},
		AllowedScopes:   []string{deadletter.ReadScope, deadletter.ReplayScope},
		AuthenticatedAt: time.Now(), IdentityRevision: "revision-1",
	}
}
