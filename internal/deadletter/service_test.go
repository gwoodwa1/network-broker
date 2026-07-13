package deadletter

import (
	"context"
	"errors"
	"testing"
	"time"

	"network_broker/internal/authctx"
)

type repositoryStub struct {
	entries     []Entry
	get         Entry
	replay      ReplayResult
	lastTenant  string
	lastCommand ReplayCommand
}

func (r *repositoryStub) List(_ context.Context, tenant string, _ int64, _ int) ([]Entry, error) {
	r.lastTenant = tenant

	return append([]Entry(nil), r.entries...), nil
}

func (r *repositoryStub) Get(_ context.Context, tenant, _ string) (Entry, error) {
	r.lastTenant = tenant

	return r.get, nil
}

func (r *repositoryStub) Replay(_ context.Context, command ReplayCommand) (ReplayResult, error) {
	r.lastTenant = command.TenantID
	r.lastCommand = command

	return r.replay, nil
}

func TestServiceScopesEveryOperationToAuthenticatedTenant(t *testing.T) {
	repository := &repositoryStub{
		entries: []Entry{{EventID: "evt-1"}}, get: Entry{EventID: "evt-1"},
		replay: ReplayResult{ActionID: "action-1", EventID: "evt-1", Replayed: true},
	}
	service, err := NewService(repository, func(string) (string, error) { return "action-1", nil })
	if err != nil {
		t.Fatal(err)
	}
	actor := operatorActor(ReadScope, ReplayScope)
	if _, err := service.List(context.Background(), actor, 0, 50); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Get(context.Background(), actor, "evt-1"); err != nil {
		t.Fatal(err)
	}
	result, err := service.Replay(context.Background(), actor, "evt-1", "request-1", "broker issue resolved")
	if err != nil {
		t.Fatal(err)
	}
	if repository.lastTenant != "tenant-a" || repository.lastCommand.ActorID != "operator-a" ||
		repository.lastCommand.SPIFFEID == "" || repository.lastCommand.IdentityRevision != "revision-1" ||
		result.ActionID != "action-1" {
		t.Fatalf("unexpected authorized operation: tenant=%q command=%+v result=%+v",
			repository.lastTenant, repository.lastCommand, result)
	}
}

func TestServiceDeniesMissingRoleScopeOrVerifiedIdentity(t *testing.T) {
	service, err := NewService(&repositoryStub{}, func(string) (string, error) { return "action-1", nil })
	if err != nil {
		t.Fatal(err)
	}
	tests := []authctx.AuthContext{
		operatorActor(),
		operatorActor(ReadScope),
		{
			SubjectID: "operator-a", TenantID: "tenant-a", Roles: []string{OperatorRole},
			AllowedScopes: []string{ReplayScope}, AuthenticatedAt: time.Now(), IdentityRevision: "revision-1",
		},
	}
	for _, actor := range tests {
		if _, err := service.Replay(context.Background(), actor, "evt-1", "request-1", "reason"); !errors.Is(err, ErrDenied) {
			t.Fatalf("expected authorization denial for %+v, got %v", actor, err)
		}
	}
}

func TestServiceRejectsMalformedOperatorInput(t *testing.T) {
	service, err := NewService(&repositoryStub{}, func(string) (string, error) { return "action-1", nil })
	if err != nil {
		t.Fatal(err)
	}
	actor := operatorActor(ReadScope, ReplayScope)
	if _, err := service.List(context.Background(), actor, -1, 101); err == nil {
		t.Fatal("expected invalid pagination to fail")
	}
	if _, err := service.Get(context.Background(), actor, "../evt"); err == nil {
		t.Fatal("expected malformed event id to fail")
	}
	if _, err := service.Replay(context.Background(), actor, "evt-1", "", "reason"); err == nil {
		t.Fatal("expected missing idempotency key to fail")
	}
}

func operatorActor(scopes ...string) authctx.AuthContext {
	return authctx.AuthContext{
		SubjectID: "operator-a", SPIFFEID: "spiffe://broker.example/tenant/tenant-a/role/outbox-operator/workload/operator-a",
		TenantID: "tenant-a", Roles: []string{OperatorRole}, AllowedScopes: scopes,
		AuthenticatedAt: time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC), IdentityRevision: "revision-1",
	}
}
