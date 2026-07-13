package resolution

import "testing"

func TestServiceCreateAndGet(t *testing.T) {
	service := NewService()
	res, err := service.Create("actor-a", "tenant-a")
	if err != nil {
		t.Fatalf("expected create to succeed, got %v", err)
	}
	if res.State != ResolutionReceived {
		t.Fatalf("expected initial state %q, got %q", ResolutionReceived, res.State)
	}
	got, err := service.Get(res.ID)
	if err != nil {
		t.Fatalf("expected get to succeed, got %v", err)
	}
	if got.ID != res.ID {
		t.Fatalf("expected id %q, got %q", res.ID, got.ID)
	}
}

func TestServiceUpdate(t *testing.T) {
	service := NewService()
	res, err := service.Create("actor-a", "tenant-a")
	if err != nil {
		t.Fatalf("expected create to succeed, got %v", err)
	}
	if err := service.Update(res.ID, ResolutionQueued); err != nil {
		t.Fatalf("expected update to succeed, got %v", err)
	}
	got, err := service.Get(res.ID)
	if err != nil {
		t.Fatalf("expected get to succeed, got %v", err)
	}
	if got.State != ResolutionQueued {
		t.Fatalf("expected state %q, got %q", ResolutionQueued, got.State)
	}
}
