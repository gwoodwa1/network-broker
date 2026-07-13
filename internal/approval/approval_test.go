package approval

import "testing"

func TestCreateAndConsumeGrant(t *testing.T) {
	service := NewService()
	grant, err := service.Create("grant-1", "tenant-a", "vendor_cli_show_interface", "subset-abc", 2)
	if err != nil {
		t.Fatalf("expected create to succeed, got %v", err)
	}
	if grant.MaxUses != 2 {
		t.Fatalf("expected max uses 2, got %d", grant.MaxUses)
	}
	if err := service.Consume("grant-1"); err != nil {
		t.Fatalf("expected first consume to succeed, got %v", err)
	}
	if err := service.Consume("grant-1"); err != nil {
		t.Fatalf("expected second consume to succeed, got %v", err)
	}
	if err := service.Consume("grant-1"); err == nil {
		t.Fatal("expected exhausted grant to be rejected")
	}
}
