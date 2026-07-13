package migrations

import "testing"

func TestMigrationVersion(t *testing.T) {
	version, err := migrationVersion("000002_outbox_delivery.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if version != 2 {
		t.Fatalf("expected version 2, got %d", version)
	}
	if _, err := migrationVersion("invalid.sql"); err == nil {
		t.Fatal("expected invalid migration name to fail")
	}
}
