package collectorruntime

import "testing"

func TestNewFailsClosedWithoutProductionDependencies(t *testing.T) {
	if _, err := New(Config{}, Dependencies{}); err == nil {
		t.Fatal("expected incomplete production collector construction to fail")
	}
}
