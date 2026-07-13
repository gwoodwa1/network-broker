package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLoadConfigRequiresDatabaseAndParsesOperationalSettings(t *testing.T) {
	values := map[string]string{
		"DATABASE_URL":     "postgres://localhost/broker",
		"LISTEN_ADDRESS":   "127.0.0.1:9000",
		"APPLY_MIGRATIONS": "true",
	}
	configuration, err := loadConfig(func(key string) string { return values[key] })
	if err != nil {
		t.Fatal(err)
	}
	if configuration.DatabaseURL != values["DATABASE_URL"] ||
		configuration.ListenAddress != values["LISTEN_ADDRESS"] || !configuration.ApplyMigrations {
		t.Fatalf("unexpected configuration: %+v", configuration)
	}
	if _, err := loadConfig(func(string) string { return "" }); err == nil {
		t.Fatal("expected missing database URL to fail")
	}
}

func TestReadinessFailsClosedWithoutDependencies(t *testing.T) {
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	(&application{}).readiness(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d, got %d", http.StatusServiceUnavailable, response.Code)
	}
}

func TestLivenessDoesNotDependOnDatabase(t *testing.T) {
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/livez", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	(&application{}).routes().ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, response.Code)
	}
}
