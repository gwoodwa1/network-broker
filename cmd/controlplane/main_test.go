package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"network_broker/internal/outbox"
)

func TestLoadConfigRequiresDatabaseAndParsesOperationalSettings(t *testing.T) {
	values := map[string]string{
		"DATABASE_URL":     "postgres://localhost/broker",
		"LISTEN_ADDRESS":   "127.0.0.1:9000",
		"APPLY_MIGRATIONS": "true",
		"NATS_URL":         "nats://localhost:4222",
		"OUTBOX_WORKER_ID": "worker-a",
	}
	configuration, err := loadConfig(func(key string) string { return values[key] })
	if err != nil {
		t.Fatal(err)
	}
	if configuration.DatabaseURL != values["DATABASE_URL"] ||
		configuration.ListenAddress != values["LISTEN_ADDRESS"] || !configuration.ApplyMigrations ||
		configuration.NATSURL != values["NATS_URL"] || configuration.OutboxWorkerID != values["OUTBOX_WORKER_ID"] ||
		configuration.NATSStream != defaultNATSStream || configuration.NATSSubject != defaultNATSSubject {
		t.Fatalf("unexpected configuration: %+v", configuration)
	}
	if _, err := loadConfig(func(string) string { return "" }); err == nil {
		t.Fatal("expected missing database URL to fail")
	}
}

func TestLoadConfigRequiresCompleteNATSTLSIdentity(t *testing.T) {
	values := map[string]string{
		"DATABASE_URL": "postgres://localhost/broker", "NATS_URL": "tls://localhost:4222",
		"OUTBOX_WORKER_ID": "worker-a", "NATS_CERT_FILE": "/identity/client.pem",
	}
	if _, err := loadConfig(func(key string) string { return values[key] }); err == nil {
		t.Fatal("expected an incomplete client certificate identity to fail")
	}
}

func TestLoadConfigRequiresCompleteOperatorMTLSConfiguration(t *testing.T) {
	values := map[string]string{
		"DATABASE_URL": "postgres://localhost/broker", "NATS_URL": "nats://localhost:4222",
		"OUTBOX_WORKER_ID": "worker-a", "SERVER_TLS_CERT_FILE": "/identity/server.pem",
	}
	if _, err := loadConfig(func(key string) string { return values[key] }); err == nil {
		t.Fatal("expected incomplete operator mTLS configuration to fail")
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

func TestMetricsEndpointExposesOutboxCounters(t *testing.T) {
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	(&application{metrics: &outbox.Metrics{}}).routes().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "network_broker_outbox_published_total 0") {
		t.Fatalf("unexpected metrics response: status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestOutboxRetryDelayIsBounded(t *testing.T) {
	if outboxRetryDelay(1) != time.Second || outboxRetryDelay(3) != 4*time.Second ||
		outboxRetryDelay(100) != 5*time.Minute {
		t.Fatal("unexpected outbox retry schedule")
	}
}
