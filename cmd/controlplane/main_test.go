package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"network_broker/internal/collector"
	"network_broker/internal/outbox"
)

func TestLoadConfigRequiresDatabaseAndParsesOperationalSettings(t *testing.T) {
	values := map[string]string{
		"DATABASE_URL":           "postgres://localhost/broker",
		"DATABASE_ROLE":          "broker_controlplane",
		"MIGRATION_DATABASE_URL": "postgres://migrator@localhost/broker",
		"LISTEN_ADDRESS":         "127.0.0.1:9000",
		"APPLY_MIGRATIONS":       "true",
		"NATS_URL":               "nats://localhost:4222",
		"OUTBOX_WORKER_ID":       "worker-a",
	}
	configuration, err := loadConfig(func(key string) string { return values[key] })
	if err != nil {
		t.Fatal(err)
	}
	if configuration.DatabaseURL != values["DATABASE_URL"] || configuration.DatabaseRole != values["DATABASE_ROLE"] ||
		configuration.MigrationDatabaseURL != values["MIGRATION_DATABASE_URL"] ||
		configuration.ListenAddress != values["LISTEN_ADDRESS"] || !configuration.ApplyMigrations ||
		configuration.NATSURL != values["NATS_URL"] || configuration.OutboxWorkerID != values["OUTBOX_WORKER_ID"] ||
		configuration.NATSStream != defaultNATSStream || configuration.NATSSubject != defaultNATSSubject ||
		configuration.ReconciliationBatchSize != defaultReconciliationBatchSize ||
		configuration.ReconciliationPoll != defaultReconciliationPoll ||
		configuration.ReconciliationFailureDelay != defaultReconciliationFailure {
		t.Fatalf("unexpected configuration: %+v", configuration)
	}
	if _, err := loadConfig(func(string) string { return "" }); err == nil {
		t.Fatal("expected missing database URL to fail")
	}
}

func TestLoadConfigRequiresSeparateMigrationIdentity(t *testing.T) {
	values := map[string]string{
		"DATABASE_URL": "postgres://runtime@localhost/broker", "DATABASE_ROLE": "broker_controlplane",
		"NATS_URL": "nats://localhost:4222", "OUTBOX_WORKER_ID": "worker-a", "APPLY_MIGRATIONS": "true",
	}
	if _, err := loadConfig(func(key string) string { return values[key] }); err == nil {
		t.Fatal("expected a missing migration identity to fail")
	}
	values["MIGRATION_DATABASE_URL"] = values["DATABASE_URL"]
	if _, err := loadConfig(func(key string) string { return values[key] }); err == nil {
		t.Fatal("expected runtime identity reuse for migrations to fail")
	}
	values["MIGRATION_DATABASE_URL"] = "postgres://migrator@localhost/broker"
	if _, err := loadConfig(func(key string) string { return values[key] }); err != nil {
		t.Fatal(err)
	}
}

func TestLoadConfigRequiresDatabaseRole(t *testing.T) {
	values := map[string]string{
		"DATABASE_URL": "postgres://localhost/broker", "NATS_URL": "nats://localhost:4222",
		"OUTBOX_WORKER_ID": "worker-a",
	}
	if _, err := loadConfig(func(key string) string { return values[key] }); err == nil {
		t.Fatal("expected a missing database role to fail")
	}
}

func TestLoadConfigValidatesReconciliationBounds(t *testing.T) {
	values := map[string]string{
		"DATABASE_URL": "postgres://localhost/broker", "NATS_URL": "nats://localhost:4222",
		"DATABASE_ROLE":    "broker_controlplane",
		"OUTBOX_WORKER_ID": "worker-a", "RECONCILIATION_BATCH_SIZE": "25",
		"RECONCILIATION_POLL_INTERVAL": "2s", "RECONCILIATION_FAILURE_DELAY": "3s",
	}
	configuration, err := loadConfig(func(key string) string { return values[key] })
	if err != nil {
		t.Fatal(err)
	}
	if configuration.ReconciliationBatchSize != 25 || configuration.ReconciliationPoll != 2*time.Second ||
		configuration.ReconciliationFailureDelay != 3*time.Second {
		t.Fatalf("unexpected reconciliation configuration: %+v", configuration)
	}
	values["RECONCILIATION_BATCH_SIZE"] = "10001"
	if _, err := loadConfig(func(key string) string { return values[key] }); err == nil {
		t.Fatal("expected oversized reconciliation batch to fail")
	}
}

func TestLoadConfigRequiresCompleteNATSTLSIdentity(t *testing.T) {
	values := map[string]string{
		"DATABASE_URL": "postgres://localhost/broker", "NATS_URL": "tls://localhost:4222",
		"DATABASE_ROLE":    "broker_controlplane",
		"OUTBOX_WORKER_ID": "worker-a", "NATS_CERT_FILE": "/identity/client.pem",
	}
	if _, err := loadConfig(func(key string) string { return values[key] }); err == nil {
		t.Fatal("expected an incomplete client certificate identity to fail")
	}
}

func TestLoadConfigRequiresCompleteOperatorMTLSConfiguration(t *testing.T) {
	values := map[string]string{
		"DATABASE_URL": "postgres://localhost/broker", "NATS_URL": "nats://localhost:4222",
		"DATABASE_ROLE":    "broker_controlplane",
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

func TestMetricsEndpointExposesReconciliationCounters(t *testing.T) {
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", http.NoBody)
	response := httptest.NewRecorder()
	app := &application{
		metrics: &outbox.Metrics{}, reconciliationMetrics: &collector.ReconciliationMetrics{},
	}
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(),
		"network_broker_evidence_reconciled_total 0") {
		t.Fatalf("unexpected reconciliation metrics: status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestMetricsEndpointExposesDeadLetterOperatorCounters(t *testing.T) {
	api := testDeadLetterAPI(t, &deadLetterRepositoryStub{}, operatorAuthenticatorStub{actor: testOperatorActor()})
	api.metrics.replayApplied.Add(2)
	api.metrics.replayIdempotent.Add(3)
	api.metrics.denied.Add(4)
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", http.NoBody)
	response := httptest.NewRecorder()
	app := &application{metrics: &outbox.Metrics{}, deadLetters: api}
	app.routes().ServeHTTP(response, request)
	for _, metric := range []string{
		"network_broker_dead_letter_replay_applied_total 2",
		"network_broker_dead_letter_replay_idempotent_total 3",
		"network_broker_dead_letter_operator_denied_total 4",
	} {
		if !strings.Contains(response.Body.String(), metric) {
			t.Errorf("missing metric %q in %q", metric, response.Body.String())
		}
	}
}

func TestOutboxRetryDelayIsBounded(t *testing.T) {
	if outboxRetryDelay(1) != time.Second || outboxRetryDelay(3) != 4*time.Second ||
		outboxRetryDelay(100) != 5*time.Minute {
		t.Fatal("unexpected outbox retry schedule")
	}
}
