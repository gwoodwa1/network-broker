package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"golang.org/x/sync/errgroup"

	"network_broker/internal/collector"
	"network_broker/internal/databaseauth"
	"network_broker/internal/deadletter"
	"network_broker/internal/operatorauth"
	"network_broker/internal/outbox"
	"network_broker/internal/planning"
	"network_broker/internal/resolution"
	"network_broker/internal/workloadidentity"
	"network_broker/migrations"
)

const (
	defaultListenAddress           = ":8080"
	shutdownTimeout                = 10 * time.Second
	databaseTimeout                = 5 * time.Second
	defaultNATSStream              = "BROKER_EVENTS"
	defaultNATSSubject             = "network-broker.events"
	defaultBatchSize               = 100
	defaultMaxAttempts             = 10
	defaultLease                   = 30 * time.Second
	defaultPollInterval            = 250 * time.Millisecond
	defaultFailureDelay            = 2 * time.Second
	defaultReconciliationBatchSize = 100
	defaultReconciliationPoll      = 5 * time.Second
	defaultReconciliationFailure   = 5 * time.Second
)

type config struct {
	DatabaseURL                string
	DatabaseRole               string
	MigrationDatabaseURL       string
	ListenAddress              string
	ApplyMigrations            bool
	NATSURL                    string
	NATSStream                 string
	NATSSubject                string
	NATSCredentials            string
	NATSCAFile                 string
	NATSCertFile               string
	NATSKeyFile                string
	OutboxWorkerID             string
	ServerTLSCertFile          string
	ServerTLSKeyFile           string
	OperatorClientCAFile       string
	OperatorSPIFFETrustDomain  string
	ReconciliationBatchSize    int
	ReconciliationPoll         time.Duration
	ReconciliationFailureDelay time.Duration
}

type application struct {
	database              *sql.DB
	resolutions           *resolution.PostgresRepository
	outbox                *outbox.PostgresStore
	nats                  *nats.Conn
	metrics               *outbox.Metrics
	deadLetters           *deadLetterAPI
	planning              *planningAPI
	resolutionCreate      *resolutionCreateAPI
	resolutionStatus      *resolutionStatusAPI
	resolutionWatch       *resolutionWatchAPI
	reconciliation        *collector.PostgresRepository
	reconciliationMetrics *collector.ReconciliationMetrics
}

type deliveryRuntime struct {
	connection *nats.Conn
	runner     outbox.Runner
	metrics    *outbox.Metrics
}

type reconciliationRuntime struct {
	repository *collector.PostgresRepository
	runner     collector.ReconciliationRunner
	metrics    *collector.ReconciliationMetrics
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	exitCode := run(ctx, os.Getenv, os.Stdout, os.Stderr)
	stop()
	os.Exit(exitCode)
}

func run(ctx context.Context, getenv func(string) string, stdout, stderr io.Writer) int {
	configuration, err := loadConfig(getenv)
	if err != nil {
		fmt.Fprintf(stderr, "configure control plane: %v\n", err)
		return 2
	}
	logger := slog.New(slog.NewJSONHandler(stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	database, err := openApplicationDatabase(ctx, configuration)
	if err != nil {
		logger.Error("database bootstrap failed", "error", err)
		return 1
	}
	defer func() {
		if closeErr := database.Close(); closeErr != nil {
			logger.Error("database close failed", "error", closeErr)
		}
	}()
	resolutionRepository, err := resolution.NewPostgresRepository(database)
	if err != nil {
		logger.Error("resolution repository bootstrap failed", "error", err)
		return 1
	}
	outboxStore, err := outbox.NewPostgresStore(database)
	if err != nil {
		logger.Error("outbox repository bootstrap failed", "error", err)
		return 1
	}
	reconciliation, err := newReconciliationRuntime(configuration, database, logger)
	if err != nil {
		logger.Error("evidence reconciliation bootstrap failed", "error", err)
		return 1
	}
	delivery, err := newDeliveryRuntime(configuration, outboxStore, logger)
	if err != nil {
		logger.Error("event broker bootstrap failed", "error", err)
		return 1
	}
	defer func() {
		if drainErr := delivery.connection.Drain(); drainErr != nil {
			logger.Error("event broker drain failed", "error", drainErr)
		}
	}()
	deadLetterAPI, serverTLS, err := newOperatorRuntime(configuration, database, logger)
	if err != nil {
		logger.Error("operator API bootstrap failed", "error", err)
		return 1
	}
	app, err := newApplication(configuration, database, resolutionRepository, outboxStore,
		delivery, reconciliation, deadLetterAPI, serverTLS, logger)
	if err != nil {
		logger.Error("planning API bootstrap failed", "error", err)
		return 1
	}
	server := &http.Server{
		Addr:              configuration.ListenAddress,
		Handler:           app.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
		TLSConfig:         serverTLS,
	}
	logger.Info("control plane starting", "listen_address", configuration.ListenAddress,
		"operator_api_enabled", deadLetterAPI != nil, "planning_api_enabled", app.planning != nil,
		"resolution_create_api_enabled", app.resolutionCreate != nil,
		"resolution_status_api_enabled", app.resolutionStatus != nil,
		"resolution_watch_api_enabled", app.resolutionWatch != nil)
	if err := serve(ctx, server, delivery.runner, reconciliation.runner); err != nil {
		if errors.Is(err, context.Canceled) && ctx.Err() != nil {
			logger.Info("control plane stopped")
			return 0
		}
		logger.Error("control plane stopped", "error", err)
		return 1
	}
	logger.Info("control plane stopped")

	return 0
}

func newApplication(configuration config, database *sql.DB,
	resolutionRepository *resolution.PostgresRepository, outboxStore *outbox.PostgresStore,
	delivery *deliveryRuntime, reconciliation *reconciliationRuntime,
	deadLetters *deadLetterAPI, serverTLS *tls.Config, logger *slog.Logger,
) (*application, error) {
	planningAPI, err := newPlanningRuntime(configuration, reconciliation.repository,
		serverTLS, logger)
	if err != nil {
		return nil, err
	}
	resolutionStatusAPI, err := newResolutionStatusRuntime(configuration,
		resolutionRepository, serverTLS, logger)
	if err != nil {
		return nil, err
	}
	resolutionCreateAPI, err := newResolutionCreateRuntime(configuration,
		resolutionRepository, serverTLS, logger)
	if err != nil {
		return nil, err
	}
	resolutionWatchAPI, err := newResolutionWatchRuntime(configuration,
		resolutionRepository, serverTLS, logger)
	if err != nil {
		return nil, err
	}

	return &application{
		database: database, resolutions: resolutionRepository, outbox: outboxStore,
		nats: delivery.connection, metrics: delivery.metrics, deadLetters: deadLetters,
		planning: planningAPI, resolutionCreate: resolutionCreateAPI,
		resolutionStatus: resolutionStatusAPI, resolutionWatch: resolutionWatchAPI,
		reconciliation: reconciliation.repository, reconciliationMetrics: reconciliation.metrics,
	}, nil
}

func newPlanningRuntime(configuration config, repository planning.FanoutRepository,
	serverTLS *tls.Config, logger *slog.Logger,
) (*planningAPI, error) {
	if serverTLS == nil {
		return nil, nil
	}
	service, err := planning.NewService(repository, time.Now, randomIdentifier)
	if err != nil {
		return nil, err
	}
	authenticator := workloadidentity.Authenticator{
		TrustDomain: configuration.OperatorSPIFFETrustDomain, Now: time.Now,
		// #nosec G101 -- these values are authorization labels, not credentials.
		Roles: map[string]workloadidentity.RoleBinding{
			"planner": {
				Scopes: []string{"resolutions:plan"}, CredentialClass: "mtls-spiffe",
			},
		},
	}

	return newPlanningAPI(service, authenticator, logger)
}

func newResolutionStatusRuntime(configuration config, repository resolution.Repository,
	serverTLS *tls.Config, logger *slog.Logger,
) (*resolutionStatusAPI, error) {
	if serverTLS == nil {
		return nil, nil
	}
	authenticator := workloadidentity.Authenticator{
		TrustDomain: configuration.OperatorSPIFFETrustDomain, Now: time.Now,
		// #nosec G101 -- these values are authorization labels, not credentials.
		Roles: map[string]workloadidentity.RoleBinding{
			"agent": {
				Scopes: []string{resolutionReadScope}, CredentialClass: "mtls-spiffe",
			},
		},
	}

	return newResolutionStatusAPI(repository, authenticator, logger)
}

func newResolutionCreateRuntime(configuration config, repository resolution.Repository,
	serverTLS *tls.Config, logger *slog.Logger,
) (*resolutionCreateAPI, error) {
	if serverTLS == nil {
		return nil, nil
	}
	service := resolution.NewServiceWithRepository(repository, time.Now, randomIdentifier)
	authenticator := workloadidentity.Authenticator{
		TrustDomain: configuration.OperatorSPIFFETrustDomain, Now: time.Now,
		// #nosec G101 -- these values are authorization labels, not credentials.
		Roles: map[string]workloadidentity.RoleBinding{
			"agent": {
				Scopes: []string{resolutionCreateScope}, CredentialClass: "mtls-spiffe",
			},
		},
	}

	return newResolutionCreateAPI(service, authenticator, logger)
}

func newResolutionWatchRuntime(configuration config, reader resolutionEventReader,
	serverTLS *tls.Config, logger *slog.Logger,
) (*resolutionWatchAPI, error) {
	if serverTLS == nil {
		return nil, nil
	}
	authenticator := workloadidentity.Authenticator{
		TrustDomain: configuration.OperatorSPIFFETrustDomain, Now: time.Now,
		// #nosec G101 -- these values are authorization labels, not credentials.
		Roles: map[string]workloadidentity.RoleBinding{
			"agent": {
				Scopes: []string{resolutionWatchScope}, CredentialClass: "mtls-spiffe",
			},
		},
	}

	return newResolutionWatchAPI(reader, authenticator, logger)
}

func newReconciliationRuntime(configuration config, database *sql.DB,
	logger *slog.Logger,
) (*reconciliationRuntime, error) {
	repository, err := collector.NewPostgresRepository(database)
	if err != nil {
		return nil, err
	}
	metrics := &collector.ReconciliationMetrics{}
	runner := collector.ReconciliationRunner{
		Repository: repository, BatchSize: configuration.ReconciliationBatchSize,
		PollInterval: configuration.ReconciliationPoll,
		FailureDelay: configuration.ReconciliationFailureDelay,
		Now:          time.Now, Metrics: metrics,
		OnError: func(reconciliationErr error) {
			logger.Error("evidence reconciliation failed", "error", reconciliationErr)
		},
	}

	return &reconciliationRuntime{repository: repository, runner: runner, metrics: metrics}, nil
}

func newOperatorRuntime(configuration config, database *sql.DB, logger *slog.Logger) (*deadLetterAPI, *tls.Config, error) {
	if configuration.ServerTLSCertFile == "" {
		return nil, nil, nil
	}
	certificate, err := tls.LoadX509KeyPair(configuration.ServerTLSCertFile, configuration.ServerTLSKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("load control-plane TLS identity: %w", err)
	}
	// #nosec G304 -- this deployment-controlled CA path is required for operator mTLS trust.
	clientCA, err := os.ReadFile(configuration.OperatorClientCAFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read operator client CA: %w", err)
	}
	clientCAPool := x509.NewCertPool()
	if !clientCAPool.AppendCertsFromPEM(clientCA) {
		return nil, nil, fmt.Errorf("operator client CA contains no certificates")
	}
	repository, err := deadletter.NewPostgresRepository(database)
	if err != nil {
		return nil, nil, err
	}
	service, err := deadletter.NewService(repository, randomIdentifier)
	if err != nil {
		return nil, nil, err
	}
	authenticator := operatorauth.Authenticator{TrustDomain: configuration.OperatorSPIFFETrustDomain, Now: time.Now}
	api, err := newDeadLetterAPI(service, authenticator, logger)
	if err != nil {
		return nil, nil, err
	}
	tlsConfiguration := &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate},
		ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: clientCAPool,
	}

	return api, tlsConfiguration, nil
}

func newDeliveryRuntime(configuration config, store outbox.Store, logger *slog.Logger) (*deliveryRuntime, error) {
	connection, client, err := openNATS(configuration, logger)
	if err != nil {
		return nil, err
	}
	publisher, err := outbox.NewJetStreamPublisher(client, configuration.NATSStream, configuration.NATSSubject)
	if err != nil {
		connection.Close()
		return nil, fmt.Errorf("create outbox publisher: %w", err)
	}
	metrics := &outbox.Metrics{}
	dispatcher := outbox.Dispatcher{
		Store: store, Publisher: publisher, WorkerID: configuration.OutboxWorkerID,
		BatchSize: defaultBatchSize, MaxAttempts: defaultMaxAttempts, Lease: defaultLease,
		RetryDelay: outboxRetryDelay, Now: time.Now, Metrics: metrics,
	}
	runner := outbox.Runner{
		Dispatcher: dispatcher, PollInterval: defaultPollInterval, FailureDelay: defaultFailureDelay,
		OnError: func(dispatchErr error) { logger.Error("outbox dispatch failed", "error", dispatchErr) },
	}

	return &deliveryRuntime{connection: connection, runner: runner, metrics: metrics}, nil
}

func loadConfig(getenv func(string) string) (config, error) {
	if getenv == nil {
		return config{}, fmt.Errorf("environment reader is required")
	}
	configuration := config{
		DatabaseURL:                getenv("DATABASE_URL"),
		DatabaseRole:               getenv("DATABASE_ROLE"),
		MigrationDatabaseURL:       getenv("MIGRATION_DATABASE_URL"),
		ListenAddress:              getenv("LISTEN_ADDRESS"),
		NATSURL:                    getenv("NATS_URL"),
		NATSStream:                 getenv("NATS_STREAM"),
		NATSSubject:                getenv("NATS_SUBJECT"),
		NATSCredentials:            getenv("NATS_CREDENTIALS_FILE"),
		NATSCAFile:                 getenv("NATS_CA_FILE"),
		NATSCertFile:               getenv("NATS_CERT_FILE"),
		NATSKeyFile:                getenv("NATS_KEY_FILE"),
		OutboxWorkerID:             getenv("OUTBOX_WORKER_ID"),
		ServerTLSCertFile:          getenv("SERVER_TLS_CERT_FILE"),
		ServerTLSKeyFile:           getenv("SERVER_TLS_KEY_FILE"),
		OperatorClientCAFile:       getenv("OPERATOR_CLIENT_CA_FILE"),
		OperatorSPIFFETrustDomain:  getenv("OPERATOR_SPIFFE_TRUST_DOMAIN"),
		ReconciliationBatchSize:    defaultReconciliationBatchSize,
		ReconciliationPoll:         defaultReconciliationPoll,
		ReconciliationFailureDelay: defaultReconciliationFailure,
	}
	applyConfigDefaults(&configuration)
	if err := validateRequiredConfig(configuration); err != nil {
		return config{}, err
	}
	if err := loadMigrationConfig(getenv, &configuration); err != nil {
		return config{}, err
	}
	if err := loadReconciliationConfig(getenv, &configuration); err != nil {
		return config{}, err
	}

	return configuration, nil
}

func applyConfigDefaults(configuration *config) {
	if configuration.ListenAddress == "" {
		configuration.ListenAddress = defaultListenAddress
	}
	if configuration.NATSStream == "" {
		configuration.NATSStream = defaultNATSStream
	}
	if configuration.NATSSubject == "" {
		configuration.NATSSubject = defaultNATSSubject
	}
}

func validateRequiredConfig(configuration config) error {
	if configuration.DatabaseURL == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}
	if err := databaseauth.ValidateName(configuration.DatabaseRole); err != nil {
		return fmt.Errorf("DATABASE_ROLE is required and invalid: %w", err)
	}
	if configuration.NATSURL == "" {
		return fmt.Errorf("NATS_URL is required")
	}
	if configuration.OutboxWorkerID == "" {
		return fmt.Errorf("OUTBOX_WORKER_ID is required")
	}
	if (configuration.NATSCertFile == "") != (configuration.NATSKeyFile == "") {
		return fmt.Errorf("NATS_CERT_FILE and NATS_KEY_FILE must be configured together")
	}
	operatorTLSValues := []string{
		configuration.ServerTLSCertFile, configuration.ServerTLSKeyFile,
		configuration.OperatorClientCAFile, configuration.OperatorSPIFFETrustDomain,
	}
	configuredOperatorTLSValues := 0
	for _, value := range operatorTLSValues {
		if value != "" {
			configuredOperatorTLSValues++
		}
	}
	if configuredOperatorTLSValues != 0 && configuredOperatorTLSValues != len(operatorTLSValues) {
		return fmt.Errorf("server TLS identity, operator client CA and SPIFFE trust domain must be configured together")
	}

	return nil
}

func loadMigrationConfig(getenv func(string) string, configuration *config) error {
	if raw := getenv("APPLY_MIGRATIONS"); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("APPLY_MIGRATIONS must be a boolean: %w", err)
		}
		configuration.ApplyMigrations = value
	}
	if configuration.ApplyMigrations && configuration.MigrationDatabaseURL == "" {
		return fmt.Errorf("MIGRATION_DATABASE_URL is required when APPLY_MIGRATIONS is true")
	}
	if !configuration.ApplyMigrations && configuration.MigrationDatabaseURL != "" {
		return fmt.Errorf("MIGRATION_DATABASE_URL requires APPLY_MIGRATIONS=true")
	}
	if configuration.ApplyMigrations && configuration.MigrationDatabaseURL == configuration.DatabaseURL {
		return fmt.Errorf("migration and runtime database identities must be separate")
	}

	return nil
}

func loadReconciliationConfig(getenv func(string) string, configuration *config) error {
	if raw := getenv("RECONCILIATION_BATCH_SIZE"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value <= 0 || value > 10_000 {
			return fmt.Errorf("RECONCILIATION_BATCH_SIZE must be between 1 and 10000")
		}
		configuration.ReconciliationBatchSize = value
	}
	if raw := getenv("RECONCILIATION_POLL_INTERVAL"); raw != "" {
		value, err := time.ParseDuration(raw)
		if err != nil || value <= 0 {
			return fmt.Errorf("RECONCILIATION_POLL_INTERVAL must be a positive duration")
		}
		configuration.ReconciliationPoll = value
	}
	if raw := getenv("RECONCILIATION_FAILURE_DELAY"); raw != "" {
		value, err := time.ParseDuration(raw)
		if err != nil || value <= 0 {
			return fmt.Errorf("RECONCILIATION_FAILURE_DELAY must be a positive duration")
		}
		configuration.ReconciliationFailureDelay = value
	}

	return nil
}

func openNATS(configuration config, logger *slog.Logger) (*nats.Conn, jetstream.JetStream, error) {
	options := []nats.Option{
		nats.Name("network-broker-controlplane"),
		nats.Timeout(databaseTimeout),
		nats.ReconnectWait(time.Second),
		nats.MaxReconnects(-1),
		nats.RetryOnFailedConnect(true),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			logger.Warn("event broker disconnected", "error", err)
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) { logger.Info("event broker reconnected") }),
		nats.ClosedHandler(func(connection *nats.Conn) {
			if err := connection.LastError(); err != nil {
				logger.Error("event broker connection closed", "error", err)
			}
		}),
	}
	if configuration.NATSCredentials != "" {
		options = append(options, nats.UserCredentials(configuration.NATSCredentials))
	}
	if configuration.NATSCAFile != "" {
		options = append(options, nats.RootCAs(configuration.NATSCAFile))
	}
	if configuration.NATSCertFile != "" {
		options = append(options, nats.ClientCert(configuration.NATSCertFile, configuration.NATSKeyFile))
	}
	connection, err := nats.Connect(configuration.NATSURL, options...)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to nats: %w", err)
	}
	client, err := jetstream.New(connection)
	if err != nil {
		connection.Close()
		return nil, nil, fmt.Errorf("create jetstream client: %w", err)
	}

	return connection, client, nil
}

func outboxRetryDelay(attempt int) time.Duration {
	if attempt <= 1 {
		return time.Second
	}
	if attempt >= 9 {
		return 5 * time.Minute
	}

	return time.Second << (attempt - 1)
}

func openDatabase(ctx context.Context, databaseURL string) (*sql.DB, error) {
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	database.SetMaxOpenConns(20)
	database.SetMaxIdleConns(5)
	database.SetConnMaxIdleTime(5 * time.Minute)
	database.SetConnMaxLifetime(30 * time.Minute)
	pingCtx, cancel := context.WithTimeout(ctx, databaseTimeout)
	defer cancel()
	if err := database.PingContext(pingCtx); err != nil {
		if closeErr := database.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	return database, nil
}

func openApplicationDatabase(ctx context.Context, configuration config) (*sql.DB, error) {
	if configuration.ApplyMigrations {
		migrationDatabase, err := openDatabase(ctx, configuration.MigrationDatabaseURL)
		if err != nil {
			return nil, fmt.Errorf("open migration database identity: %w", err)
		}
		if err := migrations.Apply(ctx, migrationDatabase); err != nil {
			if closeErr := migrationDatabase.Close(); closeErr != nil {
				err = errors.Join(err, closeErr)
			}

			return nil, fmt.Errorf("apply database migrations: %w", err)
		}
		if err := migrationDatabase.Close(); err != nil {
			return nil, fmt.Errorf("close migration database identity: %w", err)
		}
	}
	database, err := openDatabase(ctx, configuration.DatabaseURL)
	if err != nil {
		return nil, err
	}
	if _, err := databaseauth.VerifyControlPlane(ctx, database, configuration.DatabaseRole); err != nil {
		if closeErr := database.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}

		return nil, fmt.Errorf("verify database authority: %w", err)
	}

	return database, nil
}

func (a *application) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /readyz", a.readiness)
	mux.HandleFunc("GET /metrics", a.metricsHandler)
	if a != nil && a.deadLetters != nil {
		a.deadLetters.register(mux)
	}
	if a != nil && a.planning != nil {
		a.planning.register(mux)
	}
	if a != nil && a.resolutionStatus != nil {
		a.resolutionStatus.register(mux)
	}
	if a != nil && a.resolutionCreate != nil {
		a.resolutionCreate.register(mux)
	}
	if a != nil && a.resolutionWatch != nil {
		a.resolutionWatch.register(mux)
	}

	return mux
}

func (a *application) readiness(response http.ResponseWriter, request *http.Request) {
	if a == nil || a.database == nil || a.resolutions == nil || a.outbox == nil ||
		a.reconciliation == nil || a.nats == nil || a.nats.Status() != nats.CONNECTED {
		http.Error(response, "not ready", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), databaseTimeout)
	defer cancel()
	if err := a.database.PingContext(ctx); err != nil {
		http.Error(response, "not ready", http.StatusServiceUnavailable)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (a *application) metricsHandler(response http.ResponseWriter, _ *http.Request) {
	if a == nil || a.metrics == nil {
		http.Error(response, "metrics unavailable", http.StatusServiceUnavailable)
		return
	}
	snapshot := a.metrics.Snapshot()
	response.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(response, "# HELP network_broker_outbox_claimed_total Outbox records claimed for delivery.\n")
	fmt.Fprintf(response, "# TYPE network_broker_outbox_claimed_total counter\n")
	fmt.Fprintf(response, "network_broker_outbox_claimed_total %d\n", snapshot.Claimed)
	fmt.Fprintf(response, "# HELP network_broker_outbox_published_total Outbox records acknowledged by the broker.\n")
	fmt.Fprintf(response, "# TYPE network_broker_outbox_published_total counter\n")
	fmt.Fprintf(response, "network_broker_outbox_published_total %d\n", snapshot.Published)
	fmt.Fprintf(response, "# HELP network_broker_outbox_retried_total Outbox records scheduled for retry.\n")
	fmt.Fprintf(response, "# TYPE network_broker_outbox_retried_total counter\n")
	fmt.Fprintf(response, "network_broker_outbox_retried_total %d\n", snapshot.Retried)
	fmt.Fprintf(response, "# HELP network_broker_outbox_dead_lettered_total Outbox records moved to terminal failure state.\n")
	fmt.Fprintf(response, "# TYPE network_broker_outbox_dead_lettered_total counter\n")
	fmt.Fprintf(response, "network_broker_outbox_dead_lettered_total %d\n", snapshot.DeadLettered)
	fmt.Fprintf(response, "# HELP network_broker_outbox_failures_total Outbox delivery or state-update failures.\n")
	fmt.Fprintf(response, "# TYPE network_broker_outbox_failures_total counter\n")
	fmt.Fprintf(response, "network_broker_outbox_failures_total %d\n", snapshot.Failures)
	if a.deadLetters != nil {
		fmt.Fprintf(response, "# HELP network_broker_dead_letter_replay_applied_total Dead-letter replay actions applied.\n")
		fmt.Fprintf(response, "# TYPE network_broker_dead_letter_replay_applied_total counter\n")
		fmt.Fprintf(response, "network_broker_dead_letter_replay_applied_total %d\n",
			a.deadLetters.metrics.replayApplied.Load())
		fmt.Fprintf(response, "# HELP network_broker_dead_letter_replay_idempotent_total Idempotent dead-letter replay responses.\n")
		fmt.Fprintf(response, "# TYPE network_broker_dead_letter_replay_idempotent_total counter\n")
		fmt.Fprintf(response, "network_broker_dead_letter_replay_idempotent_total %d\n",
			a.deadLetters.metrics.replayIdempotent.Load())
		fmt.Fprintf(response, "# HELP network_broker_dead_letter_operator_denied_total Denied operator requests.\n")
		fmt.Fprintf(response, "# TYPE network_broker_dead_letter_operator_denied_total counter\n")
		fmt.Fprintf(response, "network_broker_dead_letter_operator_denied_total %d\n",
			a.deadLetters.metrics.denied.Load())
	}
	if a.reconciliationMetrics != nil {
		snapshot := a.reconciliationMetrics.Snapshot()
		fmt.Fprintf(response, "# HELP network_broker_evidence_reconciliation_candidates_total Expired evidence candidates inspected.\n")
		fmt.Fprintf(response, "# TYPE network_broker_evidence_reconciliation_candidates_total counter\n")
		fmt.Fprintf(response, "network_broker_evidence_reconciliation_candidates_total %d\n", snapshot.Candidates)
		fmt.Fprintf(response, "# HELP network_broker_evidence_reconciled_total Evidence envelopes accepted after collector process loss.\n")
		fmt.Fprintf(response, "# TYPE network_broker_evidence_reconciled_total counter\n")
		fmt.Fprintf(response, "network_broker_evidence_reconciled_total %d\n", snapshot.Reconciled)
		fmt.Fprintf(response, "# HELP network_broker_evidence_reconciliation_skipped_total Candidates fenced or otherwise no longer eligible.\n")
		fmt.Fprintf(response, "# TYPE network_broker_evidence_reconciliation_skipped_total counter\n")
		fmt.Fprintf(response, "network_broker_evidence_reconciliation_skipped_total %d\n", snapshot.Skipped)
		fmt.Fprintf(response, "# HELP network_broker_evidence_reconciliation_failures_total Reconciliation storage or integrity failures.\n")
		fmt.Fprintf(response, "# TYPE network_broker_evidence_reconciliation_failures_total counter\n")
		fmt.Fprintf(response, "network_broker_evidence_reconciliation_failures_total %d\n", snapshot.Failures)
	}
}

func serve(ctx context.Context, server *http.Server, outboxRunner outbox.Runner,
	reconciliationRunner collector.ReconciliationRunner,
) error {
	group, serviceCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		var err error
		if server.TLSConfig == nil {
			err = server.ListenAndServe()
		} else {
			err = server.ListenAndServeTLS("", "")
		}
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}

		return err
	})
	group.Go(func() error { return outboxRunner.Run(serviceCtx) })
	group.Go(func() error { return reconciliationRunner.Run(serviceCtx) })
	group.Go(func() error {
		<-serviceCtx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(serviceCtx), shutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown control plane: %w", err)
		}

		return nil
	})

	return group.Wait()
}
