package main

import (
	"context"
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

	"network_broker/internal/outbox"
	"network_broker/internal/resolution"
	"network_broker/migrations"
)

const (
	defaultListenAddress = ":8080"
	shutdownTimeout      = 10 * time.Second
	databaseTimeout      = 5 * time.Second
)

type config struct {
	DatabaseURL     string
	ListenAddress   string
	ApplyMigrations bool
}

type application struct {
	database    *sql.DB
	resolutions *resolution.PostgresRepository
	outbox      *outbox.PostgresStore
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
	database, err := openDatabase(ctx, configuration.DatabaseURL)
	if err != nil {
		logger.Error("database bootstrap failed", "error", err)
		return 1
	}
	defer func() {
		if closeErr := database.Close(); closeErr != nil {
			logger.Error("database close failed", "error", closeErr)
		}
	}()
	if configuration.ApplyMigrations {
		if err := migrations.Apply(ctx, database); err != nil {
			logger.Error("database migration failed", "error", err)
			return 1
		}
	}
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
	app := &application{database: database, resolutions: resolutionRepository, outbox: outboxStore}
	server := &http.Server{
		Addr:              configuration.ListenAddress,
		Handler:           app.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}
	logger.Info("control plane starting", "listen_address", configuration.ListenAddress)
	if err := serve(ctx, server); err != nil {
		logger.Error("control plane stopped", "error", err)
		return 1
	}
	logger.Info("control plane stopped")

	return 0
}

func loadConfig(getenv func(string) string) (config, error) {
	if getenv == nil {
		return config{}, fmt.Errorf("environment reader is required")
	}
	configuration := config{
		DatabaseURL:   getenv("DATABASE_URL"),
		ListenAddress: getenv("LISTEN_ADDRESS"),
	}
	if configuration.DatabaseURL == "" {
		return config{}, fmt.Errorf("DATABASE_URL is required")
	}
	if configuration.ListenAddress == "" {
		configuration.ListenAddress = defaultListenAddress
	}
	if raw := getenv("APPLY_MIGRATIONS"); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return config{}, fmt.Errorf("APPLY_MIGRATIONS must be a boolean: %w", err)
		}
		configuration.ApplyMigrations = value
	}

	return configuration, nil
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

func (a *application) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /readyz", a.readiness)

	return mux
}

func (a *application) readiness(response http.ResponseWriter, request *http.Request) {
	if a == nil || a.database == nil || a.resolutions == nil || a.outbox == nil {
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

func serve(ctx context.Context, server *http.Server) error {
	result := make(chan error, 1)
	go func() {
		err := server.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		result <- err
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown control plane: %w", err)
		}

		return <-result
	}
}
