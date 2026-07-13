// Package migrations embeds and applies the broker's PostgreSQL schema.
package migrations

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	migrationLockID        int64 = 6_629_471_193_041_352_841
	migrationUnlockTimeout       = 5 * time.Second
)

//go:embed *.up.sql
var migrationFiles embed.FS

// Apply acquires a session-level advisory lock and applies every pending
// migration transactionally. Previously applied files must retain the same
// checksum or startup fails closed.
func Apply(ctx context.Context, database *sql.DB) (err error) {
	if database == nil {
		return fmt.Errorf("migration database is required")
	}
	connection, err := database.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer func() {
		if closeErr := connection.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close migration connection: %w", closeErr))
		}
	}()
	if _, err := connection.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, migrationLockID); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), migrationUnlockTimeout)
		defer cancel()
		var unlocked bool
		unlockErr := connection.QueryRowContext(unlockCtx,
			`SELECT pg_advisory_unlock($1)`, migrationLockID).Scan(&unlocked)
		if unlockErr != nil {
			err = errors.Join(err, fmt.Errorf("release migration lock: %w", unlockErr))
		} else if !unlocked {
			err = errors.Join(err, fmt.Errorf("migration lock was not held during release"))
		}
	}()

	if _, err := connection.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS broker_schema_migrations (
			version BIGINT PRIMARY KEY,
			name TEXT NOT NULL,
			checksum TEXT NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}

	files, err := fs.Glob(migrationFiles, "*.up.sql")
	if err != nil {
		return fmt.Errorf("list embedded migrations: %w", err)
	}
	sort.Strings(files)
	for _, name := range files {
		if err := applyFile(ctx, connection, name); err != nil {
			return err
		}
	}

	return nil
}

func applyFile(ctx context.Context, connection *sql.Conn, name string) (err error) {
	version, err := migrationVersion(name)
	if err != nil {
		return err
	}
	contents, err := migrationFiles.ReadFile(name)
	if err != nil {
		return fmt.Errorf("read migration %q: %w", name, err)
	}
	digest := sha256.Sum256(contents)
	checksum := hex.EncodeToString(digest[:])

	var appliedChecksum string
	err = connection.QueryRowContext(ctx,
		`SELECT checksum FROM broker_schema_migrations WHERE version = $1`, version).Scan(&appliedChecksum)
	if err == nil {
		if appliedChecksum != checksum {
			return fmt.Errorf("migration %d checksum does not match applied schema", version)
		}

		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read migration %d status: %w", version, err)
	}

	transaction, err := connection.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration %d: %w", version, err)
	}
	defer func() {
		if rollbackErr := transaction.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("rollback migration %d: %w", version, rollbackErr))
		}
	}()
	if _, err := transaction.ExecContext(ctx, string(contents)); err != nil {
		return fmt.Errorf("apply migration %d: %w", version, err)
	}
	if _, err := transaction.ExecContext(ctx, `
		INSERT INTO broker_schema_migrations (version, name, checksum)
		VALUES ($1, $2, $3)`, version, name, checksum); err != nil {
		return fmt.Errorf("record migration %d: %w", version, err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit migration %d: %w", version, err)
	}

	return nil
}

func migrationVersion(name string) (int64, error) {
	prefix, _, found := strings.Cut(name, "_")
	if !found || prefix == "" {
		return 0, fmt.Errorf("migration %q has no numeric version prefix", name)
	}
	version, err := strconv.ParseInt(prefix, 10, 64)
	if err != nil || version <= 0 {
		return 0, fmt.Errorf("migration %q has an invalid version prefix", name)
	}

	return version, nil
}
