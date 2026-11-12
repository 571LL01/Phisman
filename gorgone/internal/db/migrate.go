package db

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// ErrSchemaTooNew is returned when the file was written by a newer binary.
// Running forward-only migrations on such a file would either be a no-op with
// an unknown schema or corrupt data, so the process must refuse to start.
var ErrSchemaTooNew = errors.New("db: database schema is newer than this binary")

const schemaMigrationsDDL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
	version    INTEGER PRIMARY KEY,
	applied_at TEXT NOT NULL
);`

type migration struct {
	version int
	name    string
	sql     string
}

// Migrate brings the database to the schema version embedded in this binary.
// It is forward-only and idempotent: already-applied versions are skipped.
// It owns the whole file schema, collector and operational tables alike, so a
// single version number gates every table the binary can read or write.
func Migrate(ctx context.Context, handle *sql.DB) error {
	if handle == nil {
		return errors.New("db: nil database")
	}
	if _, err := handle.ExecContext(ctx, schemaMigrationsDDL); err != nil {
		return fmt.Errorf("db: schema_migrations: %w", err)
	}

	current, err := SchemaVersion(ctx, handle)
	if err != nil {
		return err
	}

	migrations, err := loadMigrations()
	if err != nil {
		return err
	}
	if len(migrations) == 0 {
		return errors.New("db: no embedded migrations")
	}
	latest := migrations[len(migrations)-1].version
	if current > latest {
		return fmt.Errorf("%w: database=%d binary=%d", ErrSchemaTooNew, current, latest)
	}

	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		if err := applyMigration(ctx, handle, m); err != nil {
			return err
		}
	}
	return nil
}

// SchemaVersion reports the highest applied version, or zero on a fresh file.
func SchemaVersion(ctx context.Context, handle *sql.DB) (int, error) {
	var version int
	err := handle.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("db: read schema version: %w", err)
	}
	return version, nil
}

// applyMigration runs one file and records its version in the same transaction.
// A crash leaves either both the DDL and the row or neither.
//
// The version is re-read after BEGIN on purpose. The caller checked the version
// before opening the transaction, but on a fresh file two processes can both
// read zero, and the loser would then replay non-idempotent DDL after the
// winner commits. BEGIN IMMEDIATE holds the write lock, so a row that appeared
// in the meantime is visible here and the whole migration is skipped.
func applyMigration(ctx context.Context, handle *sql.DB, m migration) error {
	tx, err := handle.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("db: begin migration %d: %w", m.version, err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit

	var already int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, m.version,
	).Scan(&already); err != nil {
		return fmt.Errorf("db: check migration %d: %w", m.version, err)
	}
	if already > 0 {
		return nil
	}

	if _, err := tx.ExecContext(ctx, m.sql); err != nil {
		return fmt.Errorf("db: migration %d (%s): %w", m.version, m.name, err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
		m.version, FormatTime(time.Now()),
	); err != nil {
		return fmt.Errorf("db: record migration %d: %w", m.version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("db: commit migration %d: %w", m.version, err)
	}
	return nil
}

func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("db: read migrations: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	out := make([]migration, 0, len(entries))
	prev := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		version, err := migrationVersion(entry.Name())
		if err != nil {
			return nil, err
		}
		if version <= prev {
			return nil, fmt.Errorf("db: migration %q is not after version %d", entry.Name(), prev)
		}
		body, err := migrationFS.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("db: read %q: %w", entry.Name(), err)
		}
		out = append(out, migration{version: version, name: entry.Name(), sql: string(body)})
		prev = version
	}
	return out, nil
}

func migrationVersion(name string) (int, error) {
	prefix, _, ok := strings.Cut(name, "_")
	if !ok {
		return 0, fmt.Errorf("db: migration %q must be named NNNN_description.sql", name)
	}
	version, err := strconv.Atoi(prefix)
	if err != nil || version < 1 {
		return 0, fmt.Errorf("db: migration %q has an invalid version", name)
	}
	return version, nil
}
