package db

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// TestApplyMigrationSkipsVersionRecordedAfterRead models the window between the
// caller's version read and BEGIN: the version appears in schema_migrations
// before the transaction starts. The in-transaction re-read must skip the file,
// otherwise a second process replays non-idempotent DDL.
func TestApplyMigrationSkipsVersionRecordedAfterRead(t *testing.T) {
	d, err := Open("file:" + filepath.Join(t.TempDir(), "after-read.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer d.Close()

	if _, err := d.Exec(schemaMigrationsDDL); err != nil {
		t.Fatalf("schema_migrations: %v", err)
	}
	if _, err := d.Exec(
		`INSERT INTO schema_migrations (version, applied_at) VALUES (1, ?)`,
		FormatTime(time.Now()),
	); err != nil {
		t.Fatalf("record version: %v", err)
	}

	// Invalid SQL: if the re-read does not skip, this runs and the test fails.
	m := migration{version: 1, name: "0001_race.sql", sql: `THIS IS NOT SQL`}
	if err := applyMigration(context.Background(), d.DB, m); err != nil {
		t.Fatalf("applyMigration replayed an already-applied version: %v", err)
	}

	var rows int
	if err := d.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 1`).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 1 {
		t.Fatalf("version rows = %d, want 1", rows)
	}
}
