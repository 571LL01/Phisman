package db_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	sirendb "github.com/siren-core/gorgone/internal/db"
)

func TestOpenAppliesPragmasToEveryConnection(t *testing.T) {
	d, err := sirendb.Open("file:" + filepath.Join(t.TempDir(), "pragmas.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer d.Close()

	// Hold four connections at once so the DSN pragmas, not a one-off Exec, are
	// what is being verified on each of them.
	ctx := context.Background()
	conns := make([]*sql.Conn, 0, 4)
	for i := 0; i < 4; i++ {
		conn, err := d.Conn(ctx)
		if err != nil {
			t.Fatalf("Conn %d: %v", i, err)
		}
		conns = append(conns, conn)

		var mode string
		if err := conn.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&mode); err != nil {
			t.Fatalf("journal_mode: %v", err)
		}
		if mode != "wal" {
			t.Fatalf("connection %d: journal_mode = %q, want wal", i, mode)
		}
		var timeout int
		if err := conn.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&timeout); err != nil {
			t.Fatalf("busy_timeout: %v", err)
		}
		if timeout != 5000 {
			t.Fatalf("connection %d: busy_timeout = %d, want 5000", i, timeout)
		}
		var fk int
		if err := conn.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&fk); err != nil {
			t.Fatalf("foreign_keys: %v", err)
		}
		if fk != 1 {
			t.Fatalf("connection %d: foreign_keys = %d, want 1", i, fk)
		}
	}
	for _, conn := range conns {
		conn.Close()
	}
}

func TestCloseCheckpointsWAL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint.db")
	d, err := sirendb.Open("file:" + path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := d.Exec(`CREATE TABLE t (v TEXT NOT NULL); INSERT INTO t (v) VALUES ('kept')`); err != nil {
		t.Fatalf("write: %v", err)
	}

	wal := path + "-wal"
	info, err := os.Stat(wal)
	if err != nil {
		t.Fatalf("WAL missing before close: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("WAL is empty before close: the test would not prove a checkpoint")
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if info, err := os.Stat(wal); err == nil && info.Size() != 0 {
		t.Fatalf("WAL still holds %d bytes after Close", info.Size())
	}

	reopened, err := sirendb.Open("file:" + path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	var v string
	if err := reopened.QueryRow(`SELECT v FROM t`).Scan(&v); err != nil {
		t.Fatalf("read after checkpoint: %v", err)
	}
	if v != "kept" {
		t.Fatalf("v = %q, want kept", v)
	}
}

func TestMemoryDSNIsPinnedToOneConnection(t *testing.T) {
	dsns := map[string]string{
		"plain":        ":memory:",
		"shared-cache": "file::memory:?cache=shared",
		"named":        "file:siren-test?mode=memory&cache=shared",
	}
	for name, dsn := range dsns {
		t.Run(name, func(t *testing.T) {
			d, err := sirendb.Open(dsn)
			if err != nil {
				t.Fatalf("Open(%q): %v", dsn, err)
			}
			t.Cleanup(func() {
				if err := d.Close(); err != nil {
					t.Errorf("Close(%q): %v", dsn, err)
				}
			})

			if got := d.Stats().MaxOpenConnections; got != 1 {
				t.Fatalf("MaxOpenConnections = %d, want 1 for %q", got, dsn)
			}
			if _, err := d.Exec(`CREATE TABLE m (v TEXT NOT NULL); INSERT INTO m (v) VALUES ('x')`); err != nil {
				t.Fatalf("write: %v", err)
			}
			// A second connection would be a different memory database and
			// would fail here with "no such table: m".
			var n int
			if err := d.QueryRow(`SELECT COUNT(*) FROM m`).Scan(&n); err != nil {
				t.Fatalf("read after write: %v", err)
			}
			if n != 1 {
				t.Fatalf("rows = %d, want 1", n)
			}
		})
	}
}

func TestFileDSNKeepsPoolWidth(t *testing.T) {
	d, err := sirendb.Open("file:" + filepath.Join(t.TempDir(), "pool.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer d.Close()

	if got := d.Stats().MaxOpenConnections; got != 4 {
		t.Fatalf("MaxOpenConnections = %d, want 4 for a file DSN", got)
	}
}

// TestMigrateAdoptsLegacyArtifactsTable starts from the schema the new binary
// knows, then rewinds the artifacts table and bookkeeping to the state a file
// written by the previous binary has: the 0001 tables exist, artifacts exists
// from the old boot-time DDL without contact_id, and only version 1 is
// recorded. Migration 0002 must adopt the existing objects, then 0003 adds the
// attribution column without touching the operational rows.
func TestMigrateAdoptsLegacyArtifactsTable(t *testing.T) {
	ctx := context.Background()
	d, err := sirendb.Open("file:" + filepath.Join(t.TempDir(), "legacy.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer d.Close()

	if err := sirendb.Migrate(ctx, d.DB); err != nil {
		t.Fatalf("seed migrations: %v", err)
	}
	// Rebuild the pre-0003/0004 table shape. Rewinding version 4 also needs
	// the campaigns table rebuilt without export_token_hash.
	if _, err := d.Exec(`
DROP TABLE events;
DROP TABLE artifacts;
CREATE TABLE artifacts (
	id          TEXT PRIMARY KEY,
	campaign_id TEXT NOT NULL,
	template_id TEXT NOT NULL,
	step        TEXT NOT NULL,
	received_at TEXT NOT NULL,
	remote_ip   TEXT NOT NULL,
	body        BLOB NOT NULL
);
DROP TABLE sends;
DROP TABLE contacts;
DROP TABLE campaigns;
CREATE TABLE campaigns (
	id         TEXT PRIMARY KEY,
	name       TEXT NOT NULL,
	state      TEXT NOT NULL CHECK (state IN ('draft', 'armed', 'running', 'closed')),
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE TABLE contacts (
	id          TEXT PRIMARY KEY,
	campaign_id TEXT NOT NULL REFERENCES campaigns (id) ON DELETE CASCADE,
	email       TEXT NOT NULL,
	vars_json   TEXT NOT NULL DEFAULT '{}',
	created_at  TEXT NOT NULL
);
CREATE UNIQUE INDEX contacts_campaign_email_ci
	ON contacts (campaign_id, lower(email));
CREATE TABLE sends (
	id          TEXT PRIMARY KEY,
	contact_id  TEXT NOT NULL REFERENCES contacts (id) ON DELETE CASCADE,
	template_id TEXT NOT NULL,
	step_id     TEXT NOT NULL,
	sent_at     TEXT NOT NULL,
	status      TEXT NOT NULL
);
CREATE INDEX sends_contact_sent
	ON sends (contact_id, sent_at);
DELETE FROM schema_migrations WHERE version >= 2;`); err != nil {
		t.Fatalf("rewind schema: %v", err)
	}

	for _, table := range []string{"campaigns", "contacts", "sends", "artifacts"} {
		if !tableExists(t, d, table) {
			t.Fatalf("%s table missing before adoption", table)
		}
	}

	const ts = "2026-01-01T00:00:00.000000000Z"
	if _, err := d.Exec(`
INSERT INTO campaigns (id, name, state, created_at, updated_at)
	VALUES ('c1', 'legacy', 'draft', ?, ?);
INSERT INTO contacts (id, campaign_id, email, vars_json, created_at)
	VALUES ('k1', 'c1', 'alice@example.com', '{}', ?);
INSERT INTO sends (id, contact_id, template_id, step_id, sent_at, status)
	VALUES ('s1', 'k1', 't1', 's1', ?, 'sent');`, ts, ts, ts, ts); err != nil {
		t.Fatalf("seed rows: %v", err)
	}

	if err := sirendb.Migrate(ctx, d.DB); err != nil {
		t.Fatalf("migrate legacy file: %v", err)
	}
	version, err := sirendb.SchemaVersion(ctx, d.DB)
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if version != 7 {
		t.Fatalf("version = %d, want 7", version)
	}
	for _, table := range []string{"campaigns", "contacts", "sends", "artifacts", "admin_sessions"} {
		if !tableExists(t, d, table) {
			t.Fatalf("%s table missing after adoption", table)
		}
	}
	if !columnExists(t, d, "artifacts", "contact_id") {
		t.Fatal("artifacts.contact_id was not added by migration 0003")
	}
	if !columnExists(t, d, "campaigns", "export_token_hash") {
		t.Fatal("campaigns.export_token_hash was not added by migration 0004")
	}
	for _, table := range []string{"campaigns", "contacts", "sends"} {
		if n := tableCount(t, d, table); n != 1 {
			t.Fatalf("%s rows after adoption = %d, want 1", table, n)
		}
	}
}

func tableExists(t *testing.T, d *sirendb.DB, table string) bool {
	t.Helper()
	var n int
	if err := d.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table,
	).Scan(&n); err != nil {
		t.Fatalf("lookup %s: %v", table, err)
	}
	return n == 1
}

func columnExists(t *testing.T, d *sirendb.DB, table, column string) bool {
	t.Helper()
	rows, err := d.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		t.Fatalf("table_info %s: %v", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("table_info %s: %v", table, err)
		}
		if name == column {
			return true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("table_info %s: %v", table, err)
	}
	return false
}

// TestConcurrentMigrateOnFreshFile exercises two independent handles racing on
// the same empty file, which is what two processes starting together do. Both
// must return successfully: the loser waits on BEGIN IMMEDIATE, then sees the
// winner's version row and skips instead of replaying 0001.
func TestConcurrentMigrateOnFreshFile(t *testing.T) {
	for i := 0; i < 5; i++ {
		t.Run(fmt.Sprintf("run-%d", i), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fresh.db")
			a, err := sirendb.Open("file:" + path)
			if err != nil {
				t.Fatalf("Open a: %v", err)
			}
			defer a.Close()
			b, err := sirendb.Open("file:" + path)
			if err != nil {
				t.Fatalf("Open b: %v", err)
			}
			defer b.Close()

			start := make(chan struct{})
			errs := make(chan error, 2)
			var wg sync.WaitGroup
			for _, h := range []*sirendb.DB{a, b} {
				wg.Add(1)
				go func(h *sirendb.DB) {
					defer wg.Done()
					<-start
					errs <- sirendb.Migrate(context.Background(), h.DB)
				}(h)
			}
			close(start)
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatalf("concurrent migrate: %v", err)
				}
			}

			version, err := sirendb.SchemaVersion(context.Background(), a.DB)
			if err != nil {
				t.Fatalf("version: %v", err)
			}
			if version != 7 {
				t.Fatalf("version = %d, want 7", version)
			}
			for _, table := range []string{"campaigns", "contacts", "sends", "artifacts"} {
				if !tableExists(t, a, table) {
					t.Fatalf("%s table missing after concurrent migrate", table)
				}
			}
		})
	}
}

func tableCount(t *testing.T, d *sirendb.DB, table string) int {
	t.Helper()
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// TestAppliedAtUsesFixedWidth guards the property the fixed layout exists for:
// applied_at must sort chronologically as TEXT, so every value needs the same
// number of digits after the decimal point.
func TestAppliedAtUsesFixedWidth(t *testing.T) {
	d, err := sirendb.Open("file:" + filepath.Join(t.TempDir(), "timestamps.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer d.Close()

	if err := sirendb.Migrate(context.Background(), d.DB); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	rows, err := d.Query(`SELECT version, applied_at FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()

	const width = len("2006-01-02T15:04:05.000000000Z")
	seen := 0
	for rows.Next() {
		var version int
		var applied string
		if err := rows.Scan(&version, &applied); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if len(applied) != width {
			t.Fatalf("version %d: applied_at %q has %d bytes, want %d", version, applied, len(applied), width)
		}
		if _, err := sirendb.ParseTime(applied); err != nil {
			t.Fatalf("version %d: applied_at %q: %v", version, applied, err)
		}
		seen++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if seen != 7 {
		t.Fatalf("migration rows = %d, want 7", seen)
	}
}
