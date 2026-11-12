// Package db owns the single SQLite handle shared by the collector, the
// operational store and, later, the admin plane. One handle means one pool,
// one set of pragmas and one close path; a second sql.Open on the same file
// would give two independent write queues and reintroduce SQLITE_BUSY.
//
// Transaction rule for every package that shares this handle: BeginTx is for
// read-then-write sequences and multi-statement writes only. Because the DSN
// pins _txlock=immediate, BEGIN takes the database write lock. Wrapping a pure
// SELECT in a transaction therefore serializes it behind every writer and
// spends busy_timeout for nothing. Reads go through QueryContext directly.
package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

const (
	// Four connections let readers and one writer progress together while
	// busy_timeout serializes the writers. The previous max of one turned the
	// database into a global mutex and made busy_timeout pointless.
	maxOpenConns = 4
	busyTimeout  = 5000
)

// DB is the shared handle. The embedded *sql.DB is the surface components
// consume; Close is shadowed so a checkpoint always precedes the last close.
type DB struct {
	*sql.DB
}

// Open applies the pragmas through the DSN, not through a follow-up Exec:
// database/sql may open new connections at any time, and a PRAGMA executed once
// only binds the connection that ran it.
//
// A memory DSN is pinned to one connection. ":memory:" creates a distinct
// database per connection, so a four-connection pool would hand out four empty
// schemas. file::memory:?cache=shared would let connections share one memory
// file, but it cannot use WAL and buys nothing over a single connection here,
// so it is accepted and still pinned.
func Open(dsn string) (*DB, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("db: empty DSN")
	}

	conns := maxOpenConns
	if isMemoryDSN(dsn) {
		conns = 1
	}

	handle, err := sql.Open("sqlite", withPragmas(dsn))
	if err != nil {
		return nil, fmt.Errorf("db: open: %w", err)
	}
	handle.SetMaxOpenConns(conns)
	handle.SetMaxIdleConns(conns)
	handle.SetConnMaxLifetime(0)

	if err := handle.Ping(); err != nil {
		handle.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}
	return &DB{DB: handle}, nil
}

// isMemoryDSN recognises the three spellings modernc.org/sqlite accepts for an
// in-memory database. Query parameters are stripped from non-file DSNs, so
// ":memory:?cache=shared" is memory too and the prefix check covers it.
func isMemoryDSN(dsn string) bool {
	s := strings.TrimSpace(dsn)
	switch {
	case strings.HasPrefix(s, ":memory:"):
		return true
	case strings.HasPrefix(s, "file::memory:"):
		return true
	case strings.Contains(s, "mode=memory"):
		return true
	default:
		return false
	}
}

// withPragmas appends the per-connection settings to an existing DSN. Values
// are applied by modernc.org/sqlite on every new connection.
//
// _txlock=immediate makes every database/sql transaction take the write lock at
// BEGIN. Without it, two read-then-write transactions deadlock on the upgrade
// and SQLite reports SQLITE_BUSY to one of them; busy_timeout does not help
// there because the busy handler is not invoked for a snapshot upgrade.
//
// This makes a transaction a write lock, so BeginTx is reserved for
// read-then-write or multi-statement writes. A pure read must use QueryContext
// directly or it queues behind every writer and burns busy_timeout.
func withPragmas(dsn string) string {
	sep := "?"
	switch {
	case strings.HasSuffix(dsn, "?"):
		sep = ""
	case strings.Contains(dsn, "?"):
		sep = "&"
	}
	return dsn + sep +
		"_pragma=busy_timeout(" + fmt.Sprint(busyTimeout) + ")" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=foreign_keys(1)" +
		"&_txlock=immediate"
}

// Close checkpoints the WAL before closing, so the -wal file does not survive
// the process and a copy of the database is complete on its own. A checkpoint
// failure does not prevent the close: returning it lets the caller log it, but
// leaving the handle open would be worse.
func (d *DB) Close() error {
	_, checkpointErr := d.DB.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	closeErr := d.DB.Close()
	if checkpointErr != nil {
		checkpointErr = fmt.Errorf("db: checkpoint: %w", checkpointErr)
	}
	return errors.Join(checkpointErr, closeErr)
}
