package collect

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	sirendb "github.com/siren-core/gorgone/internal/db"
)

var ErrArtifactNotFound = errors.New("collect: artifact not found")

type Store interface {
	Insert(ctx context.Context, a *Artifact) error
	AttachFingerprint(ctx context.Context, id string, fp *Fingerprint) error
	// Get loads one artifact by ID.
	Get(ctx context.Context, id string) (*Artifact, error)
	// Export streams a campaign's decrypted artifacts in (received_at, id)
	// order, strictly after since when since is non-zero. fn is called once
	// per artifact; returning an error stops the scan and is passed through.
	Export(ctx context.Context, campaignID string, since time.Time, fn func(*Artifact) error) error
	// Rotate re-seals every row with the active key and reports how many were
	// rewritten. Run offline, after the new key is in the set and before the
	// old one is withdrawn.
	Rotate(ctx context.Context) (int, error)
	// KeyUsage counts stored rows per key ID.
	KeyUsage(ctx context.Context) (map[byte]int, error)
	// RetireKey refuses while any row still carries the key ID.
	RetireKey(ctx context.Context, id byte) error
	Close() error
}

type sqliteStore struct {
	db      *sql.DB
	keys    *KeySet
	closeFn func() error
}

// NewSQLite is the standalone constructor: it opens the shared handle, installs
// the collector schema and owns the close. Production wiring uses
// NewSQLiteFrom so one handle is shared with internal/store.
func NewSQLite(dsn string, keys *KeySet) (Store, error) {
	handle, err := sirendb.Open(dsn)
	if err != nil {
		return nil, fmt.Errorf("collect: %w", err)
	}
	st, err := newSQLiteStore(handle.DB, keys)
	if err != nil {
		handle.Close()
		return nil, err
	}
	st.closeFn = handle.Close
	return st, nil
}

// NewSQLiteFrom installs the collector schema on an existing handle. The caller
// retains ownership: Close on the returned Store is a no-op.
func NewSQLiteFrom(db *sql.DB, keys *KeySet) (Store, error) {
	return newSQLiteStore(db, keys)
}

func newSQLiteStore(db *sql.DB, keys *KeySet) (*sqliteStore, error) {
	if db == nil {
		return nil, errors.New("collect: nil database")
	}
	if keys == nil {
		return nil, errors.New("collect: keyset is required")
	}
	// The artifacts table is part of the file's single migration chain, not a
	// boot-time DDL. Migrate is idempotent, so the later store.New call in the
	// same process is a version read and a no-op.
	if err := sirendb.Migrate(context.Background(), db); err != nil {
		return nil, fmt.Errorf("collect: %w", err)
	}
	return &sqliteStore{db: db, keys: keys}, nil
}

func (s *sqliteStore) Insert(ctx context.Context, a *Artifact) error {
	blob, err := s.encode(a)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO artifacts (id, campaign_id, template_id, step, contact_id, received_at, remote_ip, body)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.CampaignID, a.TemplateID, a.Step, a.ContactID,
		sirendb.FormatTime(a.ReceivedAt), a.RemoteIP, blob,
	)
	if err != nil {
		return fmt.Errorf("collect: insert: %w", err)
	}
	return nil
}

func (s *sqliteStore) AttachFingerprint(ctx context.Context, id string, fp *Fingerprint) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("collect: begin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit

	var blob []byte
	err = tx.QueryRowContext(ctx, `SELECT body FROM artifacts WHERE id = ?`, id).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrArtifactNotFound
	}
	if err != nil {
		return fmt.Errorf("collect: load for merge: %w", err)
	}

	a, err := s.decode(id, blob)
	if err != nil {
		return err
	}
	a.Fingerprint = fp

	updated, err := s.encode(a)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE artifacts SET body = ? WHERE id = ?`, updated, id); err != nil {
		return fmt.Errorf("collect: merge: %w", err)
	}
	return tx.Commit()
}

func (s *sqliteStore) Get(ctx context.Context, id string) (*Artifact, error) {
	var blob []byte
	err := s.db.QueryRowContext(ctx, `SELECT body FROM artifacts WHERE id = ?`, id).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrArtifactNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("collect: get: %w", err)
	}
	return s.decode(id, blob)
}

func (s *sqliteStore) Export(ctx context.Context, campaignID string, since time.Time, fn func(*Artifact) error) error {
	query := `SELECT id, body FROM artifacts WHERE campaign_id = ?`
	args := []any{campaignID}
	if !since.IsZero() {
		// Strictly after: since is the last row already delivered.
		query += ` AND received_at > ?`
		args = append(args, sirendb.FormatTime(since))
	}
	query += ` ORDER BY received_at, id`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("collect: export scan: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id string
		var blob []byte
		if err := rows.Scan(&id, &blob); err != nil {
			return fmt.Errorf("collect: export scan: %w", err)
		}
		a, err := s.decode(id, blob)
		if err != nil {
			return err
		}
		if err := fn(a); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("collect: export scan: %w", err)
	}
	return nil
}

func (s *sqliteStore) Rotate(ctx context.Context) (int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, body FROM artifacts`)
	if err != nil {
		return 0, fmt.Errorf("collect: rotate scan: %w", err)
	}

	type pending struct {
		id   string
		blob []byte
	}
	var todo []pending

	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.blob); err != nil {
			rows.Close()
			return 0, fmt.Errorf("collect: rotate scan: %w", err)
		}
		if len(p.blob) > 4 && p.blob[4] != s.keys.Active() {
			a, err := s.decode(p.id, p.blob)
			if err != nil {
				rows.Close()
				return 0, err
			}
			blob, err := s.encode(a)
			if err != nil {
				rows.Close()
				return 0, err
			}
			p.blob = blob
			todo = append(todo, p)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck

	for _, p := range todo {
		if _, err := tx.ExecContext(ctx, `UPDATE artifacts SET body = ? WHERE id = ?`, p.blob, p.id); err != nil {
			return 0, fmt.Errorf("collect: rotate write: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(todo), nil
}

func (s *sqliteStore) Close() error {
	if s.closeFn != nil {
		return s.closeFn()
	}
	return nil
}

// KeyUsage walks the sealed bodies. The key ID is the fifth byte of the blob,
// which SQLite cannot index without a generated column; a retire is an offline
// operation, so a full scan is the right trade.
func (s *sqliteStore) KeyUsage(ctx context.Context) (map[byte]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT body FROM artifacts`)
	if err != nil {
		return nil, fmt.Errorf("collect: key usage: %w", err)
	}
	defer rows.Close()

	usage := make(map[byte]int, len(s.keys.IDs()))
	for rows.Next() {
		var blob []byte
		if err := rows.Scan(&blob); err != nil {
			return nil, fmt.Errorf("collect: key usage: %w", err)
		}
		if len(blob) > 4 && string(blob[:4]) == blobMagic {
			usage[blob[4]]++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("collect: key usage: %w", err)
	}
	return usage, nil
}

func (s *sqliteStore) RetireKey(ctx context.Context, id byte) error {
	usage, err := s.KeyUsage(ctx)
	if err != nil {
		return err
	}
	if n := usage[id]; n > 0 {
		return fmt.Errorf("%w: %d rows still carry key %d", ErrKeyInUse, n, id)
	}
	return nil
}

func (s *sqliteStore) encode(a *Artifact) ([]byte, error) {
	plain, err := json.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf("collect: marshal: %w", err)
	}
	// AAD is the row id: a sealed body cannot be lifted onto another artifact.
	return s.keys.Seal([]byte(a.ID), plain)
}

func (s *sqliteStore) decode(id string, blob []byte) (*Artifact, error) {
	plain, err := s.keys.Open([]byte(id), blob)
	if err != nil {
		return nil, fmt.Errorf("collect: artifact %s: %w", id, err)
	}
	var a Artifact
	if err := json.Unmarshal(plain, &a); err != nil {
		return nil, fmt.Errorf("collect: decode: %w", err)
	}
	return &a, nil
}
