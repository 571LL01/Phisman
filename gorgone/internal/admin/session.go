package admin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	sirendb "github.com/siren-core/gorgone/internal/db"
)

const (
	SessionCookieName = "__Host-siren-session"
	sessionTTL        = 15 * time.Minute
)

// SessionStore is the interface satisfied by both Store (in-memory, testing)
// and SQLiteSessionStore (production).
type SessionStore interface {
	New() (string, error)
	Validate(token string) bool
	Delete(token string)
}

// ── in-memory store (kept for tests and standalone use) ──────────────────────

type session struct {
	expiresAt time.Time
}

// Store is the in-memory session store. Use NewStore() for tests or when
// no database is available. For production use NewSQLiteSessionStore.
type Store struct {
	mu   sync.Mutex
	data map[string]session
	now  func() time.Time
}

func NewStore() *Store {
	return &Store{data: make(map[string]session), now: func() time.Time { return time.Now().UTC() }}
}

func (s *Store) New() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(b[:])
	s.mu.Lock()
	s.data[token] = session{expiresAt: s.now().Add(sessionTTL)}
	s.mu.Unlock()
	return token, nil
}

func (s *Store) Validate(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.data[token]
	if !ok || s.now().After(sess.expiresAt) {
		delete(s.data, token)
		return false
	}
	s.data[token] = session{expiresAt: s.now().Add(sessionTTL)}
	return true
}

func (s *Store) Delete(token string) {
	s.mu.Lock()
	delete(s.data, token)
	s.mu.Unlock()
}

// ── SQLite-backed store (production) ─────────────────────────────────────────

// SQLiteSessionStore persists admin sessions in the shared SQLite database.
// Sessions survive process restarts; expired rows are removed on startup and
// after each logout.
type SQLiteSessionStore struct {
	db  *sql.DB
	now func() time.Time
}

// NewSQLiteSessionStore opens (or migrates) the admin_sessions table on the
// given shared handle. The handle is owned by the caller; Close is not called.
func NewSQLiteSessionStore(handle *sql.DB) (*SQLiteSessionStore, error) {
	if handle == nil {
		return nil, errors.New("admin: SQLiteSessionStore: nil database")
	}
	// Migrate creates the table if it does not exist.
	if err := sirendb.Migrate(context.Background(), handle); err != nil {
		return nil, fmt.Errorf("admin: session store migrate: %w", err)
	}
	st := &SQLiteSessionStore{db: handle, now: func() time.Time { return time.Now().UTC() }}
	// Best-effort startup cleanup of expired rows.
	st.cleanup()
	return st, nil
}

// hashToken stores only the SHA-256 hex of the clear token.
// The clear token exists only in the response cookie; it is never persisted.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (st *SQLiteSessionStore) New() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("admin: session new: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(b[:])
	hash := hashToken(token)
	expiresAt := sirendb.FormatTime(st.now().Add(sessionTTL))

	_, err := st.db.ExecContext(context.Background(),
		`INSERT INTO admin_sessions (token_hash, expires_at) VALUES (?, ?)
		 ON CONFLICT(token_hash) DO UPDATE SET expires_at = excluded.expires_at`,
		hash, expiresAt)
	if err != nil {
		return "", fmt.Errorf("admin: session insert: %w", err)
	}
	return token, nil
}

func (st *SQLiteSessionStore) Validate(token string) bool {
	hash := hashToken(token)
	now := sirendb.FormatTime(st.now())
	newExpiry := sirendb.FormatTime(st.now().Add(sessionTTL))

	// Slide the TTL atomically: update and check rows-affected.
	res, err := st.db.ExecContext(context.Background(),
		`UPDATE admin_sessions SET expires_at = ? WHERE token_hash = ? AND expires_at > ?`,
		newExpiry, hash, now)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n == 1
}

func (st *SQLiteSessionStore) Delete(token string) {
	hash := hashToken(token)
	st.db.ExecContext(context.Background(), //nolint:errcheck // best-effort
		`DELETE FROM admin_sessions WHERE token_hash = ?`, hash)
	st.cleanup()
}

// cleanup removes expired sessions. Best-effort; errors are silently ignored.
func (st *SQLiteSessionStore) cleanup() {
	now := sirendb.FormatTime(st.now())
	st.db.ExecContext(context.Background(), //nolint:errcheck // best-effort
		`DELETE FROM admin_sessions WHERE expires_at <= ?`, now)
}

// ── cookie helpers (shared by both stores) ───────────────────────────────────

// SetCookie writes the session cookie. When secure is false (HTTP dev mode)
// the __Host- prefix is replaced by a plain name because that prefix requires
// Secure=true; without it the browser silently drops the cookie over HTTP.
func SetCookie(w http.ResponseWriter, token string, secure bool) {
	name := SessionCookieName
	if !secure {
		name = "siren-session-dev"
	}
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearCookie removes the session cookie (must match the name used by SetCookie).
func ClearCookie(w http.ResponseWriter, secure bool) {
	name := SessionCookieName
	if !secure {
		name = "siren-session-dev"
	}
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// cookieName returns the session cookie name matching the current secure flag.
func cookieName(secure bool) string {
	if secure {
		return SessionCookieName
	}
	return "siren-session-dev"
}
