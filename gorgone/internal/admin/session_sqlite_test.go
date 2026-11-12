package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sirendb "github.com/siren-core/gorgone/internal/db"
)

func openSessionDB(t *testing.T) *sirendb.DB {
	t.Helper()
	d, err := sirendb.Open("file:" + filepath.Join(t.TempDir(), "sessions.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() {
		if err := d.Close(); err != nil {
			t.Errorf("close db: %v", err)
		}
	})
	return d
}

func TestSQLiteSessionStoreRoundtrip(t *testing.T) {
	d := openSessionDB(t)
	st, err := NewSQLiteSessionStore(d.DB)
	if err != nil {
		t.Fatalf("NewSQLiteSessionStore: %v", err)
	}

	token, err := st.New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !st.Validate(token) {
		t.Fatal("fresh token did not validate")
	}
	if st.Validate("not-a-token") {
		t.Fatal("unknown token validated")
	}

	st.Delete(token)
	if st.Validate(token) {
		t.Fatal("deleted token still validates")
	}
}

func TestSQLiteSessionStoreSurvivesRestart(t *testing.T) {
	d := openSessionDB(t)
	first, err := NewSQLiteSessionStore(d.DB)
	if err != nil {
		t.Fatalf("first store: %v", err)
	}
	token, err := first.New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// A second store on the same file simulates a process restart: the
	// session must still be valid because it lives in SQLite, not in memory.
	second, err := NewSQLiteSessionStore(d.DB)
	if err != nil {
		t.Fatalf("second store: %v", err)
	}
	if !second.Validate(token) {
		t.Fatal("session did not survive a restart")
	}
}

func TestSQLiteSessionStoreExpiry(t *testing.T) {
	d := openSessionDB(t)
	st, err := NewSQLiteSessionStore(d.DB)
	if err != nil {
		t.Fatalf("NewSQLiteSessionStore: %v", err)
	}
	base := time.Now().UTC()
	st.now = func() time.Time { return base }

	token, err := st.New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !st.Validate(token) {
		t.Fatal("fresh token did not validate")
	}

	// Past the 15-minute TTL, the row is rejected. The sliding window means
	// the last Validate pushed the expiry, so jump one TTL past that.
	st.now = func() time.Time { return base.Add(sessionTTL + time.Second) }
	if st.Validate(token) {
		t.Fatal("expired token validated")
	}
}

func TestSQLiteSessionStoreStoresHashOnly(t *testing.T) {
	d := openSessionDB(t)
	st, err := NewSQLiteSessionStore(d.DB)
	if err != nil {
		t.Fatalf("NewSQLiteSessionStore: %v", err)
	}
	token, err := st.New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var stored string
	if err := d.QueryRow(`SELECT token_hash FROM admin_sessions`).Scan(&stored); err != nil {
		t.Fatalf("select token_hash: %v", err)
	}
	sum := sha256.Sum256([]byte(token))
	want := hex.EncodeToString(sum[:])
	if stored != want {
		t.Fatalf("stored hash = %q, want %q", stored, want)
	}
	if stored == token {
		t.Fatal("clear token was persisted")
	}
}

func TestSQLiteSessionStoreCleanupRemovesExpired(t *testing.T) {
	d := openSessionDB(t)
	st, err := NewSQLiteSessionStore(d.DB)
	if err != nil {
		t.Fatalf("NewSQLiteSessionStore: %v", err)
	}
	base := time.Now().UTC()
	st.now = func() time.Time { return base }
	if _, err := st.New(); err != nil {
		t.Fatalf("New: %v", err)
	}
	if n := countAdminSessions(t, d); n != 1 {
		t.Fatalf("rows before cleanup = %d, want 1", n)
	}

	// Delete triggers cleanup; the expired row must be gone.
	st.now = func() time.Time { return base.Add(sessionTTL + time.Second) }
	st.cleanup()
	if n := countAdminSessions(t, d); n != 0 {
		t.Fatalf("rows after cleanup = %d, want 0", n)
	}
}

func TestNewSQLiteSessionStoreRejectsNilDB(t *testing.T) {
	if _, err := NewSQLiteSessionStore(nil); err == nil {
		t.Fatal("nil database accepted")
	}
}

func TestHashTokenIsStableAndOpaque(t *testing.T) {
	a := hashToken("token-value")
	b := hashToken("token-value")
	if a != b {
		t.Fatalf("hashToken not stable: %q != %q", a, b)
	}
	if a == "token-value" || len(a) != 64 || strings.Contains(a, "token") {
		t.Fatalf("hashToken did not hash the token: %q", a)
	}
}

func countAdminSessions(t *testing.T, d *sirendb.DB) int {
	t.Helper()
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM admin_sessions`).Scan(&n); err != nil {
		t.Fatalf("count admin_sessions: %v", err)
	}
	return n
}
