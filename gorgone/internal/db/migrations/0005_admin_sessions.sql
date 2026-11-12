-- Admin session store. Tokens are stored hashed (SHA-256 hex).
-- The table is small and grows only during active admin sessions (TTL 15 min).
-- A periodic cleanup removes expired rows; the binary performs it on startup
-- and after each successful logout.
CREATE TABLE IF NOT EXISTS admin_sessions (
    token_hash  TEXT PRIMARY KEY,
    expires_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires
    ON admin_sessions (expires_at);
