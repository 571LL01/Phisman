package admin

import (
	"encoding/base32"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/siren-core/gorgone/internal/collect"
)

// Config holds everything the admin handlers need.
type Config struct {
	// PasswordHash is a PBKDF2-SHA256 verifier produced by HashPassword.
	// Format: pbkdf2$<iterations>$<salt-hex>$<hash-hex>
	PasswordHash string
	// TOTPSecret is the base32-encoded TOTP secret for the admin operator.
	// It must be validated at construction time with ValidateTOTPSecret.
	TOTPSecret string
	// CSRFSecret is a 32-byte random key used to sign CSRF tokens.
	// Generate: openssl rand 32 > csrf.key (read raw bytes, not hex).
	// Must be non-empty in production. CSRF protection is disabled only
	// when CSRFSecret is empty AND the environment variable SIREN_DEV=1
	// is set. A free boolean field is intentionally not provided; opt-out
	// must come from the environment so it cannot be set by accident in
	// application code.
	CSRFSecret []byte
	// Allowlist is the set of CIDRs allowed to reach any admin route.
	// Empty means allow all (useful for local dev; not recommended for prod).
	Allowlist []*net.IPNet
	// TrustedProxies controls which peers may set forwarding headers.
	TrustedProxies []*net.IPNet
	// Sessions is the session store. Use NewSQLiteSessionStore for production
	// (survives restarts) or NewStore for tests.
	Sessions SessionStore
	// RateLimit is the maximum number of failed login attempts before an IP
	// (and globally) is locked out. Zero disables rate limiting (dev only).
	RateLimit int
	// SecureCookies controls the Secure flag on session and CSRF cookies.
	// Set to false only when running over plain HTTP (local dev).
	// When false, the __Host- cookie prefix is also dropped because it
	// requires Secure=true; the browser would silently reject it over HTTP.
	SecureCookies bool
	// Logger receives structured diagnostics.
	Logger *slog.Logger
}

// DevMode reports whether SIREN_DEV=1 is set. It is the only accepted opt-out
// for the two development shortcuts: no CSRF secret, and an empty IP allowlist.
// It is exported so the binary can enforce boot-time invariants (for example,
// refusing to combine SIREN_DEV with SIREN_KEY_FILE).
func DevMode() bool {
	return os.Getenv("SIREN_DEV") == "1"
}

// Validate checks the Config for missing required fields. It must be called
// before constructing handlers and treated as a fatal boot failure on error.
//
//   - PasswordHash must be a parseable pbkdf2 verifier.
//   - TOTPSecret must be non-empty and valid base32.
//   - CSRFSecret must be non-empty, OR SIREN_DEV=1 must be set in the
//     environment. A boolean flag is not provided; opt-out is environment-only
//     so it cannot be set by accident in application code.
//   - Allowlist must be non-empty, OR SIREN_DEV=1 must be set. In production an
//     empty allowlist would expose the admin surface to every IP; in dev it
//     means "allow all" and is documented as such.
//   - Sessions and Logger must be non-nil.
func (c *Config) Validate() error {
	if err := csrfConfigErr(*c); err != nil {
		return err
	}
	if err := ValidatePasswordHash(c.PasswordHash); err != nil {
		return err
	}
	if err := ValidateTOTPSecret(c.TOTPSecret); err != nil {
		return err
	}
	if len(c.Allowlist) == 0 && !DevMode() {
		return fmt.Errorf("admin: Allowlist is empty; set at least one CIDR. " +
			"An empty allowlist is allowed only with SIREN_DEV=1, where it means \"allow all\"")
	}
	if c.Sessions == nil {
		return fmt.Errorf("admin: Sessions store is required")
	}
	if c.Logger == nil {
		return fmt.Errorf("admin: Logger is required")
	}
	return nil
}

// csrfConfigErr is the single source of truth for the CSRF invariant, shared
// by Validate and the request-time fail-closed guards. A handler built from a
// Config that skipped Validate must still refuse to serve without CSRF rather
// than silently disabling protection.
func csrfConfigErr(c Config) error {
	if len(c.CSRFSecret) == 0 && !DevMode() {
		return fmt.Errorf("admin: CSRFSecret is empty; " +
			"set a 32-byte random CSRFSecret in production, " +
			"or set SIREN_DEV=1 to disable CSRF protection for local development")
	}
	return nil
}

// ValidateTOTPSecret decodes the base32 TOTP secret and returns an error if it
// is malformed or empty. Call this at boot: a misconfigured secret makes every
// login fail silently with 401 and there is no other indication.
func ValidateTOTPSecret(secretB32 string) error {
	if strings.TrimSpace(secretB32) == "" {
		return fmt.Errorf("admin: TOTP secret is empty")
	}
	_, err := base32.StdEncoding.DecodeString(
		strings.ToUpper(strings.TrimRight(secretB32, "=")))
	if err != nil {
		return fmt.Errorf("admin: TOTP secret is not valid base32: %w", err)
	}
	return nil
}

// replayEntry records which (user, step) pairs have already been accepted in
// the current 30-second window. The key is a string "user:step" so two
// different users each get their own replay counter, and an operator who is
// testing from two tabs does not lock out the other.
//
// Entries older than the ±1 window (3 steps = 90 s) are pruned on every write
// so the map does not grow without bound.
type replayStore struct {
	mu   sync.Mutex
	seen map[string]int64 // key → step accepted; value is the step itself for pruning
	now  func() time.Time
}

func newReplayStore(now func() time.Time) *replayStore {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &replayStore{seen: make(map[string]int64), now: now}
}

func (rs *replayStore) check(user string, step int64) bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	key := fmt.Sprintf("%s:%d", user, step)
	if _, seen := rs.seen[key]; seen {
		return false
	}
	rs.seen[key] = step

	// Prune entries outside the ±1 window.  current step ±2 covers the full
	// ±1 window plus one slot of safety margin.
	current := totpStep(rs.now())
	for k, s := range rs.seen {
		if s < current-2 || s > current+2 {
			delete(rs.seen, k)
		}
	}
	return true
}

// rateLimiter counts failed login attempts per IP. It issues a lockout after
// maxFailures consecutive failures and clears on success.
type rateLimiter struct {
	mu          sync.Mutex
	failures    map[string]int
	maxFailures int
}

func newRateLimiter(max int) *rateLimiter {
	return &rateLimiter{failures: make(map[string]int), maxFailures: max}
}

func (rl *rateLimiter) allow(ip string) bool {
	if rl.maxFailures <= 0 {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.failures[ip] < rl.maxFailures
}

func (rl *rateLimiter) failure(ip string) {
	rl.mu.Lock()
	rl.failures[ip]++
	rl.mu.Unlock()
}

func (rl *rateLimiter) success(ip string) {
	rl.mu.Lock()
	delete(rl.failures, ip)
	rl.mu.Unlock()
}

// handler bundles per-Handler state so the package-level globals of the
// previous version are gone. Create one per LoginHandler call.
type handler struct {
	cfg     Config
	replay  *replayStore
	limiter *rateLimiter
	now     func() time.Time
}

func newHandler(cfg Config) *handler {
	// Use UTC wall time for both the replay store and TOTP validation.
	// The session store's internal clock is not accessible through the
	// SessionStore interface; both stores use time.Now() internally.
	nowFn := func() time.Time { return time.Now().UTC() }
	if concrete, ok := cfg.Sessions.(*Store); ok {
		nowFn = concrete.now
	}
	return &handler{
		cfg:     cfg,
		replay:  newReplayStore(nowFn),
		limiter: newRateLimiter(cfg.RateLimit),
		now:     nowFn,
	}
}

func clientIP(r *http.Request, cfg Config) string {
	return collect.ClientIP(r, cfg.TrustedProxies)
}

func inAllowlist(ip string, allowlist []*net.IPNet) bool {
	if len(allowlist) == 0 {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range allowlist {
		if n != nil && n.Contains(parsed) {
			return true
		}
	}
	return false
}

// LoginPageHandler serves GET /admin/login with a fresh CSRF token embedded
// in a hidden form field and stored in a cookie.
func LoginPageHandler(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ip := clientIP(r, cfg)
		if !inAllowlist(ip, cfg.Allowlist) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		// Fail closed: never render a login form that would POST without CSRF
		// protection because the Config skipped Validate().
		if err := csrfConfigErr(cfg); err != nil {
			cfg.Logger.Error("admin login page: refusing to serve without CSRF protection", "err", err)
			http.Error(w, "internal configuration error", http.StatusInternalServerError)
			return
		}
		cookieVal, fieldVal, err := newCSRFToken(cfg.CSRFSecret)
		if err != nil {
			cfg.Logger.Error("admin login page: csrf token generation failed", "err", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		setCSRFCookie(w, cookieVal, cfg.SecureCookies)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, loginPageHTML(fieldVal))
	}
}

// LoginHandler returns an http.HandlerFunc for POST /admin/login.
//
// Order of checks (each logs and returns immediately on failure):
//  1. IP allowlist → 403 (before any password work)
//  2. CSRF token → 403 (double-submit cookie, constant-time)
//  3. Rate limit → 429
//  4. PBKDF2 password → 401
//  5. TOTP ±1 window → 401
//  6. Replay check per (user, step) → 401
//
// All auth failures return the same body ("unauthorized") to avoid leaking
// which field was wrong.
func LoginHandler(cfg Config) http.HandlerFunc {
	h := newHandler(cfg)
	return h.login
}

func (h *handler) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := clientIP(r, h.cfg)
	if !inAllowlist(ip, h.cfg.Allowlist) {
		h.cfg.Logger.Warn("admin login: IP not in allowlist", "ip", ip)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Fail closed: a Config that skipped Validate() must never serve with CSRF
	// silently disabled. The only accepted opt-out is SIREN_DEV=1.
	if err := csrfConfigErr(h.cfg); err != nil {
		h.cfg.Logger.Error("admin login: refusing to serve without CSRF protection", "err", err)
		http.Error(w, "internal configuration error", http.StatusInternalServerError)
		return
	}

	// CSRF: validate the double-submit cookie+field pair. When CSRFSecret is
	// empty, csrfConfigErr above has already proven SIREN_DEV=1 is set; the
	// protection is then explicitly waived by the operator.
	if len(h.cfg.CSRFSecret) > 0 {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if !checkCSRF(r, h.cfg.CSRFSecret, h.cfg.SecureCookies) {
			h.cfg.Logger.Warn("admin login: CSRF token mismatch", "ip", ip)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}

	if !h.limiter.allow(ip) {
		h.cfg.Logger.Warn("admin login: rate limit exceeded", "ip", ip)
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	password := r.FormValue("password")
	code := r.FormValue("totp_code")

	if !CheckPassword(password, h.cfg.PasswordHash) {
		h.cfg.Logger.Warn("admin login: bad credentials", "ip", ip)
		h.limiter.failure(ip)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	now := h.now()
	// user is a fixed constant in a single-operator deployment; if the system
	// later supports multiple operators this becomes a form field.
	const user = "admin"
	step, ok := ValidateTOTP(h.cfg.TOTPSecret, code, now)
	if !ok {
		h.cfg.Logger.Warn("admin login: bad TOTP", "ip", ip)
		h.limiter.failure(ip)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if !h.replay.check(user, step) {
		h.cfg.Logger.Warn("admin login: TOTP replay detected", "ip", ip, "step", step)
		h.limiter.failure(ip)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	token, err := h.cfg.Sessions.New()
	if err != nil {
		h.cfg.Logger.Error("admin login: session creation failed", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	h.limiter.success(ip)
	SetCookie(w, token, h.cfg.SecureCookies)
	h.cfg.Logger.Info("admin login: success", "ip", ip)
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}

// LogoutHandler revokes the session and clears both cookies. It accepts POST
// only: a logout triggerable by a cross-origin GET or form would be a denial of
// service, and the router's CSRF guard rejects any POST without a valid token.
func LogoutHandler(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if ck, err := r.Cookie(cookieName(cfg.SecureCookies)); err == nil {
			cfg.Sessions.Delete(ck.Value)
		}
		ClearCookie(w, cfg.SecureCookies)
		clearCSRFCookie(w, cfg.SecureCookies)
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
	}
}

// RequireSession is middleware that validates the session cookie. On failure it
// redirects to /admin/login (302) or returns 401 for JSON clients.
func RequireSession(cfg Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ck, err := r.Cookie(cookieName(cfg.SecureCookies))
			if err != nil || !cfg.Sessions.Validate(ck.Value) {
				if strings.Contains(r.Header.Get("Accept"), "application/json") {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
				http.Redirect(w, r, "/admin/login", http.StatusFound)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// IPAllowlistMiddleware blocks requests whose resolved client IP is not in
// cfg.Allowlist. An empty allowlist permits all traffic.
func IPAllowlistMiddleware(cfg Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r, cfg)
			if !inAllowlist(ip, cfg.Allowlist) {
				cfg.Logger.Warn("admin: IP not in allowlist", "ip", ip, "path", r.URL.Path)
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
