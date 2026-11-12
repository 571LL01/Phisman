package admin

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// guardedConfig builds a production-shaped Config: every required field is
// present, CSRF is enforced, and the allowlist is loopback by default.
func guardedConfig(t *testing.T, cidrs ...string) Config {
	t.Helper()
	cfg := Config{
		PasswordHash:  mustHashPassword("correct-horse"),
		TOTPSecret:    testSecret,
		CSRFSecret:    bytes.Repeat([]byte{0x42}, 32),
		Sessions:      NewStore(),
		Logger:        quietLogger(),
		SecureCookies: true,
	}
	if len(cidrs) == 0 {
		cidrs = []string{"127.0.0.1/32"}
	}
	for _, c := range cidrs {
		cfg.Allowlist = append(cfg.Allowlist, mustParseCIDR(c))
	}
	return cfg
}

func newAdminRequest(method, target, remote string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	if remote != "" {
		req.RemoteAddr = remote
	}
	return req
}

func TestRouterRequiresSessionForDashboard(t *testing.T) {
	cfg := guardedConfig(t)
	h := Router(cfg, nil)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, newAdminRequest(http.MethodGet, "/admin/", "127.0.0.1:1234"))
	if rr.Code != http.StatusFound {
		t.Fatalf("GET /admin/ without session: status = %d, want 302", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/admin/login" {
		t.Fatalf("Location = %q, want /admin/login", loc)
	}
}

func TestRouterLogoutWithoutCSRFIs403(t *testing.T) {
	cfg := guardedConfig(t)
	token, err := cfg.Sessions.New()
	if err != nil {
		t.Fatal(err)
	}

	req := newAdminRequest(http.MethodPost, "/admin/logout", "127.0.0.1:1234")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
	rr := httptest.NewRecorder()
	Router(cfg, nil).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("logout without CSRF: status = %d, want 403", rr.Code)
	}
	if !cfg.Sessions.Validate(token) {
		t.Fatal("session was revoked by a CSRF-less logout")
	}
}

func TestRouterLogoutWithCSRFRevokes(t *testing.T) {
	cfg := guardedConfig(t)
	token, err := cfg.Sessions.New()
	if err != nil {
		t.Fatal(err)
	}

	// Load the dashboard to obtain a CSRF cookie + form field.
	get := newAdminRequest(http.MethodGet, "/admin/", "127.0.0.1:1234")
	get.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
	getRR := httptest.NewRecorder()
	Router(cfg, nil).ServeHTTP(getRR, get)
	if getRR.Code != http.StatusOK {
		t.Fatalf("dashboard: status = %d, want 200", getRR.Code)
	}
	csrfCookie := cookieNamed(getRR, csrfCookieName)
	if csrfCookie == nil {
		t.Fatal("dashboard did not set a CSRF cookie")
	}
	field := extractCSRFField(getRR.Body.String())
	if field == "" {
		t.Fatal("dashboard did not embed a CSRF field")
	}

	form := url.Values{csrfFieldName: {field}}
	post := httptest.NewRequest(http.MethodPost, "/admin/logout", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.RemoteAddr = "127.0.0.1:1234"
	post.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
	post.AddCookie(csrfCookie)
	rr := httptest.NewRecorder()
	Router(cfg, nil).ServeHTTP(rr, post)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("logout with CSRF: status = %d, want 303", rr.Code)
	}
	if cfg.Sessions.Validate(token) {
		t.Fatal("session still valid after logout")
	}
}

func TestRouterEmptyCSRFSecretOutsideDevReturns500(t *testing.T) {
	t.Setenv("SIREN_DEV", "")
	cfg := guardedConfig(t)
	cfg.CSRFSecret = nil

	// POST /admin/login must be refused before any password work.
	rr := httptest.NewRecorder()
	Router(cfg, nil).ServeHTTP(rr, newAdminRequest(http.MethodPost, "/admin/login", "127.0.0.1:1234"))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("POST login without CSRF config: status = %d, want 500", rr.Code)
	}
	if cookieSet(rr) {
		t.Fatal("session cookie set despite invalid CSRF config")
	}

	// GET /admin/login must not render a form that cannot be protected.
	rr = httptest.NewRecorder()
	Router(cfg, nil).ServeHTTP(rr, newAdminRequest(http.MethodGet, "/admin/login", "127.0.0.1:1234"))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("GET login without CSRF config: status = %d, want 500", rr.Code)
	}
	if len(rr.Header().Values("Set-Cookie")) != 0 {
		t.Fatal("login page emitted cookies despite invalid CSRF config")
	}
}

func TestRouterAllowlistBeforePassword(t *testing.T) {
	cfg := guardedConfig(t, "10.0.0.0/8")
	now := time.Now().UTC()

	// Valid credentials + valid CSRF pair, but from an IP outside the allowlist.
	// The response must be 403, proving the allowlist runs before the password.
	cookieVal, fieldVal, err := newCSRFToken(cfg.CSRFSecret)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{
		"password":    {"correct-horse"},
		"totp_code":   {totpAt(now)},
		csrfFieldName: {fieldVal},
	}
	post := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.RemoteAddr = "203.0.113.9:1234"
	post.AddCookie(&http.Cookie{Name: csrfCookieName, Value: cookieVal})
	rr := httptest.NewRecorder()
	Router(cfg, nil).ServeHTTP(rr, post)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("outside allowlist: status = %d, want 403", rr.Code)
	}
	if cookieSet(rr) {
		t.Fatal("session cookie set for an IP outside the allowlist")
	}

	// Same request from inside the allowlist succeeds, proving the credentials
	// were valid and the allowlist was the deciding check.
	cookieVal, fieldVal, err = newCSRFToken(cfg.CSRFSecret)
	if err != nil {
		t.Fatal(err)
	}
	form = url.Values{
		"password":    {"correct-horse"},
		"totp_code":   {totpAt(now)},
		csrfFieldName: {fieldVal},
	}
	post = httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.RemoteAddr = "10.0.0.1:1234"
	post.AddCookie(&http.Cookie{Name: csrfCookieName, Value: cookieVal})
	rr = httptest.NewRecorder()
	Router(cfg, nil).ServeHTTP(rr, post)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("inside allowlist: status = %d, want 303", rr.Code)
	}
}

func TestRouterDashboardRendersStyledPage(t *testing.T) {
	cfg := guardedConfig(t)
	token, err := cfg.Sessions.New()
	if err != nil {
		t.Fatal(err)
	}

	list := func(context.Context) ([]Campaign, error) {
		return []Campaign{
			{ID: "acme", Name: "Campagne A", State: "running", Created: "2026-11-01 10:00"},
			{ID: "beta", Name: "<script>alert(1)</script>", State: "draft", Created: ""},
		}, nil
	}

	req := newAdminRequest(http.MethodGet, "/admin/", "127.0.0.1:1234")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
	rr := httptest.NewRecorder()
	Router(cfg, list).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("dashboard: status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", ct)
	}
	if csp := rr.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self'") {
		t.Fatalf("CSP = %q, missing form-action", csp)
	}
	body := rr.Body.String()
	for _, want := range []string{
		"<table>", `action="/admin/logout"`, `name="` + csrfFieldName + `"`,
		"Campagne A", "En cours", "Brouillon", "2 campagne(s)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard body missing %q", want)
		}
	}
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Error("campaign name was not HTML-escaped")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("escaped campaign name not found; escaping may have dropped it")
	}
}

func TestRouterDashboardRendersWhenListerFails(t *testing.T) {
	cfg := guardedConfig(t)
	token, err := cfg.Sessions.New()
	if err != nil {
		t.Fatal(err)
	}
	list := func(context.Context) ([]Campaign, error) {
		return nil, errors.New("database offline")
	}

	req := newAdminRequest(http.MethodGet, "/admin/", "127.0.0.1:1234")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
	rr := httptest.NewRecorder()
	Router(cfg, list).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 even when the lister fails", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Liste des campagnes indisponible") {
		t.Error("missing lister failure notice")
	}
	if !strings.Contains(body, `action="/admin/logout"`) {
		t.Error("logout form must remain reachable during a database outage")
	}
}

func TestRouterUnknownPathAndMethods(t *testing.T) {
	cfg := guardedConfig(t)
	h := Router(cfg, nil)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, newAdminRequest(http.MethodGet, "/admin/unknown", "127.0.0.1:1234"))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown admin path: status = %d, want 404", rr.Code)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, newAdminRequest(http.MethodGet, "/admin/logout", "127.0.0.1:1234"))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET logout: status = %d, want 405", rr.Code)
	}
	if allow := rr.Header().Get("Allow"); allow != "POST" {
		t.Fatalf("Allow = %q, want POST", allow)
	}
}

func TestConfigValidateRejectsEmptyAllowlistOutsideDev(t *testing.T) {
	t.Setenv("SIREN_DEV", "")
	cfg := guardedConfig(t)
	cfg.Allowlist = nil
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "Allowlist") {
		t.Fatalf("Validate = %v, want an allowlist error", err)
	}
}

func TestConfigValidateAcceptsEmptyAllowlistInDev(t *testing.T) {
	t.Setenv("SIREN_DEV", "1")
	cfg := guardedConfig(t)
	cfg.Allowlist = nil
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate in dev with empty allowlist: %v", err)
	}
}

func TestValidatePasswordHash(t *testing.T) {
	good := mustHashPassword("pw")
	if err := ValidatePasswordHash(good); err != nil {
		t.Fatalf("valid hash rejected: %v", err)
	}
	for _, bad := range []string{
		"",
		"plain",
		"pbkdf2$600000$abcd$abcd",
		"sha256$600000$" + strings.Repeat("aa", 16) + "$" + strings.Repeat("bb", 32),
		"pbkdf2$1$" + strings.Repeat("aa", 16) + "$" + strings.Repeat("bb", 32),
		"pbkdf2$600000$zz$" + strings.Repeat("bb", 32),
		"pbkdf2$600000$" + strings.Repeat("aa", 16) + "$" + strings.Repeat("bb", 16),
	} {
		if err := ValidatePasswordHash(bad); err == nil {
			t.Errorf("ValidatePasswordHash(%q) accepted", bad)
		}
	}
}

func cookieNamed(rr *httptest.ResponseRecorder, name string) *http.Cookie {
	resp := &http.Response{Header: rr.Header()}
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}
