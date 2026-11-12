package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/siren-core/gorgone/internal/admin"
	"github.com/siren-core/gorgone/internal/collect"
	sirendb "github.com/siren-core/gorgone/internal/db"
	"github.com/siren-core/gorgone/internal/store"
)

// testTOTPSecret is the RFC 6238 test secret encoded as base32. It is public
// test material, not a deployment secret.
const testTOTPSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func writeSecretFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func writeConfigFile(t *testing.T, cfg *fileConfig) string {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func testAdminConfig(t *testing.T) *admin.Config {
	t.Helper()
	hash, err := admin.HashPassword("correct-horse-battery")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	return &admin.Config{
		PasswordHash: hash,
		TOTPSecret:   testTOTPSecret,
		CSRFSecret:   bytes.Repeat([]byte{0x5a}, 32),
		Allowlist:    []*net.IPNet{mustCIDR(t, "127.0.0.1/32")},
		Sessions:     admin.NewStore(),
		RateLimit:    5,
		Logger:       testLogger(),
	}
}

func mustCIDR(t *testing.T, raw string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(raw)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", raw, err)
	}
	return n
}

func TestAdminRoutesAreMountedBehindGuard(t *testing.T) {
	h, err := newHandlerWithAdmin(validConfig(), &captureStore{}, store.NewFake(), testLogger(), testAdminConfig(t), nil)
	if err != nil {
		t.Fatalf("newHandlerWithAdmin: %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("GET /admin/ without session: status = %d, want 302", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/admin/login" {
		t.Fatalf("Location = %q, want /admin/login", loc)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/admin/logout", strings.NewReader(""))
	req.RemoteAddr = "127.0.0.1:1234"
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("POST /admin/logout without CSRF: status = %d, want 403", rr.Code)
	}
}

func TestAdminRouteOutsideAllowlistIs403(t *testing.T) {
	ac := testAdminConfig(t)
	ac.Allowlist = []*net.IPNet{mustCIDR(t, "10.0.0.0/8")}

	h, err := newHandlerWithAdmin(validConfig(), &captureStore{}, store.NewFake(), testLogger(), ac, nil)
	if err != nil {
		t.Fatalf("newHandlerWithAdmin: %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader("password=x&totp_code=000000"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.9:1234"
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("outside allowlist: status = %d, want 403", rr.Code)
	}
	if cookies := rr.Header().Values("Set-Cookie"); len(cookies) != 0 {
		t.Fatalf("outside allowlist emitted cookies: %v", cookies)
	}
}

func TestMountedAdminWithoutCSRFReturns500(t *testing.T) {
	t.Setenv("SIREN_DEV", "")
	ac := testAdminConfig(t)
	ac.CSRFSecret = nil

	h, err := newHandlerWithAdmin(validConfig(), &captureStore{}, store.NewFake(), testLogger(), ac, nil)
	if err != nil {
		t.Fatalf("newHandlerWithAdmin must not validate at construction: %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/login", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("POST /admin/login without CSRF config: status = %d, want 500", rr.Code)
	}
}

func TestLoadAdminSecretsReadsAllFiles(t *testing.T) {
	dir := t.TempDir()
	hash, err := admin.HashPassword("correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	a := &adminFileConfig{
		PasswordHashFile: writeSecretFile(t, dir, "password.hash", []byte(hash+"\n")),
		TOTPSecretFile:   writeSecretFile(t, dir, "totp.secret", []byte(testTOTPSecret+"\n")),
		CSRFSecretFile:   writeSecretFile(t, dir, "csrf.key", bytes.Repeat([]byte{0x11}, 32)),
		Allowlist:        []string{"127.0.0.1/32"},
	}
	if err := a.validate(); err != nil {
		t.Fatalf("admin config: %v", err)
	}

	d, err := sirendb.Open("file:" + filepath.Join(dir, "admin.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer d.Close()

	cfg := &fileConfig{Admin: a}
	ac, err := loadAdminSecrets(cfg, d.DB, testLogger())
	if err != nil {
		t.Fatalf("loadAdminSecrets: %v", err)
	}
	if ac.PasswordHash != hash {
		t.Fatalf("password hash not trimmed: %q", ac.PasswordHash)
	}
	if ac.TOTPSecret != testTOTPSecret {
		t.Fatalf("TOTP secret = %q", ac.TOTPSecret)
	}
	if len(ac.CSRFSecret) != 32 {
		t.Fatalf("CSRF secret length = %d, want 32", len(ac.CSRFSecret))
	}
	if ac.RateLimit != defaultAdminRateLimit {
		t.Fatalf("default RateLimit = %d, want %d", ac.RateLimit, defaultAdminRateLimit)
	}
	if ac.Sessions == nil {
		t.Fatal("Sessions is nil")
	}
	if len(ac.Allowlist) != 1 {
		t.Fatalf("Allowlist = %v", ac.Allowlist)
	}
}

func TestLoadAdminSecretsRejectsShortOrPaddedCSRF(t *testing.T) {
	dir := t.TempDir()
	hash, err := admin.HashPassword("correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	base := func() *adminFileConfig {
		return &adminFileConfig{
			PasswordHashFile: writeSecretFile(t, dir, "password.hash", []byte(hash)),
			TOTPSecretFile:   writeSecretFile(t, dir, "totp.secret", []byte(testTOTPSecret)),
			Allowlist:        []string{"127.0.0.1/32"},
		}
	}

	d, err := sirendb.Open("file:" + filepath.Join(dir, "admin.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer d.Close()

	for name, payload := range map[string][]byte{
		"short":  bytes.Repeat([]byte{0x11}, 31),
		"padded": append(bytes.Repeat([]byte{0x11}, 32), '\n'),
	} {
		t.Run(name, func(t *testing.T) {
			a := base()
			a.CSRFSecretFile = writeSecretFile(t, dir, "csrf-"+name, payload)
			if err := a.validate(); err != nil {
				t.Fatalf("admin config: %v", err)
			}
			if _, err := loadAdminSecrets(&fileConfig{Admin: a}, d.DB, testLogger()); err == nil {
				t.Fatal("invalid CSRF secret accepted")
			}
		})
	}
}

func TestLoadConfigRejectsInlineAdminSecret(t *testing.T) {
	cfg := validConfig()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["admin"] = map[string]any{
		"password_hash": "pbkdf2$600000$aa$bb",
	}
	path := filepath.Join(t.TempDir(), "config.json")
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = loadConfig(path)
	if err == nil {
		t.Fatal("inline password_hash accepted by strict decoding")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("error = %v, want unknown field", err)
	}
}

func TestRunRefusesDevModeWithKeyFile(t *testing.T) {
	t.Setenv("SIREN_DEV", "1")
	t.Setenv("SIREN_KEY_FILE", filepath.Join(t.TempDir(), "siren-key"))

	cfg := validConfig()
	cfg.DataDir = t.TempDir()
	err := run(testLogger(), options{configPath: writeConfigFile(t, cfg)})
	if err == nil {
		t.Fatal("run accepted SIREN_DEV=1 with SIREN_KEY_FILE")
	}
	if !strings.Contains(err.Error(), "SIREN_DEV") {
		t.Fatalf("error = %v, want the SIREN_DEV/SIREN_KEY_FILE refusal", err)
	}
}

func TestRunRefusesEmptyCSRFAtStartup(t *testing.T) {
	t.Setenv("SIREN_DEV", "")
	t.Setenv("SIREN_DEV_KEYS", "")
	t.Setenv("SIREN_ARTIFACT_KEYS", "")

	keyDir := t.TempDir()
	keyPath := filepath.Join(keyDir, "siren-key")
	ks, err := collect.NewKeySet(1, map[byte][]byte{1: bytes.Repeat([]byte{0x2b}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	if err := collect.SaveKeyFile(keyPath, ks); err != nil {
		t.Fatalf("SaveKeyFile: %v", err)
	}
	t.Setenv("SIREN_KEY_FILE", keyPath)

	secretDir := t.TempDir()
	hash, err := admin.HashPassword("correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	cfg := validConfig()
	cfg.DataDir = t.TempDir()
	cfg.Admin = &adminFileConfig{
		PasswordHashFile: writeSecretFile(t, secretDir, "password.hash", []byte(hash)),
		TOTPSecretFile:   writeSecretFile(t, secretDir, "totp.secret", []byte(testTOTPSecret)),
		CSRFSecretFile:   writeSecretFile(t, secretDir, "csrf.key", nil),
		Allowlist:        []string{"127.0.0.1/32"},
	}

	err = run(testLogger(), options{configPath: writeConfigFile(t, cfg)})
	if err == nil {
		t.Fatal("run accepted an empty CSRF secret")
	}
	if !strings.Contains(err.Error(), "CSRF") {
		t.Fatalf("error = %v, want a CSRF refusal", err)
	}
	if code := exitCodeFor(err); code == 0 {
		t.Fatal("exitCodeFor(startup error) = 0, want non-zero")
	}
	if code := exitCodeFor(nil); code != 0 {
		t.Fatalf("exitCodeFor(nil) = %d, want 0", code)
	}
}

func TestAdminCampaignListerMapsStoreRows(t *testing.T) {
	ops := store.NewFake()
	c, err := ops.CreateCampaign(context.Background(), "Campagne A")
	if err != nil {
		t.Fatal(err)
	}
	if err := ops.SetCampaignState(context.Background(), c.ID, store.StateArmed); err != nil {
		t.Fatal(err)
	}

	rows, err := adminCampaignLister(ops)(context.Background())
	if err != nil {
		t.Fatalf("lister: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if rows[0].ID != c.ID || rows[0].Name != "Campagne A" || rows[0].State != string(store.StateArmed) {
		t.Fatalf("mapped campaign = %+v", rows[0])
	}
	if rows[0].Created == "" {
		t.Fatal("Created is empty")
	}
}
