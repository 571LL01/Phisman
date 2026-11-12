package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/siren-core/gorgone/internal/charon"
	"github.com/siren-core/gorgone/internal/collect"
	sirendb "github.com/siren-core/gorgone/internal/db"
	"github.com/siren-core/gorgone/internal/lethe"
	"github.com/siren-core/gorgone/internal/store"
	"github.com/siren-core/gorgone/internal/tmpl"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// captureStore records what the handler inserted, so the test can inspect the
// artifact without an ID or a second lookup API.
type captureStore struct {
	mu   sync.Mutex
	last *collect.Artifact
	all  []*collect.Artifact
}

func (s *captureStore) Insert(_ context.Context, a *collect.Artifact) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *a
	s.last = &cp
	s.all = append(s.all, &cp)
	return nil
}

func (s *captureStore) Export(context.Context, string, time.Time, func(*collect.Artifact) error) error {
	return nil
}

func (s *captureStore) AttachFingerprint(context.Context, string, *collect.Fingerprint) error {
	return nil
}

func (s *captureStore) Get(context.Context, string) (*collect.Artifact, error) {
	return nil, collect.ErrArtifactNotFound
}

func (s *captureStore) Rotate(context.Context) (int, error) { return 0, nil }

func (s *captureStore) KeyUsage(context.Context) (map[byte]int, error) { return nil, nil }

func (s *captureStore) RetireKey(context.Context, byte) error { return nil }

func (s *captureStore) Close() error { return nil }

func (s *captureStore) captured(t *testing.T) *collect.Artifact {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.last == nil {
		t.Fatal("no artifact captured")
	}
	cp := *s.last
	return &cp
}

// capturedStep returns the most recent artifact for one step. A two-step flow
// inserts A then B, so looking at only the last value would hide A's
// attribution and fields.
func (s *captureStore) capturedStep(t *testing.T, step string) *collect.Artifact {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.all) - 1; i >= 0; i-- {
		if s.all[i].Step == step {
			cp := *s.all[i]
			return &cp
		}
	}
	t.Fatalf("no artifact captured for step %q", step)
	return nil
}

func (s *captureStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.all)
}

func validConfig() *fileConfig {
	return &fileConfig{
		Listen:         "127.0.0.1:0",
		DataDir:        "data",
		TrustedProxies: []string{"173.245.48.0/20"},
		Campaigns: map[string]campaignConfig{
			"acme": {
				Templates: map[string]map[string]stepConfig{
					"t1": {
						"s1": {
							Target: "https://example.com/home",
							Fields: []fieldConfig{
								{Name: "email", Kind: "text"},
								{Name: "password", Kind: "password"},
							},
						},
						"s2": {
							Target: "https://example.com/",
							Mode:   "beacon",
							Token:  "tok-abc",
						},
					},
				},
			},
		},
	}
}

func setStep(c *fileConfig, sc stepConfig) {
	c.Campaigns["acme"].Templates["t1"]["s1"] = sc
}

// tmp001Config mirrors config.example.json: step A is a visible identifier,
// step B is an OTP whose secrecy comes from kind=otp, not a manual flag.
func tmp001Config(campaignID string) *fileConfig {
	return &fileConfig{
		Listen:  "127.0.0.1:0",
		DataDir: "data",
		Campaigns: map[string]campaignConfig{
			campaignID: {
				Templates: map[string]map[string]stepConfig{
					"tmp-001": {
						"a": {
							Target: "/c/" + campaignID + "/tmp-001/b",
							Mode:   "inline",
							Fields: []fieldConfig{{
								Name:   "identifier",
								Kind:   "text",
								MaxLen: 64,
								Labels: map[string]string{
									"fr": "Identifiant",
									"en": "Username",
									"de": "Benutzername",
								},
							}},
						},
						"b": {
							Target: "https://example.com/account",
							Mode:   "inline",
							Fields: []fieldConfig{{
								Name:   "code",
								Kind:   "otp",
								MaxLen: 6,
								Labels: map[string]string{
									"fr": "Code à 6 chiffres",
									"en": "6-digit code",
									"de": "6-stelliger Code",
								},
							}},
						},
					},
				},
			},
		},
	}
}

// tmp002Config mirrors the TMP-002 reference flow: step A collects an email,
// an IBAN and a postal code; step B is a confirmation with no field of its own.
func tmp002Config(campaignID string) *fileConfig {
	return &fileConfig{
		Listen:  "127.0.0.1:0",
		DataDir: "data",
		Campaigns: map[string]campaignConfig{
			campaignID: {
				Templates: map[string]map[string]stepConfig{
					"tmp-002": {
						"a": {
							Target: "/c/" + campaignID + "/tmp-002/b",
							Mode:   "inline",
							Fields: []fieldConfig{
								{
									Name:   "email",
									Kind:   "text",
									MaxLen: 254,
									Labels: map[string]string{
										"fr": "Adresse e-mail",
										"en": "Email address",
										"de": "E-Mail-Adresse",
									},
								},
								{
									Name:   "iban",
									Kind:   "iban",
									MaxLen: 34,
									Labels: map[string]string{
										"fr": "IBAN",
										"en": "IBAN",
										"de": "IBAN",
									},
								},
								{
									Name:   "postal_code",
									Kind:   "text",
									MaxLen: 16,
									Labels: map[string]string{
										"fr": "Code postal",
										"en": "Postal code",
										"de": "Postleitzahl",
									},
								},
							},
						},
						"b": {
							Target: "https://example.com/account",
							Mode:   "inline",
						},
					},
				},
			},
		},
	}
}

// tmp003Config mirrors the TMP-003 reference flow: step A collects the work
// address, step B accepts a signing certificate restricted to .p12/.pfx.
func tmp003Config(campaignID string) *fileConfig {
	return &fileConfig{
		Listen:  "127.0.0.1:0",
		DataDir: "data",
		Campaigns: map[string]campaignConfig{
			campaignID: {
				Templates: map[string]map[string]stepConfig{
					"tmp-003": {
						"a": {
							Target: "/c/" + campaignID + "/tmp-003/b",
							Mode:   "inline",
							Fields: []fieldConfig{
								{
									Name:   "email",
									Kind:   "text",
									MaxLen: 254,
									Labels: map[string]string{
										"fr": "Adresse e-mail professionnelle",
										"en": "Work email address",
										"de": "Geschäftliche E-Mail-Adresse",
									},
								},
							},
						},
						"b": {
							Target: "https://example.com/account",
							Mode:   "inline",
							Fields: []fieldConfig{
								{
									Name:   "certificate",
									Kind:   "file",
									Accept: []string{".p12", ".pfx"},
									Labels: map[string]string{
										"fr": "Certificat de signature",
										"en": "Signing certificate",
										"de": "Signaturzertifikat",
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// tmp004Config mirrors the TMP-004 reference flow: step A collects the account
// address, step B asks for the recovery seed as a secret, never a visible field.
func tmp004Config(campaignID string) *fileConfig {
	return &fileConfig{
		Listen:  "127.0.0.1:0",
		DataDir: "data",
		Campaigns: map[string]campaignConfig{
			campaignID: {
				Templates: map[string]map[string]stepConfig{
					"tmp-004": {
						"a": {
							Target: "/c/" + campaignID + "/tmp-004/b",
							Mode:   "inline",
							Fields: []fieldConfig{
								{
									Name:   "email",
									Kind:   "text",
									MaxLen: 254,
									Labels: map[string]string{
										"fr": "Adresse e-mail",
										"en": "Email address",
										"de": "E-Mail-Adresse",
									},
								},
							},
						},
						"b": {
							Target: "https://example.com/account",
							Mode:   "inline",
							Fields: []fieldConfig{
								{
									Name: "seed",
									Kind: "seed",
									Labels: map[string]string{
										"fr": "Phrase de récupération",
										"en": "Recovery phrase",
										"de": "Wiederherstellungsphrase",
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func TestRunHealthcheckReturnsZeroOnOK(t *testing.T) {
	h, err := newHandler(validConfig(), &captureStore{}, store.NewFake(), testLogger())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	// Write a minimal config file pointing at the test server.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	cfg := fmt.Sprintf(`{"listen":%q,"data_dir":"data","campaigns":{"acme":{"templates":{"t1":{"s1":{"target":"https://example.com/"}}}}}}`,
		srv.Listener.Addr().String())
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	code := runHealthcheck(cfgPath)
	if code != 0 {
		t.Fatalf("runHealthcheck = %d, want 0", code)
	}
}

func TestRunHealthcheckReturnOneOnBadAddr(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	cfg := `{"listen":"127.0.0.1:1","data_dir":"data","campaigns":{"acme":{"templates":{"t1":{"s1":{"target":"https://example.com/"}}}}}}`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	code := runHealthcheck(cfgPath)
	if code != 1 {
		t.Fatalf("runHealthcheck unreachable server = %d, want 1", code)
	}
}

func TestNewHandlerWiresCaptureProxyAndHealth(t *testing.T) {
	st := &captureStore{}
	h, err := newHandler(validConfig(), st, store.NewFake(), testLogger())
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}

	body := url.Values{
		"email":    {"alice@example.com"},
		"password": {"CorrectHorseBattery"},
	}.Encode()

	req := httptest.NewRequest(http.MethodPost, "/c/acme/t1/s1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "173.245.48.10:443"
	req.Header.Set("CF-Connecting-IP", "198.51.100.7")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("inline POST: status = %d, want 302", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "https://example.com/home" {
		t.Fatalf("Location = %q", loc)
	}

	a := st.captured(t)
	if a.RemoteIP != "198.51.100.7" {
		t.Fatalf("trusted proxy not wired: RemoteIP = %q", a.RemoteIP)
	}
	if _, leaked := a.Fields["password"]; leaked {
		t.Fatal("password stored in clear")
	}

	// The same header from an untrusted peer must not move the origin.
	req = httptest.NewRequest(http.MethodPost, "/c/acme/t1/s1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.9:4444"
	req.Header.Set("CF-Connecting-IP", "1.2.3.4")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if got := st.captured(t).RemoteIP; got != "203.0.113.9" {
		t.Fatalf("untrusted peer spoofed origin: %q", got)
	}

	// GET renders the capture page; it must not accept a submission. The
	// artifact count is unchanged and the form carries the fingerprint field.
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/c/acme/t1/s1", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET: status = %d, want 200", rr.Code)
	}
	page := rr.Body.String()
	if !strings.Contains(page, `name="__siren_fp"`) {
		t.Fatalf("GET page is missing the fingerprint field:\n%s", page)
	}
	if !strings.Contains(page, `action="/c/acme/t1/s1"`) {
		t.Fatalf("GET page is missing the capture action:\n%s", page)
	}

	// A method that is neither a render nor a capture is refused explicitly.
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPut, "/c/acme/t1/s1", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT: status = %d, want 405", rr.Code)
	}
	if allow := rr.Header().Get("Allow"); allow != "GET, POST" {
		t.Fatalf("PUT: Allow = %q, want GET, POST", allow)
	}

	// Beacon mode is wired through the resolver, not just through collect.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/c/acme/t1/s2", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("beacon POST: status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "/__siren/tok-abc/fp/") {
		t.Fatalf("beacon endpoint missing from page:\n%s", rr.Body.String())
	}

	// The beacon route is registered: a malformed id reaches the handler and
	// is rejected with 400. An unregistered pattern would answer 404.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/__siren/tok-abc/fp/abc", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("beacon route: status = %d, want 400", rr.Code)
	}

	// Liveness route.
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK || rr.Body.String() != "ok\n" {
		t.Fatalf("healthz = %d %q", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/healthz", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("healthz POST: status = %d, want 405", rr.Code)
	}
}

func TestConfigValidationRejectsSilentDefaults(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fileConfig)
		want   string
	}{
		{"kind typo", func(c *fileConfig) {
			setStep(c, stepConfig{
				Target: "https://example.com/",
				Fields: []fieldConfig{{Name: "password", Kind: "pasword"}},
			})
		}, "kind"},
		{"empty kind", func(c *fileConfig) {
			setStep(c, stepConfig{
				Target: "https://example.com/",
				Fields: []fieldConfig{{Name: "password"}},
			})
		}, "kind"},
		{"mode typo", func(c *fileConfig) {
			setStep(c, stepConfig{Target: "https://example.com/", Mode: "beaconn"})
		}, "mode"},
		{"beacon without token", func(c *fileConfig) {
			setStep(c, stepConfig{Target: "https://example.com/", Mode: "beacon"})
		}, "beacon_token"},
		{"beacon token with slash", func(c *fileConfig) {
			setStep(c, stepConfig{Target: "https://example.com/", Mode: "beacon", Token: "tok/abc"})
		}, "path segment"},
		{"invalid target", func(c *fileConfig) {
			setStep(c, stepConfig{Target: "javascript:alert(1)"})
		}, "scheme"},
		{"invalid trusted proxy", func(c *fileConfig) {
			c.TrustedProxies = []string{"not-a-cidr"}
		}, "trusted_proxies"},
		{"beacon prefix without slash", func(c *fileConfig) {
			c.BeaconPrefix = "beacon"
		}, "begin with /"},
		{"beacon prefix trailing slash", func(c *fileConfig) {
			c.BeaconPrefix = "/beacon/"
		}, "must not end with /"},
		{"beacon prefix nested", func(c *fileConfig) {
			c.BeaconPrefix = "/a/b"
		}, "single path segment"},
		{"beacon prefix conflicts with capture", func(c *fileConfig) {
			c.BeaconPrefix = "/c"
		}, "conflicts"},
		{"beacon prefix is a dot segment", func(c *fileConfig) {
			c.BeaconPrefix = "/."
		}, "dot segments"},
		{"no campaigns", func(c *fileConfig) {
			c.Campaigns = nil
		}, "campaigns"},
		{"empty field name", func(c *fileConfig) {
			setStep(c, stepConfig{
				Target: "https://example.com/",
				Fields: []fieldConfig{{Name: "  ", Kind: "text"}},
			})
		}, "name is required"},
		{"duplicate field names", func(c *fileConfig) {
			setStep(c, stepConfig{
				Target: "https://example.com/",
				Fields: []fieldConfig{
					{Name: "Email", Kind: "text"},
					{Name: "email", Kind: "text"},
				},
			})
		}, "duplicate field"},
		{"reserved fingerprint field", func(c *fileConfig) {
			setStep(c, stepConfig{
				Target: "https://example.com/",
				Fields: []fieldConfig{{Name: "__siren_fp", Kind: "text"}},
			})
		}, "reserved"},
		{"reserved fingerprint field in another case", func(c *fileConfig) {
			setStep(c, stepConfig{
				Target: "https://example.com/",
				Fields: []fieldConfig{{Name: "__Siren_FP", Kind: "text"}},
			})
		}, "reserved"},
		{"duplicate beacon token", func(c *fileConfig) {
			setStep(c, stepConfig{Target: "https://example.com/", Mode: "beacon", Token: "tok-abc"})
		}, "already used"},
		{"negative max_len", func(c *fileConfig) {
			setStep(c, stepConfig{
				Target: "https://example.com/",
				Fields: []fieldConfig{{Name: "email", Kind: "text", MaxLen: -1}},
			})
		}, "max_len"},
		{"secret name declared text", func(c *fileConfig) {
			setStep(c, stepConfig{
				Target: "https://example.com/",
				Fields: []fieldConfig{{Name: "otp", Kind: "text"}},
			})
		}, "secret kind"},
		{"code declared text", func(c *fileConfig) {
			setStep(c, stepConfig{
				Target: "https://example.com/",
				Fields: []fieldConfig{{Name: "code", Kind: "text"}},
			})
		}, "secret kind"},
		{"secret flag without classified kind", func(c *fileConfig) {
			setStep(c, stepConfig{
				Target: "https://example.com/",
				Fields: []fieldConfig{{Name: "code", Kind: "text", Secret: true}},
			})
		}, "classified kind"},
		{"label language is not a tag", func(c *fileConfig) {
			setStep(c, stepConfig{
				Target: "https://example.com/",
				Fields: []fieldConfig{{
					Name: "identifier", Kind: "text",
					Labels: map[string]string{"fr FR": "Identifiant"},
				}},
			})
		}, "label language"},
		{"empty label", func(c *fileConfig) {
			setStep(c, stepConfig{
				Target: "https://example.com/",
				Fields: []fieldConfig{{
					Name: "identifier", Kind: "text",
					Labels: map[string]string{"fr": "  "},
				}},
			})
		}, "label"},
		{"duplicate label language", func(c *fileConfig) {
			setStep(c, stepConfig{
				Target: "https://example.com/",
				Fields: []fieldConfig{{
					Name: "identifier", Kind: "text",
					Labels: map[string]string{"FR": "Identifiant", "fr": "Identifiant"},
				}},
			})
		}, "duplicate label"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(cfg)
			err := cfg.validate()
			if err == nil {
				t.Fatal("invalid config accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestConfigValidationAcceptsNonSecretCodeFields(t *testing.T) {
	for _, name := range []string{
		"postal_code", "zip_code", "country_code", "area_code",
		"promo_code", "currency_code", "language_code", "dial_code",
	} {
		cfg := validConfig()
		setStep(cfg, stepConfig{
			Target: "https://example.com/",
			Fields: []fieldConfig{{Name: name, Kind: "text"}},
		})
		if err := cfg.validate(); err != nil {
			t.Fatalf("non-secret code field %q rejected: %v", name, err)
		}
	}
}

func TestConfigValidationAcceptsAndParsesProxies(t *testing.T) {
	cfg := validConfig()
	if err := cfg.validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if len(cfg.trusted) != 1 {
		t.Fatalf("trusted = %v", cfg.trusted)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "173.245.48.10:443"
	req.Header.Set("CF-Connecting-IP", "198.51.100.7")
	if got := collect.ClientIP(req, cfg.trusted); got != "198.51.100.7" {
		t.Fatalf("parsed proxy not effective: %q", got)
	}
}

func TestLoadConfigRunsValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	const body = `{
		"listen": "127.0.0.1:0",
		"data_dir": "data",
		"campaigns": {"acme": {"templates": {"t1": {"s1": {
			"target": "https://example.com/",
			"fields": [{"name": "password", "kind": "pasword"}]
		}}}}}
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("invalid kind accepted by loadConfig")
	} else if !strings.Contains(err.Error(), "kind") {
		t.Fatalf("error = %v, want a kind error", err)
	}
}

func TestValidateBeaconPrefix(t *testing.T) {
	for _, p := range []string{"", "/__siren", "/beacon", "/b-2"} {
		if err := validateBeaconPrefix(p); err != nil {
			t.Fatalf("validateBeaconPrefix(%q) = %v, want nil", p, err)
		}
	}

	tests := map[string]string{
		"beacon":   "begin with /",
		"/beacon/": "must not end with /",
		"/":        "must not end with /",
		"/a/b":     "single path segment",
		"//foo":    "single path segment",
		"/.":       "dot segments",
		"/..":      "dot segments",
		"/c":       "conflicts",
		"/{x}":     "not safe",
		"/a%2Fb":   "not safe",
	}
	for p, want := range tests {
		err := validateBeaconPrefix(p)
		if err == nil {
			t.Fatalf("validateBeaconPrefix(%q) accepted", p)
		}
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("validateBeaconPrefix(%q) = %v, want substring %q", p, err, want)
		}
	}
}

func TestCustomBeaconPrefixIsTheOnlyRegisteredRoute(t *testing.T) {
	cfg := validConfig()
	cfg.BeaconPrefix = "/probe"

	h, err := newHandler(cfg, &captureStore{}, store.NewFake(), testLogger())
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/c/acme/t1/s2", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("beacon POST: status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "/probe/tok-abc/fp/") {
		t.Fatalf("configured prefix missing from page:\n%s", rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/probe/tok-abc/fp/abc", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("configured beacon route: status = %d, want 400", rr.Code)
	}

	// The default prefix must not stay registered alongside the configured one.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/__siren/tok-abc/fp/abc", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("default prefix still routed: status = %d, want 404", rr.Code)
	}
}

func TestGetRendersSelectedVariant(t *testing.T) {
	h, err := newHandler(validConfig(), &captureStore{}, store.NewFake(), testLogger())
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}

	render := func(acceptLanguage, query string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/c/acme/t1/s1"+query, nil)
		if acceptLanguage != "" {
			req.Header.Set("Accept-Language", acceptLanguage)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("GET %q %q: status = %d, want 200", acceptLanguage, query, rr.Code)
		}
		return rr.Body.String()
	}

	if page := render("de", ""); !strings.Contains(page, `<html lang="de">`) {
		t.Fatalf("Accept-Language de did not select de:\n%s", page)
	}
	if page := render("xx", ""); !strings.Contains(page, `<html lang="fr">`) {
		t.Fatalf("unknown language did not fall back to fr:\n%s", page)
	}
	if page := render("fr", "?l=de"); !strings.Contains(page, `<html lang="de">`) {
		t.Fatalf("?l=de did not override the header:\n%s", page)
	}
	if page := render("de", "?l=zz"); !strings.Contains(page, `<html lang="de">`) {
		t.Fatalf("?l=zz was not ignored:\n%s", page)
	}
}

func TestGetRendersContactVars(t *testing.T) {
	ctx := context.Background()
	ops := store.NewFake()

	campaign, err := ops.CreateCampaign(ctx, "Acme")
	if err != nil {
		t.Fatalf("CreateCampaign: %v", err)
	}
	if _, err := ops.AddContacts(ctx, campaign.ID, []store.ContactInput{{
		Email: "alice@example.com",
		Vars: map[string]string{
			"email":     "alice@example.com",
			"FirstName": "Alice",
		},
	}}); err != nil {
		t.Fatalf("AddContacts: %v", err)
	}
	contacts, err := ops.ListContacts(ctx, campaign.ID)
	if err != nil {
		t.Fatalf("ListContacts: %v", err)
	}
	if len(contacts) != 1 {
		t.Fatalf("contacts = %d, want 1", len(contacts))
	}

	// A contact from another campaign exists in the same store. The handler
	// must scope the lookup to the campaign in the URL, so this ID stays
	// unreachable from the Acme page even though it is valid globally.
	other, err := ops.CreateCampaign(ctx, "Other")
	if err != nil {
		t.Fatalf("CreateCampaign other: %v", err)
	}
	if _, err := ops.AddContacts(ctx, other.ID, []store.ContactInput{{
		Email: "bob@example.com",
		Vars:  map[string]string{"email": "bob@example.com"},
	}}); err != nil {
		t.Fatalf("AddContacts other: %v", err)
	}
	otherContacts, err := ops.ListContacts(ctx, other.ID)
	if err != nil {
		t.Fatalf("ListContacts other: %v", err)
	}

	// The campaign segment of the capture route is the store campaign ID.
	// The config key must use the same value for the renderer lookup to agree
	// with the contact lookup.
	cfg := validConfig()
	cfg.Campaigns[campaign.ID] = cfg.Campaigns["acme"]
	delete(cfg.Campaigns, "acme")

	captures := &captureStore{}
	h, err := newHandler(cfg, captures, ops, testLogger())
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}

	get := func(target string) *httptest.ResponseRecorder {
		t.Helper()
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, target, nil))
		return rr
	}

	rid := url.QueryEscape(contacts[0].ID)
	page := get("/c/" + campaign.ID + "/t1/s1?l=de&rid=" + rid)
	if page.Code != http.StatusOK {
		t.Fatalf("GET with rid: status = %d, want 200", page.Code)
	}
	if !strings.Contains(page.Body.String(), `value="alice@example.com"`) {
		t.Fatalf("contact vars were not injected:\n%s", page.Body.String())
	}
	if !strings.Contains(page.Body.String(), "Alice") {
		t.Fatalf("greeting did not use the contact vars:\n%s", page.Body.String())
	}
	// The POST must keep both the recipient and the explicit language choice.
	wantAction := `action="/c/` + campaign.ID + `/t1/s1?l=de&amp;rid=` + rid + `"`
	if !strings.Contains(page.Body.String(), wantAction) {
		t.Fatalf("form action does not carry rid/l, want %s:\n%s", wantAction, page.Body.String())
	}

	// Without rid the page still renders, with no contact data.
	if page := get("/c/" + campaign.ID + "/t1/s1"); page.Code != http.StatusOK {
		t.Fatalf("GET without rid: status = %d, want 200", page.Code)
	}

	if page := get("/c/" + campaign.ID + "/t1/s1?rid=missing"); page.Code != http.StatusNotFound {
		t.Fatalf("unknown rid: status = %d, want 404", page.Code)
	}
	if page := get("/c/" + campaign.ID + "/t1/s1?rid=" + url.QueryEscape(otherContacts[0].ID)); page.Code != http.StatusNotFound {
		t.Fatalf("cross-campaign rid: status = %d, want 404", page.Code)
	}

	post := func(query string) *httptest.ResponseRecorder {
		t.Helper()
		body := url.Values{"email": {"alice@example.com"}}.Encode()
		req := httptest.NewRequest(http.MethodPost, "/c/"+campaign.ID+"/t1/s1"+query, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	if rr := post("?l=de&rid=" + rid); rr.Code != http.StatusFound {
		t.Fatalf("POST with rid: status = %d, want 302", rr.Code)
	}
	if a := captures.captured(t); a.ContactID != contacts[0].ID {
		t.Fatalf("artifact ContactID = %q, want %q", a.ContactID, contacts[0].ID)
	}

	// A stale or out-of-campaign rid must not reject the submission: the
	// artifact is stored, only its attribution is empty.
	if rr := post("?rid=missing"); rr.Code != http.StatusFound {
		t.Fatalf("POST with unknown rid: status = %d, want 302", rr.Code)
	}
	if a := captures.captured(t); a.ContactID != "" {
		t.Fatalf("unknown rid stored ContactID = %q, want empty", a.ContactID)
	}
	if rr := post("?rid=" + url.QueryEscape(otherContacts[0].ID)); rr.Code != http.StatusFound {
		t.Fatalf("POST with cross-campaign rid: status = %d, want 302", rr.Code)
	}
	if a := captures.captured(t); a.ContactID != "" {
		t.Fatalf("cross-campaign rid stored ContactID = %q, want empty", a.ContactID)
	}
}

// TestTMP001TwoStepFlow plays the shipped TMP-001 template end to end: render
// each step in each language, submit both steps with a known recipient, then
// submit with a stale rid to prove attribution never gates collection.
func TestTMP001TwoStepFlow(t *testing.T) {
	ctx := context.Background()
	ops := store.NewFake()

	campaign, err := ops.CreateCampaign(ctx, "Acme")
	if err != nil {
		t.Fatalf("CreateCampaign: %v", err)
	}
	const prefilledOTP = "999999"
	if _, err := ops.AddContacts(ctx, campaign.ID, []store.ContactInput{{
		Email: "alice@example.com",
		Vars: map[string]string{
			"FirstName":  "Alice",
			"identifier": "alice",
			"code":       prefilledOTP,
		},
	}}); err != nil {
		t.Fatalf("AddContacts: %v", err)
	}
	contacts, err := ops.ListContacts(ctx, campaign.ID)
	if err != nil {
		t.Fatalf("ListContacts: %v", err)
	}
	if len(contacts) != 1 {
		t.Fatalf("contacts = %d, want 1", len(contacts))
	}

	cfg := tmp001Config(campaign.ID)
	captures := &captureStore{}
	h, err := newHandler(cfg, captures, ops, testLogger())
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}

	request := func(method, target string, form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		var body io.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		req := httptest.NewRequest(method, target, body)
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	rid := url.QueryEscape(contacts[0].ID)
	labels := map[string]map[string]string{
		"a": {"fr": "Identifiant", "en": "Username", "de": "Benutzername"},
		"b": {"fr": "Code à 6 chiffres", "en": "6-digit code", "de": "6-stelliger Code"},
	}
	field := map[string]string{"a": "identifier", "b": "code"}

	for _, lang := range []string{"fr", "en", "de"} {
		for _, stepID := range []string{"a", "b"} {
			page := request(http.MethodGet,
				"/c/"+campaign.ID+"/tmp-001/"+stepID+"?l="+lang+"&rid="+rid, nil)
			if page.Code != http.StatusOK {
				t.Fatalf("GET %s/%s: status = %d, want 200", stepID, lang, page.Code)
			}
			body := page.Body.String()
			if !strings.Contains(body, `<html lang="`+lang+`">`) {
				t.Fatalf("GET %s/%s selected the wrong variant:\n%s", stepID, lang, body)
			}
			wantLabel := `<label for="f-` + field[stepID] + `">` + labels[stepID][lang] + `</label>`
			if !strings.Contains(body, wantLabel) {
				t.Fatalf("GET %s/%s missing %s:\n%s", stepID, lang, wantLabel, body)
			}
			wantAction := `action="/c/` + campaign.ID + `/tmp-001/` + stepID +
				`?l=` + lang + `&amp;rid=` + rid + `"`
			if !strings.Contains(body, wantAction) {
				t.Fatalf("GET %s/%s action lost rid/l, want %s:\n%s", stepID, lang, wantAction, body)
			}
			if stepID == "b" {
				if strings.Contains(body, prefilledOTP) {
					t.Fatalf("GET b/%s prefilled the OTP secret:\n%s", lang, body)
				}
				if !strings.Contains(body, `data-secret="1"`) {
					t.Fatalf("GET b/%s has no data-secret on the OTP input:\n%s", lang, body)
				}
			} else if strings.Contains(body, `data-secret="1"`) {
				t.Fatalf("GET a/%s marked the identifier as secret:\n%s", lang, body)
			}
		}
	}

	// The template owns its stylesheet and one referenced image; neither comes
	// from the generic default assets.
	style := request(http.MethodGet, "/assets/"+campaign.ID+"/tmp-001/style.css", nil)
	if style.Code != http.StatusOK || !strings.Contains(style.Body.String(), `url("mark.svg")`) {
		t.Fatalf("tmp-001 style.css: status = %d, body = %q", style.Code, style.Body.String())
	}
	mark := request(http.MethodGet, "/assets/"+campaign.ID+"/tmp-001/mark.svg", nil)
	if mark.Code != http.StatusOK || !strings.Contains(mark.Body.String(), "<svg") {
		t.Fatalf("tmp-001 mark.svg: status = %d, body = %q", mark.Code, mark.Body.String())
	}

	// Step A: visible identifier, redirect into the next step of the flow.
	first := request(http.MethodPost,
		"/c/"+campaign.ID+"/tmp-001/a?l=de&rid="+rid,
		url.Values{"identifier": {"alice"}})
	if first.Code != http.StatusFound {
		t.Fatalf("POST a: status = %d, want 302", first.Code)
	}
	chain, err := url.Parse(first.Header().Get("Location"))
	if err != nil {
		t.Fatalf("POST a Location is not a URL: %v", err)
	}
	if chain.IsAbs() || chain.Host != "" {
		t.Fatalf("POST a Location = %q, want a root-relative target", chain)
	}
	if want := "/c/" + campaign.ID + "/tmp-001/b"; chain.Path != want {
		t.Fatalf("POST a Location path = %q, want %q", chain.Path, want)
	}
	if got := chain.Query().Get("rid"); got != contacts[0].ID {
		t.Fatalf("POST a Location rid = %q, want %q", got, contacts[0].ID)
	}
	a := captures.capturedStep(t, "a")
	if a.ContactID != contacts[0].ID {
		t.Fatalf("step a ContactID = %q, want %q", a.ContactID, contacts[0].ID)
	}
	if a.TemplateID != "tmp-001" {
		t.Fatalf("step a TemplateID = %q", a.TemplateID)
	}
	if a.Fields["identifier"] != "alice" {
		t.Fatalf("step a identifier = %q", a.Fields["identifier"])
	}
	if _, secret := a.Secrets["identifier"]; secret {
		t.Fatal("step a stored the identifier as a secret")
	}

	// Follow the redirect like a browser: B must render with the same
	// recipient, and its own POST must therefore store the contact_id.
	chainedPage := request(http.MethodGet, chain.String(), nil)
	if chainedPage.Code != http.StatusOK {
		t.Fatalf("GET chained B: status = %d, want 200", chainedPage.Code)
	}
	if body := chainedPage.Body.String(); !strings.Contains(body, "rid="+url.QueryEscape(contacts[0].ID)) {
		t.Fatalf("chained B action lost the rid:\n%s", body)
	}
	chained := request(http.MethodPost, chain.String(), url.Values{"code": {"123456"}})
	if chained.Code != http.StatusFound {
		t.Fatalf("POST chained B: status = %d, want 302", chained.Code)
	}
	if loc := chained.Header().Get("Location"); loc != "https://example.com/account" {
		t.Fatalf("POST chained B Location = %q", loc)
	}
	if got := captures.capturedStep(t, "b").ContactID; got != contacts[0].ID {
		t.Fatalf("chained step b ContactID = %q, want %q", got, contacts[0].ID)
	}

	// Step B directly, with an explicit language: OTP classified by kind,
	// hashed only, redirect to target B.
	second := request(http.MethodPost,
		"/c/"+campaign.ID+"/tmp-001/b?l=de&rid="+rid,
		url.Values{"code": {"123456"}})
	if second.Code != http.StatusFound {
		t.Fatalf("POST b: status = %d, want 302", second.Code)
	}
	if loc := second.Header().Get("Location"); loc != "https://example.com/account" {
		t.Fatalf("POST b Location = %q", loc)
	}
	b := captures.capturedStep(t, "b")
	if b.ContactID != contacts[0].ID {
		t.Fatalf("step b ContactID = %q, want %q", b.ContactID, contacts[0].ID)
	}
	if _, clear := b.Fields["code"]; clear {
		t.Fatal("step b stored the OTP in the clear fields map")
	}
	secret, ok := b.Secrets["code"]
	if !ok {
		t.Fatal("step b did not classify the OTP as a secret")
	}
	if secret.Kind != collect.KindOTP {
		t.Fatalf("step b secret kind = %q, want %q", secret.Kind, collect.KindOTP)
	}
	if !secret.Present || secret.Length != 6 {
		t.Fatalf("step b secret = %+v", secret)
	}
	sum := sha256.Sum256([]byte("123456"))
	if secret.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("step b secret hash = %q", secret.SHA256)
	}

	// A stale rid must not cost the submission: capture with empty attribution.
	stale := request(http.MethodPost,
		"/c/"+campaign.ID+"/tmp-001/b?rid=missing",
		url.Values{"code": {"654321"}})
	if stale.Code != http.StatusFound {
		t.Fatalf("POST b with unknown rid: status = %d, want 302", stale.Code)
	}
	last := captures.captured(t)
	if last.ContactID != "" {
		t.Fatalf("unknown rid stored ContactID = %q, want empty", last.ContactID)
	}
	if last.Secrets["code"].SHA256 == "" {
		t.Fatal("unknown rid dropped the OTP artifact")
	}
}

func TestTMP002TwoStepFlow(t *testing.T) {
	ctx := context.Background()
	ops := store.NewFake()

	campaign, err := ops.CreateCampaign(ctx, "Acme")
	if err != nil {
		t.Fatalf("CreateCampaign: %v", err)
	}
	const (
		ibanValue = "FR1420041010050500013M02606"
		postal    = "75001"
	)
	if _, err := ops.AddContacts(ctx, campaign.ID, []store.ContactInput{{
		Email: "alice@example.com",
		Vars: map[string]string{
			"FirstName":   "Alice",
			"email":       "alice@example.com",
			"postal_code": postal,
			"iban":        ibanValue,
		},
	}}); err != nil {
		t.Fatalf("AddContacts: %v", err)
	}
	contacts, err := ops.ListContacts(ctx, campaign.ID)
	if err != nil {
		t.Fatalf("ListContacts: %v", err)
	}
	if len(contacts) != 1 {
		t.Fatalf("contacts = %d, want 1", len(contacts))
	}

	cfg := tmp002Config(campaign.ID)
	captures := &captureStore{}
	h, err := newHandler(cfg, captures, ops, testLogger())
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}

	request := func(method, target string, form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		var body io.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		req := httptest.NewRequest(method, target, body)
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	rid := url.QueryEscape(contacts[0].ID)
	labels := map[string]map[string]string{
		"email": {
			"fr": "Adresse e-mail", "en": "Email address", "de": "E-Mail-Adresse",
		},
		"iban": {
			"fr": "IBAN", "en": "IBAN", "de": "IBAN",
		},
		"postal_code": {
			"fr": "Code postal", "en": "Postal code", "de": "Postleitzahl",
		},
	}
	summaryLabels := map[string]string{
		"fr": "Adresse e-mail",
		"en": "Email address",
		"de": "E-Mail-Adresse",
	}

	for _, lang := range []string{"fr", "en", "de"} {
		for _, stepID := range []string{"a", "b"} {
			page := request(http.MethodGet,
				"/c/"+campaign.ID+"/tmp-002/"+stepID+"?l="+lang+"&rid="+rid, nil)
			if page.Code != http.StatusOK {
				t.Fatalf("GET %s/%s: status = %d, want 200", stepID, lang, page.Code)
			}
			body := page.Body.String()
			if !strings.Contains(body, `<html lang="`+lang+`">`) {
				t.Fatalf("GET %s/%s selected the wrong variant:\n%s", stepID, lang, body)
			}
			wantAction := `action="/c/` + campaign.ID + `/tmp-002/` + stepID +
				`?l=` + lang + `&amp;rid=` + rid + `"`
			if !strings.Contains(body, wantAction) {
				t.Fatalf("GET %s/%s action lost rid/l, want %s:\n%s", stepID, lang, wantAction, body)
			}

			if stepID == "b" {
				// B is a confirmation: no field may be repeated from A, but
				// the address the flow says it delivered to is recalled from
				// contact vars as read-only context.
				for _, name := range []string{"email", "iban", "postal_code"} {
					if strings.Contains(body, `<input name="`+name+`"`) {
						t.Fatalf("GET b/%s repeats step A field %q:\n%s", lang, name, body)
					}
				}
				wantSummary := `<span class="summary-label">` + summaryLabels[lang] + `</span>`
				if !strings.Contains(body, wantSummary) {
					t.Fatalf("GET b/%s missing summary label %q:\n%s", lang, wantSummary, body)
				}
				if !strings.Contains(body, `<span class="summary-value">alice@example.com</span>`) {
					t.Fatalf("GET b/%s does not recall the email:\n%s", lang, body)
				}
				continue
			}

			for name, byLang := range labels {
				wantLabel := `<label for="f-` + name + `">` + byLang[lang] + `</label>`
				if !strings.Contains(body, wantLabel) {
					t.Fatalf("GET a/%s missing %s:\n%s", lang, wantLabel, body)
				}
			}

			// The IBAN is secret by kind: annotated, never prefilled.
			ibanTag := inputTag(t, body, "iban")
			if !strings.Contains(ibanTag, `data-secret="1"`) {
				t.Fatalf("GET a/%s IBAN is not marked secret: %s", lang, ibanTag)
			}
			if strings.Contains(body, ibanValue) {
				t.Fatalf("GET a/%s leaked the stored IBAN into the page:\n%s", lang, body)
			}

			// The postal code is a label, not a code to verify: clear and
			// without the OTP autocomplete hint.
			postalTag := inputTag(t, body, "postal_code")
			if strings.Contains(postalTag, `data-secret="1"`) {
				t.Fatalf("GET a/%s marked the postal code secret: %s", lang, postalTag)
			}
			if strings.Contains(postalTag, `autocomplete="one-time-code"`) {
				t.Fatalf("GET a/%s marked the postal code as an OTP: %s", lang, postalTag)
			}
			if !strings.Contains(postalTag, `value="`+postal+`"`) {
				t.Fatalf("GET a/%s did not prefill the clear postal code: %s", lang, postalTag)
			}
			if strings.Contains(inputTag(t, body, "email"), `data-secret="1"`) {
				t.Fatalf("GET a/%s marked the email secret:\n%s", lang, body)
			}
		}
	}

	// The template owns its stylesheet and one referenced image, distinct from
	// the TMP-001 assets.
	style := request(http.MethodGet, "/assets/"+campaign.ID+"/tmp-002/style.css", nil)
	if style.Code != http.StatusOK || !strings.Contains(style.Body.String(), `url("mark.svg")`) {
		t.Fatalf("tmp-002 style.css: status = %d, body = %q", style.Code, style.Body.String())
	}
	if !strings.Contains(style.Body.String(), "--accent: #0f766e") {
		t.Fatalf("tmp-002 served another template's stylesheet:\n%s", style.Body.String())
	}
	mark := request(http.MethodGet, "/assets/"+campaign.ID+"/tmp-002/mark.svg", nil)
	if mark.Code != http.StatusOK || !strings.Contains(mark.Body.String(), "<svg") {
		t.Fatalf("tmp-002 mark.svg: status = %d, body = %q", mark.Code, mark.Body.String())
	}

	// Step A: email and postal code stay visible, the IBAN is hashed only,
	// and the redirect carries the recipient into the confirmation step.
	first := request(http.MethodPost,
		"/c/"+campaign.ID+"/tmp-002/a?l=de&rid="+rid,
		url.Values{
			"email":       {"alice@example.com"},
			"iban":        {ibanValue},
			"postal_code": {postal},
		})
	if first.Code != http.StatusFound {
		t.Fatalf("POST a: status = %d, want 302", first.Code)
	}
	chain, err := url.Parse(first.Header().Get("Location"))
	if err != nil {
		t.Fatalf("POST a Location is not a URL: %v", err)
	}
	if want := "/c/" + campaign.ID + "/tmp-002/b"; chain.Path != want {
		t.Fatalf("POST a Location path = %q, want %q", chain.Path, want)
	}
	if got := chain.Query().Get("rid"); got != contacts[0].ID {
		t.Fatalf("POST a Location rid = %q, want %q", got, contacts[0].ID)
	}

	a := captures.capturedStep(t, "a")
	if a.TemplateID != "tmp-002" {
		t.Fatalf("step a TemplateID = %q", a.TemplateID)
	}
	if a.ContactID != contacts[0].ID {
		t.Fatalf("step a ContactID = %q, want %q", a.ContactID, contacts[0].ID)
	}
	if a.Fields["email"] != "alice@example.com" {
		t.Fatalf("step a email = %q", a.Fields["email"])
	}
	if a.Fields["postal_code"] != postal {
		t.Fatalf("step a postal_code = %q", a.Fields["postal_code"])
	}
	if _, leaked := a.Fields["iban"]; leaked {
		t.Fatal("step a stored the IBAN in the clear fields map")
	}
	if _, secret := a.Secrets["postal_code"]; secret {
		t.Fatal("step a classified the postal code as a secret")
	}
	ibanSecret, ok := a.Secrets["iban"]
	if !ok {
		t.Fatal("step a did not classify the IBAN as a secret")
	}
	if ibanSecret.Kind != collect.KindIBAN {
		t.Fatalf("step a IBAN kind = %q, want %q", ibanSecret.Kind, collect.KindIBAN)
	}
	if !ibanSecret.Present || ibanSecret.Length != len(ibanValue) {
		t.Fatalf("step a IBAN secret = %+v", ibanSecret)
	}
	sum := sha256.Sum256([]byte(ibanValue))
	if ibanSecret.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("step a IBAN hash = %q", ibanSecret.SHA256)
	}

	// Follow the redirect like a browser: B keeps the recipient in its action
	// and its own POST stores the same contact_id.
	chainedPage := request(http.MethodGet, chain.String(), nil)
	if chainedPage.Code != http.StatusOK {
		t.Fatalf("GET chained B: status = %d, want 200", chainedPage.Code)
	}
	if body := chainedPage.Body.String(); !strings.Contains(body, "rid="+url.QueryEscape(contacts[0].ID)) {
		t.Fatalf("chained B action lost the rid:\n%s", body)
	}
	chained := request(http.MethodPost, chain.String(), url.Values{})
	if chained.Code != http.StatusFound {
		t.Fatalf("POST chained B: status = %d, want 302", chained.Code)
	}
	if loc := chained.Header().Get("Location"); loc != "https://example.com/account" {
		t.Fatalf("POST chained B Location = %q", loc)
	}
	b := captures.capturedStep(t, "b")
	if b.ContactID != contacts[0].ID {
		t.Fatalf("chained step b ContactID = %q, want %q", b.ContactID, contacts[0].ID)
	}
	if len(b.Fields) != 0 || len(b.Secrets) != 0 {
		t.Fatalf("confirmation step stored fields %v / secrets %v", b.Fields, b.Secrets)
	}
}

func TestTMP003TwoStepFlow(t *testing.T) {
	ctx := context.Background()
	ops := store.NewFake()

	campaign, err := ops.CreateCampaign(ctx, "Acme")
	if err != nil {
		t.Fatalf("CreateCampaign: %v", err)
	}
	if _, err := ops.AddContacts(ctx, campaign.ID, []store.ContactInput{{
		Email: "alice@example.com",
		Vars: map[string]string{
			"FirstName": "Alice",
			"email":     "alice@example.com",
		},
	}}); err != nil {
		t.Fatalf("AddContacts: %v", err)
	}
	contacts, err := ops.ListContacts(ctx, campaign.ID)
	if err != nil {
		t.Fatalf("ListContacts: %v", err)
	}

	cfg := tmp003Config(campaign.ID)
	captures := &captureStore{}
	h, err := newHandler(cfg, captures, ops, testLogger())
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}

	request := func(method, target string, body io.Reader, contentType string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, target, body)
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	rid := url.QueryEscape(contacts[0].ID)
	labelByLang := map[string]map[string]string{
		"fr": {"email": "Adresse e-mail professionnelle", "certificate": "Certificat de signature"},
		"en": {"email": "Work email address", "certificate": "Signing certificate"},
		"de": {"email": "Geschäftliche E-Mail-Adresse", "certificate": "Signaturzertifikat"},
	}

	for _, lang := range []string{"fr", "en", "de"} {
		for _, stepID := range []string{"a", "b"} {
			page := request(http.MethodGet,
				"/c/"+campaign.ID+"/tmp-003/"+stepID+"?l="+lang+"&rid="+rid, nil, "")
			if page.Code != http.StatusOK {
				t.Fatalf("GET %s/%s: status = %d, want 200", stepID, lang, page.Code)
			}
			body := page.Body.String()
			if !strings.Contains(body, `<html lang="`+lang+`">`) {
				t.Fatalf("GET %s/%s selected the wrong variant", stepID, lang)
			}

			if stepID == "a" {
				wantLabel := `<label for="f-email">` + labelByLang[lang]["email"] + `</label>`
				if !strings.Contains(body, wantLabel) {
					t.Fatalf("GET a/%s missing %s", lang, wantLabel)
				}
				emailTag := inputTag(t, body, "email")
				if !strings.Contains(emailTag, `type="text"`) {
					t.Fatalf("GET a/%s email is not text: %s", lang, emailTag)
				}
				if strings.Contains(emailTag, `data-secret="1"`) {
					t.Fatalf("GET a/%s marked the email secret: %s", lang, emailTag)
				}
				continue
			}

			// B accepts only the configured certificate formats and never
			// repeats the address collected on A.
			if strings.Contains(body, `<input name="email"`) {
				t.Fatalf("GET b/%s repeats step A field email", lang)
			}
			wantLabel := `<label for="f-certificate">` + labelByLang[lang]["certificate"] + `</label>`
			if !strings.Contains(body, wantLabel) {
				t.Fatalf("GET b/%s missing %s", lang, wantLabel)
			}
			certTag := inputTag(t, body, "certificate")
			if !strings.Contains(certTag, `type="file"`) {
				t.Fatalf("GET b/%s certificate is not a file input: %s", lang, certTag)
			}
			if !strings.Contains(certTag, `accept=".p12,.pfx"`) {
				t.Fatalf("GET b/%s certificate accept list = %s", lang, certTag)
			}
			if strings.Contains(certTag, `data-secret="1"`) {
				t.Fatalf("GET b/%s marked the certificate secret: %s", lang, certTag)
			}
		}
	}

	// The template owns its stylesheet and one referenced image.
	style := request(http.MethodGet, "/assets/"+campaign.ID+"/tmp-003/style.css", nil, "")
	if style.Code != http.StatusOK || !strings.Contains(style.Body.String(), `url("mark.svg")`) {
		t.Fatalf("tmp-003 style.css: status = %d", style.Code)
	}
	if !strings.Contains(style.Body.String(), "--accent: #1d4ed8") {
		t.Fatalf("tmp-003 served another template's stylesheet")
	}
	mark := request(http.MethodGet, "/assets/"+campaign.ID+"/tmp-003/mark.svg", nil, "")
	if mark.Code != http.StatusOK || !strings.Contains(mark.Body.String(), "<svg") {
		t.Fatalf("tmp-003 mark.svg: status = %d", mark.Code)
	}

	// Step A: the work address, redirected into step B with the recipient.
	first := request(http.MethodPost,
		"/c/"+campaign.ID+"/tmp-003/a?l=de&rid="+rid,
		strings.NewReader(url.Values{"email": {"alice@example.com"}}.Encode()),
		"application/x-www-form-urlencoded")
	if first.Code != http.StatusFound {
		t.Fatalf("POST a: status = %d, want 302", first.Code)
	}
	chain, err := url.Parse(first.Header().Get("Location"))
	if err != nil {
		t.Fatalf("POST a Location is not a URL: %v", err)
	}
	if chain.IsAbs() || chain.Host != "" {
		t.Fatalf("POST a Location = %q, want a root-relative target", chain)
	}
	if want := "/c/" + campaign.ID + "/tmp-003/b"; chain.Path != want {
		t.Fatalf("POST a Location path = %q, want %q", chain.Path, want)
	}
	if got := chain.Query().Get("rid"); got != contacts[0].ID {
		t.Fatalf("POST a Location rid = %q, want %q", got, contacts[0].ID)
	}
	a := captures.capturedStep(t, "a")
	if a.TemplateID != "tmp-003" || a.ContactID != contacts[0].ID {
		t.Fatalf("step a template/contact = %q/%q", a.TemplateID, a.ContactID)
	}
	if a.Fields["email"] != "alice@example.com" {
		t.Fatalf("step a email = %q", a.Fields["email"])
	}

	// Follow the redirect like a browser: B keeps the rid in its action.
	chainedPage := request(http.MethodGet, chain.String(), nil, "")
	if chainedPage.Code != http.StatusOK {
		t.Fatalf("GET chained B: status = %d, want 200", chainedPage.Code)
	}
	if body := chainedPage.Body.String(); !strings.Contains(body, "rid="+rid) {
		t.Fatalf("chained B action lost the rid")
	}

	// The certificate is hashed and sanitised, never stored as bytes. The
	// client-supplied path must not survive in the retained name.
	certBytes := []byte("fake-pkcs12-certificate")
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("certificate", `..\evil\cert.p12`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(certBytes); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	chained := request(http.MethodPost, chain.String(), &buf, mw.FormDataContentType())
	if chained.Code != http.StatusFound {
		t.Fatalf("POST chained B: status = %d, want 302", chained.Code)
	}
	if loc := chained.Header().Get("Location"); loc != "https://example.com/account" {
		t.Fatalf("POST chained B Location = %q", loc)
	}

	b := captures.capturedStep(t, "b")
	if b.TemplateID != "tmp-003" || b.ContactID != contacts[0].ID {
		t.Fatalf("step b template/contact = %q/%q", b.TemplateID, b.ContactID)
	}
	if len(b.Files) != 1 {
		t.Fatalf("step b files = %+v, want 1", b.Files)
	}
	file := b.Files[0]
	if file.Field != "certificate" || file.Filename != "cert.p12" {
		t.Fatalf("file meta = %+v", file)
	}
	if file.Size != int64(len(certBytes)) {
		t.Fatalf("file size = %d", file.Size)
	}
	sum := sha256.Sum256(certBytes)
	if file.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("file digest = %q", file.SHA256)
	}
	if _, ok := b.Secrets["certificate"]; ok {
		t.Fatal("certificate was classified as a secret instead of file metadata")
	}

	// The accept list reaches the handler from the config, not only from the
	// rendered attribute: a wrong extension is refused before any insert.
	before := captures.count()
	var badBuf bytes.Buffer
	badWriter := multipart.NewWriter(&badBuf)
	badFile, err := badWriter.CreateFormFile("certificate", "cert.exe")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := badFile.Write(certBytes); err != nil {
		t.Fatal(err)
	}
	if err := badWriter.Close(); err != nil {
		t.Fatal(err)
	}
	bad := request(http.MethodPost, chain.String(), &badBuf, badWriter.FormDataContentType())
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("POST B with .exe: status = %d, want 400", bad.Code)
	}
	if captures.count() != before {
		t.Fatal("rejected certificate was stored")
	}
}

func TestTMP004TwoStepFlow(t *testing.T) {
	ctx := context.Background()
	ops := store.NewFake()

	campaign, err := ops.CreateCampaign(ctx, "Acme")
	if err != nil {
		t.Fatalf("CreateCampaign: %v", err)
	}
	if _, err := ops.AddContacts(ctx, campaign.ID, []store.ContactInput{{
		Email: "alice@example.com",
		Vars: map[string]string{
			"FirstName": "Alice",
			"email":     "alice@example.com",
			// Deliberately present so the test proves the seed field does not
			// prefill from contact vars, not merely that the var is absent.
			"seed": "seed-from-the-address-book",
		},
	}}); err != nil {
		t.Fatalf("AddContacts: %v", err)
	}
	contacts, err := ops.ListContacts(ctx, campaign.ID)
	if err != nil {
		t.Fatalf("ListContacts: %v", err)
	}

	cfg := tmp004Config(campaign.ID)
	captures := &captureStore{}
	h, err := newHandler(cfg, captures, ops, testLogger())
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}

	request := func(method, target string, form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		var body io.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		req := httptest.NewRequest(method, target, body)
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	rid := url.QueryEscape(contacts[0].ID)
	labels := map[string]map[string]string{
		"fr": {"email": "Adresse e-mail", "seed": "Phrase de récupération"},
		"en": {"email": "Email address", "seed": "Recovery phrase"},
		"de": {"email": "E-Mail-Adresse", "seed": "Wiederherstellungsphrase"},
	}
	// A complete 24-word BIP-39 phrase. Long enough that a rune cap would
	// silently break it; the hash assertion below proves no truncation.
	const seedValue = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

	for _, lang := range []string{"fr", "en", "de"} {
		for _, stepID := range []string{"a", "b"} {
			page := request(http.MethodGet,
				"/c/"+campaign.ID+"/tmp-004/"+stepID+"?l="+lang+"&rid="+rid, nil)
			if page.Code != http.StatusOK {
				t.Fatalf("GET %s/%s: status = %d, want 200", stepID, lang, page.Code)
			}
			body := page.Body.String()
			if !strings.Contains(body, `<html lang="`+lang+`">`) {
				t.Fatalf("GET %s/%s selected the wrong variant", stepID, lang)
			}

			if stepID == "a" {
				wantLabel := `<label for="f-email">` + labels[lang]["email"] + `</label>`
				if !strings.Contains(body, wantLabel) {
					t.Fatalf("GET a/%s missing %s", lang, wantLabel)
				}
				continue
			}

			// B asks only for the seed: the address from A is not repeated.
			if strings.Contains(body, `<input name="email"`) {
				t.Fatalf("GET b/%s repeats step A field email", lang)
			}
			wantLabel := `<label for="f-seed">` + labels[lang]["seed"] + `</label>`
			if !strings.Contains(body, wantLabel) {
				t.Fatalf("GET b/%s missing %s", lang, wantLabel)
			}
			seedTag := inputTag(t, body, "seed")
			if !strings.Contains(seedTag, `type="password"`) {
				t.Fatalf("GET b/%s seed is not a password input: %s", lang, seedTag)
			}
			if !strings.Contains(seedTag, `data-secret="1"`) {
				t.Fatalf("GET b/%s seed is not marked secret: %s", lang, seedTag)
			}
			// Never prefilled: the page does not carry the submitted value,
			// nor the contact var the address book may hold under "seed".
			if strings.Contains(seedTag, `value="`) ||
				strings.Contains(body, seedValue) ||
				strings.Contains(body, "seed-from-the-address-book") {
				t.Fatalf("GET b/%s prefilled or leaked the seed", lang)
			}
		}
	}

	style := request(http.MethodGet, "/assets/"+campaign.ID+"/tmp-004/style.css", nil)
	if style.Code != http.StatusOK || !strings.Contains(style.Body.String(), `url("mark.svg")`) {
		t.Fatalf("tmp-004 style.css: status = %d", style.Code)
	}
	if !strings.Contains(style.Body.String(), "--accent: #b45309") {
		t.Fatalf("tmp-004 served another template's stylesheet")
	}
	mark := request(http.MethodGet, "/assets/"+campaign.ID+"/tmp-004/mark.svg", nil)
	if mark.Code != http.StatusOK || !strings.Contains(mark.Body.String(), "<svg") {
		t.Fatalf("tmp-004 mark.svg: status = %d", mark.Code)
	}

	first := request(http.MethodPost,
		"/c/"+campaign.ID+"/tmp-004/a?l=fr&rid="+rid,
		url.Values{"email": {"alice@example.com"}})
	if first.Code != http.StatusFound {
		t.Fatalf("POST a: status = %d, want 302", first.Code)
	}
	chain, err := url.Parse(first.Header().Get("Location"))
	if err != nil {
		t.Fatalf("POST a Location is not a URL: %v", err)
	}
	if chain.IsAbs() || chain.Host != "" {
		t.Fatalf("POST a Location = %q, want a root-relative target", chain)
	}
	if want := "/c/" + campaign.ID + "/tmp-004/b"; chain.Path != want {
		t.Fatalf("POST a Location path = %q, want %q", chain.Path, want)
	}
	if got := chain.Query().Get("rid"); got != contacts[0].ID {
		t.Fatalf("POST a Location rid = %q, want %q", got, contacts[0].ID)
	}
	a := captures.capturedStep(t, "a")
	if a.TemplateID != "tmp-004" || a.ContactID != contacts[0].ID {
		t.Fatalf("step a template/contact = %q/%q", a.TemplateID, a.ContactID)
	}

	chainedPage := request(http.MethodGet, chain.String(), nil)
	if chainedPage.Code != http.StatusOK {
		t.Fatalf("GET chained B: status = %d, want 200", chainedPage.Code)
	}
	if body := chainedPage.Body.String(); !strings.Contains(body, "rid="+rid) {
		t.Fatalf("chained B action lost the rid")
	}

	chained := request(http.MethodPost, chain.String(), url.Values{"seed": {seedValue}})
	if chained.Code != http.StatusFound {
		t.Fatalf("POST chained B: status = %d, want 302", chained.Code)
	}
	if loc := chained.Header().Get("Location"); loc != "https://example.com/account" {
		t.Fatalf("POST chained B Location = %q", loc)
	}

	b := captures.capturedStep(t, "b")
	if b.TemplateID != "tmp-004" || b.ContactID != contacts[0].ID {
		t.Fatalf("step b template/contact = %q/%q", b.TemplateID, b.ContactID)
	}
	if _, leaked := b.Fields["seed"]; leaked {
		t.Fatal("seed stored in the clear fields map")
	}
	secret, ok := b.Secrets["seed"]
	if !ok {
		t.Fatal("seed was not stored as a secret")
	}
	if secret.Kind != collect.KindSeed {
		t.Fatalf("seed kind = %q, want %q", secret.Kind, collect.KindSeed)
	}
	if !secret.Present || secret.Length != len(seedValue) {
		t.Fatalf("seed secret = %+v", secret)
	}
	sum := sha256.Sum256([]byte(seedValue))
	if secret.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("seed hash = %q", secret.SHA256)
	}

	// The whole artifact must not carry the clear value anywhere, including
	// once it is serialized for export.
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal artifact: %v", err)
	}
	if strings.Contains(string(raw), seedValue) {
		t.Fatalf("clear seed appears in the artifact: %s", raw)
	}
}

// inputTag returns the complete opening tag of one named input, so an
// assertion can prove an attribute is attached to that field and not merely
// present somewhere on the page.
func inputTag(t *testing.T, body, name string) string {
	t.Helper()
	start := strings.Index(body, `<input name="`+name+`"`)
	if start < 0 {
		t.Fatalf("page has no input named %q:\n%s", name, body)
	}
	end := strings.IndexByte(body[start:], '>')
	if end < 0 {
		t.Fatalf("input %q has no closing bracket:\n%s", name, body)
	}
	return body[start : start+end+1]
}

func TestTMP001RejectsIncompleteLabels(t *testing.T) {
	tests := map[string]struct {
		mutate func(map[string]string) map[string]string
		want   string
	}{
		"missing language": {
			mutate: func(labels map[string]string) map[string]string {
				delete(labels, "de")
				return labels
			},
			want: "missing",
		},
		"unshipped language": {
			mutate: func(labels map[string]string) map[string]string {
				labels["es"] = "Identificador"
				return labels
			},
			want: "not shipped",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := tmp001Config("acme")
			step := cfg.Campaigns["acme"].Templates["tmp-001"]["a"]
			step.Fields[0].Labels = tc.mutate(step.Fields[0].Labels)
			cfg.Campaigns["acme"].Templates["tmp-001"]["a"] = step

			_, err := newHandler(cfg, &captureStore{}, store.NewFake(), testLogger())
			if err == nil {
				t.Fatal("incomplete labels accepted at boot")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestTMP002RejectsIBANDeclaredText(t *testing.T) {
	cfg := tmp002Config("acme")
	step := cfg.Campaigns["acme"].Templates["tmp-002"]["a"]
	step.Fields[1].Kind = "text"
	cfg.Campaigns["acme"].Templates["tmp-002"]["a"] = step

	_, err := newHandler(cfg, &captureStore{}, store.NewFake(), testLogger())
	if err == nil {
		t.Fatal("an IBAN declared as text was accepted at boot")
	}
	if !strings.Contains(err.Error(), `field "iban"`) || !strings.Contains(err.Error(), "iban") {
		t.Fatalf("error = %v, want the IBAN field and its kind", err)
	}
}

func TestTMP002RejectsFieldRepeatedAcrossSteps(t *testing.T) {
	cfg := tmp002Config("acme")
	step := cfg.Campaigns["acme"].Templates["tmp-002"]["b"]
	step.Fields = []fieldConfig{{Name: "email", Kind: "text"}}
	cfg.Campaigns["acme"].Templates["tmp-002"]["b"] = step

	_, err := newHandler(cfg, &captureStore{}, store.NewFake(), testLogger())
	if err == nil {
		t.Fatal("a field repeated on the confirmation step was accepted at boot")
	}
	if !strings.Contains(err.Error(), "declared in steps") {
		t.Fatalf("error = %v, want a cross-step duplicate", err)
	}
}

func TestExampleConfigBindsTMP001(t *testing.T) {
	cfg, err := loadConfig(filepath.Join("..", "..", "config.example.json"))
	if err != nil {
		t.Fatalf("loadConfig example: %v", err)
	}
	// The reference config must chain the flow: step A's declared target is
	// the in-app URL of step B, not an unrelated landing page.
	steps := cfg.Campaigns["acme"].Templates["tmp-001"]
	if got, want := steps["a"].Target, "/c/acme/tmp-001/b"; got != want {
		t.Fatalf("step a target = %q, want %q", got, want)
	}
	if _, err := newHandler(cfg, &captureStore{}, store.NewFake(), testLogger()); err != nil {
		t.Fatalf("newHandler example: %v", err)
	}
}

func TestValidateSummariesRejectsSecretOrUnknownField(t *testing.T) {
	cases := map[string]struct {
		field string
		want  string
	}{
		"secret kind": {field: "iban", want: "secret"},
		"unknown":     {field: "phone", want: "not declared"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			variants := map[string][]tmpl.Variant{
				"b": {{Lang: "fr", SummaryField: tc.field, SummaryLabel: "Valeur"}},
			}
			steps := map[string]stepConfig{
				"a": {Fields: []fieldConfig{{Name: "iban", Kind: "iban"}}},
			}
			err := validateSummaries(variants, steps)
			if err == nil {
				t.Fatal("invalid summary accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestExampleConfigBindsTMP002(t *testing.T) {
	cfg, err := loadConfig(filepath.Join("..", "..", "config.example.json"))
	if err != nil {
		t.Fatalf("loadConfig example: %v", err)
	}
	steps := cfg.Campaigns["acme"].Templates["tmp-002"]
	if got, want := steps["a"].Target, "/c/acme/tmp-002/b"; got != want {
		t.Fatalf("step a target = %q, want %q", got, want)
	}
	if len(steps["b"].Fields) != 0 {
		t.Fatalf("confirmation step declares %d fields, want 0", len(steps["b"].Fields))
	}
	if _, err := newHandler(cfg, &captureStore{}, store.NewFake(), testLogger()); err != nil {
		t.Fatalf("newHandler example: %v", err)
	}
}

func TestTMP004RejectsSeedDeclaredText(t *testing.T) {
	cfg := tmp004Config("acme")
	step := cfg.Campaigns["acme"].Templates["tmp-004"]["b"]
	step.Fields[0].Kind = "text"
	cfg.Campaigns["acme"].Templates["tmp-004"]["b"] = step

	_, err := newHandler(cfg, &captureStore{}, store.NewFake(), testLogger())
	if err == nil {
		t.Fatal("a recovery seed declared as text was accepted at boot")
	}
	if !strings.Contains(err.Error(), `field "seed"`) || !strings.Contains(err.Error(), `"seed"`) {
		t.Fatalf("error = %v, want the seed field and its implied kind", err)
	}
}

func TestTMP004RejectsSeedMaxLen(t *testing.T) {
	cfg := tmp004Config("acme")
	step := cfg.Campaigns["acme"].Templates["tmp-004"]["b"]
	step.Fields[0].MaxLen = 256
	cfg.Campaigns["acme"].Templates["tmp-004"]["b"] = step

	_, err := newHandler(cfg, &captureStore{}, store.NewFake(), testLogger())
	if err == nil {
		t.Fatal("a recovery seed with max_len was accepted at boot")
	}
	if !strings.Contains(err.Error(), `field "seed"`) || !strings.Contains(err.Error(), "max_len") {
		t.Fatalf("error = %v, want the seed field and max_len", err)
	}
}

func TestTMP003AndTMP004RejectFieldRepeatedAcrossSteps(t *testing.T) {
	tests := map[string]struct {
		cfg  *fileConfig
		step string
		name string
		kind string
	}{
		"tmp-003": {cfg: tmp003Config("acme"), step: "b", name: "email", kind: "text"},
		"tmp-004": {cfg: tmp004Config("acme"), step: "b", name: "email", kind: "text"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			steps := tc.cfg.Campaigns["acme"].Templates[name]
			step := steps[tc.step]
			step.Fields = append(step.Fields, fieldConfig{Name: tc.name, Kind: tc.kind})
			steps[tc.step] = step
			tc.cfg.Campaigns["acme"].Templates[name] = steps

			_, err := newHandler(tc.cfg, &captureStore{}, store.NewFake(), testLogger())
			if err == nil {
				t.Fatal("a field repeated across steps was accepted at boot")
			}
			if !strings.Contains(err.Error(), "declared in steps") {
				t.Fatalf("error = %v, want a cross-step duplicate", err)
			}
		})
	}
}

func TestAcceptNormalizesAndValidatesExtensions(t *testing.T) {
	// These inputs must be rejected after normalization.
	invalid := map[string]struct {
		field fieldConfig
		want  string
	}{
		"non-file field": {
			field: fieldConfig{Name: "certificate", Kind: "text", Accept: []string{".p12"}},
			want:  "only valid for a file field",
		},
		"MIME type": {
			field: fieldConfig{Name: "certificate", Kind: "file", Accept: []string{"application/pkcs12"}},
			want:  "is not an extension",
		},
		"path": {
			field: fieldConfig{Name: "certificate", Kind: "file", Accept: []string{".p12/x"}},
			want:  "is not an extension",
		},
		"duplicate": {
			// ".P12" normalizes to ".p12"; a second ".p12" is a duplicate.
			field: fieldConfig{Name: "certificate", Kind: "file", Accept: []string{".P12", ".p12"}},
			want:  "listed twice",
		},
		"empty token": {
			field: fieldConfig{Name: "certificate", Kind: "file", Accept: []string{""}},
			want:  "is not an extension",
		},
		"dot only": {
			// "." has length 1; the body is empty, which validAcceptExtension refuses.
			field: fieldConfig{Name: "certificate", Kind: "file", Accept: []string{"."}},
			want:  "is not an extension",
		},
		"no dot": {
			// "p12" has no leading dot; validAcceptExtension refuses it.
			field: fieldConfig{Name: "certificate", Kind: "file", Accept: []string{"p12"}},
			want:  "is not an extension",
		},
		"trailing dot": {
			// ".p12." contains a second dot in the body; the loop refuses it
			// because '.' is not in [a-z0-9].
			field: fieldConfig{Name: "certificate", Kind: "file", Accept: []string{".p12."}},
			want:  "is not an extension",
		},
	}
	for name, tc := range invalid {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig()
			setStep(cfg, stepConfig{Target: "https://example.com/", Fields: []fieldConfig{tc.field}})
			err := cfg.validate()
			if err == nil {
				t.Fatal("invalid accept list accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}

	// Uppercase extensions are normalized, not rejected. An operator who
	// writes ".JPG" or ".Jpg" gets the same result as ".jpg".
	t.Run("uppercase normalized", func(t *testing.T) {
		cfg := validConfig()
		setStep(cfg, stepConfig{Target: "https://example.com/", Fields: []fieldConfig{
			{Name: "photo", Kind: "file", Accept: []string{".JPG", ".PNG"}},
		}})
		if err := cfg.validate(); err != nil {
			t.Fatalf("uppercase accept rejected: %v", err)
		}
		got := cfg.Campaigns["acme"].Templates["t1"]["s1"].Fields[0].Accept
		if strings.Join(got, ",") != ".jpg,.png" {
			t.Fatalf("accept after normalization = %v, want [.jpg .png]", got)
		}
	})

	// An empty list is the explicit "accept any file" case: no error, no
	// attribute emitted, and the collector checks no extension.
	t.Run("empty accept any file", func(t *testing.T) {
		cfg := validConfig()
		setStep(cfg, stepConfig{Target: "https://example.com/", Fields: []fieldConfig{
			{Name: "certificate", Kind: "file"},
		}})
		if err := cfg.validate(); err != nil {
			t.Fatalf("empty accept list rejected: %v", err)
		}
		if got := cfg.Campaigns["acme"].Templates["t1"]["s1"].Fields[0].Accept; len(got) != 0 {
			t.Fatalf("empty accept list became %v", got)
		}
		if attrs := (collect.Field{Name: "certificate", Kind: collect.KindFile}).Attrs(); hasAttr(attrs, "accept") {
			t.Fatal("empty accept list rendered an accept attribute")
		}
	})
}

func hasAttr(attrs []collect.Attribute, name string) bool {
	for _, a := range attrs {
		if a.Name == name {
			return true
		}
	}
	return false
}

func TestTMP003AcceptListMatchesSignatureCopy(t *testing.T) {
	cfg, err := loadConfig(filepath.Join("..", "..", "config.example.json"))
	if err != nil {
		t.Fatalf("loadConfig example: %v", err)
	}
	steps := cfg.Campaigns["acme"].Templates["tmp-003"]
	cert := steps["b"].Fields[0]
	if len(cert.Accept) == 0 {
		t.Skip("tmp-003 step b has no accept list; nothing to verify")
	}

	// Collect all copy text from tmp003Signature variants.
	def, ok := lethe.Lookup("tmp-003")
	if !ok {
		t.Fatal("tmp-003 not registered")
	}
	sigVariants, ok := def.Steps["b"]
	if !ok {
		t.Fatal("tmp-003 step b not found")
	}
	allCopy := make([]string, 0, len(sigVariants))
	for _, v := range sigVariants {
		allCopy = append(allCopy, v.Note, v.Intro, v.Title, v.Heading)
	}
	combined := strings.Join(allCopy, " ")

	// Every extension declared in config must appear somewhere in the copy.
	// A missing extension means the copy and the config have drifted.
	for _, ext := range cert.Accept {
		// Accept entries are stored without the leading dot in display contexts,
		// and with it. Check both: ".p12" and "p12".
		withDot := ext
		withoutDot := strings.TrimPrefix(ext, ".")
		if !strings.Contains(combined, withDot) && !strings.Contains(combined, withoutDot) {
			t.Errorf("config accept extension %q not found in any tmp003Signature variant copy;\n"+
				"update the Note/Intro to mention it, or accept the documented duplication", ext)
		}
	}
}

func TestExampleConfigBindsTMP003(t *testing.T) {
	cfg, err := loadConfig(filepath.Join("..", "..", "config.example.json"))
	if err != nil {
		t.Fatalf("loadConfig example: %v", err)
	}
	steps := cfg.Campaigns["acme"].Templates["tmp-003"]
	if got, want := steps["a"].Target, "/c/acme/tmp-003/b"; got != want {
		t.Fatalf("step a target = %q, want %q", got, want)
	}
	if len(steps["b"].Fields) != 1 {
		t.Fatalf("step b declares %d fields, want 1", len(steps["b"].Fields))
	}
	cert := steps["b"].Fields[0]
	if cert.Name != "certificate" || cert.Kind != "file" {
		t.Fatalf("step b field = %+v, want a certificate file", cert)
	}
	if got, want := strings.Join(cert.Accept, ","), ".p12,.pfx"; got != want {
		t.Fatalf("accept = %q, want %q", got, want)
	}
	if _, err := newHandler(cfg, &captureStore{}, store.NewFake(), testLogger()); err != nil {
		t.Fatalf("newHandler example: %v", err)
	}
}

func TestExampleConfigBindsTMP004(t *testing.T) {
	cfg, err := loadConfig(filepath.Join("..", "..", "config.example.json"))
	if err != nil {
		t.Fatalf("loadConfig example: %v", err)
	}
	steps := cfg.Campaigns["acme"].Templates["tmp-004"]
	if got, want := steps["a"].Target, "/c/acme/tmp-004/b"; got != want {
		t.Fatalf("step a target = %q, want %q", got, want)
	}
	if len(steps["b"].Fields) != 1 {
		t.Fatalf("step b declares %d fields, want 1", len(steps["b"].Fields))
	}
	seed := steps["b"].Fields[0]
	if seed.Name != "seed" || seed.Kind != "seed" {
		t.Fatalf("step b field = %+v, want the seed kind", seed)
	}
	if _, err := newHandler(cfg, &captureStore{}, store.NewFake(), testLogger()); err != nil {
		t.Fatalf("newHandler example: %v", err)
	}
}

func TestExportCampaignNamesCorruptRow(t *testing.T) {
	handle, err := sirendb.Open("file:" + filepath.Join(t.TempDir(), "export.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { handle.Close() })

	key := bytes.Repeat([]byte{3}, 32)
	ks, err := collect.NewKeySet(1, map[byte][]byte{1: key})
	if err != nil {
		t.Fatal(err)
	}
	arts, err := collect.NewSQLiteFrom(handle.DB, ks)
	if err != nil {
		t.Fatal(err)
	}

	base := time.Date(2026, 11, 5, 15, 0, 0, 0, time.UTC)
	for i, id := range []string{"good", "corrupt", "after"} {
		a := &collect.Artifact{
			ID: id, CampaignID: "c1", TemplateID: "t", Step: "a",
			ReceivedAt: base.Add(time.Duration(i) * time.Second),
			RemoteIP:   "203.0.113.1", Target: "https://example.com/",
		}
		if err := arts.Insert(context.Background(), a); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := handle.Exec(`UPDATE artifacts SET body = X'FF' WHERE id = 'corrupt'`); err != nil {
		t.Fatal(err)
	}

	var out strings.Builder
	_, err = charon.Export(context.Background(), arts, "c1", time.Time{}, &out, nil)
	if err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("error = %v, want the corrupt id", err)
	}
	written := out.String()
	if !strings.Contains(written, `"good"`) {
		t.Fatalf("Export lost the rows written before the failure:\n%s", written)
	}
	if strings.Contains(written, `"after"`) {
		t.Fatalf("Export continued past the corrupt row:\n%s", written)
	}
}

func TestExportRouteIsWired(t *testing.T) {
	ctx := context.Background()
	ops := store.NewFake()
	campaign, err := ops.CreateCampaign(ctx, "Acme")
	if err != nil {
		t.Fatal(err)
	}
	if err := ops.SetExportTokenHash(ctx, campaign.ID, charon.HashToken("tok")); err != nil {
		t.Fatal(err)
	}

	h, err := newHandler(tmp001Config(campaign.ID), &captureStore{}, ops, testLogger())
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}

	call := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/export/"+campaign.ID, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	if rr := call("tok"); rr.Code != http.StatusOK {
		t.Fatalf("authorized export: status = %d, body = %q", rr.Code, rr.Body.String())
	}
	if rr := call(""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous export: status = %d, want 401", rr.Code)
	}
}

func TestIssueExportTokenRejectsUnknownCampaign(t *testing.T) {
	if err := issueExportToken(store.NewFake(), "missing"); err == nil {
		t.Fatal("token issued for an unknown campaign")
	}
}

func TestAssetsRoute(t *testing.T) {
	h, err := newHandler(validConfig(), &captureStore{}, store.NewFake(), testLogger())
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}

	get := func(target string) *httptest.ResponseRecorder {
		t.Helper()
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, target, nil))
		return rr
	}

	first := get("/assets/acme/t1/style.css")
	if first.Code != http.StatusOK {
		t.Fatalf("known asset: status = %d, want 200", first.Code)
	}
	if ct := first.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/css") {
		t.Fatalf("Content-Type = %q, want text/css", ct)
	}
	if !strings.Contains(first.Body.String(), "box-sizing") {
		t.Fatalf("known asset body does not look like the stylesheet:\n%s", first.Body.String())
	}
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("known asset has no ETag")
	}
	if lm := first.Header().Get("Last-Modified"); lm == "" {
		t.Fatal("known asset has no Last-Modified")
	}

	second := get("/assets/acme/t1/style.css")
	if got := second.Header().Get("ETag"); got != etag {
		t.Fatalf("ETag changed between requests: %q then %q", etag, got)
	}

	conditional := httptest.NewRequest(http.MethodGet, "/assets/acme/t1/style.css", nil)
	conditional.Header.Set("If-None-Match", etag)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, conditional)
	if rr.Code != http.StatusNotModified {
		t.Fatalf("conditional request: status = %d, want 304", rr.Code)
	}

	for _, target := range []string{
		"/assets/acme/t1/missing.css",
		"/assets/acme/unknown/style.css",
		"/assets/acme/t1/../style.css",
		"/assets/acme/t1/..%2fstyle.css",
		"/assets/acme/t1/%2e%2e/style.css",
	} {
		if rr := get(target); rr.Code != http.StatusNotFound {
			t.Fatalf("%s: status = %d, want 404", target, rr.Code)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/assets/acme/t1/style.css", nil)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST asset: status = %d, want 405", rr.Code)
	}
}

func TestExportRouteDisjointFromBeacon(t *testing.T) {
	cfg := validConfig()
	cfg.BeaconPrefix = charon.ExportPrefix
	if err := cfg.validate(); err == nil {
		t.Fatal("beacon_prefix /export was accepted")
	} else if !strings.Contains(err.Error(), "export") {
		t.Fatalf("error = %v, want an export conflict", err)
	}
	if _, err := newHandler(cfg, &captureStore{}, store.NewFake(), testLogger()); err == nil {
		t.Fatal("newHandler accepted a conflicting beacon prefix /export")
	}
}

func TestAssetsRouteDisjointFromBeacon(t *testing.T) {
	if tmpl.AssetsPrefix == "/c" {
		t.Fatal("assets and capture routes share a root segment")
	}

	cfg := validConfig()
	cfg.BeaconPrefix = tmpl.AssetsPrefix
	if err := cfg.validate(); err == nil {
		t.Fatal("beacon_prefix /assets accepted")
	} else if !strings.Contains(err.Error(), "assets") {
		t.Fatalf("error = %v, want an assets conflict", err)
	}

	// newHandler validates before registering patterns, so the conflict must
	// be an error rather than a ServeMux panic.
	if _, err := newHandler(cfg, &captureStore{}, store.NewFake(), testLogger()); err == nil {
		t.Fatal("newHandler accepted a conflicting beacon prefix")
	}

	cfg = validConfig()
	cfg.BeaconPrefix = collect.DefaultBeaconPrefix
	if err := cfg.validate(); err != nil {
		t.Fatalf("default beacon prefix rejected: %v", err)
	}
}

func TestFieldNameCharset(t *testing.T) {
	bad := []string{
		"first name",
		`email"`,
		"<script>",
		"a%2Fb",
		"user[email]",
		"naïve",
		"a/b",
		"a:b",
		"a\tb",
	}
	for _, name := range bad {
		cfg := validConfig()
		setStep(cfg, stepConfig{
			Target: "https://example.com/",
			Fields: []fieldConfig{{Name: name, Kind: "text"}},
		})
		err := cfg.validate()
		if err == nil {
			t.Fatalf("field name %q accepted", name)
		}
		if !strings.Contains(err.Error(), "must match [A-Za-z0-9_.-]+") {
			t.Fatalf("field name %q: error = %v, want charset error", name, err)
		}
	}

	for _, name := range []string{"email", "user.name_1-2", "A", "__siren", "f-1"} {
		cfg := validConfig()
		setStep(cfg, stepConfig{
			Target: "https://example.com/",
			Fields: []fieldConfig{{Name: name, Kind: "text"}},
		})
		if err := cfg.validate(); err != nil {
			t.Fatalf("safe field name %q rejected: %v", name, err)
		}
	}
}

// TestDotSegmentPatternIsUnreachable pins the reason validateBeaconPrefix
// rejects /./... and /../...: ServeMux redirects the request to the cleaned
// path, which the pattern no longer matches. If a future Go release normalized
// the pattern at registration instead, this test would fail and the guard
// would need revisiting.
func TestDotSegmentPatternIsUnreachable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/./{token}/fp/{id}", func(http.ResponseWriter, *http.Request) {
		t.Fatal("dot-segment pattern reached its handler")
	})

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "http://beacon.invalid/./tok/fp/id", strings.NewReader("{}")))
	if rr.Code < 300 || rr.Code >= 400 {
		t.Fatalf("dot-segment request: status = %d, want a redirect to the cleaned path", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if loc != "/tok/fp/id" {
		t.Fatalf("Location = %q, want /tok/fp/id", loc)
	}

	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "http://beacon.invalid"+loc, strings.NewReader("{}")))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("cleaned path: status = %d, want 404", rr.Code)
	}
}

func TestLoadConfigRejectsUnknownFields(t *testing.T) {
	const body = `{
		"listen": "127.0.0.1:0",
		"data_dir": "data",
		"trusted_proxy": ["173.245.48.0/20"],
		"campaigns": {"acme": {"templates": {"t1": {"s1": {
			"target": "https://example.com/"
		}}}}}
	}`
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("mistyped trusted_proxy accepted: strict decoding is off")
	} else if !strings.Contains(err.Error(), "trusted_proxy") {
		t.Fatalf("error = %v, want the unknown field name", err)
	}
}

func TestLoadConfigRejectsTrailingValues(t *testing.T) {
	const base = `{
		"listen": "127.0.0.1:0",
		"data_dir": "data",
		"campaigns": {"acme": {"templates": {"t1": {"s1": {
			"target": "https://example.com/"
		}}}}}
	}`
	for name, body := range map[string]string{
		"second JSON value": base + `{}`,
		"trailing garbage":  base + `x`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadConfig(path); err == nil {
				t.Fatal("trailing data accepted")
			}
		})
	}
}

func TestEnsureDataDir(t *testing.T) {
	t.Run("creates nested directory", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "siren", "data")
		if err := ensureDataDir(dir); err != nil {
			t.Fatalf("ensureDataDir: %v", err)
		}
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if !info.IsDir() {
			t.Fatalf("%q is not a directory", dir)
		}
		if runtime.GOOS != "windows" {
			if perm := info.Mode().Perm(); perm != 0o700 {
				t.Fatalf("mode = %04o, want 0700", perm)
			}
		}
	})

	t.Run("accepts existing private directory", func(t *testing.T) {
		if err := ensureDataDir(t.TempDir()); err != nil {
			t.Fatalf("ensureDataDir on existing dir: %v", err)
		}
	})

	t.Run("rejects regular file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "not-a-dir")
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := ensureDataDir(path); err == nil {
			t.Fatal("file accepted as data_dir")
		}
	})

	t.Run("rejects directory open to group or others", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("POSIX mode bits are not the access boundary on Windows")
		}
		dir := filepath.Join(t.TempDir(), "loose")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		if err := ensureDataDir(dir); err == nil {
			t.Fatal("world-traversable data_dir accepted")
		}
	})
}

func TestResolveDBPath(t *testing.T) {
	dataDir := filepath.Join("srv", "siren", "data")

	if got, want := resolveDBPath("", dataDir), filepath.Join(dataDir, "artifacts.db"); got != want {
		t.Fatalf("default = %q, want %q", got, want)
	}
	// -db must win outright: the boot path secures filepath.Dir(result), so a
	// wrong answer here would chmod the data_dir instead of the real parent.
	override := filepath.Join("mnt", "fast", "siren.db")
	if got := resolveDBPath(override, dataDir); got != override {
		t.Fatalf("-db override = %q, want %q", got, override)
	}
	abs := filepath.Join(string(filepath.Separator), "var", "lib", "siren", "artifacts.db")
	if got := resolveDBPath(abs, dataDir); got != abs {
		t.Fatalf("-db absolute override = %q, want %q", got, abs)
	}
}

func TestRetireKeyIDRange(t *testing.T) {
	for _, v := range []int{1, 44, 255} {
		got, err := retireKeyID(v)
		if err != nil || got != byte(v) {
			t.Fatalf("retireKeyID(%d) = %d, %v", v, got, err)
		}
	}
	for _, v := range []int{-1, 0, 256, 300} {
		if _, err := retireKeyID(v); err == nil {
			t.Fatalf("retireKeyID(%d) accepted", v)
		}
	}
}

func TestServeShutsDownOnContextCancel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- serve(ctx, ln, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}), testLogger())
	}()

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + ln.Addr().String() + "/healthz")
	if err != nil {
		t.Fatalf("request before shutdown: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("serve returned %v, want nil after cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return within 5s of cancellation")
	}
}
