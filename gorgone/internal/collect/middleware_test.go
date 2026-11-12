package collect

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
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
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------- fixtures

type memStore struct {
	mu   sync.Mutex
	m    map[string]*Artifact
	fail error
}

func newMemStore() *memStore { return &memStore{m: make(map[string]*Artifact)} }

func (s *memStore) Insert(_ context.Context, a *Artifact) error {
	if s.fail != nil {
		return s.fail
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *a
	s.m[a.ID] = &cp
	return nil
}

func (s *memStore) AttachFingerprint(_ context.Context, id string, fp *Fingerprint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.m[id]
	if !ok {
		return ErrArtifactNotFound
	}
	a.Fingerprint = fp
	return nil
}

func (s *memStore) Get(_ context.Context, id string) (*Artifact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.m[id]
	if !ok {
		return nil, ErrArtifactNotFound
	}
	cp := *a
	return &cp, nil
}

func (s *memStore) Export(_ context.Context, campaignID string, since time.Time, fn func(*Artifact) error) error {
	s.mu.Lock()
	out := make([]*Artifact, 0, len(s.m))
	for _, a := range s.m {
		cp := *a
		out = append(out, &cp)
	}
	s.mu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		if !out[i].ReceivedAt.Equal(out[j].ReceivedAt) {
			return out[i].ReceivedAt.Before(out[j].ReceivedAt)
		}
		return out[i].ID < out[j].ID
	})
	for _, a := range out {
		if a.CampaignID != campaignID {
			continue
		}
		if !since.IsZero() && !a.ReceivedAt.After(since) {
			continue
		}
		if err := fn(a); err != nil {
			return err
		}
	}
	return nil
}

func (s *memStore) Rotate(context.Context) (int, error) { return 0, nil }

func (s *memStore) KeyUsage(context.Context) (map[byte]int, error) { return map[byte]int{}, nil }

func (s *memStore) RetireKey(context.Context, byte) error { return nil }

func (s *memStore) Close() error { return nil }

func (s *memStore) all(t *testing.T) []*Artifact {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Artifact, 0, len(s.m))
	for _, a := range s.m {
		out = append(out, a)
	}
	return out
}

func (s *memStore) only(t *testing.T) *Artifact {
	t.Helper()
	all := s.all(t)
	if len(all) != 1 {
		t.Fatalf("expected exactly 1 artifact, got %d", len(all))
	}
	return all[0]
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func steps(m map[string]Step) Resolver {
	return func(c, tpl, s string) (Step, error) {
		st, ok := m[c+"/"+tpl+"/"+s]
		if !ok {
			return Step{}, errors.New("unknown step")
		}
		return st, nil
	}
}

func newTestCollector(t *testing.T, st Store, m map[string]Step) *Collector {
	t.Helper()
	c, err := New(Config{Resolve: steps(m), Logger: quietLogger()}, st)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func post(t *testing.T, h http.HandlerFunc, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func testKeySet(t *testing.T, active byte, ids ...byte) *KeySet {
	t.Helper()
	keys := map[byte][]byte{}
	for _, id := range ids {
		k := make([]byte, 32)
		for i := range k {
			k[i] = id
		}
		keys[id] = k
	}
	ks, err := NewKeySet(active, keys)
	if err != nil {
		t.Fatalf("keyset: %v", err)
	}
	return ks
}

// ---------------------------------------------------------------- capture

func TestCaptureRedirectsDirectlyAndHashesSecrets(t *testing.T) {
	st := newMemStore()
	const target = "https://portal.example.com/home"

	c := newTestCollector(t, st, map[string]Step{
		"acme/tmp-001/step-b": {
			Target: target,
			Fields: []Field{
				{Name: "email", Kind: KindText},
				{Name: "password", Kind: KindPassword},
				{Name: "code", Kind: KindOTP},
			},
		},
	})

	rec := post(t, c.Capture("acme", "tmp-001", "step-b"), "/c/acme/tmp-001/step-b", url.Values{
		"email":    {"alice@example.com"},
		"password": {"CorrectHorseBattery"},
		"code":     {"418902"},
	})

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != target {
		t.Fatalf("Location = %q, want %q", loc, target)
	}
	if body := rec.Body.String(); body != "" {
		t.Fatalf("inline mode must not render a bridge, got %q", body)
	}

	a := st.only(t)
	if _, leaked := a.Fields["password"]; leaked {
		t.Fatal("password stored in clear")
	}
	sec, ok := a.Secrets["password"]
	if !ok || !sec.Present || sec.Length != len("CorrectHorseBattery") || len(sec.SHA256) != 64 {
		t.Fatalf("bad secret shape: %+v", sec)
	}
	if sec.Kind != KindPassword {
		t.Fatalf("kind = %q", sec.Kind)
	}
	if a.Secrets["code"].Kind != KindOTP {
		t.Fatal("schema kind not propagated")
	}
	if a.Fields["email"] != "alice@example.com" {
		t.Fatalf("email mangled: %q", a.Fields["email"])
	}
}

func TestSchemaOverridesNameHeuristic(t *testing.T) {
	st := newMemStore()
	c := newTestCollector(t, st, map[string]Step{
		"acme/tmp-002/step-b": {
			Target: "https://example.com/",
			Fields: []Field{
				// "user" is not password-shaped, but the schema says it is.
				{Name: "user", Kind: KindText, Secret: true},
				// "password_hint" matches the name heuristic but is declared
				// non-secret: the schema wins.
				{Name: "password_hint", Kind: KindText, Secret: false},
			},
		},
	})

	post(t, c.Capture("acme", "tmp-002", "step-b"), "/c/acme/tmp-002/step-b", url.Values{
		"user":          {"alice"},
		"password_hint": {"first pet"},
	})

	a := st.only(t)
	if _, ok := a.Secrets["user"]; !ok {
		t.Fatal("schema-declared secret was stored in clear")
	}
	if a.Fields["password_hint"] != "first pet" {
		t.Fatal("schema exemption was overridden by the name heuristic")
	}
}

func TestShapeDetectionCatchesUnlabelledValues(t *testing.T) {
	st := newMemStore()
	c := newTestCollector(t, st, map[string]Step{
		"acme/tmp-002/step-b": {
			Target: "https://example.com/",
			Fields: []Field{{Name: "account", Kind: KindText}, {Name: "num", Kind: KindText}},
		},
	})

	post(t, c.Capture("acme", "tmp-002", "step-b"), "/c/acme/tmp-002/step-b", url.Values{
		"account": {"FR7630006000011234567890189"},
		"num":     {"4111111111111111"},
	})

	a := st.only(t)
	if _, ok := a.Secrets["account"]; !ok {
		t.Fatal("IBAN under a neutral name was stored in clear")
	}
	if a.Secrets["account"].Kind != KindIBAN {
		t.Fatalf("kind = %q, want iban", a.Secrets["account"].Kind)
	}
	if _, ok := a.Secrets["num"]; !ok {
		t.Fatal("PAN under a neutral name was stored in clear")
	}
	if a.Secrets["num"].Kind != KindPAN {
		t.Fatalf("kind = %q, want pan", a.Secrets["num"].Kind)
	}
}

func TestIBANChecksumRejectsLookalikes(t *testing.T) {
	if !looksLikeIBAN("FR7630006000011234567890189") {
		t.Fatal("canonical IBAN rejected")
	}
	if looksLikeIBAN("FR7630006000011234567890188") {
		t.Fatal("IBAN with a broken checksum accepted")
	}
	if looksLikeIBAN("FR763000600001123456789") {
		t.Fatal("short IBAN accepted")
	}
	if !luhnValid("4111 1111 1111 1111") {
		t.Fatal("spaced PAN rejected")
	}
	if luhnValid("4111111111111112") {
		t.Fatal("invalid PAN accepted")
	}
}

func TestInlineFingerprintFieldIsParsedNotStored(t *testing.T) {
	st := newMemStore()
	c := newTestCollector(t, st, map[string]Step{
		"acme/tmp-001/step-b": {
			Target: "https://example.com/",
			Fields: []Field{{Name: "email", Kind: KindText}},
		},
	})

	fpJSON, _ := json.Marshal(Fingerprint{Timezone: "Europe/Paris", WebGLHash: "deadbeef"})
	encoded := base64.RawURLEncoding.EncodeToString(fpJSON)

	post(t, c.Capture("acme", "tmp-001", "step-b"), "/c/acme/tmp-001/step-b", url.Values{
		"email":          {"alice@example.com"},
		FingerprintField: {encoded},
	})

	a := st.only(t)
	if a.Fingerprint == nil || a.Fingerprint.Timezone != "Europe/Paris" {
		t.Fatalf("fingerprint not parsed: %+v", a.Fingerprint)
	}
	if a.Fingerprint.CollectedAt.IsZero() {
		t.Fatal("CollectedAt not stamped")
	}
	if _, ok := a.Fields[FingerprintField]; ok {
		t.Fatal("raw fingerprint blob retained as a field")
	}
}

func TestMalformedFingerprintDoesNotRejectSubmission(t *testing.T) {
	st := newMemStore()
	c := newTestCollector(t, st, map[string]Step{
		"acme/tmp-001/step-b": {Target: "https://example.com/"},
	})
	rec := post(t, c.Capture("acme", "tmp-001", "step-b"), "/c/acme/tmp-001/step-b", url.Values{
		"email":          {"alice@example.com"},
		FingerprintField: {"!!!not-base64!!!"},
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	a := st.only(t)
	if a.Fingerprint != nil {
		t.Fatal("malformed fingerprint accepted")
	}
	if a.Fields["email"] != "alice@example.com" {
		t.Fatal("submission lost because the fingerprint was bad")
	}
}

func TestDoubleSubmissionPersistsTwoArtifacts(t *testing.T) {
	st := newMemStore()
	c := newTestCollector(t, st, map[string]Step{
		"acme/tmp-001/step-b": {
			Target: "https://example.com/",
			Fields: []Field{{Name: "code", Kind: KindOTP}},
		},
	})

	h := c.Capture("acme", "tmp-001", "step-b")
	for i := 0; i < 2; i++ {
		rec := post(t, h, "/c/acme/tmp-001/step-b", url.Values{"code": {"111111"}})
		if rec.Code != http.StatusFound {
			t.Fatalf("submission %d: status = %d", i, rec.Code)
		}
	}

	all := st.all(t)
	if len(all) != 2 {
		t.Fatalf("expected 2 artifacts, got %d", len(all))
	}
	if all[0].ID == all[1].ID {
		t.Fatal("two submissions shared an ID")
	}
}

func TestStoreFailureStillRedirects(t *testing.T) {
	st := newMemStore()
	st.fail = errors.New("disk full")
	c := newTestCollector(t, st, map[string]Step{
		"acme/tmp-001/step-b": {Target: "https://example.com/"},
	})

	rec := post(t, c.Capture("acme", "tmp-001", "step-b"), "/c/acme/tmp-001/step-b", url.Values{
		"email": {"alice@example.com"},
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 despite store failure", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://example.com/" {
		t.Fatalf("Location = %q", loc)
	}
}

func TestTargetSchemeIsConstrained(t *testing.T) {
	for _, bad := range []string{
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"file:///etc/passwd",
		"//evil.example.com",
		"///evil.example.com",
		`/\evil.example.com`,
		"/..//evil.example.com",
		// No scheme, no leading slash: admitting an empty scheme must not
		// turn an authority-looking string into a valid target.
		"evil.example.com/path",
		"https://user:pass@example.com/",
	} {
		if _, err := ValidateTarget(bad, false); err == nil {
			t.Fatalf("%q accepted as a target", bad)
		}
	}
	if _, err := ValidateTarget("http://example.com/", false); err == nil {
		t.Fatal("plain http accepted without opt-in")
	}
	if _, err := ValidateTarget("http://example.com/", true); err != nil {
		t.Fatalf("http rejected with opt-in: %v", err)
	}

	// A single leading slash is an in-app target and needs no scheme opt-in.
	for _, good := range []string{
		"/c/acme/tmp-001/b",
		"/c/acme/tmp-001/b?l=de",
		"/",
	} {
		got, err := ValidateTarget(good, false)
		if err != nil {
			t.Fatalf("internal target %q rejected: %v", good, err)
		}
		if !isInternalTarget(got) {
			t.Fatalf("internal target %q was not recognised as internal", got)
		}
	}
}

// Carrying rid must merge into the target's own query. Replacing the whole
// query would silently drop the campaign's own parameters.
func TestWithQueryParamMergesExistingQuery(t *testing.T) {
	target, err := ValidateTarget("/c/acme/tmp-002/b?l=de&source=mail", false)
	if err != nil {
		t.Fatalf("ValidateTarget: %v", err)
	}
	got := withQueryParam(target, "rid", "contact-1")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("Location %q is not a URL: %v", got, err)
	}
	q := u.Query()
	if q.Get("l") != "de" || q.Get("source") != "mail" {
		t.Fatalf("existing query lost: %q", got)
	}
	if q.Get("rid") != "contact-1" {
		t.Fatalf("rid not added: %q", got)
	}
	if len(q["rid"]) != 1 {
		t.Fatalf("rid duplicated: %q", got)
	}

	// A stale rid already on the target is replaced, not appended twice.
	got = withQueryParam(target+"&rid=stale", "rid", "contact-2")
	u, err = url.Parse(got)
	if err != nil {
		t.Fatalf("Location %q is not a URL: %v", got, err)
	}
	if ids := u.Query()["rid"]; len(ids) != 1 || ids[0] != "contact-2" {
		t.Fatalf("rid = %q, want a single contact-2", ids)
	}
}

// ---------------------------------------------------------------- contact id

func TestCaptureAttributesKnownContact(t *testing.T) {
	st := newMemStore()
	var gotCampaign, gotContact string
	c, err := New(Config{
		Resolve: steps(map[string]Step{
			"acme/t1/s1": {Target: "https://example.com/"},
		}),
		Logger: quietLogger(),
		ResolveContact: func(_ context.Context, campaignID, contactID string) (bool, error) {
			gotCampaign, gotContact = campaignID, contactID
			return contactID == "contact-1", nil
		},
	}, st)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := post(t, c.Capture("acme", "t1", "s1"), "/c/acme/t1/s1?rid=contact-1", url.Values{
		"email": {"alice@example.com"},
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	a := st.only(t)
	if a.ContactID != "contact-1" {
		t.Fatalf("ContactID = %q, want contact-1", a.ContactID)
	}
	if gotCampaign != "acme" || gotContact != "contact-1" {
		t.Fatalf("resolver saw campaign=%q contact=%q", gotCampaign, gotContact)
	}
}

func TestCaptureMergesRIDIntoExistingQuery(t *testing.T) {
	st := newMemStore()
	c, err := New(Config{
		Resolve: steps(map[string]Step{
			"acme/t1/s1": {Target: "/c/acme/t1/s2?l=de&source=mail"},
		}),
		Logger: quietLogger(),
		ResolveContact: func(_ context.Context, _, contactID string) (bool, error) {
			return contactID == "contact-1", nil
		},
	}, st)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := post(t, c.Capture("acme", "t1", "s1"), "/c/acme/t1/s1?rid=contact-1", url.Values{
		"email": {"alice@example.com"},
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("Location is not a URL: %v", err)
	}
	if loc.Path != "/c/acme/t1/s2" {
		t.Fatalf("Location path = %q", loc.Path)
	}
	q := loc.Query()
	if q.Get("l") != "de" || q.Get("source") != "mail" {
		t.Fatalf("target query was overwritten: %q", loc.String())
	}
	if q.Get("rid") != "contact-1" {
		t.Fatalf("rid missing from redirect: %q", loc.String())
	}
}

func TestCaptureKeepsArtifactWhenContactIsUnknown(t *testing.T) {
	cases := map[string]func(context.Context, string, string) (bool, error){
		"unknown": func(context.Context, string, string) (bool, error) {
			return false, nil
		},
		"lookup error": func(context.Context, string, string) (bool, error) {
			return false, errors.New("database unavailable")
		},
	}
	for name, resolve := range cases {
		t.Run(name, func(t *testing.T) {
			st := newMemStore()
			c, err := New(Config{
				Resolve: steps(map[string]Step{
					"acme/t1/s1": {Target: "https://example.com/"},
				}),
				Logger:         quietLogger(),
				ResolveContact: resolve,
			}, st)
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			rec := post(t, c.Capture("acme", "t1", "s1"), "/c/acme/t1/s1?rid=other", url.Values{
				"email": {"alice@example.com"},
			})
			if rec.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302 even when attribution fails", rec.Code)
			}
			a := st.only(t)
			if a.ContactID != "" {
				t.Fatalf("ContactID = %q, want empty", a.ContactID)
			}
			if a.Fields["email"] != "alice@example.com" {
				t.Fatal("submission was not captured")
			}
		})
	}
}

func TestCaptureAttributesContactAfterClientCancel(t *testing.T) {
	st := newMemStore()
	c, err := New(Config{
		Resolve: steps(map[string]Step{
			"acme/t1/s1": {Target: "https://example.com/"},
		}),
		Logger: quietLogger(),
		ResolveContact: func(ctx context.Context, _, _ string) (bool, error) {
			// The old wiring passed r.Context() here, so a closed tab made
			// this branch win and dropped the attribution.
			if err := ctx.Err(); err != nil {
				return false, err
			}
			return true, nil
		},
	}, st)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	form := url.Values{"email": {"alice@example.com"}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/c/acme/t1/s1?rid=contact-1", strings.NewReader(form))
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	c.Capture("acme", "t1", "s1")(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rr.Code)
	}
	if a := st.only(t); a.ContactID != "contact-1" {
		t.Fatalf("ContactID = %q, want contact-1 after client cancel", a.ContactID)
	}
}

func TestCaptureSetsNoReferrer(t *testing.T) {
	cases := map[string]Step{
		"inline": {Target: "https://example.com/"},
		"beacon": {Target: "https://example.com/", Mode: ModeBeacon, BeaconToken: "tok-1"},
	}
	for name, step := range cases {
		t.Run(name, func(t *testing.T) {
			c := newTestCollector(t, newMemStore(), map[string]Step{"acme/t1/s1": step})
			rec := post(t, c.Capture("acme", "t1", "s1"), "/c/acme/t1/s1?rid=contact-1", url.Values{
				"email": {"alice@example.com"},
			})
			if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
				t.Fatalf("Referrer-Policy = %q, want no-referrer", got)
			}
		})
	}
}

// ---------------------------------------------------------------- beacon

func TestBeaconPageEscapesHostileTarget(t *testing.T) {
	st := newMemStore()
	const step = "acme/tmp-003/step-c"
	c := newTestCollector(t, st, map[string]Step{
		step: {
			Target:      `https://example.com/"><script>alert(1)</script>`,
			Mode:        ModeBeacon,
			BeaconToken: "tok-9f3a",
		},
	})

	rec := post(t, c.Capture("acme", "tmp-003", "step-c"), "/c/acme/tmp-003/step-c", url.Values{
		"email": {"a@b.c"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if n := strings.Count(body, "<script"); n != 1 {
		t.Fatalf("hostile target injected markup: %d script tags in body\n%s", n, body)
	}
	if strings.Contains(body, "<script>alert(1)") {
		t.Fatal("target broke out of its context")
	}
}

func TestBeaconTokenIsRequiredAndPerCampaign(t *testing.T) {
	ks := testKeySet(t, 1, 1)
	st, err := NewSQLite("file:"+filepath.Join(t.TempDir(), "a.db"), ks)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	const stepKey = "acme/tmp-003/step-c"
	c, err := New(Config{
		Resolve: steps(map[string]Step{
			stepKey: {Target: "https://example.com/", Mode: ModeBeacon, BeaconToken: "tok-right"},
		}),
		Logger: quietLogger(),
	}, st)
	if err != nil {
		t.Fatal(err)
	}

	a := &Artifact{ID: NewID(), CampaignID: "acme", TemplateID: "tmp-003", Step: "step-c"}
	if err := st.Insert(context.Background(), a); err != nil {
		t.Fatal(err)
	}

	payload, _ := json.Marshal(Fingerprint{Timezone: "Europe/Paris"})

	do := func(token string) int {
		req := httptest.NewRequest(http.MethodPost, "/__siren/"+token+"/fp/"+a.ID, bytes.NewReader(payload))
		req.SetPathValue("token", token)
		req.SetPathValue("id", a.ID)
		rr := httptest.NewRecorder()
		c.BeaconHandler()(rr, req)
		return rr.Code
	}

	if code := do("tok-wrong"); code != http.StatusNotFound {
		t.Fatalf("wrong token: status = %d, want 404", code)
	}
	if code := do("tok-right"); code != http.StatusNoContent {
		t.Fatalf("right token: status = %d, want 204", code)
	}
	got, err := st.Get(context.Background(), a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint == nil || got.Fingerprint.Timezone != "Europe/Paris" {
		t.Fatal("fingerprint not merged")
	}
}

// TestBeaconRejectedOnInlineStep closes the second write path: an inline step
// must never accept a merge, even with the right token.
func TestBeaconRejectedOnInlineStep(t *testing.T) {
	st := newMemStore()
	const stepKey = "acme/tmp-005/step-inline"
	c := newTestCollector(t, st, map[string]Step{
		stepKey: {Target: "https://example.com/", Mode: ModeInline, BeaconToken: "tok-allowed"},
	})

	a := &Artifact{ID: NewID(), CampaignID: "acme", TemplateID: "tmp-005", Step: "step-inline"}
	if err := st.Insert(context.Background(), a); err != nil {
		t.Fatal(err)
	}

	payload, _ := json.Marshal(Fingerprint{Timezone: "UTC"})
	req := httptest.NewRequest(http.MethodPost, "/__siren/tok-allowed/fp/"+a.ID, bytes.NewReader(payload))
	req.SetPathValue("token", "tok-allowed")
	req.SetPathValue("id", a.ID)
	rr := httptest.NewRecorder()
	c.BeaconHandler()(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for a beacon on an inline step", rr.Code)
	}
	got, err := st.Get(context.Background(), a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != nil {
		t.Fatal("beacon merged into an inline step")
	}
}

func TestConcurrentBeaconMerge(t *testing.T) {
	ks := testKeySet(t, 1, 1)
	st, err := NewSQLite("file:"+filepath.Join(t.TempDir(), "b.db"), ks)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	a := &Artifact{ID: NewID(), CampaignID: "acme", TemplateID: "tmp-003", Step: "step-c",
		Fields: map[string]string{"email": "a@b.c"}}
	if err := st.Insert(context.Background(), a); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			fp := &Fingerprint{Timezone: "TZ", WebGLHash: string(rune('a' + i))}
			errs <- st.AttachFingerprint(context.Background(), a.ID, fp)
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent merge: %v", err)
		}
	}

	got, err := st.Get(context.Background(), a.ID)
	if err != nil {
		t.Fatalf("artifact unreadable after concurrent merge: %v", err)
	}
	if got.Fields["email"] != "a@b.c" {
		t.Fatal("concurrent merge corrupted the body")
	}
	if got.Fingerprint == nil {
		t.Fatal("no fingerprint survived")
	}
}

// ---------------------------------------------------------------- limits

func TestBodyLimitsDifferForMultipart(t *testing.T) {
	st := newMemStore()
	c := newTestCollector(t, st, map[string]Step{
		"acme/tmp-003/step-c": {Target: "https://example.com/"},
	})

	// urlencoded over the 64 KiB budget
	big := strings.Repeat("x", defaultMaxBody+1024)
	req := httptest.NewRequest(http.MethodPost, "/c/acme/tmp-003/step-c",
		strings.NewReader("note="+big))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	c.Capture("acme", "tmp-003", "step-c")(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("urlencoded oversize: status = %d, want 413", rr.Code)
	}

	// multipart above the urlencoded budget but below its own
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("email", "a@b.c")
	blob := bytes.Repeat([]byte("P"), 200<<10)
	fw, _ := mw.CreateFormFile("certificate", `..\evil\cert.p12`)
	_, _ = fw.Write(blob)
	_ = mw.Close()

	req = httptest.NewRequest(http.MethodPost, "/c/acme/tmp-003/step-c", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr = httptest.NewRecorder()
	c.Capture("acme", "tmp-003", "step-c")(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("multipart within budget: status = %d, want 302", rr.Code)
	}

	a := st.only(t)
	if len(a.Files) != 1 {
		t.Fatalf("expected 1 file meta, got %d", len(a.Files))
	}
	sum := sha256.Sum256(blob)
	if a.Files[0].SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("file digest mismatch")
	}
	if a.Files[0].Filename != "cert.p12" {
		t.Fatalf("filename not sanitised: %q", a.Files[0].Filename)
	}
	if a.Files[0].Size != int64(len(blob)) {
		t.Fatalf("size = %d", a.Files[0].Size)
	}
}

func TestMultipartOverLimitIs413(t *testing.T) {
	st := newMemStore()
	c, err := New(Config{
		Resolve: steps(map[string]Step{
			"acme/tmp-003/step-c": {
				Target: "https://example.com/",
				Fields: []Field{{Name: "certificate", Kind: KindFile}},
			},
		}),
		Logger:       quietLogger(),
		MaxMultipart: 512,
	}, st)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("certificate", "cert.p12")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(bytes.Repeat([]byte("P"), 1024)); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/c/acme/tmp-003/step-c", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr := httptest.NewRecorder()
	c.Capture("acme", "tmp-003", "step-c")(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("multipart oversize: status = %d, want 413", rr.Code)
	}
	if len(st.all(t)) != 0 {
		t.Fatalf("oversize upload stored %d artifacts", len(st.all(t)))
	}
}

func TestUploadAcceptIsEnforcedServerSide(t *testing.T) {
	st := newMemStore()
	c := newTestCollector(t, st, map[string]Step{
		"acme/tmp-003/step-c": {
			Target: "https://example.com/",
			Fields: []Field{{
				Name:   "certificate",
				Kind:   KindFile,
				Accept: []string{".p12", ".pfx"},
			}},
		},
	})

	upload := func(name string) *httptest.ResponseRecorder {
		t.Helper()
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fw, err := mw.CreateFormFile("certificate", name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte("blob")); err != nil {
			t.Fatal(err)
		}
		if err := mw.Close(); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/c/acme/tmp-003/step-c", &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		rr := httptest.NewRecorder()
		c.Capture("acme", "tmp-003", "step-c")(rr, req)
		return rr
	}

	// cert.P12: filename extension is uppercase, config list is lowercase.
	// acceptedExtension must lower the filename ext before comparing.
	for _, name := range []string{"cert.p12", "cert.PFX", "cert.P12", `..\evil\cert.p12`} {
		if rr := upload(name); rr.Code != http.StatusFound {
			t.Fatalf("%q rejected: status = %d, want 302", name, rr.Code)
		}
	}

	before := len(st.all(t))
	for _, name := range []string{"cert.exe", "cert.p12.txt", "cert"} {
		if rr := upload(name); rr.Code != http.StatusBadRequest {
			t.Fatalf("%q accepted: status = %d, want 400", name, rr.Code)
		}
	}
	if got := len(st.all(t)); got != before {
		t.Fatalf("rejected uploads stored artifacts: %d -> %d", before, got)
	}
}

// TestFileDigestCoversWholeUploadWithinBudget pins that the digest describes
// every byte the configured budget admitted. A fixed LimitReader in
// describeFile would truncate at the package default and still return 302,
// so the test raises the budget above that default.
func TestFileDigestCoversWholeUploadWithinBudget(t *testing.T) {
	const budget = 10 << 20
	st := newMemStore()
	c, err := New(Config{
		Resolve: steps(map[string]Step{
			"acme/tmp-003/step-c": {
				Target: "https://example.com/",
				Fields: []Field{{
					Name:   "certificate",
					Kind:   KindFile,
					Accept: []string{".p12"},
				}},
			},
		}),
		Logger:       quietLogger(),
		MaxMultipart: budget,
	}, st)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	blob := bytes.Repeat([]byte("P"), (budget - (1 << 20)))
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("certificate", "large.p12")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(blob); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/c/acme/tmp-003/step-c", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr := httptest.NewRecorder()
	c.Capture("acme", "tmp-003", "step-c")(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rr.Code)
	}

	meta := st.only(t).Files[0]
	if meta.Size != int64(len(blob)) {
		t.Fatalf("size = %d, want %d", meta.Size, len(blob))
	}
	sum := sha256.Sum256(blob)
	if meta.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("digest covers only a prefix: %q", meta.SHA256)
	}
}

// TestEmptyAcceptAcceptsAnyFile pins the "accept any file" semantics: an
// empty list is a declaration, not a missing constraint to guess about.
func TestEmptyAcceptAcceptsAnyFile(t *testing.T) {
	st := newMemStore()
	c := newTestCollector(t, st, map[string]Step{
		"acme/tmp-003/step-c": {
			Target: "https://example.com/",
			Fields: []Field{{Name: "certificate", Kind: KindFile}},
		},
	})

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("certificate", "anything.exe")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte("blob")); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/c/acme/tmp-003/step-c", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr := httptest.NewRecorder()
	c.Capture("acme", "tmp-003", "step-c")(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rr.Code)
	}
	if files := st.only(t).Files; len(files) != 1 || files[0].Filename != "anything.exe" {
		t.Fatalf("files = %+v", files)
	}
}

// TestMultipartTempFilesAreRemoved pins the RemoveAll contract: anything the
// standard library spilled to disk for this request is gone when the handler
// returns. Without it a campaign fills the temp volume one upload at a time.
func TestMultipartTempFilesAreRemoved(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMP", tmp)
	t.Setenv("TMPDIR", tmp)

	st := newMemStore()
	c := newTestCollector(t, st, map[string]Step{
		"acme/tmp-004/step-d": {Target: "https://example.com/"},
	})

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("email", "a@b.c")
	fw, err := mw.CreateFormFile("scan", "scan.pdf")
	if err != nil {
		t.Fatal(err)
	}
	// Above multipartMemory (1 MiB), so net/http spills the part to a file.
	if _, err := fw.Write(bytes.Repeat([]byte("P"), multipartMemory+(512<<10))); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/c/acme/tmp-004/step-d", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr := httptest.NewRecorder()
	c.Capture("acme", "tmp-004", "step-d")(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rr.Code)
	}
	if files := st.only(t).Files; len(files) != 1 {
		t.Fatalf("upload not recorded: %+v", files)
	}

	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("multipart temp files left behind: %v", names)
	}
}

func TestMethodAndOversizeFieldCountRejected(t *testing.T) {
	st := newMemStore()
	c := newTestCollector(t, st, map[string]Step{
		"a/b/c": {Target: "https://example.com/"},
	})

	req := httptest.NewRequest(http.MethodPut, "/c/a/b/c", nil)
	rr := httptest.NewRecorder()
	c.Capture("a", "b", "c")(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT: status = %d", rr.Code)
	}

	form := url.Values{}
	for i := 0; i < maxFieldCount+1; i++ {
		form.Set(fmt.Sprintf("f%d", i), "v")
	}
	rr = post(t, c.Capture("a", "b", "c"), "/c/a/b/c", form)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("field count: status = %d, want 413", rr.Code)
	}
}

// ---------------------------------------------------------------- storage

func TestSQLiteRoundTripAndKeyRotation(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "artifacts.db")

	ks1 := testKeySet(t, 1, 1)
	st, err := NewSQLite(dsn, ks1)
	if err != nil {
		t.Fatal(err)
	}
	a := &Artifact{
		ID: NewID(), CampaignID: "acme", TemplateID: "tmp-001", Step: "step-b",
		ContactID: "contact-7",
		RemoteIP:  "198.51.100.7",
		Fields:    map[string]string{"email": "alice@example.com"},
		Cookies:   []Cookie{{Name: "sess", Value: "replayable"}},
	}
	if err := st.Insert(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	st.Close()

	// New active key, old still present: reads work, rotation rewrites.
	ks2 := testKeySet(t, 2, 1, 2)
	st, err = NewSQLite(dsn, ks2)
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.Get(context.Background(), a.ID)
	if err != nil {
		t.Fatalf("read with retired key: %v", err)
	}
	if got.Fields["email"] != "alice@example.com" {
		t.Fatal("round trip lost a field")
	}
	if got.ContactID != "contact-7" {
		t.Fatalf("round trip lost contact_id: %q", got.ContactID)
	}
	n, err := st.Rotate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("rotated %d rows, want 1", n)
	}
	st.Close()

	// Old key withdrawn: everything must still open.
	ks3 := testKeySet(t, 2, 2)
	st, err = NewSQLite(dsn, ks3)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.Get(context.Background(), a.ID); err != nil {
		t.Fatalf("read after rotation: %v", err)
	}
}

func TestWrongKeyFailsClosed(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "artifacts.db")

	st, err := NewSQLite(dsn, testKeySet(t, 1, 1))
	if err != nil {
		t.Fatal(err)
	}
	a := &Artifact{ID: NewID(), Fields: map[string]string{"email": "x"}}
	if err := st.Insert(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	st.Close()

	st2, err := NewSQLite(dsn, testKeySet(t, 1, 1))
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()

	// Same key id, different material: AAD matches, key does not.
	impostor := map[byte][]byte{1: bytes.Repeat([]byte{9}, 32)}
	ks, err := NewKeySet(1, impostor)
	if err != nil {
		t.Fatal(err)
	}
	st3, err := NewSQLite(dsn, ks)
	if err != nil {
		t.Fatal(err)
	}
	defer st3.Close()
	if _, err := st3.Get(context.Background(), a.ID); err == nil {
		t.Fatal("impostor key decrypted an artifact")
	}
}

func TestGuardKeyLocation(t *testing.T) {
	dir := t.TempDir()
	if err := GuardKeyLocation(filepath.Join(dir, "key.bin"), dir); err == nil {
		t.Fatal("key inside data dir accepted")
	}
	if err := GuardKeyLocation(filepath.Join(filepath.Dir(dir), "key.bin"), dir); err != nil {
		t.Fatalf("key outside data dir rejected: %v", err)
	}
	if err := GuardKeyLocation("", dir); err != nil {
		t.Fatalf("empty path should be a no-op: %v", err)
	}
}

// TestGuardKeyLocationResolvesSymlinks covers the bypass where a key outside
// data_dir is a link pointing back into it.
func TestGuardKeyLocationResolvesSymlinks(t *testing.T) {
	dataDir := t.TempDir()
	elsewhere := t.TempDir()

	target := filepath.Join(dataDir, "key.bin")
	if err := os.WriteFile(target, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(elsewhere, "key.bin")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := GuardKeyLocation(link, dataDir); err == nil {
		t.Fatal("symlink into data dir accepted as an outside key")
	}
}

// TestGuardKeyLocationRejectsDanglingLinkIntoDataDir closes the boot-order
// hole: the link does not resolve yet, but its target will exist later.
func TestGuardKeyLocationRejectsDanglingLinkIntoDataDir(t *testing.T) {
	dataDir := t.TempDir()
	elsewhere := t.TempDir()

	link := filepath.Join(elsewhere, "key.bin")
	if err := os.Symlink(filepath.Join(dataDir, "missing.bin"), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := GuardKeyLocation(link, dataDir); err == nil {
		t.Fatal("dangling link into data dir accepted as an outside key")
	}
}

func TestLoadKeyFileAcceptsDockerSecretPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits not enforced on Windows")
	}
	// Docker secrets are mounted as root:root 0444 (world-readable, not writable).
	// LoadKeyFile must accept this so the container does not need to run as root.
	dir := t.TempDir()
	path := filepath.Join(dir, "siren-key.json")

	// Write a minimal valid key file.
	kf := `{"keys":[{"id":1,"key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}],"active":1}`
	if err := os.WriteFile(path, []byte(kf), 0o600); err != nil {
		t.Fatal(err)
	}
	// Simulate Docker secret: 0444 (read by all, write by none).
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyFile(path); err != nil {
		t.Fatalf("LoadKeyFile 0444: %v (Docker secrets are 0444 by default)", err)
	}

	// A world-writable file must still be refused (key replacement attack).
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyFile(path); err == nil {
		t.Fatal("0644 (group-writable) was accepted")
	}
}

func TestKeySetParsing(t *testing.T) {
	k1 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	k2 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	ks, err := ParseKeySet("1:"+k1+", 2:"+k2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if ks.Active() != 2 {
		t.Fatalf("active = %d", ks.Active())
	}
	if ids := ks.IDs(); len(ids) != 2 || ids[0] != 1 || ids[1] != 2 {
		t.Fatalf("ids = %v", ids)
	}
	if _, err := ParseKeySet("1:"+k1, 7); err == nil {
		t.Fatal("active id missing from set accepted")
	}
	if _, err := ParseKeySet("1:notbase64", 1); err == nil {
		t.Fatal("bad base64 accepted")
	}
}

// ---------------------------------------------------------------- origin

func TestClientIPHonoursTrustedProxiesOnly(t *testing.T) {
	_, cloudflare, err := net.ParseCIDR("173.245.48.0/20")
	if err != nil {
		t.Fatal(err)
	}
	trusted := []*net.IPNet{cloudflare}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:4444"
	req.Header.Set("CF-Connecting-IP", "198.51.100.7")
	if got := ClientIP(req, trusted); got != "203.0.113.9" {
		t.Fatalf("untrusted peer spoofed origin: %q", got)
	}

	req.RemoteAddr = "173.245.48.10:443"
	if got := ClientIP(req, trusted); got != "198.51.100.7" {
		t.Fatalf("trusted peer: %q", got)
	}

	req.Header.Del("CF-Connecting-IP")
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 198.51.100.7, 173.245.48.10")
	if got := ClientIP(req, trusted); got != "198.51.100.7" {
		t.Fatalf("xff chain: %q, want the rightmost untrusted hop", got)
	}
}

// TestClientIPCannotBeSpoofedThroughXFF pins the attack the left-to-right walk
// allowed: the client prepends an address, Cloudflare appends the real one, and
// only the rightmost untrusted hop may be trusted as the origin.
func TestClientIPCannotBeSpoofedThroughXFF(t *testing.T) {
	_, cloudflare, err := net.ParseCIDR("173.245.48.0/20")
	if err != nil {
		t.Fatal(err)
	}
	trusted := []*net.IPNet{cloudflare}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "173.245.48.10:443"
	req.Header.Set("X-Forwarded-For", "9.9.9.9, 198.51.100.7")
	if got := ClientIP(req, trusted); got != "198.51.100.7" {
		t.Fatalf("spoofed prefix won: %q, want 198.51.100.7", got)
	}

	// Only trusted hops: fall back to the peer, never to a client-supplied hop.
	req.Header.Set("X-Forwarded-For", "173.245.48.11, 173.245.48.10")
	if got := ClientIP(req, trusted); got != "173.245.48.10" {
		t.Fatalf("all-trusted chain: %q, want the peer", got)
	}
}

// TestInjectedFieldEscapedAtRender pins the boundary: the collector stores the
// submitted value byte-exact, and escaping happens at render time. If collect
// ever started HTML-escaping on write, the artifact would no longer be the
// literal submission; if the renderer failed to escape, this test fails.
func TestInjectedFieldEscapedAtRender(t *testing.T) {
	st := newMemStore()
	c := newTestCollector(t, st, map[string]Step{
		"acme/tmp-002/step-b": {
			Target: "https://example.com/",
			Fields: []Field{{Name: "comment", Kind: KindText}},
		},
	})

	const hostile = `"><script>alert(1)</script>`
	post(t, c.Capture("acme", "tmp-002", "step-b"), "/c/acme/tmp-002/step-b", url.Values{
		"comment": {hostile},
	})

	a := st.only(t)
	if a.Fields["comment"] != hostile {
		t.Fatalf("collector altered the submitted value: %q", a.Fields["comment"])
	}

	tpl := template.Must(template.New("row").Parse(`<td>{{.}}</td>`))
	var out bytes.Buffer
	if err := tpl.Execute(&out, a.Fields["comment"]); err != nil {
		t.Fatal(err)
	}
	rendered := out.String()
	if strings.Contains(rendered, "<script>") {
		t.Fatalf("renderer did not escape: %s", rendered)
	}
	if !strings.Contains(rendered, "&lt;script&gt;") {
		t.Fatalf("unexpected escaping shape: %s", rendered)
	}
}

func TestBeaconRendersWhenStoreFails(t *testing.T) {
	st := newMemStore()
	st.fail = errors.New("disk full")
	c := newTestCollector(t, st, map[string]Step{
		"acme/tmp-003/step-c": {
			Target:      "https://example.com/",
			Mode:        ModeBeacon,
			BeaconToken: "tok-abc",
		},
	})

	rec := post(t, c.Capture("acme", "tmp-003", "step-c"), "/c/acme/tmp-003/step-c", url.Values{})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 even when the store fails", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "https://example.com/") {
		t.Fatal("beacon page lost its target after a store failure")
	}
	if !strings.Contains(body, "/__siren/tok-abc/fp/") {
		t.Fatalf("beacon endpoint missing or not tokenised:\n%s", body)
	}
}

func TestBeaconCeilingIs900ms(t *testing.T) {
	st := newMemStore()
	c := newTestCollector(t, st, map[string]Step{
		"acme/tmp-003/step-c": {
			Target:      "https://example.com/",
			Mode:        ModeBeacon,
			BeaconToken: "tok",
		},
	})
	rec := post(t, c.Capture("acme", "tmp-003", "step-c"), "/c/acme/tmp-003/step-c", url.Values{})
	body := rec.Body.String()
	if !strings.Contains(body, "setTimeout(leave, 900)") {
		t.Fatal("beacon ceiling is not 900 ms")
	}
	// The meta refresh must live inside <noscript>, otherwise it races the JS.
	if strings.Contains(body, `<meta http-equiv="refresh"`) &&
		!strings.Contains(body, `<noscript><meta http-equiv="refresh"`) {
		t.Fatal("meta refresh is outside <noscript> and can race the beacon")
	}
}

func TestRetireKeyBlockedWhileRowsRemain(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "retire.db")

	// Write one row under key 1.
	st, err := NewSQLite(dsn, testKeySet(t, 1, 1))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Insert(context.Background(), &Artifact{ID: NewID(), CampaignID: "a"}); err != nil {
		t.Fatal(err)
	}
	st.Close()

	// Reopen with key 2 active and key 1 retained: the row still carries 1.
	st, err = NewSQLite(dsn, testKeySet(t, 2, 1, 2))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := st.RetireKey(context.Background(), 1); !errors.Is(err, ErrKeyInUse) {
		t.Fatalf("retire of a referenced key: %v, want ErrKeyInUse", err)
	}
	usage, err := st.KeyUsage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if usage[1] != 1 || usage[2] != 0 {
		t.Fatalf("usage = %v", usage)
	}

	if _, err := st.Rotate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := st.RetireKey(context.Background(), 1); err != nil {
		t.Fatalf("retire after rotation: %v", err)
	}

	// The active key is protected at the keyset layer, not the store layer.
	ks := testKeySet(t, 2, 1, 2)
	if _, err := ks.Without(2); err == nil {
		t.Fatal("Without refused to remove the active key")
	}
	next, err := ks.Without(1)
	if err != nil {
		t.Fatal(err)
	}
	if ids := next.IDs(); len(ids) != 1 || ids[0] != 2 {
		t.Fatalf("remaining ids = %v", ids)
	}
}

func TestFieldAttrsEmitDataSecret(t *testing.T) {
	secret := Field{Name: "code", Kind: KindOTP}
	if !secret.DataSecret() {
		t.Fatal("OTP field must carry data-secret")
	}
	attrs := secret.Attrs()
	var found bool
	for _, a := range attrs {
		if a.Name == "data-secret" && a.Value == "1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("data-secret missing from %v", attrs)
	}

	plain := Field{Name: "email", Kind: KindText}
	for _, a := range plain.Attrs() {
		if a.Name == "data-secret" {
			t.Fatal("plain text field must not carry data-secret")
		}
	}

	// Declared non-secret but password-kind implies secret: same path as
	// Classify, by construction.
	implied := Field{Name: "pw", Kind: KindPassword, Secret: false}
	if !implied.DataSecret() {
		t.Fatal("KindPassword must be secret without an explicit flag")
	}
}

func TestFieldAttrsEmitPasswordType(t *testing.T) {
	cases := map[Kind]string{
		KindPassword: "password",
		KindSeed:     "password",
		KindFile:     "file",
		KindText:     "text",
		KindOTP:      "text",
	}
	for kind, want := range cases {
		attrs := Field{Name: "f", Kind: kind}.Attrs()
		var got string
		for _, a := range attrs {
			if a.Name == "type" {
				got = a.Value
			}
		}
		if got != want {
			t.Fatalf("kind %q: type = %q, want %q", kind, got, want)
		}
	}

	// A password rendered with autocomplete enabled leaks into the browser's
	// suggestion store; the attribute is part of the contract, not decoration.
	var autocomplete string
	for _, a := range (Field{Name: "password", Kind: KindPassword}).Attrs() {
		if a.Name == "autocomplete" {
			autocomplete = a.Value
		}
	}
	if autocomplete != "off" {
		t.Fatalf("password autocomplete = %q, want off", autocomplete)
	}
}

func TestSensitiveKindUsesTokens(t *testing.T) {
	cases := map[string]Kind{
		"user_pass":         KindPassword,
		"userPass":          KindPassword,
		"USER.PASSWORD":     KindPassword,
		"newpassword":       KindPassword,
		"api_token":         KindPassword,
		"otp":               KindOTP,
		"account_otp":       KindOTP,
		"code":              KindOTP,
		"verification_code": KindOTP,
		"one-time-code":     KindOTP,
		"recovery_phrase":   KindSeed,
	}
	for name, want := range cases {
		got, ok := sensitiveKind(name)
		if !ok || got != want {
			t.Fatalf("sensitiveKind(%q) = %q, %v; want %q, true", name, got, ok, want)
		}
	}
	if _, ok := sensitiveKind("compass"); ok {
		t.Fatal("substring match labelled a benign name as sensitive")
	}
	// "code" alone is an OTP, but a qualifier makes it a classification label.
	for _, name := range []string{
		"postal_code", "zip_code", "country_code", "area_code",
		"promo_code", "currency_code", "language_code", "dial_code",
		"postalCode", "COUNTRY-CODE",
	} {
		if got, ok := sensitiveKind(name); ok {
			t.Fatalf("sensitiveKind(%q) = %q, true; want non-secret", name, got)
		}
	}
	// A real secret token next to the qualifier still wins.
	if got, ok := sensitiveKind("postal_code_otp"); !ok || got != KindOTP {
		t.Fatalf("sensitiveKind(postal_code_otp) = %q, %v; want otp", got, ok)
	}
}

func TestSanitizeFilename(t *testing.T) {
	cases := map[string]string{
		`..\evil\cert.p12`: "cert.p12",
		"../../etc/passwd": "passwd",
		"a\x00b\x1fc.txt":  "abc.txt",
		"plain.pdf":        "plain.pdf",
	}
	for in, want := range cases {
		if got := sanitizeFilename(in); got != want {
			t.Fatalf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}
