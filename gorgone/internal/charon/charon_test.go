package charon

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/siren-core/gorgone/internal/collect"
	sirendb "github.com/siren-core/gorgone/internal/db"
	"github.com/siren-core/gorgone/internal/store"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)) }

func keys(t *testing.T) *collect.KeySet {
	t.Helper()
	key := bytes.Repeat([]byte{7}, 32)
	ks, err := collect.NewKeySet(1, map[byte][]byte{1: key})
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

type env struct {
	artifacts collect.Store
	ops       *store.SQL
	handle    *sirendb.DB
}

func newEnv(t *testing.T) *env {
	t.Helper()
	handle, err := sirendb.Open("file:" + filepath.Join(t.TempDir(), "charon.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { handle.Close() })

	arts, err := collect.NewSQLiteFrom(handle.DB, keys(t))
	if err != nil {
		t.Fatal(err)
	}
	ops, err := store.New(handle.DB)
	if err != nil {
		t.Fatal(err)
	}
	return &env{artifacts: arts, ops: ops, handle: handle}
}

func (e *env) campaign(t *testing.T) *store.Campaign {
	t.Helper()
	c, err := e.ops.CreateCampaign(context.Background(), "Acme")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (e *env) token(t *testing.T, campaignID string) string {
	t.Helper()
	token, err := IssueToken(context.Background(), e.ops, campaignID)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func (e *env) artifact(t *testing.T, id, campaignID, contactID string, at time.Time) {
	t.Helper()
	a := &collect.Artifact{
		ID:          id,
		CampaignID:  campaignID,
		TemplateID:  "tmp-001",
		Step:        "b",
		ContactID:   contactID,
		ReceivedAt:  at,
		RemoteIP:    "203.0.113.9",
		Method:      "POST",
		Path:        "/c/acme/tmp-001/b",
		Fields:      map[string]string{"email": "alice@example.com"},
		Secrets:     map[string]collect.Secret{"code": collect.NewSecret("123456", collect.KindOTP)},
		Files:       []collect.FileMeta{},
		Target:      "https://example.com/account",
		Fingerprint: &collect.Fingerprint{Timezone: "UTC"},
	}
	if err := e.artifacts.Insert(context.Background(), a); err != nil {
		t.Fatal(err)
	}
}

func get(t *testing.T, h http.Handler, campaignID, token, since string) *httptest.ResponseRecorder {
	t.Helper()
	url := "/export/" + campaignID
	if since != "" {
		url += "?since=" + since
	}
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.SetPathValue("campaign", campaignID)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func lines(t *testing.T, body []byte) []map[string]json.RawMessage {
	t.Helper()
	var out []map[string]json.RawMessage
	for _, raw := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		if raw == "" {
			continue
		}
		var line map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &line); err != nil {
			t.Fatalf("line is not JSON: %v: %q", err, raw)
		}
		out = append(out, line)
	}
	return out
}

func TestExportShapeOrderAndContactID(t *testing.T) {
	e := newEnv(t)
	campaignA := e.campaign(t)
	campaignB := e.campaign(t)
	tokenA := e.token(t, campaignA.ID)
	tokenB := e.token(t, campaignB.ID)

	base := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	// IDs deliberately sort against the timestamps, so only time can decide.
	e.artifact(t, "z-first", campaignA.ID, "contact-1", base)
	e.artifact(t, "m-middle", campaignA.ID, "", base.Add(time.Second))
	e.artifact(t, "a-last", campaignA.ID, "contact-2", base.Add(2*time.Second))
	e.artifact(t, "b-other", campaignB.ID, "", base)

	h := NewHandler(e.artifacts, e.ops, quiet())
	rr := get(t, h, campaignA.ID, tokenA, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != ContentType {
		t.Fatalf("Content-Type = %q, want %q", ct, ContentType)
	}

	got := lines(t, rr.Body.Bytes())
	if len(got) != 3 {
		t.Fatalf("lines = %d, want 3", len(got))
	}
	wantOrder := []string{"z-first", "m-middle", "a-last"}
	for i, want := range wantOrder {
		var id string
		if err := json.Unmarshal(got[i]["id"], &id); err != nil || id != want {
			t.Fatalf("line %d id = %q, want %q", i, id, want)
		}
		for _, key := range []string{
			"type", "id", "campaign_id", "template_id", "step", "contact_id",
			"received_at", "remote_ip", "fields", "secrets", "files",
			"target", "fingerprint",
		} {
			if _, ok := got[i][key]; !ok {
				t.Fatalf("line %d is missing key %q", i, key)
			}
		}
		var typ string
		if err := json.Unmarshal(got[i]["type"], &typ); err != nil || typ != "artifact" {
			t.Fatalf("line %d type = %q, want artifact", i, typ)
		}
	}

	var emptyContact string
	if err := json.Unmarshal(got[1]["contact_id"], &emptyContact); err != nil {
		t.Fatal(err)
	}
	if emptyContact != "" {
		t.Fatalf("middle contact_id = %q, want empty", emptyContact)
	}
	var contact1 string
	if err := json.Unmarshal(got[0]["contact_id"], &contact1); err != nil {
		t.Fatal(err)
	}
	if contact1 != "contact-1" {
		t.Fatalf("first contact_id = %q", contact1)
	}

	// Another campaign's token is forbidden; absence is unauthenticated.
	if rr := get(t, h, campaignA.ID, tokenB, ""); rr.Code != http.StatusForbidden {
		t.Fatalf("foreign token: status = %d, want 403", rr.Code)
	}
	missing := get(t, h, campaignA.ID, "", "")
	if missing.Code != http.StatusUnauthorized {
		t.Fatalf("missing token: status = %d, want 401", missing.Code)
	}
	if missing.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("401 has no WWW-Authenticate")
	}

	// The stored value is a hash, never the clear token.
	stored, err := e.ops.GetExportTokenHash(context.Background(), campaignA.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored == tokenA || stored != HashToken(tokenA) || len(stored) != 64 {
		t.Fatalf("stored token hash = %q", stored)
	}
}

func TestSinceIsStrictlyExclusiveAndExportsAreIdentical(t *testing.T) {
	e := newEnv(t)
	campaign := e.campaign(t)
	token := e.token(t, campaign.ID)

	base := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	e.artifact(t, "one", campaign.ID, "", base)
	e.artifact(t, "two", campaign.ID, "", base.Add(time.Second))
	e.artifact(t, "three", campaign.ID, "", base.Add(2*time.Second))

	h := NewHandler(e.artifacts, e.ops, quiet())

	first := get(t, h, campaign.ID, token, "")
	second := get(t, h, campaign.ID, token, "")
	if first.Code != http.StatusOK || second.Code != http.StatusOK {
		t.Fatalf("statuses = %d/%d", first.Code, second.Code)
	}
	if !bytes.Equal(first.Body.Bytes(), second.Body.Bytes()) {
		t.Fatal("two exports without since differ")
	}

	// since is exclusive: the row at the bound is not replayed.
	since := base.UTC().Format(time.RFC3339Nano)
	rr := get(t, h, campaign.ID, token, since)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	got := lines(t, rr.Body.Bytes())
	if len(got) != 2 {
		t.Fatalf("lines = %d, want 2", len(got))
	}
	var id string
	_ = json.Unmarshal(got[0]["id"], &id)
	if id != "two" {
		t.Fatalf("first line after since = %q, want two", id)
	}

	if rr := get(t, h, campaign.ID, token, "not-a-time"); rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid since: status = %d, want 400", rr.Code)
	}
}

// countingWriter is a ResponseWriter that counts writes and flushes, proving
// the stream is not accumulated: one write and one flush per artifact.
type countingWriter struct {
	header  http.Header
	buf     bytes.Buffer
	writes  int
	flushes int
	status  int
}

func (c *countingWriter) Header() http.Header {
	if c.header == nil {
		c.header = make(http.Header)
	}
	return c.header
}

func (c *countingWriter) WriteHeader(status int) { c.status = status }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.writes++
	return c.buf.Write(p)
}

func (c *countingWriter) FlushError() error {
	c.flushes++
	return nil
}

func TestStreamWritesAndFlushesPerLine(t *testing.T) {
	e := newEnv(t)
	campaign := e.campaign(t)
	token := e.token(t, campaign.ID)
	base := time.Date(2026, 11, 5, 13, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		e.artifact(t, string(rune('a'+i)), campaign.ID, "", base.Add(time.Duration(i)*time.Second))
	}

	req := httptest.NewRequest(http.MethodGet, "/export/"+campaign.ID, nil)
	req.SetPathValue("campaign", campaign.ID)
	req.Header.Set("Authorization", "Bearer "+token)
	out := &countingWriter{}
	NewHandler(e.artifacts, e.ops, quiet()).ServeHTTP(out, req)

	if out.status != 0 && out.status != http.StatusOK {
		t.Fatalf("status = %d", out.status)
	}
	if out.writes != 3 {
		t.Fatalf("writes = %d, want 3 (one per line)", out.writes)
	}
	if out.flushes != 3 {
		t.Fatalf("flushes = %d, want 3 (one per line)", out.flushes)
	}
	if n := len(lines(t, out.buf.Bytes())); n != 3 {
		t.Fatalf("parsed lines = %d", n)
	}
}

func TestCorruptRowFailsWithIDAndWithoutSilentPartialStream(t *testing.T) {
	e := newEnv(t)
	campaign := e.campaign(t)
	token := e.token(t, campaign.ID)
	base := time.Date(2026, 11, 5, 14, 0, 0, 0, time.UTC)
	e.artifact(t, "good", campaign.ID, "", base)
	e.artifact(t, "broken", campaign.ID, "", base.Add(time.Second))
	e.artifact(t, "after", campaign.ID, "", base.Add(2*time.Second))

	// Replace the sealed body with bytes that cannot be opened.
	if _, err := e.handle.Exec(
		`UPDATE artifacts SET body = X'00' WHERE id = 'broken'`); err != nil {
		t.Fatal(err)
	}

	h := NewHandler(e.artifacts, e.ops, quiet())
	rr := get(t, h, campaign.ID, token, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "broken") || !strings.Contains(body, `"type":"error"`) {
		t.Fatalf("partial stream is silent or missing type:error:\n%s", body)
	}
	if strings.Contains(body, `"after"`) {
		t.Fatalf("export continued past the corrupt row:\n%s", body)
	}

	// The core error names the row too, which is what the CLI exits on.
	var buf bytes.Buffer
	if err := func() error {
		_, err := Export(context.Background(), e.artifacts, campaign.ID, time.Time{}, &buf, nil)
		return err
	}(); err == nil || !strings.Contains(err.Error(), "broken") {
		t.Fatalf("Export error = %v, want the artifact id", err)
	}
}

func TestExportCapacityLimitReturns503(t *testing.T) {
	e := newEnv(t)
	campaign := e.campaign(t)
	token := e.token(t, campaign.ID)
	h := NewHandler(e.artifacts, e.ops, quiet())

	// Fill all semaphore slots directly.
	h.sem <- struct{}{}
	h.sem <- struct{}{}

	rr := get(t, h, campaign.ID, token, "")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("over-capacity: status = %d, want 503", rr.Code)
	}

	// Release one slot: next request must succeed.
	<-h.sem
	rr = get(t, h, campaign.ID, token, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("after release: status = %d, want 200", rr.Code)
	}
}

func TestTokenIssueRejectsUnknownCampaign(t *testing.T) {
	e := newEnv(t)
	if _, err := IssueToken(context.Background(), e.ops, "missing"); err == nil {
		t.Fatal("token issued for an unknown campaign")
	}
}
