package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/siren-core/gorgone/internal/collect"
	sirendb "github.com/siren-core/gorgone/internal/db"
	"github.com/siren-core/gorgone/internal/store"
)

// trackingHarness builds a real-DB handler with one tmp-001/a step and one
// imported contact, and returns the handler, the store, the campaign id and the
// contact id. It is the minimal wiring the open/click paths need.
func trackingHarness(t *testing.T) (http.Handler, *store.SQL, string, string) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()

	key := bytes.Repeat([]byte{0xCD}, 32)
	ks, err := collect.NewKeySet(1, map[byte][]byte{1: key})
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	handle, err := sirendb.Open("file:" + filepath.Join(dir, "artifacts.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { handle.Close() })

	arts, err := collect.NewSQLiteFrom(handle.DB, ks)
	if err != nil {
		t.Fatalf("collect.NewSQLiteFrom: %v", err)
	}
	ops, err := store.New(handle.DB)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	campaign, err := ops.CreateCampaign(ctx, "Tracking")
	if err != nil {
		t.Fatalf("CreateCampaign: %v", err)
	}
	cid := campaign.ID
	if _, err := ops.AddContacts(ctx, cid, []store.ContactInput{{Email: "alice@example.com"}}); err != nil {
		t.Fatalf("AddContacts: %v", err)
	}
	contacts, err := ops.ListContacts(ctx, cid)
	if err != nil || len(contacts) != 1 {
		t.Fatalf("ListContacts: %v (n=%d)", err, len(contacts))
	}

	cfg := &fileConfig{
		Listen:  "127.0.0.1:0",
		DataDir: dir,
		Campaigns: map[string]campaignConfig{
			cid: {Templates: map[string]map[string]stepConfig{
				"tmp-001": {"a": {
					Target: "/c/" + cid + "/tmp-001/b",
					Mode:   "inline",
					Fields: []fieldConfig{{
						Name: "identifier", Kind: "text", MaxLen: 64,
						Labels: map[string]string{"fr": "Identifiant", "en": "Username", "de": "Benutzername"},
					}},
				}},
			}},
		},
	}
	h, err := newHandler(cfg, arts, ops, testLogger())
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	return h, ops, cid, contacts[0].ID
}

// TestSubmissionStaysOnDeliveryCampaign reproduces the bug where the config
// campaign key ("acme") differs from the DB campaign id (a UUID): the delivered
// link uses the UUID, but the rendered form action and the next-step redirect
// must ALSO use the UUID, so the submitted artifact is stored under the same
// campaign the UI queries and is attributed to the contact.
func TestSubmissionStaysOnDeliveryCampaign(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	key := bytes.Repeat([]byte{0xEF}, 32)
	ks, err := collect.NewKeySet(1, map[byte][]byte{1: key})
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	handle, err := sirendb.Open("file:" + filepath.Join(dir, "artifacts.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { handle.Close() })
	arts, err := collect.NewSQLiteFrom(handle.DB, ks)
	if err != nil {
		t.Fatalf("collect.NewSQLiteFrom: %v", err)
	}
	ops, err := store.New(handle.DB)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	campaign, err := ops.CreateCampaign(ctx, "Real")
	if err != nil {
		t.Fatalf("CreateCampaign: %v", err)
	}
	cid := campaign.ID // a UUID, NOT "acme"
	if _, err := ops.AddContacts(ctx, cid, []store.ContactInput{{Email: "cible@example.com"}}); err != nil {
		t.Fatalf("AddContacts: %v", err)
	}
	contacts, _ := ops.ListContacts(ctx, cid)
	rid := contacts[0].ID

	// Config template lives under the human key "acme", with an internal target
	// that also names "acme" — exactly the shipped config shape.
	cfg := &fileConfig{
		Listen:  "127.0.0.1:0",
		DataDir: dir,
		Campaigns: map[string]campaignConfig{
			"acme": {Templates: map[string]map[string]stepConfig{
				"tmp-001": {
					"a": {
						Target: "/c/acme/tmp-001/b",
						Mode:   "inline",
						Fields: []fieldConfig{{Name: "identifier", Kind: "text", MaxLen: 64,
							Labels: map[string]string{"fr": "Identifiant", "en": "Username", "de": "Benutzername"}}},
					},
					"b": {
						Target: "https://example.com/done",
						Mode:   "inline",
						Fields: []fieldConfig{{Name: "code", Kind: "otp", MaxLen: 6,
							Labels: map[string]string{"fr": "Code", "en": "Code", "de": "Code"}}},
					},
				},
			}},
		},
	}
	h, err := newHandler(cfg, arts, ops, testLogger())
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}

	// 1. The rendered page's form action must point at the UUID, not "acme".
	rr := getReq(t, h, "/c/"+cid+"/tmp-001/a?l=fr&rid="+url.QueryEscape(rid))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET page status = %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `action="/c/`+cid+`/tmp-001/a`) {
		t.Fatalf("form action does not use the delivery campaign id; body:\n%s", body)
	}
	if strings.Contains(body, `action="/c/acme/`) {
		t.Fatalf("form action still uses the config key 'acme'")
	}

	// 2. POST the submission to the UUID URL; the redirect to step b must keep
	//    the UUID, not fall back to "acme".
	req := httptest.NewRequest(http.MethodPost, "/c/"+cid+"/tmp-001/a?rid="+url.QueryEscape(rid),
		strings.NewReader(url.Values{"identifier": {"j.dupont"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	pr := httptest.NewRecorder()
	h.ServeHTTP(pr, req)
	if pr.Code != http.StatusFound {
		t.Fatalf("POST status = %d, want 302", pr.Code)
	}
	if loc := pr.Header().Get("Location"); !strings.HasPrefix(loc, "/c/"+cid+"/tmp-001/b") {
		t.Fatalf("redirect Location = %q, want /c/%s/tmp-001/b…", loc, cid)
	}

	// 3. The artifact must be stored under the UUID campaign and attributed.
	var found *collect.Artifact
	if err := arts.Export(ctx, cid, time.Time{}, func(a *collect.Artifact) error {
		found = a
		return nil
	}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if found == nil {
		t.Fatalf("no artifact stored under campaign %s (the bug: it landed on 'acme')", cid)
	}
	if found.ContactID != rid {
		t.Fatalf("artifact contact_id = %q, want %q", found.ContactID, rid)
	}
	if found.Fields["identifier"] != "j.dupont" {
		t.Fatalf("artifact fields = %v", found.Fields)
	}
}

func getReq(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
	return rr
}

func TestOpenPixelRecordsAndServesGIF(t *testing.T) {
	h, ops, cid, rid := trackingHarness(t)
	ctx := context.Background()
	q := url.QueryEscape(rid)

	rr := getReq(t, h, "/__siren/o/"+cid+"/tmp-001/a?rid="+q)
	if rr.Code != http.StatusOK {
		t.Fatalf("pixel status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "image/gif" {
		t.Fatalf("Content-Type = %q, want image/gif", ct)
	}
	if !bytes.Equal(rr.Body.Bytes(), pixelGIF) {
		t.Fatalf("body is not the 1x1 GIF (%d bytes)", rr.Body.Len())
	}
	if cc := rr.Header().Get("Cache-Control"); cc == "" {
		t.Fatalf("missing Cache-Control on pixel")
	}

	// A second open by the same recipient must not change the distinct count.
	getReq(t, h, "/__siren/o/"+cid+"/tmp-001/a?rid="+q)

	stats, err := ops.EventStats(ctx, cid)
	if err != nil {
		t.Fatalf("EventStats: %v", err)
	}
	if stats.Opened != 1 || stats.Clicked != 0 {
		t.Fatalf("after opens: %+v, want {Opened:1 Clicked:0}", stats)
	}
}

func TestOpenPixelWithoutValidRidRecordsNothing(t *testing.T) {
	h, ops, cid, _ := trackingHarness(t)
	ctx := context.Background()

	// No rid, and a bad rid: both still serve the image, neither records.
	for _, path := range []string{
		"/__siren/o/" + cid + "/tmp-001/a",
		"/__siren/o/" + cid + "/tmp-001/a?rid=deadbeef",
	} {
		rr := getReq(t, h, path)
		if rr.Code != http.StatusOK || !bytes.Equal(rr.Body.Bytes(), pixelGIF) {
			t.Fatalf("%s: status=%d served-gif=%v", path, rr.Code, bytes.Equal(rr.Body.Bytes(), pixelGIF))
		}
	}
	stats, err := ops.EventStats(ctx, cid)
	if err != nil {
		t.Fatalf("EventStats: %v", err)
	}
	if stats.Opened != 0 {
		t.Fatalf("opened = %d, want 0 (no attribution)", stats.Opened)
	}
}

func TestPageGETRecordsClick(t *testing.T) {
	h, ops, cid, rid := trackingHarness(t)
	ctx := context.Background()
	q := url.QueryEscape(rid)

	// Rendering the phishing page for a resolved recipient is one click.
	rr := getReq(t, h, "/c/"+cid+"/tmp-001/a?l=fr&rid="+q)
	if rr.Code != http.StatusOK {
		t.Fatalf("page GET status = %d, want 200", rr.Code)
	}
	// Two visits, one distinct contact.
	getReq(t, h, "/c/"+cid+"/tmp-001/a?l=fr&rid="+q)

	stats, err := ops.EventStats(ctx, cid)
	if err != nil {
		t.Fatalf("EventStats: %v", err)
	}
	if stats.Clicked != 1 {
		t.Fatalf("clicked = %d, want 1", stats.Clicked)
	}

	// An anonymous preview (no rid) renders but records no click.
	if rr := getReq(t, h, "/c/"+cid+"/tmp-001/a?l=fr"); rr.Code != http.StatusOK {
		t.Fatalf("anon page GET status = %d, want 200", rr.Code)
	}
	stats, _ = ops.EventStats(ctx, cid)
	if stats.Clicked != 1 {
		t.Fatalf("clicked after anon visit = %d, want 1", stats.Clicked)
	}
}
