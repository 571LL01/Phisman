package mgmt

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReportCSVExport(t *testing.T) {
	deps := Deps{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		GetCampaign: func(_ context.Context, id string) (*Campaign, error) {
			return &Campaign{ID: id, Name: "Acme Q4 2026"}, nil
		},
		ContactReport: func(_ context.Context, _ string) (ContactReport, error) {
			return ContactReport{
				Total: 2, Sent: 2, Opened: 1, Clicked: 1, Submitted: 1,
				Rows: []ContactStatus{
					{ID: "k1", Email: "alice@example.com",
						Sent: true, SentAt: "2026-11-12 09:00 UTC",
						Opened: true, OpenedAt: "2026-11-12 09:05 UTC",
						Clicked: true, ClickedAt: "2026-11-12 09:06 UTC",
						Submitted: true, SubmittedAt: "2026-11-12 09:07 UTC"},
					{ID: "k2", Email: "bob@example.com", Sent: true, SentAt: "2026-11-12 09:00 UTC"},
				},
			}, nil
		},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/campaigns/c1/report.csv", nil)
	New(deps).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("content-type = %q", ct)
	}
	if cd := rr.Header().Get("Content-Disposition"); !strings.Contains(cd, "rapport-Acme-Q4-2026.csv") {
		t.Fatalf("content-disposition = %q", cd)
	}
	body := rr.Body.String()
	wantLines := []string{
		"email,contact_id,envoye,envoye_le,ouvert,ouvert_le,clique,clique_le,soumis,soumis_le",
		"alice@example.com,k1,oui,2026-11-12 09:05 UTC", // opened_at follows sent cols
		"bob@example.com,k2,oui,2026-11-12 09:00 UTC,non,,non,,non,",
	}
	// Header + alice has all "oui", bob partial.
	if !strings.Contains(body, wantLines[0]) {
		t.Fatalf("missing header line; body:\n%s", body)
	}
	if !strings.Contains(body, "alice@example.com,k1,oui,2026-11-12 09:00 UTC,oui,2026-11-12 09:05 UTC,oui,2026-11-12 09:06 UTC,oui,2026-11-12 09:07 UTC") {
		t.Fatalf("alice row wrong; body:\n%s", body)
	}
	if !strings.Contains(body, "bob@example.com,k2,oui,2026-11-12 09:00 UTC,non,,non,,non,") {
		t.Fatalf("bob row wrong; body:\n%s", body)
	}
}

func TestSafeFilename(t *testing.T) {
	cases := map[string]string{
		"Acme Q4 2026": "Acme-Q4-2026",
		`bad"\r\nname`: "bad--r-nname",
		"":             "campagne",
		"///":          "campagne",
		"café-écho":    "caf---cho",
	}
	for in, want := range cases {
		if got := safeFilename(in); got != want {
			t.Fatalf("safeFilename(%q) = %q, want %q", in, got, want)
		}
	}
}
