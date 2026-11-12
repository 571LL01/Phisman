package mgmt

import (
	"bytes"
	"html/template"
	"strings"
	"testing"
)

// renderPage executes one named template and fails on any error.
func renderPage(t *testing.T, name string, data pageData) string {
	t.Helper()
	var buf bytes.Buffer
	if err := mgmtTmpl.ExecuteTemplate(&buf, name, data); err != nil {
		t.Fatalf("execute %q: %v", name, err)
	}
	out := buf.String()
	// html/template emits this token when it refuses to interpolate a value in
	// a sensitive context (e.g. a CSS width). The funnel bars put an integer
	// percentage into a style attribute; guard that it survives.
	if strings.Contains(out, "ZgotmplZ") {
		t.Fatalf("template %q produced ZgotmplZ (unsafe interpolation):\n%s", name, out)
	}
	return out
}

func TestDashboardShowsFunnelColumns(t *testing.T) {
	data := pageData{
		Title:  "Tableau de bord",
		Active: "dashboard",
		Campaigns: []Campaign{{
			ID:    "camp1",
			Name:  "Acme Q4",
			State: "running",
			Stats: Stats{Contacts: 10, SentA: 8, Opened: 6, Clicked: 3},
		}},
	}
	out := renderPage(t, "dashboard", data)
	for _, want := range []string{"Ouverts", "Clics", "Acme Q4", "75%", "37%"} {
		if !strings.Contains(out, want) {
			t.Fatalf("dashboard missing %q", want)
		}
	}
}

func TestCampaignDetailShowsFunnel(t *testing.T) {
	data := pageData{
		Title:  "Acme Q4",
		Active: "campaigns",
		Campaign: &Campaign{
			ID:    "camp1",
			Name:  "Acme Q4",
			State: "running",
			Stats: Stats{Contacts: 10, SentA: 8, Opened: 6, Clicked: 3},
		},
	}
	out := renderPage(t, "campaign-detail", data)
	for _, want := range []string{"Tunnel de conversion", "Ouvertures", "Clics", "width:75%", "width:37%"} {
		if !strings.Contains(out, want) {
			t.Fatalf("campaign-detail missing %q:\n%s", want, out)
		}
	}
}

func TestCampaignTrackingRendersPerContactRows(t *testing.T) {
	data := pageData{
		Title:    "Suivi",
		Active:   "campaigns",
		Campaign: &Campaign{ID: "camp1", Name: "Acme Q4", State: "running"},
		Tracking: &ContactReport{
			Total: 2, Sent: 2, Opened: 1, Clicked: 1, Submitted: 1,
			Rows: []ContactStatus{
				{ID: "k1", Email: "alice@example.com", Sent: true, SentAt: "2026-11-12 09:00 UTC",
					Opened: true, OpenedAt: "2026-11-12 09:05 UTC", Clicked: true, ClickedAt: "2026-11-12 09:06 UTC",
					Submitted: true, SubmittedAt: "2026-11-12 09:07 UTC"},
				{ID: "k2", Email: "bob@example.com", Sent: true, SentAt: "2026-11-12 09:00 UTC"},
			},
		},
	}
	out := renderPage(t, "campaign-tracking", data)
	for _, want := range []string{"alice@example.com", "bob@example.com", "A soumis", "Suivi par contact", "✓"} {
		if !strings.Contains(out, want) {
			t.Fatalf("campaign-tracking missing %q", want)
		}
	}
}

func TestArtifactsShowCapturedSecretWithoutValue(t *testing.T) {
	data := pageData{
		Title:    "Artefacts",
		Active:   "campaigns",
		Campaign: &Campaign{ID: "camp1", Name: "Acme", State: "running"},
		Artifacts: []ArtifactRow{{
			ID: "a1", Template: "tmp-001", Step: "b", ContactID: "k1",
			ReceivedAt: "2026-11-12 09:07 UTC", RemoteIP: "203.0.113.5",
			Secrets: []SecretKV{{Name: "code", Kind: "otp", Length: 6}},
		}},
	}
	out := renderPage(t, "campaign-artifacts", data)
	// The field name, kind and length must show...
	for _, want := range []string{"code", "otp", "6 car."} {
		if !strings.Contains(out, want) {
			t.Fatalf("artifacts page missing %q", want)
		}
	}
	// ...and the captured-but-hashed marker.
	if !strings.Contains(out, "haché") {
		t.Fatalf("artifacts page should mark the secret as hashed")
	}
}

func TestSendFormListsEmailTemplates(t *testing.T) {
	data := pageData{
		Title:          "Envoyer",
		Active:         "campaigns",
		Campaign:       &Campaign{ID: "camp1", Name: "Acme", State: "running"},
		Tmpls:          []TemplateInfo{{ID: "tmp-001", Steps: []string{"a", "b"}, ConfigCampaignID: "acme"}},
		EmailTemplates: BuiltinEmailTemplates,
		Send:           &sendView{},
	}
	out := renderPage(t, "campaign-send", data)
	if !strings.Contains(out, "Modèle d'email prêt") {
		t.Fatalf("send form missing email-template picker")
	}
	for _, et := range BuiltinEmailTemplates {
		// Option text is auto-escaped by html/template (e.g. "&" -> "&amp;"),
		// so compare against the escaped form.
		if !strings.Contains(out, template.HTMLEscapeString(et.Name)) {
			t.Fatalf("send form missing template %q", et.Name)
		}
	}
	// The body data attribute must carry the {{.Link}} token for the operator.
	if !strings.Contains(out, "data-body=") {
		t.Fatalf("send form missing data-body attribute")
	}
	// The picker must carry the spoofed sender so it can pre-fill the From fields.
	if !strings.Contains(out, "data-from=") || !strings.Contains(out, "data-fromname=") {
		t.Fatalf("send form missing data-from/data-fromname attributes")
	}
}

func TestStatsRatesRoundAndGuardZeroDivision(t *testing.T) {
	s := Stats{SentA: 0, Opened: 4, Clicked: 2}
	if s.OpenRate() != 0 || s.ClickRate() != 0 {
		t.Fatalf("rates with zero sends = %d/%d, want 0/0", s.OpenRate(), s.ClickRate())
	}
	s = Stats{SentA: 8, Opened: 6, Clicked: 3}
	if s.OpenRate() != 75 || s.ClickRate() != 37 {
		t.Fatalf("rates = %d/%d, want 75/37", s.OpenRate(), s.ClickRate())
	}
}
