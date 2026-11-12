package mgmt

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"html/template"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Handler is the HTTP handler for the management UI. Mount it on /admin/ after
// wrapping with admin.Guard and per-route admin.RequireSession.
type Handler struct {
	deps Deps
}

// New returns a Handler ready to serve.
func New(deps Deps) *Handler { return &Handler{deps: deps} }

// ServeHTTP dispatches /admin/* management routes. Admin auth routes
// (/admin/login, /admin/logout) are handled upstream; this handler only sees
// routes that require an active session.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path

	switch {
	case p == "/admin" || p == "/admin/":
		h.dashboard(w, r)

	case p == "/admin/campaigns/new":
		switch r.Method {
		case http.MethodGet:
			h.campaignNewForm(w, r)
		case http.MethodPost:
			h.campaignCreate(w, r)
		default:
			methodNotAllowed(w, "GET, POST")
		}

	case matchPath(p, `/admin/campaigns/[^/]+/state`):
		if r.Method != http.MethodPost {
			methodNotAllowed(w, "POST")
			return
		}
		h.campaignTransition(w, r, campaignIDFromPath(p, 3))

	case matchPath(p, `/admin/campaigns/[^/]+/token`):
		if r.Method != http.MethodPost {
			methodNotAllowed(w, "POST")
			return
		}
		h.campaignIssueToken(w, r, campaignIDFromPath(p, 3))

	case matchPath(p, `/admin/campaigns/[^/]+/contacts`):
		switch r.Method {
		case http.MethodGet:
			h.contactsForm(w, r, campaignIDFromPath(p, 3))
		case http.MethodPost:
			h.contactsImport(w, r, campaignIDFromPath(p, 3))
		default:
			methodNotAllowed(w, "GET, POST")
		}

	case matchPath(p, `/admin/campaigns/[^/]+/artifacts`):
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		h.artifacts(w, r, campaignIDFromPath(p, 3))

	case matchPath(p, `/admin/campaigns/[^/]+/send`):
		switch r.Method {
		case http.MethodGet:
			h.sendForm(w, r, campaignIDFromPath(p, 3))
		case http.MethodPost:
			h.sendRun(w, r, campaignIDFromPath(p, 3))
		default:
			methodNotAllowed(w, "GET, POST")
		}

	case matchPath(p, `/admin/campaigns/[^/]+$`):
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		h.campaignDetail(w, r, campaignIDFromPath(p, 3))

	case p == "/admin/settings/smtp":
		switch r.Method {
		case http.MethodGet:
			h.smtpForm(w, r)
		case http.MethodPost:
			h.smtpSave(w, r)
		default:
			methodNotAllowed(w, "GET, POST")
		}

	default:
		http.NotFound(w, r)
	}
}

// ---- page handlers -------------------------------------------------------

func (h *Handler) dashboard(w http.ResponseWriter, r *http.Request) {
	csrf, err := h.deps.IssueCSRF(w)
	if err != nil {
		h.internalError(w, "csrf", err)
		return
	}
	campaigns, err := h.deps.ListCampaigns(r.Context())
	if err != nil {
		h.internalError(w, "list campaigns", err)
		return
	}
	h.render(w, "dashboard", pageData{
		Title:     "Tableau de bord",
		Active:    "dashboard",
		Crumbs:    []crumb{{Label: "Campagnes"}},
		CSRF:      csrf,
		Campaigns: campaigns,
	})
}

func (h *Handler) campaignNewForm(w http.ResponseWriter, r *http.Request) {
	csrf, err := h.deps.IssueCSRF(w)
	if err != nil {
		h.internalError(w, "csrf", err)
		return
	}
	h.render(w, "campaign-new", pageData{
		Title:  "Nouvelle campagne",
		Active: "new-campaign",
		Crumbs: []crumb{{Label: "Campagnes", Href: "/admin/"}, {Label: "Nouvelle"}},
		CSRF:   csrf,
	})
}

func (h *Handler) campaignCreate(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		h.renderFlash(w, r, "campaign-new", pageData{
			Title:     "Nouvelle campagne",
			Active:    "new-campaign",
			Crumbs:    []crumb{{Label: "Campagnes", Href: "/admin/"}, {Label: "Nouvelle"}},
			Flash:     "Le nom de la campagne est obligatoire.",
			FlashKind: "err",
		})
		return
	}
	c, err := h.deps.CreateCampaign(r.Context(), name)
	if err != nil {
		h.internalError(w, "create campaign", err)
		return
	}
	http.Redirect(w, r, "/admin/campaigns/"+c.ID, http.StatusSeeOther)
}

func (h *Handler) campaignDetail(w http.ResponseWriter, r *http.Request, id string) {
	csrf, err := h.deps.IssueCSRF(w)
	if err != nil {
		h.internalError(w, "csrf", err)
		return
	}
	c, err := h.deps.GetCampaign(r.Context(), id)
	if err != nil {
		h.internalError(w, "get campaign", err)
		return
	}
	if c == nil {
		http.NotFound(w, r)
		return
	}
	flash, flashKind := flashFromQuery(r)
	token := r.URL.Query().Get("token")
	h.render(w, "campaign-detail", pageData{
		Title:     c.Name,
		Active:    "campaigns",
		Crumbs:    []crumb{{Label: "Campagnes", Href: "/admin/"}, {Label: c.Name}},
		CSRF:      csrf,
		Campaign:  c,
		Token:     token,
		Flash:     flash,
		FlashKind: flashKind,
	})
}

func (h *Handler) campaignTransition(w http.ResponseWriter, r *http.Request, id string) {
	to := strings.TrimSpace(r.FormValue("to"))
	if err := h.deps.TransitionCampaign(r.Context(), id, to); err != nil {
		http.Redirect(w, r, "/admin/campaigns/"+id+"?flash="+urlEncode(err.Error())+"&kind=err", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/campaigns/"+id+"?flash=État+mis+à+jour.&kind=ok", http.StatusSeeOther)
}

func (h *Handler) campaignIssueToken(w http.ResponseWriter, r *http.Request, id string) {
	tok, err := h.deps.IssueToken(r.Context(), id)
	if err != nil {
		http.Redirect(w, r, "/admin/campaigns/"+id+"?flash="+urlEncode(err.Error())+"&kind=err", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/campaigns/"+id+"?token="+tok, http.StatusSeeOther)
}

func (h *Handler) contactsForm(w http.ResponseWriter, r *http.Request, id string) {
	csrf, err := h.deps.IssueCSRF(w)
	if err != nil {
		h.internalError(w, "csrf", err)
		return
	}
	c, err := h.deps.GetCampaign(r.Context(), id)
	if err != nil || c == nil {
		http.NotFound(w, r)
		return
	}
	flash, flashKind := flashFromQuery(r)
	h.render(w, "campaign-contacts", pageData{
		Title:     "Importer des contacts — " + c.Name,
		Active:    "campaigns",
		Crumbs:    []crumb{{Label: "Campagnes", Href: "/admin/"}, {Label: c.Name, Href: "/admin/campaigns/" + id}, {Label: "Contacts"}},
		CSRF:      csrf,
		Campaign:  c,
		Flash:     flash,
		FlashKind: flashKind,
	})
}

func (h *Handler) contactsImport(w http.ResponseWriter, r *http.Request, id string) {
	raw := strings.TrimSpace(r.FormValue("csv"))
	if raw == "" {
		http.Redirect(w, r, "/admin/campaigns/"+id+"/contacts?flash=CSV+vide.&kind=warn", http.StatusSeeOther)
		return
	}
	contacts, err := parseCSV(raw)
	if err != nil {
		http.Redirect(w, r,
			"/admin/campaigns/"+id+"/contacts?flash="+urlEncode("Erreur CSV : "+err.Error())+"&kind=err",
			http.StatusSeeOther)
		return
	}
	imported, err := h.deps.ImportContacts(r.Context(), id, contacts)
	if err != nil {
		http.Redirect(w, r,
			"/admin/campaigns/"+id+"/contacts?flash="+urlEncode(err.Error())+"&kind=err",
			http.StatusSeeOther)
		return
	}
	msg := fmt.Sprintf("%d contact(s) importé(s).", imported)
	http.Redirect(w, r, "/admin/campaigns/"+id+"?flash="+urlEncode(msg)+"&kind=ok", http.StatusSeeOther)
}

func (h *Handler) artifacts(w http.ResponseWriter, r *http.Request, id string) {
	csrf, err := h.deps.IssueCSRF(w)
	if err != nil {
		h.internalError(w, "csrf", err)
		return
	}
	c, err := h.deps.GetCampaign(r.Context(), id)
	if err != nil || c == nil {
		http.NotFound(w, r)
		return
	}
	rows, err := h.deps.ListArtifacts(r.Context(), id)
	if err != nil {
		h.internalError(w, "list artifacts", err)
		return
	}
	h.render(w, "campaign-artifacts", pageData{
		Title:     "Artefacts — " + c.Name,
		Active:    "campaigns",
		Crumbs:    []crumb{{Label: "Campagnes", Href: "/admin/"}, {Label: c.Name, Href: "/admin/campaigns/" + id}, {Label: "Artefacts"}},
		CSRF:      csrf,
		Campaign:  c,
		Artifacts: rows,
	})
}

func (h *Handler) sendForm(w http.ResponseWriter, r *http.Request, id string) {
	csrf, err := h.deps.IssueCSRF(w)
	if err != nil {
		h.internalError(w, "csrf", err)
		return
	}
	c, err := h.deps.GetCampaign(r.Context(), id)
	if err != nil || c == nil {
		http.NotFound(w, r)
		return
	}
	tmpls := h.deps.AvailableTemplates(id)
	h.render(w, "campaign-send", pageData{
		Title:    "Envoyer — " + c.Name,
		Active:   "campaigns",
		Crumbs:   []crumb{{Label: "Campagnes", Href: "/admin/"}, {Label: c.Name, Href: "/admin/campaigns/" + id}, {Label: "Envoyer"}},
		CSRF:     csrf,
		Campaign: c,
		Tmpls:    tmpls,
		Send:     &sendView{},
	})
}

func (h *Handler) sendRun(w http.ResponseWriter, r *http.Request, id string) {
	csrf, err := h.deps.IssueCSRF(w)
	if err != nil {
		h.internalError(w, "csrf", err)
		return
	}
	c, err := h.deps.GetCampaign(r.Context(), id)
	if err != nil || c == nil {
		http.NotFound(w, r)
		return
	}
	req := SendRequest{
		CampaignID:       id,
		TemplateID:       strings.TrimSpace(r.FormValue("template_id")),
		StepID:           strings.TrimSpace(r.FormValue("step_id")),
		PriorStep:        strings.TrimSpace(r.FormValue("prior_step")),
		DryRun:           r.FormValue("dry_run") == "1",
		FromAddress:      strings.TrimSpace(r.FormValue("from_address")),
		FromName:         strings.TrimSpace(r.FormValue("from_name")),
		EmailSubject:     strings.TrimSpace(r.FormValue("email_subject")),
		EmailBody:        strings.TrimSpace(r.FormValue("email_body")),
		ConfigCampaignID: strings.TrimSpace(r.FormValue("config_campaign_id")),
	}
	result, sendErr := h.deps.SendEmails(r.Context(), req)

	tmpls := h.deps.AvailableTemplates(id)
	sv := &sendView{
		DryRun:           req.DryRun,
		Template:         req.TemplateID,
		Step:             req.StepID,
		Prior:            req.PriorStep,
		FromAddress:      req.FromAddress,
		FromName:         req.FromName,
		EmailSubject:     req.EmailSubject,
		EmailBody:        req.EmailBody,
		ConfigCampaignID: req.ConfigCampaignID,
	}
	flash, flashKind := "", ""
	if sendErr != nil {
		flash = "Erreur lors de l'envoi : " + sendErr.Error()
		flashKind = "err"
	} else {
		sv.Result = &result
		if req.DryRun {
			flash = fmt.Sprintf("Simulation : %d email(s) auraient été envoyés.", result.Sent)
			flashKind = "warn"
		} else {
			flash = fmt.Sprintf("%d email(s) envoyé(s), %d ignoré(s), %d échec(s).", result.Sent, result.Skipped, result.Failed)
			flashKind = "ok"
		}
	}
	h.render(w, "campaign-send", pageData{
		Title:     "Envoyer — " + c.Name,
		Active:    "campaigns",
		Crumbs:    []crumb{{Label: "Campagnes", Href: "/admin/"}, {Label: c.Name, Href: "/admin/campaigns/" + id}, {Label: "Envoyer"}},
		CSRF:      csrf,
		Campaign:  c,
		Tmpls:     tmpls,
		Send:      sv,
		Flash:     flash,
		FlashKind: flashKind,
	})
}

func (h *Handler) smtpForm(w http.ResponseWriter, r *http.Request) {
	csrf, err := h.deps.IssueCSRF(w)
	if err != nil {
		h.internalError(w, "csrf", err)
		return
	}
	s, err := h.deps.LoadSMTP(r.Context())
	if err != nil {
		h.internalError(w, "load smtp", err)
		return
	}
	flash, flashKind := flashFromQuery(r)
	h.render(w, "smtp-settings", pageData{
		Title:     "Configuration SMTP",
		Active:    "smtp",
		Crumbs:    []crumb{{Label: "Configuration"}, {Label: "SMTP"}},
		CSRF:      csrf,
		SMTP:      &s,
		Flash:     flash,
		FlashKind: flashKind,
	})
}

func (h *Handler) smtpSave(w http.ResponseWriter, r *http.Request) {
	s := SMTPSettings{
		Host:         strings.TrimSpace(r.FormValue("host")),
		Port:         strings.TrimSpace(r.FormValue("port")),
		Username:     strings.TrimSpace(r.FormValue("username")),
		PasswordFile: strings.TrimSpace(r.FormValue("password_file")),
		FromAddress:  strings.TrimSpace(r.FormValue("from_address")),
		FromName:     strings.TrimSpace(r.FormValue("from_name")),
		BaseURL:      strings.TrimSpace(r.FormValue("base_url")),
	}
	if err := h.deps.SaveSMTP(r.Context(), s); err != nil {
		http.Redirect(w, r,
			"/admin/settings/smtp?flash="+urlEncode(err.Error())+"&kind=err",
			http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/settings/smtp?flash=Paramètres+SMTP+enregistrés.&kind=ok", http.StatusSeeOther)
}

// ---- helpers ----------------------------------------------------------------

func (h *Handler) render(w http.ResponseWriter, name string, data pageData) {
	var buf bytes.Buffer
	if err := mgmtTmpl.ExecuteTemplate(&buf, name, data); err != nil {
		h.deps.Logger.Error("mgmt: template error", "name", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(buf.Bytes())
}

func (h *Handler) renderFlash(w http.ResponseWriter, r *http.Request, name string, data pageData) {
	csrf, err := h.deps.IssueCSRF(w)
	if err != nil {
		h.internalError(w, "csrf", err)
		return
	}
	data.CSRF = csrf
	h.render(w, name, data)
}

func (h *Handler) internalError(w http.ResponseWriter, op string, err error) {
	h.deps.Logger.Error("mgmt: internal error", "op", op, "err", err)
	http.Error(w, "erreur interne", http.StatusInternalServerError)
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

var rePathSeg = regexp.MustCompile(`/admin/campaigns/([^/]+)`)

func campaignIDFromPath(path string, _ int) string {
	m := rePathSeg.FindStringSubmatch(path)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func matchPath(path, pattern string) bool {
	ok, _ := regexp.MatchString("^"+pattern+"$", path)
	return ok
}

func urlEncode(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func flashFromQuery(r *http.Request) (flash, kind string) {
	flash = r.URL.Query().Get("flash")
	kind = r.URL.Query().Get("kind")
	if kind == "" {
		kind = "ok"
	}
	return
}

// parseCSV reads a CSV body from the form field, requiring an "email" header.
func parseCSV(raw string) ([]ContactInput, error) {
	rd := csv.NewReader(strings.NewReader(raw))
	rd.TrimLeadingSpace = true
	rows, err := rd.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) < 2 {
		return nil, fmt.Errorf("au moins une ligne d'en-tête et une ligne de données requises")
	}
	headers := rows[0]
	emailIdx := -1
	for i, h := range headers {
		if strings.EqualFold(strings.TrimSpace(h), "email") {
			emailIdx = i
			break
		}
	}
	if emailIdx < 0 {
		return nil, fmt.Errorf("colonne 'email' introuvable dans les en-têtes")
	}
	out := make([]ContactInput, 0, len(rows)-1)
	for _, row := range rows[1:] {
		if emailIdx >= len(row) {
			continue
		}
		email := strings.TrimSpace(row[emailIdx])
		if email == "" {
			continue
		}
		vars := make(map[string]string, len(headers)-1)
		for i, h := range headers {
			if i == emailIdx || i >= len(row) {
				continue
			}
			v := strings.TrimSpace(row[i])
			if v != "" {
				vars[strings.TrimSpace(h)] = v
			}
		}
		out = append(out, ContactInput{Email: email, Vars: vars})
	}
	return out, nil
}

// FormatTime is a helper for adapter code that formats a time.Time for display.
func FormatTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

// ensure template.HTML is importable so callers can cast render results.
var _ template.HTML
