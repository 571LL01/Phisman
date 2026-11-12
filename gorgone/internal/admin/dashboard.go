package admin

import (
	"context"
	"html/template"
	"net/http"
	"time"
)

// Campaign is the operator-facing projection of a campaign. The admin package
// deliberately does not import internal/store: the binary adapts its store to
// this narrow view, which keeps the HTTP surface independent of persistence.
type Campaign struct {
	ID         string
	Name       string
	State      string
	StateLabel string
	Created    string // pre-formatted UTC timestamp, empty when unknown
}

// CampaignLister returns every campaign for the dashboard. A nil lister is
// valid: the page renders an explicit "source unavailable" state and keeps the
// logout form reachable, so a database outage cannot lock the operator in.
type CampaignLister func(context.Context) ([]Campaign, error)

type dashboardView struct {
	CSRF      string
	Campaigns []Campaign
	Count     int
	LoadErr   string
}

// DashboardHandler renders the operator landing page. It is a styled,
// self-contained HTML page (inline CSS, no JavaScript, no external asset) that
// lists campaigns and exposes a CSRF-protected logout form. It is not a metrics
// dashboard: there are no counters beyond the campaign count and no charts.
func DashboardHandler(cfg Config, list CampaignLister) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}

		cookieVal, fieldVal, err := newCSRFToken(cfg.CSRFSecret)
		if err != nil {
			cfg.Logger.Error("admin dashboard: csrf token generation failed", "err", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		setCSRFCookie(w, cookieVal, cfg.SecureCookies)

		var campaigns []Campaign
		loadErr := ""
		if list == nil {
			loadErr = "Aucune source de campagnes n'est configurée."
		} else {
			ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			defer cancel()
			campaigns, err = list(ctx)
			if err != nil {
				cfg.Logger.Error("admin dashboard: campaign list failed", "err", err)
				loadErr = "Liste des campagnes indisponible. La déconnexion reste possible."
				campaigns = nil
			}
		}
		for i := range campaigns {
			campaigns[i].StateLabel = campaignStateLabel(campaigns[i].State)
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.WriteHeader(http.StatusOK)

		if err := dashboardTemplate.Execute(w, dashboardView{
			CSRF:      fieldVal,
			Campaigns: campaigns,
			Count:     len(campaigns),
			LoadErr:   loadErr,
		}); err != nil {
			cfg.Logger.Error("admin dashboard: render failed", "err", err)
		}
	}
}

var dashboardTemplate = template.Must(template.New("dashboard").Parse(`<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SIREN — Administration</title>
<style>
:root{--ink:#111827;--muted:#6b7280;--line:#e5e7eb;--bg:#f4f4f5;--card:#fff;--brand:#1d4ed8}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:var(--bg);color:var(--ink);
     font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
header{display:flex;align-items:center;justify-content:space-between;gap:1rem;
       padding:.9rem 1.5rem;background:#0f172a;color:#fff}
.brand{display:flex;align-items:baseline;gap:.6rem}
.brand strong{font-size:1.05rem;letter-spacing:.14em}
.brand span{font-size:.78rem;color:#cbd5e1}
header form{margin:0}
header button{padding:.45rem .9rem;border:1px solid #475569;border-radius:.35rem;
              background:transparent;color:#e2e8f0;font:inherit;font-size:.82rem;cursor:pointer}
header button:hover{background:#1e293b}
main{max-width:64rem;margin:2rem auto;padding:0 1.25rem}
h1{margin:0 0 .3rem;font-size:1.35rem}
.sub{margin:0 0 1.5rem;color:var(--muted);font-size:.88rem}
.notice{margin:0 0 1.25rem;padding:.75rem 1rem;border:1px solid #fecaca;
        border-radius:.4rem;background:#fef2f2;color:#991b1b;font-size:.88rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:.5rem;
      box-shadow:0 1px 3px rgba(0,0,0,.06);overflow:hidden}
table{width:100%;border-collapse:collapse}
th,td{padding:.7rem 1rem;text-align:left;border-bottom:1px solid var(--line);
      font-size:.86rem;vertical-align:top}
th{background:#f8fafc;color:var(--muted);font-weight:600;font-size:.74rem;
   letter-spacing:.06em;text-transform:uppercase}
tr:last-child td{border-bottom:0}
td.id{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8rem;color:#374151}
.pill{display:inline-block;padding:.12rem .5rem;border-radius:999px;
      background:#eef2ff;color:#3730a3;font-size:.72rem;font-weight:600}
.empty{padding:2.5rem 1rem;text-align:center;color:var(--muted);font-size:.9rem}
footer{max-width:64rem;margin:1rem auto 2rem;padding:0 1.25rem;
       color:var(--muted);font-size:.75rem}
</style>
</head>
<body>
<header>
<div class="brand"><strong>SIREN</strong><span>Administration</span></div>
<form method="post" action="/admin/logout">
<input type="hidden" name="csrf_token" value="{{.CSRF}}">
<button type="submit">Se déconnecter</button>
</form>
</header>
<main>
<h1>Campagnes</h1>
<p class="sub">{{.Count}} campagne(s) dans le magasin opérationnel.</p>
{{if .LoadErr}}<p class="notice">{{.LoadErr}}</p>{{end}}
<div class="card">
{{if .Campaigns}}
<table>
<thead><tr><th>Identifiant</th><th>Nom</th><th>État</th><th>Créée le</th></tr></thead>
<tbody>
{{range .Campaigns}}<tr>
<td class="id">{{.ID}}</td>
<td>{{.Name}}</td>
<td><span class="pill">{{.StateLabel}}</span></td>
<td>{{if .Created}}{{.Created}}{{else}}—{{end}}</td>
</tr>{{end}}
</tbody>
</table>
{{else}}
<p class="empty">Aucune campagne à afficher.</p>
{{end}}
</div>
</main>
<footer>Session administrateur · expiration glissante 15 min · page en lecture seule</footer>
</body>
</html>
`))
