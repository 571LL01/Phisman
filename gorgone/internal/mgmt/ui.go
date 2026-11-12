package mgmt

import "html/template"

// pageData is the top-level view passed to every management template.
type pageData struct {
	Title     string
	Active    string // which sidebar link is active
	Crumbs    []crumb
	CSRF      string
	Flash     string
	FlashKind string // "ok" | "err" | "warn"

	// Page-specific payloads (only the relevant one is set per page).
	Campaigns []Campaign
	Campaign  *Campaign
	Token     string // freshly issued export token (shown once)
	Contacts  int    // count after import
	Artifacts []ArtifactRow
	Send      *sendView
	SMTP      *SMTPSettings
	Tmpls     []TemplateInfo // for send form dropdowns
}

type crumb struct {
	Label string
	Href  string
}

type sendView struct {
	Result           *SendResult
	DryRun           bool
	Template         string
	Step             string
	Prior            string
	FromAddress      string
	FromName         string
	EmailSubject     string
	EmailBody        string
	ConfigCampaignID string
}

// mgmtTmpl is the full template set for the management UI.
var mgmtTmpl = template.Must(template.New("root").Parse(sharedCSS + allPages))

const sharedCSS = `
{{define "css"}}
<style>
:root{--ink:#0f172a;--muted:#64748b;--faint:#94a3b8;--line:#e2e8f0;
  --bg:#f1f5f9;--card:#fff;--accent:#2563eb;--accent-h:#1d4ed8;
  --ok:#16a34a;--warn:#d97706;--danger:#dc2626;
  --ok-bg:#f0fdf4;--warn-bg:#fffbeb;--danger-bg:#fef2f2}
*{box-sizing:border-box;margin:0;padding:0}
body{font:14px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif;
  color:var(--ink);background:var(--bg);display:flex;min-height:100vh}
.side{width:220px;min-height:100vh;background:#0f172a;display:flex;
  flex-direction:column;flex-shrink:0;position:fixed;top:0;left:0;bottom:0;overflow-y:auto}
.logo{padding:1.1rem 1rem;font-weight:800;font-size:.88rem;letter-spacing:.1em;
  color:#f8fafc;border-bottom:1px solid #1e293b;display:flex;align-items:center;gap:.4rem}
.logo em{color:#60a5fa;font-style:normal}
.nav-sep{padding:.6rem 1rem .2rem;font-size:.68rem;font-weight:700;
  color:#475569;letter-spacing:.08em;text-transform:uppercase}
.nav-item{display:block;padding:.5rem 1rem;font-size:.82rem;color:#94a3b8;
  text-decoration:none}
.nav-item:hover{background:#1e293b;color:#f1f5f9}
.nav-item.on{background:#1e293b;color:#f8fafc;border-left:2px solid #3b82f6}
.side-foot{margin-top:auto;padding:.85rem 1rem;border-top:1px solid #1e293b}
.side-foot form{margin:0}
.btn-out{width:100%;padding:.4rem .75rem;border:1px solid #334155;border-radius:.35rem;
  background:transparent;color:#94a3b8;font:inherit;font-size:.8rem;cursor:pointer}
.btn-out:hover{background:#1e293b;color:#f1f5f9}
.main{margin-left:220px;flex:1;display:flex;flex-direction:column;min-height:100vh}
.topbar{padding:.6rem 1.4rem;background:#fff;border-bottom:1px solid var(--line);
  display:flex;align-items:center;gap:.4rem;min-height:46px}
.topbar a{color:var(--muted);font-size:.8rem;text-decoration:none}
.topbar a:hover{color:var(--ink)}
.topbar .sep{color:var(--faint);font-size:.75rem;margin:0 .1rem}
.topbar .cur{font-size:.8rem;color:var(--ink);font-weight:600}
.content{padding:1.4rem 1.5rem;flex:1}
.flash{padding:.7rem 1rem;border-radius:.4rem;margin-bottom:1.1rem;font-size:.83rem}
.flash.ok{background:var(--ok-bg);color:var(--ok);border:1px solid #bbf7d0}
.flash.err{background:var(--danger-bg);color:var(--danger);border:1px solid #fecaca}
.flash.warn{background:var(--warn-bg);color:var(--warn);border:1px solid #fed7aa}
.card{background:var(--card);border:1px solid var(--line);border-radius:.5rem;
  box-shadow:0 1px 3px rgba(0,0,0,.04);overflow:hidden;margin-bottom:1.1rem}
.card-head{padding:.7rem 1rem;border-bottom:1px solid var(--line);
  display:flex;align-items:center;justify-content:space-between}
.card-head h2{font-size:.9rem;font-weight:600}
.card-body{padding:1rem}
table{width:100%;border-collapse:collapse}
th,td{padding:.55rem .9rem;text-align:left;border-bottom:1px solid var(--line);font-size:.82rem}
th{background:#f8fafc;color:var(--muted);font-weight:600;font-size:.7rem;
  letter-spacing:.05em;text-transform:uppercase;white-space:nowrap}
tr:last-child td{border-bottom:0}
tr:hover td{background:#fafafa}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.78rem;color:#374151}
.badge{display:inline-block;padding:.12rem .5rem;border-radius:999px;
  font-size:.68rem;font-weight:700;letter-spacing:.04em;text-transform:uppercase}
.bd{background:#f1f5f9;color:#475569}
.ba{background:#fef3c7;color:#92400e}
.br{background:#d1fae5;color:#065f46}
.bc{background:#f3f4f6;color:#6b7280}
.btn{display:inline-flex;align-items:center;gap:.3rem;padding:.42rem .9rem;
  border-radius:.375rem;font:inherit;font-size:.82rem;cursor:pointer;
  border:1px solid transparent;text-decoration:none;font-weight:500;white-space:nowrap}
.btn-p{background:var(--accent);color:#fff;border-color:var(--accent)}
.btn-p:hover{background:var(--accent-h);border-color:var(--accent-h)}
.btn-s{background:#fff;color:var(--ink);border-color:var(--line)}
.btn-s:hover{background:#f8fafc}
.btn-d{background:var(--danger);color:#fff;border-color:var(--danger)}
.btn-d:hover{background:#b91c1c}
.btn-sm{padding:.28rem .6rem;font-size:.76rem}
.btn-g{display:flex;gap:.5rem;flex-wrap:wrap;align-items:center}
.stats{display:flex;gap:.85rem;flex-wrap:wrap;margin-bottom:1.1rem}
.stat{background:var(--card);border:1px solid var(--line);border-radius:.5rem;
  padding:.7rem 1rem;min-width:110px;flex:1}
.stat-n{font-size:1.5rem;font-weight:700;line-height:1.1}
.stat-l{font-size:.7rem;color:var(--muted);margin-top:.15rem;font-weight:500;
  text-transform:uppercase;letter-spacing:.04em}
.page-h{display:flex;align-items:flex-start;justify-content:space-between;
  margin-bottom:1.1rem;gap:1rem}
.page-h h1{font-size:1.05rem;font-weight:700}
.page-h .sub{font-size:.8rem;color:var(--muted);margin-top:.15rem}
.fg{margin-bottom:.9rem}
label{display:block;font-size:.8rem;font-weight:600;margin-bottom:.3rem}
.hint{font-size:.74rem;color:var(--muted);margin-top:.2rem}
input[type=text],input[type=number],input[type=email],input[type=password],
input[type=url],select,textarea{width:100%;padding:.42rem .65rem;
  border:1px solid var(--line);border-radius:.375rem;font:inherit;font-size:.83rem;
  background:#fff;color:var(--ink)}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent);
  box-shadow:0 0 0 2px rgba(37,99,235,.12)}
textarea{resize:vertical;min-height:130px;font-family:ui-monospace,monospace;font-size:.78rem}
.check-row{display:flex;align-items:center;gap:.4rem;font-size:.83rem}
input[type=checkbox]{width:1rem;height:1rem;flex-shrink:0}
.empty{padding:2.5rem 1rem;text-align:center;color:var(--muted);font-size:.88rem}
.wrap{max-width:860px}
.state-bar{display:flex;align-items:center;gap:.6rem;flex-wrap:wrap;
  padding:.7rem 1rem;background:#f8fafc;border-bottom:1px solid var(--line)}
.state-bar .arrow{color:var(--faint);font-size:.8rem}
.state-bar .step{font-size:.8rem;color:var(--muted)}
.state-bar .step.cur{color:var(--ink);font-weight:700}
.token-box{font-family:ui-monospace,monospace;font-size:.82rem;padding:.6rem .9rem;
  background:#fefce8;border:1px solid #fde68a;border-radius:.4rem;word-break:break-all}
.sep-line{border:0;border-top:1px solid var(--line);margin:1rem 0}
</style>
{{end}}
`

const allPages = `
{{define "nav"}}
<nav class="side">
  <div class="logo"><em>⬡</em> SIREN</div>
  <div class="nav-sep">Principal</div>
  <a class="nav-item{{if eq .Active "dashboard"}} on{{end}}" href="/admin/">Tableau de bord</a>
  <div class="nav-sep">Campagnes</div>
  <a class="nav-item{{if eq .Active "campaigns"}} on{{end}}" href="/admin/">Campagnes</a>
  <a class="nav-item{{if eq .Active "new-campaign"}} on{{end}}" href="/admin/campaigns/new">+ Nouvelle</a>
  <div class="nav-sep">Configuration</div>
  <a class="nav-item{{if eq .Active "smtp"}} on{{end}}" href="/admin/settings/smtp">SMTP</a>
  <div class="side-foot">
    <form method="post" action="/admin/logout">
      <input type="hidden" name="csrf_token" value="{{.CSRF}}">
      <button class="btn-out" type="submit">Se déconnecter</button>
    </form>
  </div>
</nav>
{{end}}

{{define "topbar"}}
<div class="topbar">
  {{range $i,$c := .Crumbs}}
    {{if $i}}<span class="sep">›</span>{{end}}
    {{if $c.Href}}<a href="{{$c.Href}}">{{$c.Label}}</a>
    {{else}}<span class="cur">{{$c.Label}}</span>{{end}}
  {{end}}
</div>
{{end}}

{{define "flash"}}
{{if .Flash}}<div class="flash {{.FlashKind}}">{{.Flash}}</div>{{end}}
{{end}}

{{define "badgeClass"}}{{if eq . "draft"}}bd{{else if eq . "armed"}}ba{{else if eq . "running"}}br{{else}}bc{{end}}{{end}}

{{define "stateLabel"}}{{if eq . "draft"}}Brouillon{{else if eq . "armed"}}Armée{{else if eq . "running"}}En cours{{else if eq . "closed"}}Clôturée{{else}}{{.}}{{end}}{{end}}

{{define "dashboard"}}
<!doctype html><html lang="fr"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}} — SIREN</title>{{template "css" .}}</head>
<body>
{{template "nav" .}}
<div class="main">
{{template "topbar" .}}
<div class="content wrap">
{{template "flash" .}}
<div class="page-h">
  <div><h1>Campagnes</h1><p class="sub">{{len .Campaigns}} campagne(s) au total</p></div>
  <a class="btn btn-p" href="/admin/campaigns/new">+ Nouvelle campagne</a>
</div>
<div class="card">
{{if .Campaigns}}
<table>
<thead><tr><th>Nom</th><th>ID</th><th>État</th><th>Contacts</th><th>Envois A</th><th>Artefacts</th><th></th></tr></thead>
<tbody>
{{range .Campaigns}}
<tr>
  <td><strong>{{.Name}}</strong></td>
  <td class="mono">{{.ID}}</td>
  <td><span class="badge {{template "badgeClass" .State}}">{{template "stateLabel" .State}}</span></td>
  <td>{{.Stats.Contacts}}</td>
  <td>{{.Stats.SentA}}</td>
  <td>{{.Stats.Artifacts}}</td>
  <td><a class="btn btn-s btn-sm" href="/admin/campaigns/{{.ID}}">Gérer →</a></td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<div class="empty">
  <strong>Aucune campagne</strong>
  <p>Commencez par créer une campagne pour gérer vos opérations.</p>
</div>
{{end}}
</div>
</div></div>
</body></html>
{{end}}

{{define "campaign-new"}}
<!doctype html><html lang="fr"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}} — SIREN</title>{{template "css" .}}</head>
<body>
{{template "nav" .}}
<div class="main">
{{template "topbar" .}}
<div class="content wrap">
{{template "flash" .}}
<div class="page-h">
  <div><h1>Nouvelle campagne</h1>
  <p class="sub">Crée une campagne en état Brouillon. Vous pourrez importer les contacts ensuite.</p></div>
</div>
<div class="card">
<div class="card-body">
<form method="post" action="/admin/campaigns/new">
  <input type="hidden" name="csrf_token" value="{{.CSRF}}">
  <div class="fg">
    <label for="name">Nom de la campagne <span style="color:var(--danger)">*</span></label>
    <input type="text" id="name" name="name" required maxlength="120" placeholder="ex. Phishing Q4 2026 — Finance">
    <p class="hint">Choisissez un nom descriptif. L'identifiant unique sera généré automatiquement.</p>
  </div>
  <div class="btn-g" style="margin-top:1.25rem">
    <button class="btn btn-p" type="submit">Créer la campagne</button>
    <a class="btn btn-s" href="/admin/">Annuler</a>
  </div>
</form>
</div>
</div>
</div></div>
</body></html>
{{end}}

{{define "campaign-detail"}}
<!doctype html><html lang="fr"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}} — SIREN</title>{{template "css" .}}</head>
<body>
{{template "nav" .}}
<div class="main">
{{template "topbar" .}}
<div class="content wrap">
{{template "flash" .}}
{{with .Campaign}}
<div class="page-h">
  <div>
    <h1>{{.Name}}</h1>
    <p class="sub">ID : <span class="mono">{{.ID}}</span> · Créée le {{.CreatedAt}}</p>
  </div>
  <span class="badge {{template "badgeClass" .State}}" style="font-size:.8rem;padding:.25rem .75rem">
    {{template "stateLabel" .State}}
  </span>
</div>

<div class="stats">
  <div class="stat"><div class="stat-n">{{.Stats.Contacts}}</div><div class="stat-l">Contacts</div></div>
  <div class="stat"><div class="stat-n">{{.Stats.SentA}}</div><div class="stat-l">Envois étape A</div></div>
  <div class="stat"><div class="stat-n">{{.Stats.SentB}}</div><div class="stat-l">Envois étape B</div></div>
  <div class="stat"><div class="stat-n">{{.Stats.Artifacts}}</div><div class="stat-l">Artefacts capturés</div></div>
</div>

{{if $.Token}}
<div class="flash ok">
  <strong>Token d'export émis (affiché une seule fois) :</strong><br>
  <div class="token-box" style="margin-top:.5rem">{{$.Token}}</div>
  <p style="margin-top:.4rem;font-size:.78rem">Conservez-le immédiatement. Il ne sera plus affiché.</p>
</div>
{{end}}

<div class="card">
<div class="card-head"><h2>Cycle de vie</h2></div>
<div class="card-body">
  <p style="font-size:.82rem;color:var(--muted);margin-bottom:.85rem">
    Une campagne progresse dans l'ordre : Brouillon → Armée → En cours → Clôturée.
    Chaque transition est irréversible.
  </p>
  <div class="btn-g">
    {{if eq .State "draft"}}
      <form method="post" action="/admin/campaigns/{{.ID}}/state">
        <input type="hidden" name="csrf_token" value="{{$.CSRF}}">
        <input type="hidden" name="to" value="armed">
        <button class="btn btn-p" type="submit">Armer la campagne</button>
      </form>
    {{else if eq .State "armed"}}
      <form method="post" action="/admin/campaigns/{{.ID}}/state">
        <input type="hidden" name="csrf_token" value="{{$.CSRF}}">
        <input type="hidden" name="to" value="running">
        <button class="btn btn-p" type="submit">Lancer la campagne</button>
      </form>
    {{else if eq .State "running"}}
      <form method="post" action="/admin/campaigns/{{.ID}}/state">
        <input type="hidden" name="csrf_token" value="{{$.CSRF}}">
        <input type="hidden" name="to" value="closed">
        <button class="btn btn-d" type="submit">Clôturer la campagne</button>
      </form>
    {{else}}
      <span style="font-size:.82rem;color:var(--muted)">Campagne clôturée — aucune transition possible.</span>
    {{end}}
  </div>
</div>
</div>

<div class="card">
<div class="card-head"><h2>Actions</h2></div>
<div class="card-body">
  <div class="btn-g">
    <a class="btn btn-s" href="/admin/campaigns/{{.ID}}/contacts">📋 Importer des contacts</a>
    <a class="btn btn-s" href="/admin/campaigns/{{.ID}}/send">📧 Envoyer les emails</a>
    <a class="btn btn-s" href="/admin/campaigns/{{.ID}}/artifacts">🔍 Voir les artefacts</a>
  </div>
  <hr class="sep-line">
  <form method="post" action="/admin/campaigns/{{.ID}}/token" style="display:inline">
    <input type="hidden" name="csrf_token" value="{{$.CSRF}}">
    <button class="btn btn-s btn-sm" type="submit">🔑 Émettre un token d'export</button>
  </form>
  <span class="hint" style="display:inline;margin-left:.5rem">Révoque l'ancien token si existant.</span>
</div>
</div>
{{end}}
</div></div>
</body></html>
{{end}}

{{define "campaign-contacts"}}
<!doctype html><html lang="fr"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}} — SIREN</title>{{template "css" .}}</head>
<body>
{{template "nav" .}}
<div class="main">
{{template "topbar" .}}
<div class="content wrap">
{{template "flash" .}}
{{with .Campaign}}
<div class="page-h">
  <div><h1>Importer des contacts</h1>
  <p class="sub">Campagne : <strong>{{.Name}}</strong> · {{.Stats.Contacts}} contact(s) déjà présent(s)</p></div>
  <a class="btn btn-s btn-sm" href="/admin/campaigns/{{.ID}}">← Retour</a>
</div>
{{end}}
<div class="card">
<div class="card-head"><h2>Format CSV</h2></div>
<div class="card-body">
  <p style="font-size:.82rem;color:var(--muted);margin-bottom:.6rem">
    Première ligne = en-têtes. La colonne <code>email</code> est obligatoire.
    Les autres colonnes deviennent des variables de personnalisation
    (ex. <code>lang</code>, <code>first_name</code>, <code>locale</code>).
    Les doublons (même email dans la même campagne) sont silencieusement ignorés.
  </p>
  <pre style="background:#f8fafc;border:1px solid var(--line);border-radius:.35rem;
    padding:.6rem .9rem;font-size:.77rem;overflow-x:auto">email,lang,first_name
alice@example.com,fr,Alice
bob@example.com,en,Bob</pre>
</div>
</div>
{{with .Campaign}}
<div class="card">
<div class="card-body">
<form method="post" action="/admin/campaigns/{{.ID}}/contacts">
  <input type="hidden" name="csrf_token" value="{{$.CSRF}}">
  <div class="fg">
    <label for="csv">Contacts (CSV)</label>
    <textarea id="csv" name="csv" placeholder="email,lang&#10;alice@example.com,fr&#10;bob@example.com,en" rows="12"></textarea>
  </div>
  <div class="btn-g">
    <button class="btn btn-p" type="submit">Importer</button>
    <a class="btn btn-s" href="/admin/campaigns/{{.ID}}">Annuler</a>
  </div>
</form>
</div>
</div>
{{end}}
</div></div>
</body></html>
{{end}}

{{define "campaign-artifacts"}}
<!doctype html><html lang="fr"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}} — SIREN</title>{{template "css" .}}</head>
<body>
{{template "nav" .}}
<div class="main">
{{template "topbar" .}}
<div class="content">
{{template "flash" .}}
{{with .Campaign}}
<div class="page-h">
  <div><h1>Artefacts capturés</h1>
  <p class="sub">Campagne : <strong>{{.Name}}</strong> · {{.Stats.Artifacts}} artefact(s)</p></div>
  <a class="btn btn-s btn-sm" href="/admin/campaigns/{{.ID}}">← Retour</a>
</div>
{{end}}
<div class="card">
{{if $.Artifacts}}
<table>
<thead><tr>
  <th>Reçu le</th><th>Modèle</th><th>Étape</th><th>Contact</th><th>IP</th><th>Champs capturés</th>
</tr></thead>
<tbody>
{{range $.Artifacts}}
<tr>
  <td class="mono" style="white-space:nowrap">{{.ReceivedAt}}</td>
  <td class="mono">{{.Template}}</td>
  <td><span class="badge bd">{{.Step}}</span></td>
  <td class="mono">{{if .ContactID}}{{.ContactID}}{{else}}<span style="color:var(--faint)">—</span>{{end}}</td>
  <td class="mono">{{.RemoteIP}}</td>
  <td>
    {{range .Fields}}
    <div style="font-size:.78rem"><strong>{{.Name}}</strong> :
      {{if eq .Name "password"}}
        <span style="color:var(--muted)">••••••••</span>
      {{else if eq .Name "seed"}}
        <span style="color:var(--muted)">••• (phrase de récupération) •••</span>
      {{else}}
        {{.Value}}
      {{end}}
    </div>
    {{end}}
  </td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<div class="empty"><strong>Aucun artefact</strong><p>Aucune soumission reçue pour cette campagne.</p></div>
{{end}}
</div>
</div></div>
</body></html>
{{end}}

{{define "campaign-send"}}
<!doctype html><html lang="fr"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}} — SIREN</title>{{template "css" .}}</head>
<body>
{{template "nav" .}}
<div class="main">
{{template "topbar" .}}
<div class="content wrap">
{{template "flash" .}}
{{with .Campaign}}
<div class="page-h">
  <div><h1>Envoyer les emails</h1>
  <p class="sub">Campagne : <strong>{{.Name}}</strong> · {{.Stats.Contacts}} contact(s) disponible(s)</p></div>
  <a class="btn btn-s btn-sm" href="/admin/campaigns/{{.ID}}">← Retour</a>
</div>
{{end}}
{{with $.Send}}
{{if .Result}}
<div class="flash{{if .DryRun}} warn{{else}} ok{{end}}">
  {{if .DryRun}}<strong>Simulation (dry run) :</strong>{{else}}<strong>Envoi effectué :</strong>{{end}}
  {{.Result.Sent}} envoyé(s) · {{.Result.Skipped}} ignoré(s) · {{.Result.Failed}} échec(s)
</div>
{{end}}
{{end}}
{{with .Campaign}}
<div class="card">
<div class="card-body">
<form method="post" action="/admin/campaigns/{{.ID}}/send">
  <input type="hidden" name="csrf_token" value="{{$.CSRF}}">
  <input type="hidden" id="config_campaign_id" name="config_campaign_id" value="{{with index $.Tmpls 0}}{{.ConfigCampaignID}}{{end}}">
  <div class="fg">
    <label for="tmpl">Modèle (template)</label>
    <select id="tmpl" name="template_id" required
      onchange="var o=this.options[this.selectedIndex];document.getElementById('config_campaign_id').value=o.dataset.cfg||''">
      <option value="">— Choisir un modèle —</option>
      {{range $.Tmpls}}
      <option value="{{.ID}}" data-cfg="{{.ConfigCampaignID}}">{{.ID}} <small>({{.ConfigCampaignID}})</small></option>
      {{end}}
    </select>
  </div>
  <div class="fg">
    <label for="step">Étape</label>
    <select id="step" name="step_id" required>
      <option value="">— Choisir une étape —</option>
      {{range $.Tmpls}}{{range .Steps}}
      <option value="{{.}}">{{.}}</option>
      {{end}}{{end}}
    </select>
    <p class="hint">En général : <strong>a</strong> = premier email, <strong>b</strong> = email de suivi</p>
  </div>
  <div class="fg">
    <label for="prior">Envoyer uniquement aux contacts ayant déjà reçu l'étape :</label>
    <input type="text" id="prior" name="prior_step" placeholder="ex. a (laissez vide pour envoyer à tous)">
    <p class="hint">Vide = envoyer à tous les contacts de la campagne.</p>
  </div>
  <hr class="sep-line">
  <p style="font-size:.8rem;font-weight:600;margin-bottom:.6rem">
    Usurpation de l'expéditeur <span style="color:var(--muted);font-weight:400">(optionnel — écrase le From global)</span>
  </p>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:0 1rem">
    <div class="fg">
      <label for="from_address">Adresse From à usurper</label>
      <input type="email" id="from_address" name="from_address"
        placeholder="ex. IT@rest.com"
        value="{{with $.Send}}{{.FromAddress}}{{end}}">
      <p class="hint">Ex. : <code>IT@acme-corp.com</code> — le destinataire verra cette adresse.</p>
    </div>
    <div class="fg">
      <label for="from_name">Nom d'affichage</label>
      <input type="text" id="from_name" name="from_name"
        placeholder="ex. Département IT"
        value="{{with $.Send}}{{.FromName}}{{end}}">
      <p class="hint">Ex. : <code>Support Informatique</code></p>
    </div>
  </div>
  <div style="background:#fef3c7;border:1px solid #fde68a;border-radius:.4rem;
    padding:.55rem .85rem;font-size:.77rem;color:#92400e;margin-bottom:.5rem">
    ⚠ La livraison dépend de la politique SPF/DMARC du domaine cible et de votre relay SMTP.
    Testez d'abord en <strong>dry run</strong>.
  </div>
  <hr class="sep-line">
  <p style="font-size:.8rem;font-weight:600;margin-bottom:.6rem">
    Contenu du mail <span style="color:var(--muted);font-weight:400">(optionnel — laissez vide pour le texte par défaut)</span>
  </p>
  <div class="fg">
    <label for="email_subject">Sujet</label>
    <input type="text" id="email_subject" name="email_subject"
      placeholder="ex. Action requise : vérification de votre compte"
      value="{{with $.Send}}{{.EmailSubject}}{{end}}">
  </div>
  <div class="fg">
    <label for="email_body">Corps du message</label>
    <textarea id="email_body" name="email_body" rows="8"
      placeholder="Bonjour,&#10;&#10;Votre accès nécessite une vérification urgente.&#10;&#10;Cliquez ici pour procéder : &#123;&#123;.Link&#125;&#125;&#10;&#10;Cordialement,&#10;Le Service Informatique"
      style="width:100%;padding:.5rem .75rem;border:1px solid var(--line);border-radius:.375rem;font:inherit;font-size:.83rem;resize:vertical">{{with $.Send}}{{.EmailBody}}{{end}}</textarea>
    <p class="hint">Utilisez <code>&#123;&#123;.Link&#125;&#125;</code> pour insérer le lien de phishing. Supporte le HTML (balises &lt;a&gt;, &lt;b&gt;, &lt;br&gt;, etc.).</p>
  </div>
  <hr class="sep-line">
  <div class="fg">
    <label class="check-row">
      <input type="checkbox" name="dry_run" value="1" checked>
      Simulation (dry run) — ne pas envoyer réellement, juste compter
    </label>
  </div>
  <div class="btn-g" style="margin-top:1rem">
    <button class="btn btn-p" type="submit">Lancer</button>
    <a class="btn btn-s" href="/admin/campaigns/{{.ID}}">Annuler</a>
  </div>
</form>
</div>
</div>
{{end}}
</div></div>
</body></html>
{{end}}

{{define "smtp-settings"}}
<!doctype html><html lang="fr"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}} — SIREN</title>{{template "css" .}}</head>
<body>
{{template "nav" .}}
<div class="main">
{{template "topbar" .}}
<div class="content wrap">
{{template "flash" .}}
<div class="page-h">
  <div><h1>Configuration SMTP</h1>
  <p class="sub">Paramètres du relais d'envoi d'emails. Le mot de passe SMTP n'est jamais stocké ici.</p></div>
</div>
<div class="card">
<div class="card-body">
<form method="post" action="/admin/settings/smtp">
  <input type="hidden" name="csrf_token" value="{{.CSRF}}">
  {{with .SMTP}}
  <div style="display:grid;grid-template-columns:1fr 160px;gap:0 1rem">
    <div class="fg">
      <label for="host">Hôte SMTP <span style="color:var(--danger)">*</span></label>
      <input type="text" id="host" name="host" value="{{.Host}}" placeholder="smtp.example.com" required>
    </div>
    <div class="fg">
      <label for="port">Port</label>
      <input type="number" id="port" name="port" value="{{if .Port}}{{.Port}}{{else}}587{{end}}" min="1" max="65535">
    </div>
  </div>
  <div class="fg">
    <label for="user">Nom d'utilisateur SMTP</label>
    <input type="text" id="user" name="username" value="{{.Username}}" placeholder="siren@example.com">
  </div>
  <div class="fg">
    <label for="pwfile">Chemin du fichier de mot de passe SMTP</label>
    <input type="text" id="pwfile" name="password_file" value="{{.PasswordFile}}" placeholder="/run/secrets/smtp-password">
    <p class="hint">Le fichier doit contenir uniquement le mot de passe SMTP, sans retour à la ligne.</p>
  </div>
  <hr class="sep-line">
  <div class="fg">
    <label for="from">Adresse d'expédition (From) <span style="color:var(--danger)">*</span></label>
    <input type="email" id="from" name="from_address" value="{{.FromAddress}}" placeholder="siren@example.com" required>
  </div>
  <div class="fg">
    <label for="fromname">Nom d'affichage de l'expéditeur</label>
    <input type="text" id="fromname" name="from_name" value="{{.FromName}}" placeholder="Équipe Sécurité">
  </div>
  <div class="fg">
    <label for="baseurl">URL de base du serveur (sans slash final) <span style="color:var(--danger)">*</span></label>
    <input type="url" id="baseurl" name="base_url" value="{{.BaseURL}}" placeholder="https://siren.example.com" required>
    <p class="hint">Utilisée pour construire les liens dans les emails.</p>
  </div>
  {{end}}
  <div class="btn-g" style="margin-top:1.25rem">
    <button class="btn btn-p" type="submit">Enregistrer</button>
  </div>
</form>
</div>
</div>
</div></div>
</body></html>
{{end}}
`
