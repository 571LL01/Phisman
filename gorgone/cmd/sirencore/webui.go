package main

// webui.go wires the management UI into the binary. It builds mgmt.Deps from
// the already-open store.Store, collect.Store and *sql.DB, then returns a
// combined http.Handler covering both the admin auth surface and the
// management pages under /admin/*, all behind admin.Guard.

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/siren-core/gorgone/internal/admin"
	"github.com/siren-core/gorgone/internal/charon"
	"github.com/siren-core/gorgone/internal/collect"
	sirendb "github.com/siren-core/gorgone/internal/db"
	"github.com/siren-core/gorgone/internal/mgmt"
	"github.com/siren-core/gorgone/internal/store"
)

// buildMgmtDeps constructs mgmt.Deps from the binary's already-open resources.
func buildMgmtDeps(
	adminCfg *admin.Config,
	st store.Store,
	cst collect.Store,
	db *sql.DB,
	fileCfg *fileConfig,
	logger *slog.Logger,
) mgmt.Deps {
	return mgmt.Deps{
		Logger: logger,

		IssueCSRF: adminCfg.IssueCSRF,

		ListCampaigns: func(ctx context.Context) ([]mgmt.Campaign, error) {
			rows, err := st.ListCampaigns(ctx)
			if err != nil {
				return nil, err
			}
			out := make([]mgmt.Campaign, 0, len(rows))
			for _, c := range rows {
				mc := campaignToMgmt(ctx, c, st)
				out = append(out, mc)
			}
			return out, nil
		},

		GetCampaign: func(ctx context.Context, id string) (*mgmt.Campaign, error) {
			c, err := st.GetCampaign(ctx, id)
			if err != nil {
				return nil, err
			}
			mc := campaignToMgmt(ctx, *c, st)
			return &mc, nil
		},

		CreateCampaign: func(ctx context.Context, name string) (*mgmt.Campaign, error) {
			c, err := st.CreateCampaign(ctx, name)
			if err != nil {
				return nil, err
			}
			mc := campaignToMgmt(ctx, *c, st)
			return &mc, nil
		},

		TransitionCampaign: func(ctx context.Context, id, to string) error {
			c, err := st.GetCampaign(ctx, id)
			if err != nil {
				return err
			}
			if err := store.CheckTransition(c.State, store.State(to)); err != nil {
				return err
			}
			return st.SetCampaignState(ctx, id, store.State(to))
		},

		ImportContacts: func(ctx context.Context, campaignID string, contacts []mgmt.ContactInput) (int, error) {
			in := make([]store.ContactInput, len(contacts))
			for i, c := range contacts {
				in[i] = store.ContactInput{Email: c.Email, Vars: c.Vars}
			}
			return st.AddContacts(ctx, campaignID, in)
		},

		ListArtifacts: func(ctx context.Context, campaignID string) ([]mgmt.ArtifactRow, error) {
			var rows []mgmt.ArtifactRow
			err := cst.Export(ctx, campaignID, time.Time{}, func(a *collect.Artifact) error {
				row := mgmt.ArtifactRow{
					ID:         a.ID,
					Template:   a.TemplateID,
					Step:       a.Step,
					ContactID:  a.ContactID,
					ReceivedAt: mgmt.FormatTime(a.ReceivedAt),
					RemoteIP:   a.RemoteIP,
				}
				for k, v := range a.Fields {
					row.Fields = append(row.Fields, mgmt.KV{Name: k, Value: v})
				}
				rows = append(rows, row)
				return nil
			})
			return rows, err
		},

		SendEmails: func(ctx context.Context, req mgmt.SendRequest) (mgmt.SendResult, error) {
			s, err := loadSMTPSettings(ctx, db)
			if err != nil {
				return mgmt.SendResult{}, fmt.Errorf("smtp non configuré: %w", err)
			}
			return runSend(ctx, st, s, req, fileCfg, logger)
		},

		IssueToken: func(ctx context.Context, campaignID string) (string, error) {
			return charon.IssueToken(ctx, st, campaignID)
		},

		LoadSMTP: func(ctx context.Context) (mgmt.SMTPSettings, error) {
			return loadSMTPSettings(ctx, db)
		},

		SaveSMTP: func(ctx context.Context, s mgmt.SMTPSettings) error {
			return saveSMTPSettings(ctx, db, s)
		},

		AvailableTemplates: func(_ string) []mgmt.TemplateInfo {
			// Return all templates across all config campaigns so DB-UUID campaigns
			// can still use config-defined templates.
			var infos []mgmt.TemplateInfo
			for cfgID, campaign := range fileCfg.Campaigns {
				for tid, steps := range campaign.Templates {
					stepIDs := make([]string, 0, len(steps))
					for sid := range steps {
						stepIDs = append(stepIDs, sid)
					}
					infos = append(infos, mgmt.TemplateInfo{
						ID:               tid,
						Steps:            stepIDs,
						ConfigCampaignID: cfgID,
					})
				}
			}
			return infos
		},
	}
}

// campaignToMgmt converts a store.Campaign to the mgmt view, with stats.
func campaignToMgmt(ctx context.Context, c store.Campaign, st store.Store) mgmt.Campaign {
	mc := mgmt.Campaign{
		ID:        c.ID,
		Name:      c.Name,
		State:     string(c.State),
		CreatedAt: sirendb.FormatTime(c.CreatedAt),
	}
	if contacts, err := st.ListContacts(ctx, c.ID); err == nil {
		mc.Stats.Contacts = len(contacts)
	}
	if sends, err := st.ListSendsByCampaign(ctx, c.ID); err == nil {
		for _, s := range sends {
			switch s.StepID {
			case "a":
				mc.Stats.SentA++
			case "b":
				mc.Stats.SentB++
			}
		}
	}
	return mc
}

// newCombinedAdminRouter builds the full /admin/* handler:
//   - Guard (IP allowlist + CSRF) wraps everything
//   - /admin/login and /admin/logout require no session
//   - all other /admin/* routes require a valid session and delegate to mgmtHandler
func newCombinedAdminRouter(adminCfg admin.Config, mgmtHandler http.Handler) http.Handler {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch p {
		case "/admin/login":
			switch r.Method {
			case http.MethodGet:
				admin.LoginPageHandler(adminCfg)(w, r)
			case http.MethodPost:
				admin.LoginHandler(adminCfg)(w, r)
			default:
				w.Header().Set("Allow", "GET, POST")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			}
		case "/admin/logout":
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", "POST")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			admin.LogoutHandler(adminCfg)(w, r)
		default:
			admin.RequireSession(adminCfg)(mgmtHandler).ServeHTTP(w, r)
		}
	})
	return admin.Guard(adminCfg)(inner)
}

// ---- settings table ---------------------------------------------------------

const (
	settingSMTPHost         = "smtp.host"
	settingSMTPPort         = "smtp.port"
	settingSMTPUsername     = "smtp.username"
	settingSMTPPasswordFile = "smtp.password_file"
	settingSMTPFromAddress  = "smtp.from_address"
	settingSMTPFromName     = "smtp.from_name"
	settingSMTPBaseURL      = "smtp.base_url"
)

func loadSMTPSettings(ctx context.Context, db *sql.DB) (mgmt.SMTPSettings, error) {
	rows, err := db.QueryContext(ctx, `SELECT key, value FROM settings WHERE key LIKE 'smtp.%'`)
	if err != nil {
		return mgmt.SMTPSettings{}, err
	}
	defer rows.Close()
	kv := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return mgmt.SMTPSettings{}, err
		}
		kv[k] = v
	}
	return mgmt.SMTPSettings{
		Host:         kv[settingSMTPHost],
		Port:         kv[settingSMTPPort],
		Username:     kv[settingSMTPUsername],
		PasswordFile: kv[settingSMTPPasswordFile],
		FromAddress:  kv[settingSMTPFromAddress],
		FromName:     kv[settingSMTPFromName],
		BaseURL:      kv[settingSMTPBaseURL],
	}, nil
}

func saveSMTPSettings(ctx context.Context, db *sql.DB, s mgmt.SMTPSettings) error {
	pairs := map[string]string{
		settingSMTPHost:         s.Host,
		settingSMTPPort:         s.Port,
		settingSMTPUsername:     s.Username,
		settingSMTPPasswordFile: s.PasswordFile,
		settingSMTPFromAddress:  s.FromAddress,
		settingSMTPFromName:     s.FromName,
		settingSMTPBaseURL:      s.BaseURL,
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	for k, v := range pairs {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO settings (key, value) VALUES (?, ?)
			 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
			k, v); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ---- email sending ----------------------------------------------------------

// runSend iterates campaign contacts and sends via SMTP. DryRun just counts.
func runSend(ctx context.Context, st store.Store, smtpCfg mgmt.SMTPSettings, req mgmt.SendRequest, fileCfg *fileConfig, logger *slog.Logger) (mgmt.SendResult, error) {
	if strings.TrimSpace(smtpCfg.Host) == "" {
		return mgmt.SendResult{}, fmt.Errorf("SMTP non configuré — renseignez l'hôte dans Paramètres › SMTP")
	}

	contacts, err := st.ListContacts(ctx, req.CampaignID)
	if err != nil {
		return mgmt.SendResult{}, err
	}

	var alreadySentSet map[string]bool
	if req.PriorStep != "" {
		sends, err := st.ListSendsByCampaign(ctx, req.CampaignID)
		if err != nil {
			return mgmt.SendResult{}, err
		}
		alreadySentSet = make(map[string]bool)
		for _, s := range sends {
			if s.StepID == req.PriorStep {
				alreadySentSet[s.ContactID] = true
			}
		}
	}

	var res mgmt.SendResult
	for _, c := range contacts {
		if alreadySentSet != nil && !alreadySentSet[c.ID] {
			res.Skipped++
			continue
		}
		if req.DryRun {
			res.Sent++
			continue
		}
		// Per-campaign From overrides the global SMTP setting when provided.
		effective := smtpCfg
		if req.FromAddress != "" {
			effective.FromAddress = req.FromAddress
		}
		if req.FromName != "" {
			effective.FromName = req.FromName
		}
		link := buildLink(smtpCfg.BaseURL, req.CampaignID, req.TemplateID, req.StepID, c.ID)
		if err := sendSMTP(effective, c.Email, link, req.EmailSubject, req.EmailBody); err != nil {
			logger.Error("mgmt: smtp send failed", "contact", c.ID, "err", err)
			res.Failed++
		} else {
			if _, err := st.RecordSend(ctx, store.SendInput{
				ContactID:  c.ID,
				TemplateID: req.TemplateID,
				StepID:     req.StepID,
				Status:     "sent",
			}); err != nil {
				logger.Error("mgmt: record send failed", "contact", c.ID, "err", err)
			}
			res.Sent++
		}
	}
	return res, nil
}

func buildLink(baseURL, campaignID, templateID, stepID, contactID string) string {
	base := strings.TrimRight(baseURL, "/")
	return fmt.Sprintf("%s/c/%s/%s/%s?rid=%s", base, campaignID, templateID, stepID, contactID)
}

// sendSMTP sends one email via STARTTLS SMTP. The password is read from the
// file each call so a rotation on disk takes effect without restart.
// subject and body are the per-send template; body may contain {{.Link}}.
// If empty, built-in defaults are used.
func sendSMTP(s mgmt.SMTPSettings, to, link, subject, body string) error {
	port := s.Port
	if port == "" {
		port = "587"
	}
	addr := net.JoinHostPort(s.Host, port)

	var password string
	if s.PasswordFile != "" {
		raw, err := os.ReadFile(s.PasswordFile)
		if err != nil {
			return fmt.Errorf("smtp password file: %w", err)
		}
		password = strings.TrimSpace(string(raw))
	}

	from := s.FromAddress
	fromHeader := s.FromAddress
	if s.FromName != "" {
		fromHeader = fmt.Sprintf("%s <%s>", s.FromName, s.FromAddress)
	}

	if subject == "" {
		subject = "Important : vérification requise"
	}
	contentType := "text/plain; charset=UTF-8"
	if body == "" {
		body = fmt.Sprintf("Veuillez accéder au lien suivant pour compléter votre demande :\r\n\r\n%s\r\n", link)
	} else {
		body = strings.ReplaceAll(body, "{{.Link}}", link)
		if strings.Contains(body, "<") {
			contentType = "text/html; charset=UTF-8"
		}
		body = strings.ReplaceAll(body, "\n", "\r\n")
	}
	msg := []byte(fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: %s\r\n\r\n%s",
		fromHeader, to, subject, contentType, body,
	))

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	client, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer client.Close()

	if ok, _ := client.Extension("STARTTLS"); ok {
		tlsCfg := &tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12}
		if err := client.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
	}

	if s.Username != "" && password != "" {
		auth := smtp.PlainAuth("", s.Username, password, s.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}

	if err := client.Mail(from); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("smtp RCPT TO: %w", err)
	}
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := wc.Write(msg); err != nil {
		wc.Close()
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("smtp close data: %w", err)
	}
	return client.Quit()
}
