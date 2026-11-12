package mgmt

import (
	"context"
	"log/slog"
	"net/http"
)

// Campaign is the management-layer view of a campaign.
type Campaign struct {
	ID         string
	Name       string
	State      string
	StateLabel string
	CreatedAt  string
	Stats      Stats
}

// Stats aggregates campaign metrics shown on the detail page.
type Stats struct {
	Contacts  int
	SentA     int
	SentB     int
	Artifacts int
}

// ContactInput is one row from the CSV import.
type ContactInput struct {
	Email string
	Vars  map[string]string
}

// ArtifactRow is one decrypted artifact displayed in the UI.
type ArtifactRow struct {
	ID         string
	Template   string
	Step       string
	ContactID  string
	ReceivedAt string
	RemoteIP   string
	Fields     []KV
}

// KV is a display-safe field name/value pair.
type KV struct {
	Name  string
	Value string
}

// SendRequest carries the parameters from the send form.
type SendRequest struct {
	CampaignID string
	TemplateID string
	StepID     string
	PriorStep  string
	DryRun     bool
	// FromAddress and FromName override the global SMTP settings for this send.
	// Leave empty to use the values from SMTPSettings.
	FromAddress string
	FromName    string
	// EmailSubject and EmailBody are the per-send email template.
	// EmailBody may contain {{.Link}} which is replaced with the phishing URL.
	// Leave empty to use built-in defaults.
	EmailSubject string
	EmailBody    string
	// ConfigCampaignID is the config file key that owns the template (e.g. "acme").
	// It may differ from CampaignID (the DB UUID). Used for phishing link routing.
	ConfigCampaignID string
}

// SendResult holds the outcome of one send run.
type SendResult struct {
	Sent    int
	Failed  int
	Skipped int
}

// SMTPSettings mirrors the fields stored in the settings table.
type SMTPSettings struct {
	Host         string
	Port         string
	Username     string
	PasswordFile string
	FromAddress  string
	FromName     string
	BaseURL      string
}

// TemplateInfo is one template available in the config, used for the send form.
type TemplateInfo struct {
	ID               string
	Steps            []string
	ConfigCampaignID string // the config key that owns this template (used for link building)
}

// Deps bundles every dependency the management UI needs. All fields are
// functions so cmd/sirencore can adapt its own types without importing mgmt.
type Deps struct {
	// Campaign
	ListCampaigns      func(ctx context.Context) ([]Campaign, error)
	GetCampaign        func(ctx context.Context, id string) (*Campaign, error)
	CreateCampaign     func(ctx context.Context, name string) (*Campaign, error)
	TransitionCampaign func(ctx context.Context, id, to string) error

	// Contacts
	ImportContacts func(ctx context.Context, campaignID string, contacts []ContactInput) (int, error)

	// Artifacts
	ListArtifacts func(ctx context.Context, campaignID string) ([]ArtifactRow, error)

	// Email sending
	SendEmails func(ctx context.Context, req SendRequest) (SendResult, error)

	// Export token
	IssueToken func(ctx context.Context, campaignID string) (string, error)

	// SMTP settings (stored in DB settings table)
	LoadSMTP func(ctx context.Context) (SMTPSettings, error)
	SaveSMTP func(ctx context.Context, s SMTPSettings) error

	// CSRF: generates a token and sets the cookie; returns the form field value.
	IssueCSRF func(w http.ResponseWriter) (string, error)

	// Available templates per campaign from config (for send form).
	AvailableTemplates func(campaignID string) []TemplateInfo

	Logger *slog.Logger
}
