package store

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// State is the campaign lifecycle. The only legal edges are draft → armed →
// running → closed; every other pair is refused with *TransitionError.
type State string

const (
	StateDraft   State = "draft"
	StateArmed   State = "armed"
	StateRunning State = "running"
	StateClosed  State = "closed"
)

// TransitionError reports an illegal state change. It is a concrete type, not a
// formatted string, so callers can distinguish a business refusal from a
// storage failure with errors.As.
type TransitionError struct {
	From State
	To   State
}

func (e *TransitionError) Error() string {
	return fmt.Sprintf("store: invalid campaign transition %s -> %s", e.From, e.To)
}

// CheckTransition validates one edge of the campaign state machine.
func CheckTransition(from, to State) error {
	switch {
	case from == StateDraft && to == StateArmed,
		from == StateArmed && to == StateRunning,
		from == StateRunning && to == StateClosed:
		return nil
	default:
		return &TransitionError{From: from, To: to}
	}
}

var (
	ErrCampaignNotFound = errors.New("store: campaign not found")
	ErrContactNotFound  = errors.New("store: contact not found")
)

type Campaign struct {
	ID        string
	Name      string
	State     State
	CreatedAt time.Time
	UpdatedAt time.Time
	// exportHash is the SHA-256 of the campaign export token. It is unexported
	// so it cannot accidentally be serialized into an operator-facing view.
	exportHash string
}

type Contact struct {
	ID         string
	CampaignID string
	Email      string
	// Vars are template render inputs (FirstName, LastTransaction, ...).
	// They are plaintext by design and never hold captured secrets.
	Vars      map[string]string
	CreatedAt time.Time
}

type ContactInput struct {
	Email string
	Vars  map[string]string
}

type Send struct {
	ID         string
	ContactID  string
	TemplateID string
	StepID     string
	SentAt     time.Time
	Status     string
}

type SendInput struct {
	ContactID  string
	TemplateID string
	StepID     string
	Status     string
	// SentAt defaults to the current UTC time when zero.
	SentAt time.Time
}

// Store is the operational schema consumed by the campaign, sending and admin
// planes. SQL is the durable implementation; Fake is the in-memory one used by
// consumers that do not need SQLite.
type Store interface {
	CreateCampaign(ctx context.Context, name string) (*Campaign, error)
	GetCampaign(ctx context.Context, id string) (*Campaign, error)
	SetCampaignState(ctx context.Context, id string, to State) error
	ListCampaigns(ctx context.Context) ([]Campaign, error)

	// AddContacts inserts the batch in one transaction and reports how many
	// rows were new. Duplicates, including case variants already present,
	// are skipped rather than failing the batch.
	AddContacts(ctx context.Context, campaignID string, contacts []ContactInput) (int, error)
	ListContacts(ctx context.Context, campaignID string) ([]Contact, error)
	// GetContact loads one contact by ID, scoped to its campaign. The campaign
	// check is what stops a recipient ID from one campaign rendering another
	// campaign's page with someone else's vars.
	GetContact(ctx context.Context, campaignID, contactID string) (*Contact, error)

	RecordSend(ctx context.Context, in SendInput) (*Send, error)
	ListSendsByCampaign(ctx context.Context, campaignID string) ([]Send, error)

	// SetExportTokenHash stores the SHA-256 of a campaign's export token. The
	// clear token is never persisted. GetExportTokenHash returns "" when no
	// token has been issued.
	SetExportTokenHash(ctx context.Context, campaignID, hash string) error
	GetExportTokenHash(ctx context.Context, campaignID string) (string, error)
}
