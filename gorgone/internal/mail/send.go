package mail

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/siren-core/gorgone/internal/collect"
	"github.com/siren-core/gorgone/internal/store"
	"github.com/siren-core/gorgone/internal/tmpl"
)

const (
	StatusSent   = "sent"
	statusFailed = "failed"
)

// Ops is the slice of store.Store the sender needs. It is narrower than the
// full Store interface so a test can supply a minimal fake.
type Ops interface {
	ListContacts(ctx context.Context, campaignID string) ([]store.Contact, error)
	ListSendsByCampaign(ctx context.Context, campaignID string) ([]store.Send, error)
	RecordSend(ctx context.Context, in store.SendInput) (*store.Send, error)
}

// Resolver returns the Step for a campaign coordinate, used to build the form
// that appears in the email body.
type Resolver func(campaignID, templateID, stepID string) (collect.Step, error)

// Runner orchestrates one delivery run for a campaign.
type Runner struct {
	composer *Composer
	sender   interface {
		Send(ctx context.Context, msg *Message) error
	}
	ops       Ops
	resolve   Resolver
	logger    *slog.Logger
	dryRun    bool
	priorStep string
}

// RunnerConfig carries the dependencies for a Runner.
type RunnerConfig struct {
	Composer *Composer
	Sender   interface {
		Send(ctx context.Context, msg *Message) error
	}
	Ops     Ops
	Resolve Resolver
	Logger  *slog.Logger
	// DryRun renders and logs without sending or writing to the store.
	DryRun bool
	// PriorStep, when set, restricts delivery to contacts that have at least
	// one successful prior send for this template at the named step. This is
	// the guard for multi-step flows: step B should only reach contacts who
	// completed step A. An empty PriorStep means "send to all contacts".
	//
	// Note: the guard operates on send records (what the mailer wrote), not on
	// collect artifacts (what the visitor submitted). A contact who received
	// step A but whose browser failed to load it would still be gated. Full
	// artifact-based gating is deferred to step 11.
	PriorStep string
}

// NewRunner validates RunnerConfig and returns a Runner.
func NewRunner(cfg RunnerConfig) (*Runner, error) {
	if cfg.Composer == nil {
		return nil, fmt.Errorf("mail: runner composer is required")
	}
	if cfg.Sender == nil && !cfg.DryRun {
		return nil, fmt.Errorf("mail: runner sender is required (or set dry_run)")
	}
	if cfg.Ops == nil {
		return nil, fmt.Errorf("mail: runner ops store is required")
	}
	if cfg.Resolve == nil {
		return nil, fmt.Errorf("mail: runner resolver is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Runner{
		composer:  cfg.Composer,
		sender:    cfg.Sender,
		ops:       cfg.Ops,
		resolve:   cfg.Resolve,
		logger:    cfg.Logger,
		dryRun:    cfg.DryRun,
		priorStep: cfg.PriorStep,
	}, nil
}

// Summary is returned by Send.
type Summary struct {
	Sent   int
	Failed int
	// Skipped is the count of contacts that already had a successful send
	// for this step (idempotency: second run does not duplicate).
	Skipped int
}

func (s Summary) String() string {
	return fmt.Sprintf("sent=%d failed=%d skipped=%d", s.Sent, s.Failed, s.Skipped)
}

// Send iterates over all contacts in the campaign, composes, delivers and
// records each send. A failure on one contact is logged and counted; the run
// continues so other contacts still receive their email.
//
// Idempotency: a contact that already has a successful send record for the
// configured template+step is skipped without sending or re-recording.
//
// In dry-run mode, messages are composed and logged but never sent and nothing
// is written to the store.
func (r *Runner) Send(ctx context.Context, campaignID string) (Summary, error) {
	c := r.composer
	step, err := r.resolve(campaignID, c.template, c.step)
	if err != nil {
		return Summary{}, fmt.Errorf("mail: resolve step %s/%s: %w", c.template, c.step, err)
	}

	contacts, err := r.ops.ListContacts(ctx, campaignID)
	if err != nil {
		return Summary{}, fmt.Errorf("mail: list contacts: %w", err)
	}

	// Build the already-sent set for idempotency. A contact with status "sent"
	// for this template+step is skipped; "failed" is retried.
	sends, err := r.ops.ListSendsByCampaign(ctx, campaignID)
	if err != nil {
		return Summary{}, fmt.Errorf("mail: list sends: %w", err)
	}
	done := make(map[string]struct{}, len(sends))
	for _, s := range sends {
		if s.TemplateID == c.template && s.StepID == c.step && s.Status == StatusSent {
			done[s.ContactID] = struct{}{}
		}
	}

	// If PriorStep is set, only send to contacts that have a successful send
	// record for that step. Contacts who never received the prior step are
	// gated out. Failed prior sends do not qualify: a failed delivery is not
	// evidence the contact interacted with the previous screen.
	var priorDone map[string]struct{}
	if r.priorStep != "" {
		priorDone = make(map[string]struct{}, len(sends))
		for _, s := range sends {
			if s.TemplateID == c.template && s.StepID == r.priorStep && s.Status == StatusSent {
				priorDone[s.ContactID] = struct{}{}
			}
		}
	}

	var sum Summary
	now := time.Now().UTC()

	for _, contact := range contacts {
		if _, skip := done[contact.ID]; skip {
			sum.Skipped++
			r.logger.Info("skipping already-sent contact",
				"campaign", campaignID, "contact", contact.ID, "template", c.template, "step", c.step)
			continue
		}

		if priorDone != nil {
			if _, ready := priorDone[contact.ID]; !ready {
				sum.Skipped++
				r.logger.Info("skipping contact: prior step not sent",
					"campaign", campaignID, "contact", contact.ID, "prior_step", r.priorStep)
				continue
			}
		}

		lang := preferredLang(contact.Vars)
		vars := tmpl.Vars(contact.Vars)

		msg, err := r.composer.Compose(contact.ID, contact.Email, vars, lang, step, now)
		if err != nil {
			r.logger.Error("compose failed",
				"campaign", campaignID, "contact", contact.ID, "err", err)
			sum.Failed++
			r.recordFailure(ctx, contact.ID, c.template, c.step, err, now)
			continue
		}

		if r.dryRun {
			r.logger.Info("dry-run: would send",
				"campaign", campaignID, "contact", contact.ID, "to", msg.To,
				"subject", msg.Subject, "lang", msg.SelectedLang,
				"message_id", msg.MessageID)
			sum.Sent++ // counts as "would have sent" in dry-run
			continue
		}

		if err := r.sender.Send(ctx, msg); err != nil {
			r.logger.Error("smtp failed",
				"campaign", campaignID, "contact", contact.ID, "err", err)
			sum.Failed++
			r.recordFailure(ctx, contact.ID, c.template, c.step, err, now)
			continue
		}

		sum.Sent++
		if _, err := r.ops.RecordSend(ctx, store.SendInput{
			ContactID:  contact.ID,
			TemplateID: c.template,
			StepID:     c.step,
			Status:     StatusSent,
			SentAt:     now,
		}); err != nil {
			// The email is delivered; losing the record is recoverable, so we
			// log the error but do not fail the whole run.
			r.logger.Error("record send failed",
				"campaign", campaignID, "contact", contact.ID, "err", err)
		}
	}

	r.logger.Info("send complete", "campaign", campaignID, "summary", sum.String())
	return sum, nil
}

// recordFailure writes a failed send record. It is best-effort: a store error
// is logged and ignored so it cannot mask the original delivery failure.
func (r *Runner) recordFailure(ctx context.Context, contactID, templateID, stepID string, cause error, at time.Time) {
	reason := truncateRunes(cause.Error(), 500)
	status := statusFailed + ": " + reason
	if _, err := r.ops.RecordSend(ctx, store.SendInput{
		ContactID:  contactID,
		TemplateID: templateID,
		StepID:     stepID,
		Status:     status,
		SentAt:     at,
	}); err != nil {
		r.logger.Error("record failure failed", "contact", contactID, "err", err)
	}
}

// preferredLang returns the contact's preferred language from vars. Keys are
// looked up case-insensitively via tmpl.Vars.Lookup so "Lang", "LANG" and
// "lang" all resolve. Falls back to "" which lets Compose apply DefaultLanguage.
func preferredLang(vars map[string]string) string {
	v := tmpl.Vars(vars)
	for _, key := range []string{"lang", "language", "locale"} {
		if val := strings.TrimSpace(v.Lookup(key)); val != "" {
			return val
		}
	}
	return ""
}

// truncateRunes cuts s to at most n runes without splitting a multi-byte
// character. Byte slicing at an arbitrary offset is undefined for UTF-8.
func truncateRunes(s string, n int) string {
	count := 0
	for i := range s {
		if count == n {
			return s[:i]
		}
		count++
	}
	return s
}
