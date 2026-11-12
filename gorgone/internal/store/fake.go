package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Fake is the in-memory Store used by consumers that do not need SQLite. It
// follows the same rules as SQL: the same state machine, the same
// case-insensitive per-campaign email uniqueness, the same typed errors.
type Fake struct {
	mu        sync.Mutex
	campaigns map[string]*Campaign
	contacts  map[string]*Contact
	sends     map[string]*Send
	events    map[string]*Event
	now       func() time.Time
}

var _ Store = (*Fake)(nil)

func NewFake() *Fake {
	return &Fake{
		campaigns: make(map[string]*Campaign),
		contacts:  make(map[string]*Contact),
		sends:     make(map[string]*Send),
		events:    make(map[string]*Event),
		now:       func() time.Time { return time.Now().UTC() },
	}
}

func (f *Fake) CreateCampaign(_ context.Context, name string) (*Campaign, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("store: campaign name is required")
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	now := f.now()
	c := &Campaign{ID: newID(), Name: name, State: StateDraft, CreatedAt: now, UpdatedAt: now}
	f.campaigns[c.ID] = c
	return cloneCampaign(c), nil
}

func (f *Fake) GetCampaign(_ context.Context, id string) (*Campaign, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	c, ok := f.campaigns[id]
	if !ok {
		return nil, ErrCampaignNotFound
	}
	return cloneCampaign(c), nil
}

func (f *Fake) SetCampaignState(_ context.Context, id string, to State) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	c, ok := f.campaigns[id]
	if !ok {
		return ErrCampaignNotFound
	}
	if err := CheckTransition(c.State, to); err != nil {
		return err
	}
	c.State = to
	c.UpdatedAt = f.now()
	return nil
}

func (f *Fake) ListCampaigns(_ context.Context) ([]Campaign, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	out := make([]Campaign, 0, len(f.campaigns))
	for _, c := range f.campaigns {
		out = append(out, *cloneCampaign(c))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (f *Fake) AddContacts(_ context.Context, campaignID string, contacts []ContactInput) (int, error) {
	emails := make([]string, len(contacts))
	for i, in := range contacts {
		emails[i] = strings.TrimSpace(in.Email)
		if emails[i] == "" {
			return 0, errors.New("store: contact email is required")
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if _, ok := f.campaigns[campaignID]; !ok {
		return 0, ErrCampaignNotFound
	}

	seen := make(map[string]struct{})
	for _, c := range f.contacts {
		if c.CampaignID == campaignID {
			seen[strings.ToLower(c.Email)] = struct{}{}
		}
	}

	now := f.now()
	inserted := 0
	for i, in := range contacts {
		key := strings.ToLower(emails[i])
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		c := &Contact{
			ID:         newID(),
			CampaignID: campaignID,
			Email:      emails[i],
			Vars:       cloneVars(in.Vars),
			CreatedAt:  now,
		}
		f.contacts[c.ID] = c
		inserted++
	}
	return inserted, nil
}

func (f *Fake) ListContacts(_ context.Context, campaignID string) ([]Contact, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, ok := f.campaigns[campaignID]; !ok {
		return nil, ErrCampaignNotFound
	}
	out := make([]Contact, 0)
	for _, c := range f.contacts {
		if c.CampaignID == campaignID {
			out = append(out, *cloneContact(c))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// GetContact mirrors SQL: a missing campaign and a missing contact are the
// same ErrContactNotFound, so callers cannot tell whether the campaign exists.
func (f *Fake) GetContact(_ context.Context, campaignID, contactID string) (*Contact, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	c, ok := f.contacts[contactID]
	if !ok || c.CampaignID != campaignID {
		return nil, ErrContactNotFound
	}
	return cloneContact(c), nil
}

func (f *Fake) RecordSend(_ context.Context, in SendInput) (*Send, error) {
	if strings.TrimSpace(in.ContactID) == "" {
		return nil, errors.New("store: send contact_id is required")
	}
	if strings.TrimSpace(in.TemplateID) == "" {
		return nil, errors.New("store: send template_id is required")
	}
	if strings.TrimSpace(in.StepID) == "" {
		return nil, errors.New("store: send step_id is required")
	}
	if strings.TrimSpace(in.Status) == "" {
		return nil, errors.New("store: send status is required")
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if _, ok := f.contacts[in.ContactID]; !ok {
		return nil, ErrContactNotFound
	}
	sentAt := in.SentAt
	if sentAt.IsZero() {
		sentAt = f.now()
	} else {
		sentAt = sentAt.UTC()
	}
	send := &Send{
		ID:         newID(),
		ContactID:  in.ContactID,
		TemplateID: in.TemplateID,
		StepID:     in.StepID,
		SentAt:     sentAt,
		Status:     in.Status,
	}
	f.sends[send.ID] = send
	return cloneSend(send), nil
}

func (f *Fake) ListSendsByCampaign(_ context.Context, campaignID string) ([]Send, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, ok := f.campaigns[campaignID]; !ok {
		return nil, ErrCampaignNotFound
	}
	out := make([]Send, 0)
	for _, s := range f.sends {
		if c, ok := f.contacts[s.ContactID]; ok && c.CampaignID == campaignID {
			out = append(out, *cloneSend(s))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].SentAt.Equal(out[j].SentAt) {
			return out[i].SentAt.Before(out[j].SentAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (f *Fake) RecordEvent(_ context.Context, in EventInput) error {
	if strings.TrimSpace(in.CampaignID) == "" {
		return errors.New("store: event campaign_id is required")
	}
	if strings.TrimSpace(in.ContactID) == "" {
		return errors.New("store: event contact_id is required")
	}
	if in.Kind != EventOpen && in.Kind != EventClick {
		return fmt.Errorf("store: invalid event kind %q", in.Kind)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	at := in.OccurredAt
	if at.IsZero() {
		at = f.now()
	} else {
		at = at.UTC()
	}
	e := &Event{
		ID:         newID(),
		CampaignID: in.CampaignID,
		ContactID:  in.ContactID,
		TemplateID: in.TemplateID,
		StepID:     in.StepID,
		Kind:       in.Kind,
		OccurredAt: at,
		RemoteIP:   in.RemoteIP,
		UserAgent:  in.UserAgent,
	}
	f.events[e.ID] = e
	return nil
}

func (f *Fake) EventStats(_ context.Context, campaignID string) (EventStats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	opened := make(map[string]struct{})
	clicked := make(map[string]struct{})
	for _, e := range f.events {
		if e.CampaignID != campaignID {
			continue
		}
		switch e.Kind {
		case EventOpen:
			opened[e.ContactID] = struct{}{}
		case EventClick:
			clicked[e.ContactID] = struct{}{}
		}
	}
	return EventStats{Opened: len(opened), Clicked: len(clicked)}, nil
}

func (f *Fake) ListEventsByCampaign(_ context.Context, campaignID string) ([]Event, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	out := make([]Event, 0)
	for _, e := range f.events {
		if e.CampaignID == campaignID {
			out = append(out, *e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].OccurredAt.Equal(out[j].OccurredAt) {
			return out[i].OccurredAt.Before(out[j].OccurredAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (f *Fake) SetExportTokenHash(_ context.Context, campaignID, hash string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	c, ok := f.campaigns[campaignID]
	if !ok {
		return ErrCampaignNotFound
	}
	c.exportHash = hash
	c.UpdatedAt = f.now()
	return nil
}

func (f *Fake) GetExportTokenHash(_ context.Context, campaignID string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	c, ok := f.campaigns[campaignID]
	if !ok {
		return "", ErrCampaignNotFound
	}
	return c.exportHash, nil
}

func cloneCampaign(c *Campaign) *Campaign {
	cp := *c
	return &cp
}

func cloneContact(c *Contact) *Contact {
	cp := *c
	cp.Vars = cloneVars(c.Vars)
	return &cp
}

func cloneVars(vars map[string]string) map[string]string {
	if vars == nil {
		return map[string]string{}
	}
	cp := make(map[string]string, len(vars))
	for k, v := range vars {
		cp[k] = v
	}
	return cp
}

func cloneSend(s *Send) *Send {
	cp := *s
	return &cp
}
