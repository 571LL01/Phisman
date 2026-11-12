package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	sirendb "github.com/siren-core/gorgone/internal/db"
)

// SQL is the durable Store. It never owns the *sql.DB: the handle is shared
// with internal/collect and closed once by internal/db.
//
// Every BeginTx below writes. Reads go straight to the pool: with
// _txlock=immediate a transaction is a global write lock, so wrapping a pure
// SELECT in one would serialize it behind all writers for no reason.
type SQL struct {
	db *sql.DB
}

var _ Store = (*SQL)(nil)

// New migrates the shared database forward and returns the store.
func New(handle *sql.DB) (*SQL, error) {
	if handle == nil {
		return nil, errors.New("store: nil database")
	}
	if err := sirendb.Migrate(context.Background(), handle); err != nil {
		return nil, err
	}
	return &SQL{db: handle}, nil
}

func (s *SQL) CreateCampaign(ctx context.Context, name string) (*Campaign, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("store: campaign name is required")
	}
	now := time.Now().UTC()
	c := &Campaign{ID: newID(), Name: name, State: StateDraft, CreatedAt: now, UpdatedAt: now}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO campaigns (id, name, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		c.ID, c.Name, string(c.State), sirendb.FormatTime(c.CreatedAt), sirendb.FormatTime(c.UpdatedAt),
	); err != nil {
		return nil, fmt.Errorf("store: create campaign: %w", err)
	}
	return c, nil
}

func (s *SQL) GetCampaign(ctx context.Context, id string) (*Campaign, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, state, created_at, updated_at FROM campaigns WHERE id = ?`, id)
	c, err := scanCampaign(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrCampaignNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get campaign: %w", err)
	}
	return c, nil
}

func (s *SQL) SetCampaignState(ctx context.Context, id string, to State) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin transition: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit

	var from State
	err = tx.QueryRowContext(ctx, `SELECT state FROM campaigns WHERE id = ?`, id).Scan(&from)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrCampaignNotFound
	}
	if err != nil {
		return fmt.Errorf("store: load campaign state: %w", err)
	}
	if err := CheckTransition(from, to); err != nil {
		return err
	}

	// The state in the WHERE clause makes the check and the write one step: a
	// concurrent transition loses the race instead of overwriting it.
	res, err := tx.ExecContext(ctx,
		`UPDATE campaigns SET state = ?, updated_at = ? WHERE id = ? AND state = ?`,
		string(to), sirendb.FormatTime(time.Now()), id, string(from),
	)
	if err != nil {
		return fmt.Errorf("store: update campaign state: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: update campaign state: %w", err)
	}
	if n == 0 {
		return &TransitionError{From: from, To: to}
	}
	return tx.Commit()
}

func (s *SQL) ListCampaigns(ctx context.Context) ([]Campaign, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, state, created_at, updated_at FROM campaigns ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("store: list campaigns: %w", err)
	}
	defer rows.Close()

	var out []Campaign
	for rows.Next() {
		c, err := scanCampaign(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list campaigns: %w", err)
		}
		out = append(out, *c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list campaigns: %w", err)
	}
	return out, nil
}

func (s *SQL) AddContacts(ctx context.Context, campaignID string, contacts []ContactInput) (int, error) {
	emails := make([]string, len(contacts))
	for i, in := range contacts {
		emails[i] = strings.TrimSpace(in.Email)
		if emails[i] == "" {
			return 0, fmt.Errorf("store: contact %d: email is required", i)
		}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: begin contacts: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit

	var exists int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM campaigns WHERE id = ?`, campaignID).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrCampaignNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("store: load campaign: %w", err)
	}

	now := sirendb.FormatTime(time.Now())

	// Prepare once for the whole batch: a 5,000-contact upload is one parse and
	// one statement on the wire, not 5,000. The transaction already holds the
	// write lock, so per-row prepare cost would be paid while everyone waits.
	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO contacts (id, campaign_id, email, vars_json, created_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT DO NOTHING`)
	if err != nil {
		return 0, fmt.Errorf("store: prepare contact insert: %w", err)
	}
	defer stmt.Close() //nolint:errcheck // statement dies with the transaction

	inserted := 0
	for i, in := range contacts {
		vars := "{}"
		if len(in.Vars) > 0 {
			raw, err := json.Marshal(in.Vars)
			if err != nil {
				return 0, fmt.Errorf("store: contact %d vars: %w", i, err)
			}
			vars = string(raw)
		}
		res, err := stmt.ExecContext(ctx, newID(), campaignID, emails[i], vars, now)
		if err != nil {
			return 0, fmt.Errorf("store: add contact %q: %w", emails[i], err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("store: add contact %q: %w", emails[i], err)
		}
		inserted += int(n)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit contacts: %w", err)
	}
	return inserted, nil
}

func (s *SQL) ListContacts(ctx context.Context, campaignID string) ([]Contact, error) {
	if err := s.campaignExists(ctx, campaignID); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, campaign_id, email, vars_json, created_at
		 FROM contacts WHERE campaign_id = ? ORDER BY created_at, id`, campaignID)
	if err != nil {
		return nil, fmt.Errorf("store: list contacts: %w", err)
	}
	defer rows.Close()

	var out []Contact
	for rows.Next() {
		c, err := scanContact(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list contacts: %w", err)
	}
	return out, nil
}

// GetContact loads one contact, scoped to its campaign. A valid ID from
// another campaign is indistinguishable from a missing ID: the caller gets
// ErrContactNotFound and cannot use the route to enumerate recipients.
func (s *SQL) GetContact(ctx context.Context, campaignID, contactID string) (*Contact, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, campaign_id, email, vars_json, created_at
		 FROM contacts WHERE id = ? AND campaign_id = ?`, contactID, campaignID)
	c, err := scanContact(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrContactNotFound
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

func scanContact(row rowScanner) (*Contact, error) {
	var c Contact
	var vars, created string
	if err := row.Scan(&c.ID, &c.CampaignID, &c.Email, &vars, &created); err != nil {
		return nil, fmt.Errorf("store: scan contact: %w", err)
	}
	if err := json.Unmarshal([]byte(vars), &c.Vars); err != nil {
		return nil, fmt.Errorf("store: contact %s vars: %w", c.ID, err)
	}
	createdAt, err := sirendb.ParseTime(created)
	if err != nil {
		return nil, fmt.Errorf("store: contact %s created_at: %w", c.ID, err)
	}
	c.CreatedAt = createdAt
	return &c, nil
}

func (s *SQL) RecordSend(ctx context.Context, in SendInput) (*Send, error) {
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

	var exists int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM contacts WHERE id = ?`, in.ContactID).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrContactNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: load contact: %w", err)
	}

	sentAt := in.SentAt
	if sentAt.IsZero() {
		sentAt = time.Now().UTC()
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
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO sends (id, contact_id, template_id, step_id, sent_at, status)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		send.ID, send.ContactID, send.TemplateID, send.StepID, sirendb.FormatTime(send.SentAt), send.Status,
	); err != nil {
		return nil, fmt.Errorf("store: record send: %w", err)
	}
	return send, nil
}

func (s *SQL) ListSendsByCampaign(ctx context.Context, campaignID string) ([]Send, error) {
	if err := s.campaignExists(ctx, campaignID); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT s.id, s.contact_id, s.template_id, s.step_id, s.sent_at, s.status
		 FROM sends s
		 JOIN contacts c ON c.id = s.contact_id
		 WHERE c.campaign_id = ?
		 ORDER BY s.sent_at, s.id`, campaignID)
	if err != nil {
		return nil, fmt.Errorf("store: list sends: %w", err)
	}
	defer rows.Close()

	var out []Send
	for rows.Next() {
		var send Send
		var sentAt string
		if err := rows.Scan(&send.ID, &send.ContactID, &send.TemplateID, &send.StepID, &sentAt, &send.Status); err != nil {
			return nil, fmt.Errorf("store: list sends: %w", err)
		}
		send.SentAt, err = sirendb.ParseTime(sentAt)
		if err != nil {
			return nil, fmt.Errorf("store: send %s sent_at: %w", send.ID, err)
		}
		out = append(out, send)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list sends: %w", err)
	}
	return out, nil
}

func (s *SQL) RecordEvent(ctx context.Context, in EventInput) error {
	if strings.TrimSpace(in.CampaignID) == "" {
		return errors.New("store: event campaign_id is required")
	}
	if strings.TrimSpace(in.ContactID) == "" {
		return errors.New("store: event contact_id is required")
	}
	if in.Kind != EventOpen && in.Kind != EventClick {
		return fmt.Errorf("store: invalid event kind %q", in.Kind)
	}
	at := in.OccurredAt
	if at.IsZero() {
		at = time.Now().UTC()
	} else {
		at = at.UTC()
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO events (id, campaign_id, contact_id, template_id, step_id, kind, occurred_at, remote_ip, user_agent)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		newID(), in.CampaignID, in.ContactID, in.TemplateID, in.StepID, in.Kind,
		sirendb.FormatTime(at), in.RemoteIP, in.UserAgent,
	); err != nil {
		return fmt.Errorf("store: record event: %w", err)
	}
	return nil
}

func (s *SQL) EventStats(ctx context.Context, campaignID string) (EventStats, error) {
	var st EventStats
	// One pass, two conditional distinct counts: a recipient who opened three
	// times and clicked twice contributes 1 to each column.
	err := s.db.QueryRowContext(ctx,
		`SELECT
			COUNT(DISTINCT CASE WHEN kind = 'open'  THEN contact_id END),
			COUNT(DISTINCT CASE WHEN kind = 'click' THEN contact_id END)
		 FROM events WHERE campaign_id = ?`, campaignID).Scan(&st.Opened, &st.Clicked)
	if err != nil {
		return EventStats{}, fmt.Errorf("store: event stats: %w", err)
	}
	return st, nil
}

func (s *SQL) ListEventsByCampaign(ctx context.Context, campaignID string) ([]Event, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, campaign_id, contact_id, template_id, step_id, kind, occurred_at, remote_ip, user_agent
		 FROM events WHERE campaign_id = ? ORDER BY occurred_at, id`, campaignID)
	if err != nil {
		return nil, fmt.Errorf("store: list events: %w", err)
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		var e Event
		var occurred string
		if err := rows.Scan(&e.ID, &e.CampaignID, &e.ContactID, &e.TemplateID,
			&e.StepID, &e.Kind, &occurred, &e.RemoteIP, &e.UserAgent); err != nil {
			return nil, fmt.Errorf("store: list events: %w", err)
		}
		e.OccurredAt, err = sirendb.ParseTime(occurred)
		if err != nil {
			return nil, fmt.Errorf("store: event %s occurred_at: %w", e.ID, err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list events: %w", err)
	}
	return out, nil
}

func (s *SQL) SetExportTokenHash(ctx context.Context, campaignID, hash string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE campaigns SET export_token_hash = ?, updated_at = ? WHERE id = ?`,
		hash, sirendb.FormatTime(time.Now()), campaignID)
	if err != nil {
		return fmt.Errorf("store: set export token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: set export token: %w", err)
	}
	if n == 0 {
		return ErrCampaignNotFound
	}
	return nil
}

func (s *SQL) GetExportTokenHash(ctx context.Context, campaignID string) (string, error) {
	var hash string
	err := s.db.QueryRowContext(ctx,
		`SELECT export_token_hash FROM campaigns WHERE id = ?`, campaignID).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrCampaignNotFound
	}
	if err != nil {
		return "", fmt.Errorf("store: get export token: %w", err)
	}
	return hash, nil
}

func (s *SQL) campaignExists(ctx context.Context, id string) error {
	var exists int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM campaigns WHERE id = ?`, id).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrCampaignNotFound
	}
	if err != nil {
		return fmt.Errorf("store: load campaign: %w", err)
	}
	return nil
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanCampaign(row rowScanner) (*Campaign, error) {
	var c Campaign
	var state, created, updated string
	if err := row.Scan(&c.ID, &c.Name, &state, &created, &updated); err != nil {
		return nil, err
	}
	c.State = State(state)
	var err error
	if c.CreatedAt, err = sirendb.ParseTime(created); err != nil {
		return nil, err
	}
	if c.UpdatedAt, err = sirendb.ParseTime(updated); err != nil {
		return nil, err
	}
	return &c, nil
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("store: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
