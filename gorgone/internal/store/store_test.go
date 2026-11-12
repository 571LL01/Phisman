package store_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/siren-core/gorgone/internal/collect"
	sirendb "github.com/siren-core/gorgone/internal/db"
	"github.com/siren-core/gorgone/internal/store"
)

func openDB(t *testing.T) *sirendb.DB {
	t.Helper()
	d, err := sirendb.Open("file:" + filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() {
		if err := d.Close(); err != nil {
			t.Errorf("close db: %v", err)
		}
	})
	return d
}

func countRows(t *testing.T, d *sirendb.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := d.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func TestMigrateFromEmptyIsIdempotent(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()

	if err := sirendb.Migrate(ctx, d.DB); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	version, err := sirendb.SchemaVersion(ctx, d.DB)
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if version != 6 {
		t.Fatalf("version = %d, want 6", version)
	}
	if n := countRows(t, d, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'artifacts'`); n != 1 {
		t.Fatalf("artifacts table = %d, want 1", n)
	}

	var applied string
	if err := d.QueryRow(`SELECT applied_at FROM schema_migrations WHERE version = 1`).Scan(&applied); err != nil {
		t.Fatalf("applied_at: %v", err)
	}

	if err := sirendb.Migrate(ctx, d.DB); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if n := countRows(t, d, `SELECT COUNT(*) FROM schema_migrations`); n != 6 {
		t.Fatalf("migration rows = %d, want 6", n)
	}
	var appliedAgain string
	if err := d.QueryRow(`SELECT applied_at FROM schema_migrations WHERE version = 1`).Scan(&appliedAgain); err != nil {
		t.Fatalf("applied_at after rerun: %v", err)
	}
	if appliedAgain != applied {
		t.Fatalf("rerun rewrote applied_at: %q -> %q", applied, appliedAgain)
	}

	// store.New runs the same path; it must not fail on an up-to-date file.
	if _, err := store.New(d.DB); err != nil {
		t.Fatalf("store.New on migrated db: %v", err)
	}
}

func TestMigrateRefusesNewerSchema(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()

	if err := sirendb.Migrate(ctx, d.DB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := d.Exec(`UPDATE schema_migrations SET version = 7 WHERE version = 6`); err != nil {
		t.Fatalf("tamper version: %v", err)
	}

	err := sirendb.Migrate(ctx, d.DB)
	if !errors.Is(err, sirendb.ErrSchemaTooNew) {
		t.Fatalf("migrate on newer schema = %v, want ErrSchemaTooNew", err)
	}
	if _, err := store.New(d.DB); !errors.Is(err, sirendb.ErrSchemaTooNew) {
		t.Fatalf("store.New on newer schema = %v, want ErrSchemaTooNew", err)
	}
}

func TestStateMachineTable(t *testing.T) {
	all := []store.State{store.StateDraft, store.StateArmed, store.StateRunning, store.StateClosed}
	valid := map[store.State]store.State{
		store.StateDraft:   store.StateArmed,
		store.StateArmed:   store.StateRunning,
		store.StateRunning: store.StateClosed,
	}

	for _, from := range append(all, store.State("paused")) {
		for _, to := range all {
			err := store.CheckTransition(from, to)
			if valid[from] == to {
				if err != nil {
					t.Fatalf("%s -> %s refused: %v", from, to, err)
				}
				continue
			}
			if err == nil {
				t.Fatalf("%s -> %s accepted", from, to)
			}
			var transition *store.TransitionError
			if !errors.As(err, &transition) {
				t.Fatalf("%s -> %s: error %T is not *TransitionError", from, to, err)
			}
		}
	}
}

// TestStoreContract runs the same behavioural checks against SQL and Fake so
// the two implementations cannot drift on the parts consumers rely on.
func TestStoreContract(t *testing.T) {
	d := openDB(t)
	sqlStore, err := store.New(d.DB)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	implementations := map[string]store.Store{
		"sql":  sqlStore,
		"fake": store.NewFake(),
	}
	for name, st := range implementations {
		t.Run(name, func(t *testing.T) {
			testStoreContract(t, st)
		})
	}
}

func testStoreContract(t *testing.T, st store.Store) {
	ctx := context.Background()

	campaign, err := st.CreateCampaign(ctx, "  Acme  ")
	if err != nil {
		t.Fatalf("CreateCampaign: %v", err)
	}
	if campaign.Name != "Acme" || campaign.State != store.StateDraft {
		t.Fatalf("campaign = %+v", campaign)
	}

	got, err := st.GetCampaign(ctx, campaign.ID)
	if err != nil {
		t.Fatalf("GetCampaign: %v", err)
	}
	if got.ID != campaign.ID {
		t.Fatalf("GetCampaign id = %q", got.ID)
	}

	if _, err := st.GetCampaign(ctx, "missing"); !errors.Is(err, store.ErrCampaignNotFound) {
		t.Fatalf("GetCampaign missing = %v", err)
	}

	list, err := st.ListCampaigns(ctx)
	if err != nil {
		t.Fatalf("ListCampaigns: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("ListCampaigns = %d, want 1", len(list))
	}

	// Skipping a state is refused and leaves the campaign untouched.
	err = st.SetCampaignState(ctx, campaign.ID, store.StateRunning)
	var transition *store.TransitionError
	if !errors.As(err, &transition) {
		t.Fatalf("draft -> running = %v, want *TransitionError", err)
	}
	if got, _ := st.GetCampaign(ctx, campaign.ID); got.State != store.StateDraft {
		t.Fatalf("refused transition changed state to %s", got.State)
	}

	for _, to := range []store.State{store.StateArmed, store.StateRunning, store.StateClosed} {
		if err := st.SetCampaignState(ctx, campaign.ID, to); err != nil {
			t.Fatalf("transition to %s: %v", to, err)
		}
	}
	if got, _ := st.GetCampaign(ctx, campaign.ID); got.State != store.StateClosed {
		t.Fatalf("final state = %s, want closed", got.State)
	}
	if err := st.SetCampaignState(ctx, campaign.ID, store.StateArmed); !errors.As(err, &transition) {
		t.Fatalf("closed -> armed = %v, want *TransitionError", err)
	}
	if err := st.SetCampaignState(ctx, "missing", store.StateArmed); !errors.Is(err, store.ErrCampaignNotFound) {
		t.Fatalf("missing campaign transition = %v", err)
	}

	inputs := []store.ContactInput{
		{Email: "alice@example.com", Vars: map[string]string{"FirstName": "Alice"}},
		{Email: "ALICE@example.com"},
		{Email: " bob@example.com ", Vars: map[string]string{"LastTransaction": "42.00"}},
	}
	n, err := st.AddContacts(ctx, campaign.ID, inputs)
	if err != nil {
		t.Fatalf("AddContacts: %v", err)
	}
	if n != 2 {
		t.Fatalf("AddContacts inserted = %d, want 2", n)
	}
	n, err = st.AddContacts(ctx, campaign.ID, []store.ContactInput{
		{Email: "alice@example.com"},
		{Email: "carol@example.com"},
	})
	if err != nil {
		t.Fatalf("AddContacts rerun: %v", err)
	}
	if n != 1 {
		t.Fatalf("AddContacts rerun inserted = %d, want 1", n)
	}
	contacts, err := st.ListContacts(ctx, campaign.ID)
	if err != nil {
		t.Fatalf("ListContacts: %v", err)
	}
	if len(contacts) != 3 {
		t.Fatalf("ListContacts = %d, want 3", len(contacts))
	}
	var alice, bob *store.Contact
	for i := range contacts {
		switch contacts[i].Email {
		case "alice@example.com":
			alice = &contacts[i]
		case "bob@example.com":
			bob = &contacts[i]
		}
	}
	if alice == nil || bob == nil {
		t.Fatalf("contacts = %+v", contacts)
	}
	if alice.Vars["FirstName"] != "Alice" {
		t.Fatalf("alice vars = %v", alice.Vars)
	}
	if bob.Vars["LastTransaction"] != "42.00" {
		t.Fatalf("bob vars = %v", bob.Vars)
	}

	// The render path loads exactly one contact, scoped to its campaign.
	loaded, err := st.GetContact(ctx, campaign.ID, alice.ID)
	if err != nil {
		t.Fatalf("GetContact: %v", err)
	}
	if loaded.ID != alice.ID || loaded.Vars["FirstName"] != "Alice" {
		t.Fatalf("GetContact = %+v", loaded)
	}
	if _, err := st.GetContact(ctx, campaign.ID, "missing"); !errors.Is(err, store.ErrContactNotFound) {
		t.Fatalf("GetContact missing = %v, want ErrContactNotFound", err)
	}
	// SQL and Fake must agree: an unknown campaign is not a separate error
	// that lets a caller probe which campaign IDs exist.
	if _, err := st.GetContact(ctx, "missing-campaign", alice.ID); !errors.Is(err, store.ErrContactNotFound) {
		t.Fatalf("GetContact missing campaign = %v, want ErrContactNotFound", err)
	}

	if _, err := st.AddContacts(ctx, "missing", []store.ContactInput{{Email: "x@example.com"}}); !errors.Is(err, store.ErrCampaignNotFound) {
		t.Fatalf("AddContacts missing campaign = %v", err)
	}
	if _, err := st.ListContacts(ctx, "missing"); !errors.Is(err, store.ErrCampaignNotFound) {
		t.Fatalf("ListContacts missing campaign = %v", err)
	}

	// Uniqueness is scoped to the campaign, not global.
	other, err := st.CreateCampaign(ctx, "Other")
	if err != nil {
		t.Fatalf("CreateCampaign other: %v", err)
	}
	n, err = st.AddContacts(ctx, other.ID, []store.ContactInput{{Email: "alice@example.com"}})
	if err != nil {
		t.Fatalf("AddContacts other campaign: %v", err)
	}
	if n != 1 {
		t.Fatalf("same email in another campaign inserted = %d, want 1", n)
	}

	// A recipient ID from another campaign must not resolve through this
	// campaign, even though the contact exists in the same database.
	if _, err := st.GetContact(ctx, other.ID, alice.ID); !errors.Is(err, store.ErrContactNotFound) {
		t.Fatalf("cross-campaign GetContact = %v, want ErrContactNotFound", err)
	}

	// TEXT timestamps must sort chronologically, including differing fractions.
	all, err := st.ListCampaigns(ctx)
	if err != nil {
		t.Fatalf("ListCampaigns: %v", err)
	}
	for i := 1; i < len(all); i++ {
		if all[i].CreatedAt.Before(all[i-1].CreatedAt) {
			t.Fatalf("campaigns out of order: %s before %s", all[i-1].CreatedAt, all[i].CreatedAt)
		}
	}

	sentAt := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	send, err := st.RecordSend(ctx, store.SendInput{
		ContactID:  alice.ID,
		TemplateID: "t1",
		StepID:     "s1",
		Status:     "sent",
		SentAt:     sentAt,
	})
	if err != nil {
		t.Fatalf("RecordSend: %v", err)
	}
	if !send.SentAt.Equal(sentAt) {
		t.Fatalf("SentAt = %s, want %s", send.SentAt, sentAt)
	}

	sends, err := st.ListSendsByCampaign(ctx, campaign.ID)
	if err != nil {
		t.Fatalf("ListSendsByCampaign: %v", err)
	}
	if len(sends) != 1 || sends[0].ID != send.ID {
		t.Fatalf("sends = %+v", sends)
	}
	if _, err := st.RecordSend(ctx, store.SendInput{ContactID: "missing", TemplateID: "t", StepID: "s", Status: "sent"}); !errors.Is(err, store.ErrContactNotFound) {
		t.Fatalf("RecordSend missing contact = %v", err)
	}
	if _, err := st.ListSendsByCampaign(ctx, "missing"); !errors.Is(err, store.ErrCampaignNotFound) {
		t.Fatalf("ListSendsByCampaign missing campaign = %v", err)
	}
}

func TestCascadeDeletesContactsAndSends(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()
	st, err := store.New(d.DB)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	campaign, err := st.CreateCampaign(ctx, "Cascade")
	if err != nil {
		t.Fatalf("CreateCampaign: %v", err)
	}
	if _, err := st.AddContacts(ctx, campaign.ID, []store.ContactInput{
		{Email: "alice@example.com"},
		{Email: "bob@example.com"},
	}); err != nil {
		t.Fatalf("AddContacts: %v", err)
	}
	contacts, err := st.ListContacts(ctx, campaign.ID)
	if err != nil {
		t.Fatalf("ListContacts: %v", err)
	}
	if _, err := st.RecordSend(ctx, store.SendInput{
		ContactID: contacts[0].ID, TemplateID: "t1", StepID: "s1", Status: "sent",
	}); err != nil {
		t.Fatalf("RecordSend: %v", err)
	}
	if n := countRows(t, d, `SELECT COUNT(*) FROM sends`); n != 1 {
		t.Fatalf("sends before delete = %d", n)
	}

	if _, err := d.Exec(`DELETE FROM campaigns WHERE id = ?`, campaign.ID); err != nil {
		t.Fatalf("delete campaign: %v", err)
	}
	if n := countRows(t, d, `SELECT COUNT(*) FROM contacts`); n != 0 {
		t.Fatalf("contacts after cascade = %d, want 0", n)
	}
	if n := countRows(t, d, `SELECT COUNT(*) FROM sends`); n != 0 {
		t.Fatalf("sends after cascade = %d, want 0", n)
	}
}

// TestConcurrentCollectAndStoreWrites is the reason the handle is shared and
// the pool has room for more than one connection: the collector and the
// operational store write at the same time, and busy_timeout must absorb the
// lock contention instead of returning SQLITE_BUSY.
func TestConcurrentCollectAndStoreWrites(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()

	keys, err := collect.NewKeySet(1, map[byte][]byte{1: bytes.Repeat([]byte{0x42}, 32)})
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	collector, err := collect.NewSQLiteFrom(d.DB, keys)
	if err != nil {
		t.Fatalf("NewSQLiteFrom: %v", err)
	}
	ops, err := store.New(d.DB)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	campaign, err := ops.CreateCampaign(ctx, "Concurrent")
	if err != nil {
		t.Fatalf("CreateCampaign: %v", err)
	}
	if _, err := ops.AddContacts(ctx, campaign.ID, []store.ContactInput{{Email: "alice@example.com"}}); err != nil {
		t.Fatalf("AddContacts: %v", err)
	}
	contacts, err := ops.ListContacts(ctx, campaign.ID)
	if err != nil {
		t.Fatalf("ListContacts: %v", err)
	}

	const writes = 50
	errs := make(chan error, 2*writes)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < writes; i++ {
			a := &collect.Artifact{
				ID:         collect.NewID(),
				CampaignID: campaign.ID,
				TemplateID: "t1",
				Step:       "s1",
				ReceivedAt: time.Now().UTC(),
				RemoteIP:   "198.51.100.7",
				Target:     "https://example.com/",
			}
			if err := collector.Insert(ctx, a); err != nil {
				errs <- err
			}
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < writes; i++ {
			_, err := ops.RecordSend(ctx, store.SendInput{
				ContactID:  contacts[0].ID,
				TemplateID: "t1",
				StepID:     "s1",
				Status:     "sent",
			})
			if err != nil {
				errs <- err
			}
		}
	}()

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent write: %v", err)
	}

	if n := countRows(t, d, `SELECT COUNT(*) FROM artifacts`); n != writes {
		t.Fatalf("artifacts = %d, want %d", n, writes)
	}
	if n := countRows(t, d, `SELECT COUNT(*) FROM sends`); n != writes {
		t.Fatalf("sends = %d, want %d", n, writes)
	}

	// artifacts.received_at uses the same fixed-width layout as the
	// operational tables, so it can be ordered as TEXT.
	var received string
	if err := d.QueryRow(`SELECT received_at FROM artifacts LIMIT 1`).Scan(&received); err != nil {
		t.Fatalf("received_at: %v", err)
	}
	if len(received) != len("2006-01-02T15:04:05.000000000Z") {
		t.Fatalf("received_at %q is not fixed width", received)
	}
}
