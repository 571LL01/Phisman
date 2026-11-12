CREATE TABLE campaigns (
	id         TEXT PRIMARY KEY,
	name       TEXT NOT NULL,
	state      TEXT NOT NULL CHECK (state IN ('draft', 'armed', 'running', 'closed')),
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

-- contacts.vars_json holds template inputs (FirstName, LastTransaction, ...).
-- It is plaintext on purpose: these are render inputs, not captured secrets.
-- Anything a target submits goes through internal/collect, which stores
-- sensitive values as salted hashes inside the sealed artifact body, never here.
CREATE TABLE contacts (
	id          TEXT PRIMARY KEY,
	campaign_id TEXT NOT NULL REFERENCES campaigns (id) ON DELETE CASCADE,
	email       TEXT NOT NULL,
	vars_json   TEXT NOT NULL DEFAULT '{}',
	created_at  TEXT NOT NULL
);

-- Emails are unique per campaign, case-insensitively. The expression index is
-- also the arbiter for the idempotent INSERT in AddContacts.
CREATE UNIQUE INDEX contacts_campaign_email_ci
	ON contacts (campaign_id, lower(email));

CREATE TABLE sends (
	id          TEXT PRIMARY KEY,
	contact_id  TEXT NOT NULL REFERENCES contacts (id) ON DELETE CASCADE,
	template_id TEXT NOT NULL,
	step_id     TEXT NOT NULL,
	sent_at     TEXT NOT NULL,
	status      TEXT NOT NULL
);

CREATE INDEX sends_contact_sent
	ON sends (contact_id, sent_at);
