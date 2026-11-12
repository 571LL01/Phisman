-- events records the tracking funnel stages that happen BEFORE a form
-- submission: an email open (tracking pixel) and a link click (phishing page
-- GET). A submission is already evidence in the sealed artifacts table; a
-- send is already in sends. events fills the two middle stages so an operator
-- can see "delivered -> opened -> clicked -> submitted".
--
-- Rows are plaintext operational metadata, like sends: no captured secret ever
-- lands here. They are only written when the recipient id (rid) resolves to a
-- contact of the campaign, so both foreign keys always point at an existing
-- row and a distinct-contact count is well defined.
CREATE TABLE events (
	id          TEXT PRIMARY KEY,
	campaign_id TEXT NOT NULL REFERENCES campaigns (id) ON DELETE CASCADE,
	contact_id  TEXT NOT NULL REFERENCES contacts (id) ON DELETE CASCADE,
	template_id TEXT NOT NULL,
	step_id     TEXT NOT NULL,
	kind        TEXT NOT NULL CHECK (kind IN ('open', 'click')),
	occurred_at TEXT NOT NULL,
	remote_ip   TEXT NOT NULL DEFAULT '',
	user_agent  TEXT NOT NULL DEFAULT ''
);

-- The funnel query is COUNT(DISTINCT contact_id) filtered by campaign and kind.
CREATE INDEX events_campaign_kind
	ON events (campaign_id, kind, contact_id);
