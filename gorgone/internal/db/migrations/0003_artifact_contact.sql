-- Recipient attribution for collected artifacts. The rid query parameter is
-- validated against the campaign at capture time; an unknown or out-of-scope
-- rid stores '' rather than dropping the submission. Existing rows predate the
-- linkage, so the column defaults to '' and keeps the table readable.
ALTER TABLE artifacts ADD COLUMN contact_id TEXT NOT NULL DEFAULT '';

CREATE INDEX idx_artifacts_contact
	ON artifacts (campaign_id, contact_id, received_at);
