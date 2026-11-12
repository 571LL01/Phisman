-- The collector's artifacts table lives under the same migration gate as the
-- operational tables. It used to be a CREATE TABLE IF NOT EXISTS executed at
-- every boot, which meant a change here never bumped the schema version and the
-- downgrade guard could not see it.
--
-- IF NOT EXISTS is deliberate for this one migration: files created by the
-- pre-migration binary already carry these objects at version 1, and the table
-- must be adopted rather than shadowed by a failing migration. Later migrations
-- are plain DDL.
CREATE TABLE IF NOT EXISTS artifacts (
	id          TEXT PRIMARY KEY,
	campaign_id TEXT NOT NULL,
	template_id TEXT NOT NULL,
	step        TEXT NOT NULL,
	received_at TEXT NOT NULL,
	remote_ip   TEXT NOT NULL,
	body        BLOB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_artifacts_campaign
	ON artifacts (campaign_id, template_id, received_at);
CREATE INDEX IF NOT EXISTS idx_artifacts_ip
	ON artifacts (remote_ip, received_at);
