-- Export tokens are per campaign and stored hashed: the clear value is shown
-- once when it is issued and never read back from the database. Existing
-- campaigns predate the column, so an empty hash means "no token issued".
ALTER TABLE campaigns ADD COLUMN export_token_hash TEXT NOT NULL DEFAULT '';
