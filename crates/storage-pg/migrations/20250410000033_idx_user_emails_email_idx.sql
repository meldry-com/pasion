-- no-transaction
-- This isn't a foreign key, but we really need that to be indexed
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  user_emails_email_idx
  ON user_emails (email);
