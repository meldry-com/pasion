-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  user_emails_user_fk
  ON user_emails (user_id);
