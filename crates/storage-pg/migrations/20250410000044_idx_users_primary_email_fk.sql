-- no-transaction
-- We don't use this column anymore, but… it will still tank the performance on
-- deletions of user_emails if we don't have it
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  users_primary_email_fk
  ON users (primary_user_email_id);
