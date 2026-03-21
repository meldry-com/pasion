-- no-transaction
-- When we're looking up an email address, we want to be able to do a case-insensitive
-- lookup, so we index the email address lowercase and request it like that
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  user_emails_lower_email_idx
  ON user_emails (LOWER(email));
