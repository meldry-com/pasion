-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  user_recovery_tickets_user_email_fk
  ON user_recovery_tickets (user_email_id);
