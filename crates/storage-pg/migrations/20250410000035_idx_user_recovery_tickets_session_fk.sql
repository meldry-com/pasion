-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  user_recovery_tickets_session_fk
  ON user_recovery_tickets (user_recovery_session_id);
