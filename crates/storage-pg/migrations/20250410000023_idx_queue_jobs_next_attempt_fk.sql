-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  queue_jobs_next_attempt_fk
  ON queue_jobs (next_attempt_id);
