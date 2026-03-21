-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  queue_jobs_started_by_fk
  ON queue_jobs (started_by);
