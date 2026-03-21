-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  queue_jobs_schedule_name_fk
  ON queue_jobs (schedule_name);
