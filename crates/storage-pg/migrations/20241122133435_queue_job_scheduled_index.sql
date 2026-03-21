-- Add a partial index on scheduled jobs
CREATE INDEX "queue_jobs_scheduled_at_idx"
  ON "queue_jobs" ("scheduled_at")
  WHERE "status" = 'scheduled';
