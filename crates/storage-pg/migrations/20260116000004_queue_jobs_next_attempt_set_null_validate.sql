-- no-transaction
-- Validate the FK constraint that was added in the previous migration
ALTER TABLE queue_jobs
  VALIDATE CONSTRAINT queue_jobs_next_attempt_id_fkey;
