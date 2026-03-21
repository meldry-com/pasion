-- Change the FK constraint on next_attempt_id to SET NULL on delete
ALTER TABLE queue_jobs
  DROP CONSTRAINT queue_jobs_next_attempt_id_fkey,
  ADD CONSTRAINT queue_jobs_next_attempt_id_fkey
    FOREIGN KEY (next_attempt_id)
    REFERENCES queue_jobs (queue_job_id)
    ON DELETE SET NULL
    NOT VALID;
