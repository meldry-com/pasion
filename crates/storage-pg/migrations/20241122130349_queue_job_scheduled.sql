-- Add a new status for scheduled jobs
ALTER TYPE "queue_job_status" ADD VALUE 'scheduled';

ALTER TABLE "queue_jobs"
  -- When the job is scheduled to run
  ADD COLUMN "scheduled_at" TIMESTAMP WITH TIME ZONE;
