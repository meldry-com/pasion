-- Convert queue_jobs.status from the legacy queue_job_status enum to TEXT.
-- New installations already have TEXT (from the initial migration), so we check first.
DO $$
BEGIN
    -- Only alter if the column is still the enum type
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'queue_jobs'
          AND column_name = 'status'
          AND udt_name = 'queue_job_status'
    ) THEN
        ALTER TABLE queue_jobs
            ALTER COLUMN status SET DEFAULT NULL,
            ALTER COLUMN status TYPE TEXT USING status::TEXT,
            ALTER COLUMN status SET DEFAULT 'available';
    END IF;
END $$;

-- Also add the 'scheduled' and 'failed' values are now just TEXT, no enum constraint needed.
-- Drop the enum type if it exists (it's no longer used).
DROP TYPE IF EXISTS queue_job_status;
