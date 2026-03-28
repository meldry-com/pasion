-- Recreate the enum type and convert back
DO $$ BEGIN
    CREATE TYPE queue_job_status AS ENUM ('available', 'running', 'completed', 'lost');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'queue_jobs'
          AND column_name = 'status'
          AND data_type = 'text'
    ) THEN
        -- Delete rows with status values not in the original enum before converting back
        DELETE FROM queue_jobs WHERE status NOT IN ('available', 'running', 'completed', 'lost');
        ALTER TABLE queue_jobs
            ALTER COLUMN status SET DEFAULT NULL,
            ALTER COLUMN status TYPE queue_job_status USING status::queue_job_status,
            ALTER COLUMN status SET DEFAULT 'available';
    END IF;
END $$;
