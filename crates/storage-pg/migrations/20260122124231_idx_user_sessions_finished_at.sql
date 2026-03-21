-- no-transaction
-- Adds a partial index on user_sessions.finished_at
CREATE INDEX CONCURRENTLY IF NOT EXISTS "user_sessions_finished_at_idx"
    ON "user_sessions" ("finished_at")
    WHERE "finished_at" IS NOT NULL;
