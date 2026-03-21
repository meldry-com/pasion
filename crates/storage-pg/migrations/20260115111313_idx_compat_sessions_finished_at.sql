-- no-transaction
-- Index to efficiently query finished compat sessions for cleanup
CREATE INDEX CONCURRENTLY IF NOT EXISTS "compat_sessions_finished_at_idx"
    ON "compat_sessions" ("finished_at")
    WHERE "finished_at" IS NOT NULL;
