-- no-transaction
-- Partial index for cleaning up IP addresses from inactive user sessions
CREATE INDEX CONCURRENTLY IF NOT EXISTS "user_sessions_inactive_ips_idx"
    ON "user_sessions" ("last_active_at")
    WHERE "last_active_ip" IS NOT NULL AND "last_active_at" IS NOT NULL;
