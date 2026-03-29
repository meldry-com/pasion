CREATE TABLE notification_requests (
    notification_request_id UUID PRIMARY KEY,
    template_key TEXT NOT NULL,
    locale TEXT NOT NULL,
    source JSONB NOT NULL,
    payload JSONB NOT NULL,
    status TEXT NOT NULL,
    dedupe_key TEXT NULL,
    correlation_key TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    scheduled_at TIMESTAMPTZ NOT NULL,
    started_at TIMESTAMPTZ NULL,
    completed_at TIMESTAMPTZ NULL,
    cancelled_at TIMESTAMPTZ NULL
);

CREATE INDEX notification_requests_status_scheduled_idx
    ON notification_requests (status, scheduled_at, notification_request_id);

CREATE UNIQUE INDEX notification_requests_dedupe_key_idx
    ON notification_requests (dedupe_key)
    WHERE dedupe_key IS NOT NULL;

CREATE TABLE notification_deliveries (
    notification_delivery_id UUID PRIMARY KEY,
    notification_request_id UUID NOT NULL REFERENCES notification_requests (notification_request_id) ON DELETE CASCADE,
    channel TEXT NOT NULL,
    destination JSONB NOT NULL,
    provider_binding_key TEXT NULL,
    provider_message_id TEXT NULL,
    attempt_count INTEGER NOT NULL,
    status TEXT NOT NULL,
    last_failure JSONB NULL,
    created_at TIMESTAMPTZ NOT NULL,
    reserved_at TIMESTAMPTZ NULL,
    sent_at TIMESTAMPTZ NULL,
    delivered_at TIMESTAMPTZ NULL,
    failed_at TIMESTAMPTZ NULL,
    next_retry_at TIMESTAMPTZ NULL
);

CREATE INDEX notification_deliveries_request_idx
    ON notification_deliveries (notification_request_id, notification_delivery_id);

CREATE INDEX notification_deliveries_status_retry_idx
    ON notification_deliveries (status, next_retry_at, created_at, notification_delivery_id);

CREATE INDEX notification_deliveries_provider_binding_idx
    ON notification_deliveries (provider_binding_key)
    WHERE provider_binding_key IS NOT NULL;

CREATE TABLE notification_event_logs (
    notification_event_log_id UUID PRIMARY KEY,
    notification_request_id UUID NOT NULL REFERENCES notification_requests (notification_request_id) ON DELETE CASCADE,
    notification_delivery_id UUID NULL REFERENCES notification_deliveries (notification_delivery_id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    actor JSONB NOT NULL,
    summary TEXT NULL,
    metadata JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX notification_event_logs_request_idx
    ON notification_event_logs (notification_request_id, notification_event_log_id);

CREATE INDEX notification_event_logs_delivery_idx
    ON notification_event_logs (notification_delivery_id, notification_event_log_id)
    WHERE notification_delivery_id IS NOT NULL;
