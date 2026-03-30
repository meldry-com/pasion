CREATE TABLE admin_operation_logs (
    admin_operation_log_id UUID PRIMARY KEY,
    admin_user_id UUID NOT NULL,
    operation TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id UUID NULL,
    details JSONB NOT NULL DEFAULT '{}',
    ip_address INET NULL,
    user_agent TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX admin_operation_logs_user_created_idx
    ON admin_operation_logs (admin_user_id, created_at);

CREATE INDEX admin_operation_logs_resource_idx
    ON admin_operation_logs (resource_type, resource_id)
    WHERE resource_id IS NOT NULL;

CREATE INDEX admin_operation_logs_created_idx
    ON admin_operation_logs (created_at);

CREATE TABLE account_security_events (
    account_security_event_id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    event_type TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    ip_address INET NULL,
    user_agent TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX account_security_events_user_created_idx
    ON account_security_events (user_id, created_at);

CREATE INDEX account_security_events_type_created_idx
    ON account_security_events (event_type, created_at);
