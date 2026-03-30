CREATE TABLE workflow_instances (
    workflow_instance_id UUID PRIMARY KEY,
    workflow_key TEXT NOT NULL,
    subject JSONB NOT NULL,
    trigger JSONB NOT NULL,
    status TEXT NOT NULL,
    current_step_key TEXT NULL,
    input JSONB NOT NULL,
    context JSONB NOT NULL DEFAULT '{}',
    correlation_key TEXT NULL,
    started_at TIMESTAMPTZ NULL,
    completed_at TIMESTAMPTZ NULL,
    failed_at TIMESTAMPTZ NULL,
    cancelled_at TIMESTAMPTZ NULL,
    expires_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX workflow_instances_key_status_idx
    ON workflow_instances (workflow_key, status);

CREATE INDEX workflow_instances_correlation_key_idx
    ON workflow_instances (correlation_key)
    WHERE correlation_key IS NOT NULL;

CREATE INDEX workflow_instances_status_expires_idx
    ON workflow_instances (status, expires_at)
    WHERE expires_at IS NOT NULL;

CREATE TABLE workflow_steps (
    workflow_step_id UUID PRIMARY KEY,
    workflow_instance_id UUID NOT NULL REFERENCES workflow_instances (workflow_instance_id) ON DELETE CASCADE,
    step_key TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    status TEXT NOT NULL,
    assignee JSONB NULL,
    input JSONB NOT NULL,
    output JSONB NULL,
    attempt_count INTEGER NOT NULL,
    last_error_code TEXT NULL,
    last_error_message TEXT NULL,
    scheduled_at TIMESTAMPTZ NULL,
    started_at TIMESTAMPTZ NULL,
    completed_at TIMESTAMPTZ NULL,
    failed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX workflow_steps_instance_sequence_idx
    ON workflow_steps (workflow_instance_id, sequence);

CREATE TABLE workflow_events (
    workflow_event_id UUID PRIMARY KEY,
    workflow_instance_id UUID NOT NULL REFERENCES workflow_instances (workflow_instance_id) ON DELETE CASCADE,
    workflow_step_id UUID NULL REFERENCES workflow_steps (workflow_step_id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    actor JSONB NOT NULL,
    payload JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX workflow_events_instance_idx
    ON workflow_events (workflow_instance_id, workflow_event_id);

CREATE TABLE workflow_deadlines (
    workflow_deadline_id UUID PRIMARY KEY,
    workflow_instance_id UUID NOT NULL REFERENCES workflow_instances (workflow_instance_id) ON DELETE CASCADE,
    workflow_step_id UUID NULL REFERENCES workflow_steps (workflow_step_id) ON DELETE CASCADE,
    deadline_key TEXT NOT NULL,
    status TEXT NOT NULL,
    payload JSONB NOT NULL,
    due_at TIMESTAMPTZ NOT NULL,
    satisfied_at TIMESTAMPTZ NULL,
    cancelled_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX workflow_deadlines_status_due_idx
    ON workflow_deadlines (status, due_at);

CREATE TABLE workflow_audit_logs (
    workflow_audit_log_id UUID PRIMARY KEY,
    workflow_instance_id UUID NOT NULL REFERENCES workflow_instances (workflow_instance_id) ON DELETE CASCADE,
    workflow_step_id UUID NULL REFERENCES workflow_steps (workflow_step_id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    actor JSONB NOT NULL,
    summary TEXT NULL,
    metadata JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX workflow_audit_logs_instance_idx
    ON workflow_audit_logs (workflow_instance_id, workflow_audit_log_id);
