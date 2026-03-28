-- Initial consolidated schema for Pasion
-- This migration creates all tables from scratch for a fresh installation.
-- Existing databases migrated from sqlx should use the `diesel_initial_setup` migration instead.

-- Custom enum type for job queue status
DO $$ BEGIN
    CREATE TYPE queue_job_status AS ENUM ('available', 'running', 'completed', 'lost');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ── Users ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS users (
    user_id UUID PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    locked_at TIMESTAMPTZ,
    can_request_admin BOOLEAN NOT NULL DEFAULT FALSE,
    is_guest BOOLEAN NOT NULL DEFAULT FALSE,
    deactivated_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS user_passwords (
    user_password_id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(user_id),
    hashed_password TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    version INTEGER NOT NULL,
    upgraded_from_id UUID REFERENCES user_passwords(user_password_id)
);

CREATE TABLE IF NOT EXISTS user_emails (
    user_email_id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS user_sessions (
    user_session_id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(user_id),
    created_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    user_agent TEXT,
    last_active_at TIMESTAMPTZ,
    last_active_ip INET
);

CREATE TABLE IF NOT EXISTS user_registration_tokens (
    user_registration_token_id UUID PRIMARY KEY,
    token TEXT NOT NULL UNIQUE,
    usage_limit INTEGER,
    times_used INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

-- ── Upstream OAuth ──────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS upstream_oauth_providers (
    upstream_oauth_provider_id UUID PRIMARY KEY,
    issuer TEXT,
    scope TEXT NOT NULL,
    client_id TEXT NOT NULL,
    encrypted_client_secret TEXT,
    token_endpoint_signing_alg TEXT,
    token_endpoint_auth_method TEXT NOT NULL,
    jwks_uri_override TEXT,
    authorization_endpoint_override TEXT,
    token_endpoint_override TEXT,
    discovery_mode TEXT NOT NULL DEFAULT 'oidc',
    pkce_mode TEXT NOT NULL DEFAULT 'auto',
    human_name TEXT,
    brand_name TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    claims_imports JSONB,
    disabled_at TIMESTAMPTZ,
    additional_parameters JSONB,
    fetch_userinfo BOOLEAN NOT NULL DEFAULT FALSE,
    userinfo_endpoint_override TEXT,
    response_mode TEXT,
    extra_callback_parameters JSONB,
    ui_order INTEGER NOT NULL DEFAULT 0,
    id_token_signed_response_alg TEXT NOT NULL DEFAULT 'RS256',
    userinfo_signed_response_alg TEXT,
    on_backchannel_logout TEXT,
    forward_login_hint BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS upstream_oauth_links (
    upstream_oauth_link_id UUID PRIMARY KEY,
    upstream_oauth_provider_id UUID NOT NULL REFERENCES upstream_oauth_providers(upstream_oauth_provider_id),
    user_id UUID REFERENCES users(user_id),
    subject TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    human_account_name TEXT,
    unlinked_at TIMESTAMPTZ,
    UNIQUE (upstream_oauth_provider_id, subject)
);

CREATE TABLE IF NOT EXISTS upstream_oauth_authorization_sessions (
    upstream_oauth_authorization_session_id UUID PRIMARY KEY,
    upstream_oauth_provider_id UUID NOT NULL REFERENCES upstream_oauth_providers(upstream_oauth_provider_id),
    upstream_oauth_link_id UUID REFERENCES upstream_oauth_links(upstream_oauth_link_id),
    id_token TEXT,
    state TEXT NOT NULL UNIQUE,
    code_challenge_verifier TEXT,
    nonce TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    id_token_claims JSONB,
    user_session_id UUID REFERENCES user_sessions(user_session_id) ON DELETE SET NULL
);

-- ── Email / Phone authentication ────────────────────────────────

CREATE TABLE IF NOT EXISTS user_email_authentications (
    user_email_authentication_id UUID PRIMARY KEY,
    user_session_id UUID REFERENCES user_sessions(user_session_id) ON DELETE SET NULL,
    user_registration_id UUID, -- FK added after user_registrations created
    email TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS user_email_authentication_codes (
    user_email_authentication_code_id UUID PRIMARY KEY,
    user_email_authentication_id UUID NOT NULL REFERENCES user_email_authentications(user_email_authentication_id) ON DELETE CASCADE,
    code TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    UNIQUE (user_email_authentication_id, code)
);

CREATE TABLE IF NOT EXISTS user_phone_authentications (
    user_phone_authentication_id UUID PRIMARY KEY,
    user_registration_id UUID, -- FK added after user_registrations created
    phone TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS user_phone_authentication_codes (
    user_phone_authentication_code_id UUID PRIMARY KEY,
    user_phone_authentication_id UUID NOT NULL REFERENCES user_phone_authentications(user_phone_authentication_id) ON DELETE CASCADE,
    code TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

-- ── User registrations ──────────────────────────────────────────

CREATE TABLE IF NOT EXISTS user_registrations (
    user_registration_id UUID PRIMARY KEY,
    ip_address INET,
    user_agent TEXT,
    post_auth_action JSONB,
    username TEXT NOT NULL,
    display_name TEXT,
    terms_url TEXT,
    email_authentication_id UUID REFERENCES user_email_authentications(user_email_authentication_id) ON DELETE SET NULL,
    hashed_password TEXT,
    hashed_password_version INTEGER,
    user_registration_token_id UUID REFERENCES user_registration_tokens(user_registration_token_id) ON DELETE SET NULL,
    upstream_oauth_authorization_session_id UUID REFERENCES upstream_oauth_authorization_sessions(upstream_oauth_authorization_session_id) ON DELETE SET NULL,
    phone_authentication_id UUID REFERENCES user_phone_authentications(user_phone_authentication_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ
);

-- Add FK from email/phone auth to registrations
ALTER TABLE user_email_authentications
    ADD CONSTRAINT fk_email_auth_registration
    FOREIGN KEY (user_registration_id) REFERENCES user_registrations(user_registration_id) ON DELETE CASCADE;

ALTER TABLE user_phone_authentications
    ADD CONSTRAINT fk_phone_auth_registration
    FOREIGN KEY (user_registration_id) REFERENCES user_registrations(user_registration_id) ON DELETE CASCADE;

-- ── Session authentication ──────────────────────────────────────

CREATE TABLE IF NOT EXISTS user_session_authentications (
    user_session_authentication_id UUID PRIMARY KEY,
    user_session_id UUID NOT NULL REFERENCES user_sessions(user_session_id),
    user_password_id UUID REFERENCES user_passwords(user_password_id),
    upstream_oauth_authorization_session_id UUID REFERENCES upstream_oauth_authorization_sessions(upstream_oauth_authorization_session_id),
    created_at TIMESTAMPTZ NOT NULL,
    authentication_source TEXT
);

-- ── Recovery ────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS user_recovery_sessions (
    user_recovery_session_id UUID PRIMARY KEY,
    email TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    ip_address INET,
    locale TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS user_recovery_tickets (
    user_recovery_ticket_id UUID PRIMARY KEY,
    user_recovery_session_id UUID NOT NULL REFERENCES user_recovery_sessions(user_recovery_session_id) ON DELETE CASCADE,
    user_email_id UUID NOT NULL REFERENCES user_emails(user_email_id) ON DELETE CASCADE,
    ticket TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

-- ── Terms / Phones / Third-party IDs ────────────────────────────

CREATE TABLE IF NOT EXISTS user_terms (
    user_terms_id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    terms_url TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (user_id, terms_url)
);

CREATE TABLE IF NOT EXISTS user_phones (
    user_phone_id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    phone TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS user_unsupported_third_party_ids (
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    medium TEXT NOT NULL,
    address TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, medium, address)
);

-- ── OAuth2 ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS oauth2_clients (
    oauth2_client_id UUID PRIMARY KEY,
    encrypted_client_secret TEXT,
    grant_type_authorization_code BOOLEAN NOT NULL,
    grant_type_refresh_token BOOLEAN NOT NULL,
    grant_type_client_credentials BOOLEAN NOT NULL DEFAULT FALSE,
    grant_type_device_code BOOLEAN,
    client_name TEXT,
    logo_uri TEXT,
    client_uri TEXT,
    policy_uri TEXT,
    tos_uri TEXT,
    jwks_uri TEXT,
    jwks JSONB,
    id_token_signed_response_alg TEXT,
    token_endpoint_auth_method TEXT,
    token_endpoint_auth_signing_alg TEXT,
    initiate_login_uri TEXT,
    userinfo_signed_response_alg TEXT,
    redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    application_type TEXT,
    contacts TEXT[] NOT NULL DEFAULT '{}',
    is_static BOOLEAN,
    created_at TIMESTAMPTZ,
    metadata_digest TEXT UNIQUE
);

CREATE TABLE IF NOT EXISTS oauth2_sessions (
    oauth2_session_id UUID PRIMARY KEY,
    user_session_id UUID REFERENCES user_sessions(user_session_id) ON DELETE SET NULL,
    oauth2_client_id UUID NOT NULL REFERENCES oauth2_clients(oauth2_client_id),
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    scope_list TEXT[] NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    user_agent TEXT,
    last_active_at TIMESTAMPTZ,
    last_active_ip INET,
    human_name TEXT
);

CREATE TABLE IF NOT EXISTS oauth2_access_tokens (
    oauth2_access_token_id UUID PRIMARY KEY,
    oauth2_session_id UUID NOT NULL REFERENCES oauth2_sessions(oauth2_session_id),
    access_token TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    first_used_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS oauth2_refresh_tokens (
    oauth2_refresh_token_id UUID PRIMARY KEY,
    oauth2_session_id UUID NOT NULL REFERENCES oauth2_sessions(oauth2_session_id),
    oauth2_access_token_id UUID REFERENCES oauth2_access_tokens(oauth2_access_token_id) ON DELETE SET NULL,
    refresh_token TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    next_oauth2_refresh_token_id UUID REFERENCES oauth2_refresh_tokens(oauth2_refresh_token_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS oauth2_authorization_grants (
    oauth2_authorization_grant_id UUID PRIMARY KEY,
    oauth2_client_id UUID NOT NULL REFERENCES oauth2_clients(oauth2_client_id),
    oauth2_session_id UUID REFERENCES oauth2_sessions(oauth2_session_id),
    authorization_code TEXT UNIQUE,
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL,
    state TEXT,
    nonce TEXT,
    response_mode TEXT NOT NULL DEFAULT 'query',
    code_challenge_method TEXT,
    code_challenge TEXT,
    response_type_code BOOLEAN NOT NULL,
    response_type_id_token BOOLEAN NOT NULL,
    requires_consent BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL,
    fulfilled_at TIMESTAMPTZ,
    cancelled_at TIMESTAMPTZ,
    exchanged_at TIMESTAMPTZ,
    locale TEXT
);

CREATE TABLE IF NOT EXISTS oauth2_device_code_grant (
    oauth2_device_code_grant_id UUID PRIMARY KEY,
    oauth2_client_id UUID NOT NULL REFERENCES oauth2_clients(oauth2_client_id) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    user_code TEXT NOT NULL UNIQUE,
    device_code TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    fulfilled_at TIMESTAMPTZ,
    rejected_at TIMESTAMPTZ,
    exchanged_at TIMESTAMPTZ,
    oauth2_session_id UUID REFERENCES oauth2_sessions(oauth2_session_id) ON DELETE CASCADE,
    user_session_id UUID REFERENCES user_sessions(user_session_id),
    ip_address INET,
    user_agent TEXT
);

-- ── Queue system ────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS queue_workers (
    queue_worker_id UUID PRIMARY KEY,
    registered_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    shutdown_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS queue_schedules (
    schedule_name TEXT PRIMARY KEY,
    last_scheduled_at TIMESTAMPTZ,
    last_scheduled_job_id UUID
);

CREATE TABLE IF NOT EXISTS queue_jobs (
    queue_job_id UUID PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'available',
    created_at TIMESTAMPTZ NOT NULL,
    started_at TIMESTAMPTZ,
    started_by UUID REFERENCES queue_workers(queue_worker_id),
    completed_at TIMESTAMPTZ,
    queue_name TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}',
    metadata JSONB NOT NULL DEFAULT '{}',
    failed_at TIMESTAMPTZ,
    failed_reason TEXT,
    attempt INTEGER NOT NULL DEFAULT 0,
    next_attempt_id UUID REFERENCES queue_jobs(queue_job_id),
    scheduled_at TIMESTAMPTZ,
    schedule_name TEXT REFERENCES queue_schedules(schedule_name)
);

-- FK from schedules back to jobs
ALTER TABLE queue_schedules
    ADD CONSTRAINT fk_schedule_last_job
    FOREIGN KEY (last_scheduled_job_id) REFERENCES queue_jobs(queue_job_id);

CREATE UNLOGGED TABLE IF NOT EXISTS queue_leader (
    active BOOLEAN NOT NULL DEFAULT TRUE UNIQUE,
    elected_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    queue_worker_id UUID NOT NULL REFERENCES queue_workers(queue_worker_id)
);

-- ── Personal sessions ───────────────────────────────────────────

CREATE TABLE IF NOT EXISTS personal_sessions (
    personal_session_id UUID PRIMARY KEY,
    owner_user_id UUID REFERENCES users(user_id),
    owner_oauth2_client_id UUID REFERENCES oauth2_clients(oauth2_client_id),
    actor_user_id UUID NOT NULL REFERENCES users(user_id),
    human_name TEXT NOT NULL,
    scope_list TEXT[] NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    last_active_at TIMESTAMPTZ,
    last_active_ip INET
);

CREATE TABLE IF NOT EXISTS personal_access_tokens (
    personal_access_token_id UUID PRIMARY KEY,
    personal_session_id UUID NOT NULL REFERENCES personal_sessions(personal_session_id),
    access_token_sha256 BYTEA NOT NULL UNIQUE CHECK (length(access_token_sha256) = 32),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

-- ── Policy data ─────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS policy_data (
    policy_data_id UUID PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    data JSONB NOT NULL
);
