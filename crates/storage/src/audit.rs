use async_trait::async_trait;
use pasion_data_model::{
    Clock,
    audit::{AccountSecurityEvent, AdminOperation, AdminOperationLog, SecurityEventType},
};
use rand_core::RngCore;
use serde_json::Value;
use ulid::Ulid;

use crate::repository_impl;

/// Parameters used when creating a new admin operation log entry.
#[derive(Debug, Clone)]
pub struct NewAdminOperationLog {
    admin_user_id: Ulid,
    operation: AdminOperation,
    resource_type: String,
    resource_id: Option<Ulid>,
    details: Value,
    ip_address: Option<std::net::IpAddr>,
    user_agent: Option<String>,
}

impl NewAdminOperationLog {
    /// Create a new admin operation log draft.
    #[must_use]
    pub fn new(
        admin_user_id: Ulid,
        operation: AdminOperation,
        resource_type: impl Into<String>,
        details: Value,
    ) -> Self {
        Self {
            admin_user_id,
            operation,
            resource_type: resource_type.into(),
            resource_id: None,
            details,
            ip_address: None,
            user_agent: None,
        }
    }

    /// Set the target resource ID.
    #[must_use]
    pub fn with_resource_id(mut self, resource_id: Ulid) -> Self {
        self.resource_id = Some(resource_id);
        self
    }

    /// Set the client IP address.
    #[must_use]
    pub fn with_ip_address(mut self, ip_address: std::net::IpAddr) -> Self {
        self.ip_address = Some(ip_address);
        self
    }

    /// Set the client user-agent string.
    #[must_use]
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// The admin user who performed the operation.
    #[must_use]
    pub fn admin_user_id(&self) -> Ulid {
        self.admin_user_id
    }

    /// The type of operation performed.
    #[must_use]
    pub fn operation(&self) -> &AdminOperation {
        &self.operation
    }

    /// The target resource type.
    #[must_use]
    pub fn resource_type(&self) -> &str {
        &self.resource_type
    }

    /// The target resource ID, if any.
    #[must_use]
    pub fn resource_id(&self) -> Option<Ulid> {
        self.resource_id
    }

    /// Structured details about the operation.
    #[must_use]
    pub fn details(&self) -> &Value {
        &self.details
    }

    /// The client IP address, if any.
    #[must_use]
    pub fn ip_address(&self) -> Option<std::net::IpAddr> {
        self.ip_address
    }

    /// The client user-agent string, if any.
    #[must_use]
    pub fn user_agent(&self) -> Option<&str> {
        self.user_agent.as_deref()
    }
}

/// Parameters used when creating a new account security event.
#[derive(Debug, Clone)]
pub struct NewAccountSecurityEvent {
    user_id: Ulid,
    event_type: SecurityEventType,
    metadata: Value,
    ip_address: Option<std::net::IpAddr>,
    user_agent: Option<String>,
}

impl NewAccountSecurityEvent {
    /// Create a new account security event draft.
    #[must_use]
    pub fn new(user_id: Ulid, event_type: SecurityEventType, metadata: Value) -> Self {
        Self {
            user_id,
            event_type,
            metadata,
            ip_address: None,
            user_agent: None,
        }
    }

    /// Set the client IP address.
    #[must_use]
    pub fn with_ip_address(mut self, ip_address: std::net::IpAddr) -> Self {
        self.ip_address = Some(ip_address);
        self
    }

    /// Set the client user-agent string.
    #[must_use]
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// The user account this event relates to.
    #[must_use]
    pub fn user_id(&self) -> Ulid {
        self.user_id
    }

    /// The type of security event.
    #[must_use]
    pub fn event_type(&self) -> &SecurityEventType {
        &self.event_type
    }

    /// Structured event metadata.
    #[must_use]
    pub fn metadata(&self) -> &Value {
        &self.metadata
    }

    /// The client IP address, if any.
    #[must_use]
    pub fn ip_address(&self) -> Option<std::net::IpAddr> {
        self.ip_address
    }

    /// The client user-agent string, if any.
    #[must_use]
    pub fn user_agent(&self) -> Option<&str> {
        self.user_agent.as_deref()
    }
}

/// Repository for admin operation logs and account security events.
#[async_trait]
pub trait AuditRepository: Send + Sync {
    /// The error type returned by the repository.
    type Error;

    /// Record a new admin operation log entry.
    async fn add_admin_operation(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewAdminOperationLog,
    ) -> Result<AdminOperationLog, Self::Error>;

    /// List admin operation log entries, optionally filtered by admin user.
    async fn list_admin_operations(
        &mut self,
        filter_admin_user_id: Option<Ulid>,
    ) -> Result<Vec<AdminOperationLog>, Self::Error>;

    /// Record a new account security event.
    async fn add_security_event(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewAccountSecurityEvent,
    ) -> Result<AccountSecurityEvent, Self::Error>;

    /// List security events for a specific user.
    async fn list_security_events(
        &mut self,
        user_id: Ulid,
    ) -> Result<Vec<AccountSecurityEvent>, Self::Error>;
}

repository_impl!(AuditRepository:
    async fn add_admin_operation(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewAdminOperationLog,
    ) -> Result<AdminOperationLog, Self::Error>;
    async fn list_admin_operations(
        &mut self,
        filter_admin_user_id: Option<Ulid>,
    ) -> Result<Vec<AdminOperationLog>, Self::Error>;
    async fn add_security_event(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewAccountSecurityEvent,
    ) -> Result<AccountSecurityEvent, Self::Error>;
    async fn list_security_events(
        &mut self,
        user_id: Ulid,
    ) -> Result<Vec<AccountSecurityEvent>, Self::Error>;
);
