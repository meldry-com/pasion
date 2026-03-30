//! Flow execution engine.
//!
//! Provides a framework for executing multi-step user interaction flows
//! (registration, recovery, authentication, etc.) as composable stage
//! sequences, inspired by authentik's flow architecture.

pub mod defaults;
mod executor;
pub mod stages;

pub use self::defaults::{
    default_authentication_flow, default_password_change_flow, default_recovery_flow,
    default_registration_flow,
};
pub use self::executor::{FlowExecutor, FlowPlan, FlowPlannerError};
