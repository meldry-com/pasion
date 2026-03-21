#![deny(clippy::future_not_send)]
#![allow(clippy::module_name_repetitions)]

pub mod client_authorization;
pub mod cookies;
pub mod csrf;
pub mod error_wrapper;
pub mod fancy_error;
pub mod jwt;
pub mod language_detection;
pub mod sentry;
pub mod session;
pub mod user_authorization;

pub use salvo;

pub use self::{
    error_wrapper::ErrorWrapper,
    fancy_error::{GenericError, InternalError},
    session::{SessionInfo, SessionInfoExt},
};
