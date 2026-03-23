//! Internationalization (i18n) support for the Pasion authentication service.
//!
//! This crate provides:
//!
//! - [`Translator`] — loads `.ftl` (Fluent) translation files and resolves
//!   messages for a given locale
//! - [`Message`] / [`ArgumentList`] — sprintf-style message formatting used by
//!   templates
//! - Re-exports of ICU crates (`icu_calendar`, `icu_datetime`, `icu_locid`) for
//!   date/time formatting in the user's locale

/// Sprintf-style message formatting (used by email and page templates).
pub mod sprintf;
/// Compiled translation data and locale definitions.
pub mod translations;
mod translator;

pub use icu_calendar;
pub use icu_datetime;
pub use icu_locid::locale;
pub use icu_provider::{DataError, DataLocale};

pub use self::{
    sprintf::{Argument, ArgumentList, Message},
    translator::{LoadError, Translator},
};
