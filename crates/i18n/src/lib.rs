//! Internationalization (i18n) support for the Pasion authentication service.
//!
//! This crate provides:
//!
//! - [`Translator`] -- loads `.ftl` (Fluent) translation files and resolves
//!   messages for a given locale, with automatic fallback.
//! - Re-exports of ICU crates (`icu_calendar`, `icu_datetime`, `icu_locid`) for
//!   date/time formatting in the user's locale.

mod translator;

pub use icu_calendar;
pub use icu_datetime;
pub use icu_locid::locale;
pub use icu_provider::{DataError, DataLocale};

pub use self::translator::{LoadError, Translator};
