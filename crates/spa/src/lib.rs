#![deny(rustdoc::missing_crate_level_docs)]

//! A crate to help serve single-page apps built by Vite.

mod vite;

pub use self::vite::{FileType, Manifest as ViteManifest};
