//! Utilities to do HTTP requests

#![deny(rustdoc::missing_crate_level_docs)]
#![allow(clippy::module_name_repetitions)]

use std::sync::LazyLock;

mod ext;
mod reqwest;

pub use self::{
    ext::{CorsLayerExt, set_propagator},
    reqwest::{RequestBuilderExt, client as reqwest_client},
};

static METER: LazyLock<opentelemetry::metrics::Meter> = LazyLock::new(|| {
    let scope = opentelemetry::InstrumentationScope::builder(env!("CARGO_PKG_NAME"))
        .with_version(env!("CARGO_PKG_VERSION"))
        .with_schema_url(opentelemetry_semantic_conventions::SCHEMA_URL)
        .build();

    opentelemetry::global::meter_with_scope(scope)
});
