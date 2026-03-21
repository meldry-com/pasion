use std::sync::OnceLock;

use http::header::HeaderName;

static PROPAGATOR_HEADERS: OnceLock<Vec<HeaderName>> = OnceLock::new();

/// Notify the CORS layer what opentelemetry propagators are being used. This
/// helps whitelisting headers in CORS requests.
///
/// # Panics
///
/// When called twice
pub fn set_propagator(propagator: &dyn opentelemetry::propagation::TextMapPropagator) {
    let headers = propagator
        .fields()
        .map(|h| HeaderName::try_from(h).unwrap())
        .collect();

    tracing::debug!(
        ?headers,
        "Headers allowed in CORS requests for trace propagators set"
    );
    PROPAGATOR_HEADERS
        .set(headers)
        .expect(concat!(module_path!(), "::set_propagator was called twice"));
}

/// Returns the list of propagator header names that should be allowed in CORS
/// requests, if any were set via [`set_propagator`].
pub fn propagator_headers() -> Option<&'static [HeaderName]> {
    PROPAGATOR_HEADERS.get().map(Vec::as_slice)
}
