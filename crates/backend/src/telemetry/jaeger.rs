// Adapted from the `opentelemetry-jaeger-propagator` crate (0.32.0), which was
// removed upstream in opentelemetry-rust 0.33.
// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//! Propagator for the [Jaeger propagation format].
//!
//! [Jaeger propagation format]: https://www.jaegertracing.io/docs/1.18/client-libraries/#propagation-format

use std::{borrow::Cow, sync::LazyLock};

use opentelemetry::{
    Context,
    propagation::{Extractor, Injector, TextMapPropagator, text_map_propagator::FieldIter},
    trace::{SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState},
};

const HEADER_NAME: &str = "uber-trace-id";
const BAGGAGE_PREFIX: &str = "uberctx-";
const DEPRECATED_PARENT_SPAN: &str = "0";
const TRACE_FLAG_DEBUG: TraceFlags = TraceFlags::new(0x04);

/// Reads and writes span contexts in the `uber-trace-id` header.
#[derive(Clone, Copy, Debug, Default)]
pub struct Propagator;

impl Propagator {
    fn extract_span_context(extractor: &dyn Extractor) -> Option<SpanContext> {
        let mut header_value = Cow::from(extractor.get(HEADER_NAME)?);
        // Without a `:` the value may be URL-encoded
        if !header_value.contains(':') {
            header_value = Cow::from(header_value.replace("%3A", ":"));
        }

        let parts: Vec<&str> = header_value.split_terminator(':').collect();
        let context = match parts.as_slice() {
            // The parent span ID is deprecated and ignored
            [trace_id, span_id, _parent, flags] => (|| {
                Some(SpanContext::new(
                    extract_trace_id(trace_id)?,
                    extract_span_id(span_id)?,
                    extract_trace_flags(flags)?,
                    true,
                    extract_trace_state(extractor)?,
                ))
            })(),
            _ => None,
        };

        if context.is_none() {
            tracing::debug!(header_value = %header_value, "Invalid Jaeger trace header");
        }
        context
    }
}

fn extract_trace_id(trace_id: &str) -> Option<TraceId> {
    if trace_id.len() > 32 {
        return None;
    }
    TraceId::from_hex(trace_id).ok()
}

fn extract_span_id(span_id: &str) -> Option<SpanId> {
    // Shorter IDs are left-padded with zeroes
    if span_id.len() > 16 {
        return None;
    }
    SpanId::from_hex(&format!("{span_id:0>16}")).ok()
}

/// Bit 1 is "sampled", bit 2 is "debug" (only meaningful when sampled).
/// Other bits are not supported.
fn extract_trace_flags(flags: &str) -> Option<TraceFlags> {
    if flags.len() > 2 {
        return None;
    }
    let flags: u8 = flags.parse().ok()?;
    Some(match (flags & 0x01 != 0, flags & 0x02 != 0) {
        (true, true) => TraceFlags::SAMPLED | TRACE_FLAG_DEBUG,
        (true, false) => TraceFlags::SAMPLED,
        (false, _) => TraceFlags::default(),
    })
}

fn extract_trace_state(extractor: &dyn Extractor) -> Option<TraceState> {
    let baggage = extractor
        .keys()
        .into_iter()
        .filter(|key| key.starts_with(BAGGAGE_PREFIX))
        .filter_map(|key| extractor.get(key).map(|v| (key.to_owned(), v.to_owned())));
    TraceState::from_key_value(baggage)
        .inspect_err(|error| tracing::debug!(?error, "Invalid Jaeger baggage"))
        .ok()
}

impl TextMapPropagator for Propagator {
    fn inject_context(&self, cx: &Context, injector: &mut dyn Injector) {
        let span = cx.span();
        let span_context = span.span_context();
        if !span_context.is_valid() {
            return;
        }

        let flags: u8 = match (
            span_context.is_sampled(),
            span_context.trace_flags() & TRACE_FLAG_DEBUG == TRACE_FLAG_DEBUG,
        ) {
            (true, true) => 0x03,
            (true, false) => 0x01,
            (false, _) => 0x00,
        };
        injector.set(
            HEADER_NAME,
            format!(
                "{}:{}:{DEPRECATED_PARENT_SPAN}:{flags:x}",
                span_context.trace_id(),
                span_context.span_id(),
            ),
        );
    }

    fn extract_with_context(&self, cx: &Context, extractor: &dyn Extractor) -> Context {
        Self::extract_span_context(extractor)
            .map(|sc| cx.with_remote_span_context(sc))
            .unwrap_or_else(|| cx.clone())
    }

    fn fields(&self) -> FieldIter<'_> {
        static FIELDS: LazyLock<[String; 1]> = LazyLock::new(|| [HEADER_NAME.to_owned()]);
        FieldIter::new(FIELDS.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    const TRACE_ID: u128 = 0x0000_0000_0000_004d_0000_0000_0000_0016;
    const SPAN_ID: u64 = 0x0000_0000_0001_7c29;

    fn extract(headers: &[(&str, &str)]) -> SpanContext {
        let headers: HashMap<String, String> = headers
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        Propagator.extract(&headers).span().span_context().clone()
    }

    fn span_context(flags: TraceFlags) -> SpanContext {
        SpanContext::new(
            TraceId::from(TRACE_ID),
            SpanId::from(SPAN_ID),
            flags,
            true,
            TraceState::default(),
        )
    }

    #[test]
    fn extracts_valid_headers() {
        for (header, flags) in [
            (
                "000000000000004d0000000000000016:0000000000017c29:0:1",
                TraceFlags::SAMPLED,
            ),
            ("4d0000000000000016:17c29:0:1", TraceFlags::SAMPLED),
            (
                "000000000000004d0000000000000016:0000000000017c29:0:3",
                TraceFlags::SAMPLED | TRACE_FLAG_DEBUG,
            ),
            (
                "000000000000004d0000000000000016:0000000000017c29:0:0",
                TraceFlags::default(),
            ),
            (
                "000000000000004d0000000000000016%3A0000000000017c29%3A0%3A1",
                TraceFlags::SAMPLED,
            ),
        ] {
            assert_eq!(
                extract(&[(HEADER_NAME, header)]),
                span_context(flags),
                "{header}"
            );
        }
    }

    #[test]
    fn rejects_invalid_headers() {
        for header in [
            "",
            "invalidtractid:0000000000017c29:0:0",
            "000000000000004d0000000000000016:invalidspanID:0:0",
            "000000000000004d0000000000000016:0000000000017c29:0:120",
            "000000000000004d0000000000000016:0000000000017c29:0",
        ] {
            assert!(!extract(&[(HEADER_NAME, header)]).is_valid(), "{header}");
        }
        assert!(!extract(&[]).is_valid());
    }

    #[test]
    fn extracts_baggage_into_trace_state() {
        let sc = extract(&[
            (HEADER_NAME, "4d0000000000000016:17c29:0:1"),
            ("uberctx-key", "value"),
        ]);
        assert_eq!(sc.trace_state().get("uberctx-key"), Some("value"));
    }

    #[test]
    fn injects_header() {
        for (flags, expected) in [
            (TraceFlags::SAMPLED, "1"),
            (TraceFlags::default(), "0"),
            (TraceFlags::SAMPLED | TRACE_FLAG_DEBUG, "3"),
            (TRACE_FLAG_DEBUG, "0"),
        ] {
            let cx = Context::new().with_remote_span_context(span_context(flags));
            let mut headers = HashMap::new();
            Propagator.inject_context(&cx, &mut headers);
            assert_eq!(
                headers.get(HEADER_NAME).map(String::as_str),
                Some(
                    format!("000000000000004d0000000000000016:0000000000017c29:0:{expected}")
                        .as_str()
                ),
            );
        }

        let mut headers = HashMap::new();
        Propagator.inject_context(&Context::new(), &mut headers);
        assert!(headers.is_empty());
    }
}
