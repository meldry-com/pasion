//! Write one OTLP JSON message per batch to the configured stdout debug output.

use std::{
    io::{self, Write},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use opentelemetry_proto::{
    tonic::collector::{
        metrics::v1::ExportMetricsServiceRequest, trace::v1::ExportTraceServiceRequest,
    },
    transform::{
        common::tonic::ResourceAttributesWithSchema,
        trace::tonic::group_spans_by_resource_and_scope,
    },
};
use opentelemetry_sdk::{
    Resource,
    error::{OTelSdkError, OTelSdkResult},
    metrics::{Temporality, data::ResourceMetrics, exporter::PushMetricExporter},
    trace::{SpanData, SpanExporter},
};

#[derive(Debug, Default)]
pub(super) struct Exporter {
    resource: ResourceAttributesWithSchema,
    closed: AtomicBool,
}

impl Exporter {
    fn write(&self, batch: &impl serde::Serialize) -> OTelSdkResult {
        if self.closed.load(Ordering::Acquire) {
            return Err(OTelSdkError::AlreadyShutdown);
        }
        let mut out = io::stdout().lock();
        serde_json::to_writer(&mut out, batch)
            .map_err(|e| OTelSdkError::InternalFailure(e.to_string()))?;
        out.write_all(b"\n")
            .and_then(|()| out.flush())
            .map_err(|e| OTelSdkError::InternalFailure(e.to_string()))
    }

    fn close(&self) -> OTelSdkResult {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Err(OTelSdkError::AlreadyShutdown);
        }
        Ok(())
    }
}

impl SpanExporter for Exporter {
    async fn export(&self, spans: Vec<SpanData>) -> OTelSdkResult {
        self.write(&ExportTraceServiceRequest {
            resource_spans: group_spans_by_resource_and_scope(spans, &self.resource),
        })
    }

    fn set_resource(&mut self, resource: &Resource) {
        self.resource = resource.into();
    }
    fn shutdown_with_timeout(&self, _timeout: Duration) -> OTelSdkResult {
        self.close()
    }
}

impl PushMetricExporter for Exporter {
    async fn export(&self, metrics: &ResourceMetrics) -> OTelSdkResult {
        self.write(&ExportMetricsServiceRequest::from(metrics))
    }

    fn temporality(&self) -> Temporality {
        Temporality::Cumulative
    }
    fn force_flush(&self) -> OTelSdkResult {
        Ok(())
    }
    fn shutdown_with_timeout(&self, _timeout: Duration) -> OTelSdkResult {
        self.close()
    }
}
