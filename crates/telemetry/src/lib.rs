//! telemetry (P0-15): JSON logs with redaction, optional bounded OTLP traces, metrics facade + Prometheus text.
//!
//! Entry point: [`init`]. Metrics ka text [`meters::render`] se milta hai (api internal endpoint par serve karega).

pub mod layer;
pub mod meters;
#[cfg(feature = "otlp")]
pub mod otlp;
pub mod redact;
pub mod request;

use std::io;

use config::{LogFormat, TelemetryConfig};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, Registry};

pub use layer::{LogStyle, RedactingLayer};
pub use meters::{DropKind, JobOutcome, RateLimitOutcome};
pub use request::{log_request_completed, request_span};

/// Default service name jab `OTEL_SERVICE_NAME` set na ho.
pub const DEFAULT_SERVICE_NAME: &str = "dsecure-api";

/// Drop par exporter flush/shutdown hota hai. Process ke end tak zinda rakho (`main` mein `let _guard = ...`).
pub struct TelemetryGuard {
    #[cfg(feature = "otlp")]
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
    otlp_active: bool,
}

impl TelemetryGuard {
    /// OTLP exporter chal raha hai?
    pub fn otlp_active(&self) -> bool {
        self.otlp_active
    }

    /// Ab tak drop hue spans (is process mein).
    pub fn dropped_spans(&self) -> u64 {
        meters::dropped_total(DropKind::Span)
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        #[cfg(feature = "otlp")]
        if let Some(p) = self.provider.take() {
            let _ = p.shutdown();
        }
    }
}

/// `LOG_LEVEL` se filter; invalid directive par `info` (startup fail nahi hona chahiye).
pub fn env_filter(level: &str) -> EnvFilter {
    EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"))
}

fn style_of(cfg: &TelemetryConfig) -> LogStyle {
    match cfg.log_format {
        LogFormat::Json => LogStyle::Json,
        LogFormat::Pretty => LogStyle::Pretty,
    }
}

/// Logging + metrics + (optional) OTLP set up karo. Dobara call safe hai (global subscriber pehle se ho to ignore).
#[cfg(feature = "otlp")]
pub fn init(cfg: &TelemetryConfig) -> TelemetryGuard {
    init_with(cfg, &otlp::OtlpOptions::default())
}

/// Logging + metrics set up karo (feature `otlp` off: sirf stdout).
#[cfg(not(feature = "otlp"))]
pub fn init(cfg: &TelemetryConfig) -> TelemetryGuard {
    meters::install();
    let _ = Registry::default()
        .with(
            RedactingLayer::new(io::stdout, style_of(cfg)).with_filter(env_filter(&cfg.log_level)),
        )
        .try_init();
    TelemetryGuard { otlp_active: false }
}

/// Jaise [`init`], explicit OTLP tuning ke saath.
#[cfg(feature = "otlp")]
pub fn init_with(cfg: &TelemetryConfig, opts: &otlp::OtlpOptions) -> TelemetryGuard {
    use opentelemetry::trace::TracerProvider as _;

    meters::install();
    let provider = cfg
        .otlp_endpoint
        .as_ref()
        .filter(|e| !e.is_blank())
        .and_then(|ep| {
            otlp::build_provider(
                ep.as_str(),
                cfg.service_name.as_deref().unwrap_or(DEFAULT_SERVICE_NAME),
                opts,
            )
        });
    let otel_layer = provider.as_ref().map(|p| {
        tracing_opentelemetry::layer()
            .with_tracer(p.tracer(DEFAULT_SERVICE_NAME))
            .with_filter(env_filter(&cfg.log_level))
    });
    let _ = Registry::default()
        .with(otel_layer)
        .with(
            RedactingLayer::new(io::stdout, style_of(cfg)).with_filter(env_filter(&cfg.log_level)),
        )
        .try_init();
    TelemetryGuard {
        otlp_active: provider.is_some(),
        provider,
    }
}

#[cfg(test)]
mod tests;
