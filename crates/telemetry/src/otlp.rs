//! Optional OTLP trace export. Sirf tab chalta hai jab `OTEL_EXPORTER_OTLP_ENDPOINT` set ho.
//!
//! Request threads kabhi block nahi hote: `BoundedSpanProcessor::on_end` sirf `try_send` karta hai ek bounded
//! channel mein; channel full ho to span drop + counter (`telemetry_dropped_total{kind="span"}`). Export ek alag
//! thread par hota hai, export timeout ke saath. Span attributes queue mein jaane se pehle redact hote hain.

use std::future::Future;
use std::pin::Pin;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TryRecvError, sync_channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, JoinHandle, Thread};
use std::time::{Duration, Instant};

use opentelemetry::{KeyValue, Value};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::{OTelSdkError, OTelSdkResult};
use opentelemetry_sdk::trace::{
    Sampler, SdkTracerProvider, Span, SpanData, SpanExporter, SpanLimits, SpanProcessor,
};

use crate::meters::{DropKind, record_dropped};
use crate::redact::{REDACTED, is_sensitive_key, mask_text};

/// OTLP tuning. Defaults 512 MB budget (telemetry buffers <= 5 MB) ke hisaab se.
#[derive(Clone, Debug)]
pub struct OtlpOptions {
    /// Bounded queue: isse zyada pending spans drop hote hain.
    pub max_queue_size: usize,
    /// Ek export mein max spans.
    pub max_export_batch_size: usize,
    /// Batch flush interval.
    pub scheduled_delay: Duration,
    /// HTTP export timeout (exporter thread block hota hai, request threads nahi).
    pub export_timeout: Duration,
    /// Head-sampling ratio (1.0 = sab, 0.1 = 10%).
    pub sample_ratio: f64,
}

impl Default for OtlpOptions {
    fn default() -> Self {
        Self {
            max_queue_size: 1024,
            max_export_batch_size: 128,
            scheduled_delay: Duration::from_secs(5),
            export_timeout: Duration::from_secs(3),
            sample_ratio: 1.0,
        }
    }
}

enum Msg {
    Span(Box<SpanData>),
    Flush(SyncSender<()>),
}

/// Redact span data in place (attributes, event attributes, status text).
pub fn redact_span(span: &mut SpanData) {
    fn fix(kv: &mut KeyValue) {
        if is_sensitive_key(kv.key.as_str()) {
            kv.value = Value::from(REDACTED);
        } else if let Value::String(s) = &kv.value {
            let mut out = String::with_capacity(s.as_str().len());
            mask_text(s.as_str(), &mut out);
            kv.value = Value::from(out);
        }
    }
    span.attributes.iter_mut().for_each(fix);
    for ev in &mut span.events.events {
        ev.attributes.iter_mut().for_each(fix);
        let mut out = String::new();
        mask_text(&ev.name, &mut out);
        ev.name = out.into();
    }
    if let opentelemetry::trace::Status::Error { description } = &mut span.status {
        let mut out = String::new();
        mask_text(description, &mut out);
        *description = out.into();
    }
}

/// Bounded, non-blocking span processor with its own export thread.
#[derive(Debug)]
pub struct BoundedSpanProcessor {
    tx: Mutex<Option<SyncSender<Msg>>>,
    worker: Mutex<Option<JoinHandle<()>>>,
    export_timeout: Duration,
}

struct ThreadWaker(Thread);

impl Wake for ThreadWaker {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}

/// Minimal block_on (export thread par; exporter ka apna timeout hai, hum bhi deadline lagate hain).
fn block_on<F: Future>(fut: F, deadline: Duration) -> Option<F::Output> {
    let mut fut = Box::pin(fut);
    let waker = Waker::from(Arc::new(ThreadWaker(thread::current())));
    let mut cx = Context::from_waker(&waker);
    let end = Instant::now() + deadline;
    loop {
        if let Poll::Ready(v) = Pin::as_mut(&mut fut).poll(&mut cx) {
            return Some(v);
        }
        let now = Instant::now();
        if now >= end {
            return None;
        }
        thread::park_timeout(end - now);
    }
}

impl BoundedSpanProcessor {
    /// Worker thread start karta hai. Thread spawn fail ho to `None` (telemetry optional hai, app chalna chahiye).
    pub fn new<E: SpanExporter + 'static>(exporter: E, opts: &OtlpOptions) -> Option<Self> {
        let (tx, rx) = sync_channel::<Msg>(opts.max_queue_size.max(1));
        let batch = opts.max_export_batch_size.max(1);
        let delay = opts.scheduled_delay;
        let timeout = opts.export_timeout;
        let worker = thread::Builder::new()
            .name("otlp-export".to_owned())
            .spawn(move || worker_loop(&exporter, &rx, batch, delay, timeout))
            .ok()?;
        Some(Self {
            tx: Mutex::new(Some(tx)),
            worker: Mutex::new(Some(worker)),
            export_timeout: opts.export_timeout,
        })
    }

    fn sender(&self) -> Option<SyncSender<Msg>> {
        self.tx
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

fn export_batch<E: SpanExporter>(exporter: &E, buf: &mut Vec<SpanData>, timeout: Duration) {
    if buf.is_empty() {
        return;
    }
    let batch = std::mem::take(buf);
    // Export fail/timeout: batch drop (retry queue nahi, memory bounded) + count.
    let n = batch.len() as u64;
    match block_on(exporter.export(batch), timeout + Duration::from_secs(1)) {
        Some(Ok(())) => {}
        Some(Err(_)) | None => record_dropped(DropKind::Span, n),
    }
}

fn worker_loop<E: SpanExporter>(
    exporter: &E,
    rx: &Receiver<Msg>,
    batch_size: usize,
    delay: Duration,
    timeout: Duration,
) {
    let mut buf: Vec<SpanData> = Vec::with_capacity(batch_size);
    let mut next_flush = Instant::now() + delay;
    loop {
        let wait = next_flush.saturating_duration_since(Instant::now());
        match rx.recv_timeout(wait) {
            Ok(Msg::Span(s)) => {
                buf.push(*s);
                if buf.len() >= batch_size {
                    export_batch(exporter, &mut buf, timeout);
                    next_flush = Instant::now() + delay;
                }
            }
            Ok(Msg::Flush(ack)) => {
                // queue mein jo pehle se hai woh bhi nikaal do
                loop {
                    match rx.try_recv() {
                        Ok(Msg::Span(s)) => {
                            buf.push(*s);
                            if buf.len() >= batch_size {
                                export_batch(exporter, &mut buf, timeout);
                            }
                        }
                        Ok(Msg::Flush(a)) => {
                            let _ = a.try_send(());
                        }
                        Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
                    }
                }
                export_batch(exporter, &mut buf, timeout);
                let _ = ack.try_send(());
            }
            Err(RecvTimeoutError::Timeout) => {
                export_batch(exporter, &mut buf, timeout);
                next_flush = Instant::now() + delay;
            }
            Err(RecvTimeoutError::Disconnected) => {
                export_batch(exporter, &mut buf, timeout);
                let _ = exporter.shutdown();
                return;
            }
        }
    }
}

impl SpanProcessor for BoundedSpanProcessor {
    fn on_start(&self, _span: &mut Span, _cx: &opentelemetry::Context) {}

    fn on_end(&self, mut span: SpanData) {
        redact_span(&mut span);
        let Some(tx) = self.sender() else {
            return;
        };
        // try_send: kabhi block nahi; full = drop + count
        if tx.try_send(Msg::Span(Box::new(span))).is_err() {
            record_dropped(DropKind::Span, 1);
        }
    }

    fn force_flush(&self) -> OTelSdkResult {
        let Some(tx) = self.sender() else {
            return Ok(());
        };
        let (ack_tx, ack_rx) = sync_channel::<()>(1);
        if tx.try_send(Msg::Flush(ack_tx)).is_err() {
            return Err(OTelSdkError::InternalFailure("otlp queue full".to_owned()));
        }
        ack_rx
            .recv_timeout(self.export_timeout + Duration::from_secs(2))
            .map_err(|_| OTelSdkError::Timeout(self.export_timeout))
    }

    fn shutdown_with_timeout(&self, _timeout: Duration) -> OTelSdkResult {
        // sender drop => worker queue drain karke exit
        self.tx
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(h) = self
            .worker
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            let _ = h.join();
        }
        Ok(())
    }

    fn shutdown(&self) -> OTelSdkResult {
        self.shutdown_with_timeout(self.export_timeout)
    }

    fn set_resource(&mut self, _resource: &Resource) {}
}

/// Endpoint ko OTLP/HTTP traces path par laao (agar `/v1/traces` nahi hai to jodo).
pub fn traces_url(endpoint: &str) -> String {
    let base = endpoint.trim_end_matches('/');
    if base.ends_with("/v1/traces") {
        base.to_owned()
    } else {
        format!("{base}/v1/traces")
    }
}

/// OTLP exporter + provider banao. `None` agar exporter/worker build na ho (telemetry optional).
pub fn build_provider(
    endpoint: &str,
    service_name: &str,
    opts: &OtlpOptions,
) -> Option<SdkTracerProvider> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(traces_url(endpoint))
        .with_timeout(opts.export_timeout)
        .build()
        .ok()?;
    let processor = BoundedSpanProcessor::new(exporter, opts)?;
    let limits = SpanLimits {
        max_events_per_span: 16,
        max_attributes_per_span: 32,
        max_links_per_span: 4,
        max_attributes_per_event: 16,
        max_attributes_per_link: 8,
    };
    let sampler = Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
        opts.sample_ratio.clamp(0.0, 1.0),
    )));
    Some(
        SdkTracerProvider::builder()
            .with_span_processor(processor)
            .with_span_limits(limits)
            .with_sampler(sampler)
            .with_resource(
                Resource::builder()
                    .with_service_name(service_name.to_owned())
                    .build(),
            )
            .build(),
    )
}
