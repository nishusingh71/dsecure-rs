//! Metrics facade (`metrics` crate) + Prometheus text renderer. Yahan koi port bind nahi hota:
//! api internal endpoint par `render()` ka output serve karega.
//!
//! Cardinality rule: labels sirf chhote fixed sets se aate hain (method whitelist, status class, route TEMPLATE
//! with ids collapsed and a hard cap, `&'static str` kinds). User/tenant/email/IP kabhi label nahi.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::Duration;

use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};

/// Metric names (stable; dashboards/alerts inhein use karenge).
pub mod names {
    pub const HTTP_REQUESTS: &str = "http_requests_total";
    pub const HTTP_DURATION: &str = "http_request_duration_seconds";
    pub const DB_POOL_CONNECTIONS: &str = "db_pool_connections";
    pub const DB_POOL_ACQUIRE: &str = "db_pool_acquire_seconds";
    pub const DB_POOL_ACQUIRE_TIMEOUTS: &str = "db_pool_acquire_timeouts_total";
    pub const LOGIN_HASH_QUEUE_DEPTH: &str = "login_hash_queue_depth";
    pub const LOGIN_HASH_DURATION: &str = "login_hash_duration_seconds";
    pub const LOGIN_HASH_REJECTED: &str = "login_hash_rejected_total";
    pub const RATE_LIMIT_DECISIONS: &str = "rate_limit_decisions_total";
    pub const JOB_QUEUE_DEPTH: &str = "job_queue_depth";
    pub const JOBS: &str = "jobs_total";
    pub const JOB_DURATION: &str = "job_duration_seconds";
    pub const TELEMETRY_DROPPED: &str = "telemetry_dropped_total";
    pub const PROCESS_RSS: &str = "process_resident_memory_bytes";
    pub const JEMALLOC_RESIDENT: &str = "jemalloc_resident_bytes";
    pub const JEMALLOC_ALLOCATED: &str = "jemalloc_allocated_bytes";
}

/// Route labels ki hard cap (usse zyada distinct templates "other" ban jate hain).
pub const MAX_ROUTE_LABELS: usize = 256;
const MAX_ROUTE_LEN: usize = 128;

const DURATION_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();
static ROUTES: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
static DROPPED_SPANS: AtomicU64 = AtomicU64::new(0);
static DROPPED_LOGS: AtomicU64 = AtomicU64::new(0);

/// Prometheus recorder install karo (idempotent). Pehle se koi aur global recorder ho to handle phir bhi milta hai
/// lekin render khali rahega.
pub fn install() -> &'static PrometheusHandle {
    HANDLE.get_or_init(|| {
        let builder = PrometheusBuilder::new()
            .set_buckets_for_metric(Matcher::Suffix("_seconds".to_owned()), DURATION_BUCKETS);
        let recorder = match builder {
            Ok(b) => b.build_recorder(),
            Err(_) => PrometheusBuilder::new().build_recorder(),
        };
        let handle = recorder.handle();
        // Err = recorder pehle se set hai (tests / double init): ignore.
        let _ = metrics::set_global_recorder(recorder);
        describe();
        handle
    })
}

fn describe() {
    describe_counter!(
        names::HTTP_REQUESTS,
        "HTTP requests by method, route template, status class"
    );
    describe_histogram!(
        names::HTTP_DURATION,
        metrics::Unit::Seconds,
        "HTTP request latency"
    );
    describe_gauge!(
        names::DB_POOL_CONNECTIONS,
        "DB pool connections by state (idle, in_use)"
    );
    describe_histogram!(
        names::DB_POOL_ACQUIRE,
        metrics::Unit::Seconds,
        "DB pool acquire wait"
    );
    describe_counter!(names::DB_POOL_ACQUIRE_TIMEOUTS, "DB pool acquire timeouts");
    describe_gauge!(
        names::LOGIN_HASH_QUEUE_DEPTH,
        "Password-hash jobs waiting or running"
    );
    describe_histogram!(
        names::LOGIN_HASH_DURATION,
        metrics::Unit::Seconds,
        "Password hash/verify duration"
    );
    describe_counter!(
        names::LOGIN_HASH_REJECTED,
        "Password-hash requests shed because the queue was full"
    );
    describe_counter!(
        names::RATE_LIMIT_DECISIONS,
        "Rate limit decisions by scope and outcome"
    );
    describe_gauge!(names::JOB_QUEUE_DEPTH, "Pending jobs by kind");
    describe_counter!(names::JOBS, "Finished jobs by kind and outcome");
    describe_histogram!(
        names::JOB_DURATION,
        metrics::Unit::Seconds,
        "Job run duration by kind"
    );
    describe_counter!(
        names::TELEMETRY_DROPPED,
        "Telemetry items dropped because a bounded queue was full"
    );
    describe_gauge!(
        names::PROCESS_RSS,
        metrics::Unit::Bytes,
        "Process resident set size"
    );
    describe_gauge!(
        names::JEMALLOC_RESIDENT,
        metrics::Unit::Bytes,
        "jemalloc stats.resident"
    );
    describe_gauge!(
        names::JEMALLOC_ALLOCATED,
        metrics::Unit::Bytes,
        "jemalloc stats.allocated"
    );
}

/// Prometheus text exposition. Process/jemalloc gauges refresh karke render karta hai.
pub fn render() -> String {
    let handle = install();
    update_process_gauges();
    handle.run_upkeep();
    handle.render()
}

// ---------------------------------------------------------------- labels

fn routes() -> &'static Mutex<HashSet<String>> {
    ROUTES.get_or_init(|| Mutex::new(HashSet::new()))
}

fn is_opaque_segment(seg: &str) -> bool {
    if seg.is_empty() || seg.starts_with(':') || seg.starts_with('{') {
        return false; // already a template placeholder
    }
    let all_digits = seg.bytes().all(|b| b.is_ascii_digit());
    let hexish = seg.len() >= 16 && seg.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-');
    all_digits || hexish || seg.len() > 32 || seg.contains('@')
}

/// Route ko template banata hai: query/fragment kata, numeric/uuid/opaque segments -> `:id`, length cap,
/// aur distinct templates ki cap (`MAX_ROUTE_LABELS`) ke baad `other`.
pub fn sanitize_route(route: &str) -> String {
    let mut set = routes().lock().unwrap_or_else(PoisonError::into_inner);
    sanitize_route_in(&mut set, route)
}

/// `sanitize_route` ka core, explicit set ke saath (tests mein local set).
pub fn sanitize_route_in(set: &mut HashSet<String>, route: &str) -> String {
    let path = route.split(['?', '#']).next().unwrap_or("");
    let mut out = String::with_capacity(path.len().min(MAX_ROUTE_LEN));
    for (i, seg) in path.split('/').enumerate() {
        if i > 0 {
            out.push('/');
        }
        if is_opaque_segment(seg) {
            out.push_str(":id");
        } else if seg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:{}".contains(&b))
        {
            out.push_str(seg);
        } else {
            out.push_str(":x");
        }
        if out.len() > MAX_ROUTE_LEN {
            out.truncate(MAX_ROUTE_LEN);
            break;
        }
    }
    if out.is_empty() {
        return "unmatched".to_owned();
    }
    if set.contains(&out) {
        return out;
    }
    if set.len() >= MAX_ROUTE_LABELS {
        return "other".to_owned();
    }
    set.insert(out.clone());
    out
}

/// Method whitelist; baaki sab `OTHER`.
pub fn method_label(method: &str) -> &'static str {
    match method.to_ascii_uppercase().as_str() {
        "GET" => "GET",
        "POST" => "POST",
        "PUT" => "PUT",
        "PATCH" => "PATCH",
        "DELETE" => "DELETE",
        "HEAD" => "HEAD",
        "OPTIONS" => "OPTIONS",
        _ => "OTHER",
    }
}

/// Status ko class label mein badalta hai (exact code label nahi banta).
pub fn status_class(status: u16) -> &'static str {
    match status {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    }
}

// ---------------------------------------------------------------- recorders

/// HTTP request RED metrics. `route` template hona chahiye; phir bhi sanitize hota hai.
pub fn record_request(method: &str, route: &str, status: u16, latency: Duration) {
    let method = method_label(method);
    let route = sanitize_route(route);
    counter!(names::HTTP_REQUESTS, "method" => method, "route" => route.clone(), "status_class" => status_class(status))
        .increment(1);
    histogram!(names::HTTP_DURATION, "method" => method, "route" => route)
        .record(latency.as_secs_f64());
}

/// DB pool snapshot (size = total open, idle = free).
pub fn record_db_pool(size: u32, idle: u32) {
    gauge!(names::DB_POOL_CONNECTIONS, "state" => "idle").set(f64::from(idle));
    gauge!(names::DB_POOL_CONNECTIONS, "state" => "in_use")
        .set(f64::from(size.saturating_sub(idle)));
}

/// Pool acquire wait; `timed_out` par timeout counter bhi badhta hai.
pub fn record_db_pool_acquire(wait: Duration, timed_out: bool) {
    histogram!(names::DB_POOL_ACQUIRE).record(wait.as_secs_f64());
    if timed_out {
        counter!(names::DB_POOL_ACQUIRE_TIMEOUTS).increment(1);
    }
}

pub fn set_login_hash_queue_depth(depth: usize) {
    gauge!(names::LOGIN_HASH_QUEUE_DEPTH).set(depth as f64);
}

pub fn record_login_hash(duration: Duration) {
    histogram!(names::LOGIN_HASH_DURATION).record(duration.as_secs_f64());
}

pub fn record_login_hash_rejected() {
    counter!(names::LOGIN_HASH_REJECTED).increment(1);
}

/// Rate limit decision outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateLimitOutcome {
    Allowed,
    Limited,
}

impl RateLimitOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Limited => "limited",
        }
    }
}

/// `scope` compile-time literal (jaise "login", "refresh", "api"): bounded set.
pub fn record_rate_limit(scope: &'static str, outcome: RateLimitOutcome) {
    counter!(names::RATE_LIMIT_DECISIONS, "scope" => scope, "outcome" => outcome.as_str())
        .increment(1);
}

pub fn set_job_queue_depth(kind: &'static str, depth: usize) {
    gauge!(names::JOB_QUEUE_DEPTH, "kind" => kind).set(depth as f64);
}

/// Job finish outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobOutcome {
    Ok,
    Failed,
    Retried,
}

impl JobOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::Retried => "retried",
        }
    }
}

pub fn record_job(kind: &'static str, outcome: JobOutcome, duration: Duration) {
    counter!(names::JOBS, "kind" => kind, "outcome" => outcome.as_str()).increment(1);
    histogram!(names::JOB_DURATION, "kind" => kind).record(duration.as_secs_f64());
}

/// Dropped telemetry ka type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropKind {
    Span,
    Log,
}

/// Dropped telemetry gino (metric + in-process atomic, taaki recorder ke bina bhi test ho sake).
pub fn record_dropped(kind: DropKind, n: u64) {
    let (label, total) = match kind {
        DropKind::Span => ("span", &DROPPED_SPANS),
        DropKind::Log => ("log", &DROPPED_LOGS),
    };
    total.fetch_add(n, Ordering::Relaxed);
    counter!(names::TELEMETRY_DROPPED, "kind" => label).increment(n);
}

/// Process-wide dropped total (is process mein).
pub fn dropped_total(kind: DropKind) -> u64 {
    match kind {
        DropKind::Span => DROPPED_SPANS.load(Ordering::Relaxed),
        DropKind::Log => DROPPED_LOGS.load(Ordering::Relaxed),
    }
}

/// RSS + (feature `jemalloc`) jemalloc resident/allocated gauges refresh karo. `render()` ise khud call karta hai.
pub fn update_process_gauges() {
    if let Some(stats) = memory_stats::memory_stats() {
        gauge!(names::PROCESS_RSS).set(stats.physical_mem as f64);
    }
    #[cfg(feature = "jemalloc")]
    {
        use tikv_jemalloc_ctl::{epoch, stats};
        // jemalloc stats tabhi sahi hain jab binary mein tikv-jemallocator global allocator ho (api crate set karega).
        if epoch::advance().is_ok() {
            if let Ok(v) = stats::resident::read() {
                gauge!(names::JEMALLOC_RESIDENT).set(v as f64);
            }
            if let Ok(v) = stats::allocated::read() {
                gauge!(names::JEMALLOC_ALLOCATED).set(v as f64);
            }
        }
    }
}
