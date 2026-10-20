//! telemetry tests: T-O1 core (log capture scan), nested redaction, metrics render, OTLP queue bound.

use std::collections::HashSet;
use std::io;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use tracing::subscriber::with_default;
use tracing_subscriber::Registry;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;

use crate::layer::{LogStyle, RedactingLayer};
use crate::meters::{self, DropKind, JobOutcome, RateLimitOutcome};
use crate::redact::{is_sensitive_key, masked};

const FIX_EMAIL: &str = "alice.fixture@example.com";
const FIX_PASSWORD: &str = "Hunter2-Fixture-Pw";
const FIX_JWT: &str =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmaXh0dXJlIn0.c2lnbmF0dXJlLWZpeHR1cmUtMTIz";
const FIX_IP: &str = "203.0.113.77";
const FIX_BEARER: &str = "Zk9xLmJlYXJlci1maXh0dXJl";
const FIX_REFRESH: &str = "rt_fixture_refresh_value_9f8e7d";

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl Buf {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap_or_else(PoisonError::into_inner)).into_owned()
    }
}

impl io::Write for Buf {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Buf {
    type Writer = Buf;
    fn make_writer(&'a self) -> Buf {
        self.clone()
    }
}

fn capture<F: FnOnce()>(style: LogStyle, f: F) -> String {
    let buf = Buf::default();
    let sub = Registry::default().with(RedactingLayer::new(buf.clone(), style));
    with_default(sub, f);
    buf.text()
}

fn assert_no_fixture(out: &str) {
    for (name, v) in [
        ("email", FIX_EMAIL),
        ("password", FIX_PASSWORD),
        ("jwt", FIX_JWT),
        ("ip", FIX_IP),
        ("bearer", FIX_BEARER),
        ("refresh", FIX_REFRESH),
    ] {
        assert!(!out.contains(v), "{name} leaked in log output:\n{out}");
    }
    // JWT ke pieces bhi nahi
    assert!(!out.contains("eyJ"), "jwt prefix leaked:\n{out}");
}

#[test]
fn t_o1_login_event_has_no_pii_but_keeps_safe_fields() {
    let out = capture(LogStyle::Json, || {
        let span = tracing::info_span!("login", request_id = "req-123", token = FIX_JWT);
        span.in_scope(|| {
            tracing::info!(
                email = FIX_EMAIL,
                password = FIX_PASSWORD,
                client_ip = FIX_IP,
                ip = FIX_IP,
                refresh_token = FIX_REFRESH,
                authorization = %format!("Bearer {FIX_BEARER}"),
                route = "/auth/login",
                status = 200_u16,
                tenant_kind = "enterprise",
                "login ok for {FIX_EMAIL} from {FIX_IP} using {FIX_JWT} auth Bearer {FIX_BEARER} pw={FIX_PASSWORD}"
            );
        });
    });
    assert_no_fixture(&out);
    assert!(out.contains("\"route\":\"/auth/login\""), "{out}");
    assert!(out.contains("\"status\":200"), "{out}");
    assert!(out.contains("\"tenant_kind\":\"enterprise\""), "{out}");
    assert!(out.contains("req-123"), "span field missing: {out}");
    assert!(out.contains("[redacted]"));
    // har line valid JSON
    for line in out.lines() {
        let v: serde_json::Value = serde_json::from_str(line).expect("valid json line");
        assert_eq!(v["level"], "INFO");
        assert_eq!(v["fields"]["email"], "[redacted]");
        assert_eq!(v["fields"]["ip"], "[redacted]");
        assert!(
            v["fields"]["message"]
                .as_str()
                .unwrap_or("")
                .contains("login ok for")
        );
    }
}

#[test]
fn pretty_style_also_redacts() {
    let out = capture(LogStyle::Pretty, || {
        tracing::warn!(
            email = FIX_EMAIL,
            route = "/auth/login",
            "failed login from {FIX_IP} {FIX_JWT}"
        );
    });
    assert_no_fixture(&out);
    assert!(out.contains("route=/auth/login"), "{out}");
    assert!(out.contains("WARN"));
}

#[test]
fn nested_and_structured_fields_are_redacted() {
    #[derive(Debug)]
    #[allow(dead_code)]
    struct Inner {
        email: String,
        password: String,
        note: String,
    }
    #[derive(Debug)]
    #[allow(dead_code)]
    struct Login {
        user: Inner,
        remote_ip: String,
        attempt: u32,
    }
    let login = Login {
        user: Inner {
            email: FIX_EMAIL.to_owned(),
            password: FIX_PASSWORD.to_owned(),
            note: "safe-note".to_owned(),
        },
        remote_ip: FIX_IP.to_owned(),
        attempt: 3,
    };
    let json_blob = format!(
        r#"{{"user":{{"email":"{FIX_EMAIL}","password":"{FIX_PASSWORD}","refresh_token":"{FIX_REFRESH}"}},"route":"/x","n":1}}"#
    );
    let headers = format!("Authorization: Bearer {FIX_BEARER}; Cookie: sid={FIX_REFRESH}");
    let out = capture(LogStyle::Json, || {
        tracing::info!(payload = ?login, body = %json_blob, headers = %headers, "structured");
    });
    assert_no_fixture(&out);
    assert!(
        out.contains("safe-note"),
        "non-sensitive nested value dropped: {out}"
    );
    assert!(out.contains("attempt"), "{out}");
    assert!(out.contains("/x"), "{out}");
}

#[test]
fn value_patterns_are_masked_in_free_text() {
    let m = masked(&format!(
        "mail {FIX_EMAIL}, ip {FIX_IP}, v6 2001:db8::1, jwt {FIX_JWT}, Bearer {FIX_BEARER}, token=abc password: {FIX_PASSWORD}"
    ));
    for leaked in [
        FIX_EMAIL,
        FIX_IP,
        "2001:db8::1",
        FIX_JWT,
        FIX_BEARER,
        FIX_PASSWORD,
        "abc",
    ] {
        assert!(!m.contains(leaked), "{leaked} in {m}");
    }
    let secret = "QWxhZGRpbjpvcGVuIHNlc2FtZTEyMzQ1Njc4OTBhYmNkZWY=";
    assert!(!masked(&format!("key {secret} end")).contains(secret));
    let url = "mysql://root:pa55w0rd@db.internal:4000/app";
    assert!(!masked(&format!("connect {url}")).contains("pa55w0rd"));
}

#[test]
fn safe_text_is_not_over_masked() {
    let uuid = "0192f8e0-7b2a-7c3d-8e4f-0123456789ab";
    let s = format!(
        "request {uuid} GET /api/v1/members took 12:30:45 version 1.2 status 200 footprint ok"
    );
    assert_eq!(masked(&s), s);
}

#[test]
fn sensitive_key_rules() {
    for k in [
        "recovery_code",
        "totp_code",
        "mfa_secret",
        "code",
        "verification_code",
        "password",
        "Password",
        "new_password",
        "token",
        "access-token",
        "refresh_token",
        "authorization",
        "cookie",
        "set-cookie",
        "secret",
        "client_secret",
        "email",
        "user_email",
        "ip",
        "client_ip",
        "remote.ip",
        "phone",
        "connection_string",
        "database_url",
        "otp",
        "api_key",
    ] {
        assert!(is_sensitive_key(k), "{k} should be sensitive");
    }
    for k in [
        "route",
        "status",
        "request_id",
        "footprint",
        "status_code",
        "http.status_code",
        "latency_ms",
        "method",
        "message",
        "tip_count",
        "ship",
    ] {
        assert!(!is_sensitive_key(k), "{k} should not be sensitive");
    }
}

#[test]
fn event_size_is_bounded() {
    let big = "lorem ipsum ".repeat(20_000);
    let out = capture(LogStyle::Json, || {
        for i in 0..200 {
            tracing::info!(f = i, big = %big, big2 = %big, "x {big}");
        }
    });
    let longest = out.lines().map(str::len).max().unwrap_or(0);
    assert!(longest < 64 * 1024, "line too long: {longest}");
    assert!(out.contains("[truncated]"));
}

#[test]
fn request_span_has_template_only() {
    let out = capture(LogStyle::Json, || {
        crate::log_request_completed(
            "req-abc-1",
            "/api/members/12345/devices?email=alice.fixture@example.com",
            "get",
            503,
            Duration::from_millis(42),
        );
        crate::log_request_completed(FIX_EMAIL, "/health", "BREW", 200, Duration::from_millis(1));
    });
    assert!(!out.contains(FIX_EMAIL), "{out}");
    assert!(!out.contains("12345"), "raw id leaked: {out}");
    assert!(out.contains("/api/members/:id/devices"), "{out}");
    assert!(out.contains("\"request_id\":\"req-abc-1\""), "{out}");
    assert!(out.contains("\"request_id\":\"invalid\""), "{out}");
    assert!(out.contains("\"latency_ms\":42"), "{out}");
    assert!(out.contains("\"method\":\"GET\""), "{out}");
    assert!(out.contains("\"method\":\"OTHER\""), "{out}");
    assert!(
        out.contains("\"level\":\"ERROR\""),
        "5xx should log at error: {out}"
    );
}

// ------------------------------------------------------------------ metrics

fn label_keys(rendered: &str) -> HashSet<String> {
    let mut keys = HashSet::new();
    for line in rendered.lines().filter(|l| !l.starts_with('#')) {
        let (Some(a), Some(b)) = (line.find('{'), line.rfind('}')) else {
            continue;
        };
        let mut rest = &line[a + 1..b];
        while let Some(eq) = rest.find("=\"") {
            keys.insert(rest[..eq].trim_start_matches(',').to_owned());
            let after = &rest[eq + 2..];
            let Some(end) = after.find('"') else { break };
            rest = after[end + 1..].trim_start_matches(',');
        }
    }
    keys
}

#[test]
fn metrics_render_has_expected_names_and_bounded_labels() {
    meters::install();
    meters::record_request(
        "GET",
        "/api/v1/members/0192f8e0-7b2a-7c3d-8e4f-0123456789ab",
        200,
        Duration::from_millis(12),
    );
    meters::record_request(
        "POST",
        "/api/v1/members/987654321",
        404,
        Duration::from_millis(3),
    );
    meters::record_request(
        "WEIRD",
        "/auth/login?email=alice.fixture@example.com",
        500,
        Duration::from_millis(80),
    );
    meters::record_db_pool(10, 4);
    meters::record_db_pool_acquire(Duration::from_millis(2), true);
    meters::set_login_hash_queue_depth(3);
    meters::record_login_hash(Duration::from_millis(60));
    meters::record_login_hash_rejected();
    meters::record_rate_limit("login", RateLimitOutcome::Limited);
    meters::record_rate_limit("login", RateLimitOutcome::Allowed);
    meters::set_job_queue_depth("email", 7);
    meters::record_job("email", JobOutcome::Ok, Duration::from_millis(5));
    meters::record_dropped(DropKind::Span, 2);

    let text = meters::render();
    for name in [
        "http_requests_total",
        "http_request_duration_seconds",
        "db_pool_connections",
        "db_pool_acquire_seconds",
        "db_pool_acquire_timeouts_total",
        "login_hash_queue_depth",
        "login_hash_duration_seconds",
        "login_hash_rejected_total",
        "rate_limit_decisions_total",
        "job_queue_depth",
        "jobs_total",
        "job_duration_seconds",
        "telemetry_dropped_total",
        "process_resident_memory_bytes",
    ] {
        assert!(text.contains(name), "missing metric {name}:\n{text}");
    }
    // route templates only, no ids/emails
    assert!(text.contains("route=\"/api/v1/members/:id\""), "{text}");
    for bad in ["0192f8e0", "987654321", "alice", "example.com"] {
        assert!(!text.contains(bad), "{bad} leaked in metrics:\n{text}");
    }
    assert!(text.contains("method=\"OTHER\""));
    assert!(text.contains("status_class=\"5xx\""));

    let allowed: HashSet<String> = [
        "method",
        "route",
        "status_class",
        "state",
        "scope",
        "outcome",
        "kind",
        "le",
        "quantile",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let keys = label_keys(&text);
    assert!(
        keys.is_subset(&allowed),
        "unexpected label keys: {:?}",
        keys.difference(&allowed).collect::<Vec<_>>()
    );
    for forbidden in ["user", "tenant", "email", "ip", "member"] {
        assert!(!keys.contains(forbidden));
    }
}

#[test]
fn route_label_cardinality_is_capped() {
    let mut set = HashSet::new();
    let mut other = 0;
    for i in 0..(meters::MAX_ROUTE_LABELS + 50) {
        if meters::sanitize_route_in(&mut set, &format!("/r/seg{i}")) == "other" {
            other += 1;
        }
    }
    assert_eq!(set.len(), meters::MAX_ROUTE_LABELS);
    assert_eq!(other, 50);
    let mut set = HashSet::new();
    assert_eq!(meters::sanitize_route_in(&mut set, ""), "unmatched");
    assert_eq!(
        meters::sanitize_route_in(&mut set, "/a/b@c.com/x"),
        "/a/:id/x"
    );
}

// ------------------------------------------------------------------ OTLP

#[cfg(feature = "otlp")]
mod otlp_tests {
    use super::*;
    use crate::otlp::{BoundedSpanProcessor, OtlpOptions};
    use opentelemetry::KeyValue;
    use opentelemetry::trace::{Span as _, Tracer, TracerProvider as _};
    use opentelemetry_sdk::error::OTelSdkResult;
    use opentelemetry_sdk::trace::{SdkTracerProvider, SpanData, SpanExporter};

    #[derive(Debug)]
    struct SlowExporter;

    impl SpanExporter for SlowExporter {
        async fn export(&self, _batch: Vec<SpanData>) -> OTelSdkResult {
            std::thread::sleep(Duration::from_millis(200));
            Ok(())
        }
    }

    #[derive(Debug, Clone, Default)]
    struct CaptureExporter(Arc<Mutex<Vec<SpanData>>>);

    impl SpanExporter for CaptureExporter {
        fn export(
            &self,
            batch: Vec<SpanData>,
        ) -> impl std::future::Future<Output = OTelSdkResult> + Send {
            let store = self.0.clone();
            async move {
                store
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .extend(batch);
                Ok(())
            }
        }
    }

    fn emit(provider: &SdkTracerProvider, n: usize) {
        let tracer = provider.tracer("test");
        for _ in 0..n {
            let mut s = tracer.start("work");
            s.set_attribute(KeyValue::new("route", "/x"));
            s.end();
        }
    }

    #[test]
    fn slow_exporter_never_blocks_and_overflow_is_counted() {
        let opts = OtlpOptions {
            max_queue_size: 8,
            max_export_batch_size: 4,
            scheduled_delay: Duration::from_millis(50),
            export_timeout: Duration::from_millis(500),
            sample_ratio: 1.0,
        };
        let proc = BoundedSpanProcessor::new(SlowExporter, &opts).expect("worker");
        let provider = SdkTracerProvider::builder()
            .with_span_processor(proc)
            .build();
        let before = meters::dropped_total(DropKind::Span);
        let start = Instant::now();
        emit(&provider, 5_000);
        let took = start.elapsed();
        let dropped = meters::dropped_total(DropKind::Span) - before;
        assert!(took < Duration::from_secs(2), "producer blocked: {took:?}");
        // queue 8 + batch in flight: baaki sab drop
        assert!(dropped >= 5_000 - 8 - 4 - 4, "dropped only {dropped}");
        let _ = provider.shutdown();
    }

    #[test]
    fn unreachable_endpoint_drops_and_counts() {
        let opts = OtlpOptions {
            max_queue_size: 4,
            max_export_batch_size: 2,
            scheduled_delay: Duration::from_millis(20),
            export_timeout: Duration::from_millis(300),
            sample_ratio: 1.0,
        };
        // port 9 (discard) par koi OTLP collector nahi
        let provider =
            crate::otlp::build_provider("http://127.0.0.1:9", "test-svc", &opts).expect("provider");
        let before = meters::dropped_total(DropKind::Span);
        let start = Instant::now();
        emit(&provider, 2_000);
        assert!(start.elapsed() < Duration::from_secs(3), "producer blocked");
        let dropped = meters::dropped_total(DropKind::Span) - before;
        assert!(dropped >= 1_900, "dropped only {dropped}");
        let t = Instant::now();
        let _ = provider.shutdown();
        assert!(t.elapsed() < Duration::from_secs(15), "shutdown unbounded");
    }

    #[test]
    fn span_attributes_are_redacted_before_export() {
        let cap = CaptureExporter::default();
        let proc = BoundedSpanProcessor::new(cap.clone(), &OtlpOptions::default()).expect("worker");
        let provider = SdkTracerProvider::builder()
            .with_span_processor(proc)
            .build();
        let tracer = provider.tracer("test");
        let mut s = tracer.start("login");
        s.set_attribute(KeyValue::new("email", FIX_EMAIL));
        s.set_attribute(KeyValue::new(
            "note",
            format!("from {FIX_IP} with {FIX_JWT}"),
        ));
        s.set_attribute(KeyValue::new("route", "/auth/login"));
        s.add_event("evt", vec![KeyValue::new("password", FIX_PASSWORD)]);
        s.end();
        provider.force_flush().expect("flush");
        let spans = cap.0.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(spans.len(), 1);
        let dump = format!("{:?}", spans[0].attributes) + &format!("{:?}", spans[0].events.events);
        for v in [FIX_EMAIL, FIX_IP, FIX_JWT, FIX_PASSWORD] {
            assert!(!dump.contains(v), "{v} leaked to exporter: {dump}");
        }
        assert!(dump.contains("/auth/login"));
        drop(spans);
        let _ = provider.shutdown();
    }

    #[test]
    fn traces_url_is_normalised() {
        assert_eq!(
            crate::otlp::traces_url("http://c:4318"),
            "http://c:4318/v1/traces"
        );
        assert_eq!(
            crate::otlp::traces_url("http://c:4318/"),
            "http://c:4318/v1/traces"
        );
        assert_eq!(
            crate::otlp::traces_url("http://c:4318/v1/traces"),
            "http://c:4318/v1/traces"
        );
    }
}

#[test]
fn totp_and_recovery_values_are_masked() {
    let out = capture(LogStyle::Json, || {
        tracing::info!(
            totp_code = 123456_u64,
            recovery_code = "abcd-efgh",
            status_code = 200_u16,
            "mfa step"
        );
    });
    assert!(
        !out.contains("123456") && !out.contains("abcd-efgh"),
        "{out}"
    );
    assert!(out.contains("\"status_code\":200"), "{out}");
}
