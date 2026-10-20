//! Redacting log layer: har event/span field yahin se guzarta hai, isliye koi sensitive value stdout tak nahi pahunchti.
//!
//! Bounded: value <= `MAX_VALUE_BYTES`, fields buffer <= `MAX_FIELDS_BYTES`, span fragment <= `MAX_SPAN_BYTES`,
//! span depth <= `MAX_SPAN_DEPTH`. Isliye ek event ka memory kabhi unbounded nahi.

use std::fmt::{self, Write as _};
use std::io::Write as _;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Record};
use tracing::{Event, Id, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

use crate::redact::{REDACTED, is_sensitive_key, mask_text};

/// Ek field value ki max length (bytes) masking se pehle.
pub const MAX_VALUE_BYTES: usize = 1024;
/// Ek event ke fields ka total max buffer.
pub const MAX_FIELDS_BYTES: usize = 12 * 1024;
/// Ek span ke stored fields ka max buffer.
pub const MAX_SPAN_BYTES: usize = 2 * 1024;
/// Itne se zyada nested spans print nahi hote (root se).
pub const MAX_SPAN_DEPTH: usize = 8;

/// Output style.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogStyle {
    Json,
    Pretty,
}

/// `fmt::Write` jo `cap` bytes ke baad Err deta hai (Debug formatting bounded rakhne ke liye).
struct Bounded {
    s: String,
    cap: usize,
}

impl fmt::Write for Bounded {
    fn write_str(&mut self, v: &str) -> fmt::Result {
        let room = self.cap.saturating_sub(self.s.len());
        if v.len() <= room {
            self.s.push_str(v);
            Ok(())
        } else {
            let mut cut = room;
            while cut > 0 && !v.is_char_boundary(cut) {
                cut -= 1;
            }
            self.s.push_str(&v[..cut]);
            Err(fmt::Error)
        }
    }
}

fn truncate_str(v: &str, cap: usize) -> (&str, bool) {
    if v.len() <= cap {
        return (v, false);
    }
    let mut cut = cap;
    while cut > 0 && !v.is_char_boundary(cut) {
        cut -= 1;
    }
    (&v[..cut], true)
}

fn push_json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Field visitor: JSON fragment (`"k":v,...`) ya pretty (`k=v k=v`) banata hai.
struct FieldWriter {
    buf: String,
    cap: usize,
    style: LogStyle,
    truncated: bool,
}

impl FieldWriter {
    fn new(cap: usize, style: LogStyle) -> Self {
        Self {
            buf: String::new(),
            cap,
            style,
            truncated: false,
        }
    }

    fn sep(&mut self) -> bool {
        if self.buf.len() >= self.cap {
            self.truncated = true;
            return false;
        }
        if !self.buf.is_empty() {
            self.buf.push(match self.style {
                LogStyle::Json => ',',
                LogStyle::Pretty => ' ',
            });
        }
        true
    }

    fn key(&mut self, name: &str) {
        match self.style {
            LogStyle::Json => {
                push_json_str(&mut self.buf, name);
                self.buf.push(':');
            }
            LogStyle::Pretty => {
                self.buf.push_str(name);
                self.buf.push('=');
            }
        }
    }

    fn add_text(&mut self, name: &str, value: &str) {
        if !self.sep() {
            return;
        }
        self.key(name);
        let mut masked = String::new();
        if is_sensitive_key(name) {
            masked.push_str(REDACTED);
        } else {
            let (v, cut) = truncate_str(value, MAX_VALUE_BYTES);
            mask_text(v, &mut masked);
            if cut {
                masked.push_str("...[truncated]");
            }
        }
        match self.style {
            LogStyle::Json => push_json_str(&mut self.buf, &masked),
            LogStyle::Pretty => self.buf.push_str(&masked.replace(['\n', '\r'], " ")),
        }
    }

    fn add_raw(&mut self, name: &str, raw: &str) {
        if is_sensitive_key(name) {
            self.add_text(name, "");
            return;
        }
        if !self.sep() {
            return;
        }
        self.key(name);
        self.buf.push_str(raw);
    }

    fn add_bounded<F: FnOnce(&mut Bounded) -> fmt::Result>(&mut self, name: &str, f: F) {
        let mut b = Bounded {
            s: String::new(),
            cap: MAX_VALUE_BYTES + 1, // +1: overflow pehchaan kar "[truncated]" lagane ke liye
        };
        let _ = f(&mut b);
        self.add_text(name, &b.s);
    }
}

impl Visit for FieldWriter {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.add_text(field.name(), value);
    }
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.add_bounded(field.name(), |b| write!(b, "{value:?}"));
    }
    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.add_bounded(field.name(), |b| write!(b, "{value}"));
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.add_raw(field.name(), &value.to_string());
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.add_raw(field.name(), &value.to_string());
    }
    fn record_i128(&mut self, field: &Field, value: i128) {
        self.add_raw(field.name(), &value.to_string());
    }
    fn record_u128(&mut self, field: &Field, value: u128) {
        self.add_raw(field.name(), &value.to_string());
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.add_raw(field.name(), if value { "true" } else { "false" });
    }
    fn record_f64(&mut self, field: &Field, value: f64) {
        if value.is_finite() {
            self.add_raw(field.name(), &value.to_string());
        } else {
            self.add_text(field.name(), "non-finite");
        }
    }
}

/// Span extension: already-redacted fields fragment.
struct SpanFields(String);

/// Redacting layer. Writer `W` stdout hota hai production mein, tests mein in-memory buffer.
pub struct RedactingLayer<W> {
    writer: W,
    style: LogStyle,
}

impl<W> RedactingLayer<W> {
    pub fn new(writer: W, style: LogStyle) -> Self {
        Self { writer, style }
    }
}

impl<S, W> Layer<S> for RedactingLayer<W>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    W: for<'w> MakeWriter<'w> + 'static,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let mut w = FieldWriter::new(MAX_SPAN_BYTES, self.style);
        attrs.record(&mut w);
        span.extensions_mut().insert(SpanFields(w.buf));
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let mut ext = span.extensions_mut();
        if let Some(SpanFields(existing)) = ext.get_mut::<SpanFields>() {
            let mut w = FieldWriter::new(MAX_SPAN_BYTES, self.style);
            w.buf = std::mem::take(existing);
            values.record(&mut w);
            *existing = w.buf;
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let meta = event.metadata();
        let mut fields = FieldWriter::new(MAX_FIELDS_BYTES, self.style);
        event.record(&mut fields);

        let ts = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_default();
        let mut line = String::with_capacity(256 + fields.buf.len());

        let mut spans: Vec<(&'static str, String)> = Vec::new();
        if let Some(scope) = ctx.event_scope(event) {
            for span in scope.from_root().take(MAX_SPAN_DEPTH) {
                let f = span
                    .extensions()
                    .get::<SpanFields>()
                    .map(|f| f.0.clone())
                    .unwrap_or_default();
                spans.push((span.name(), f));
            }
        }

        match self.style {
            LogStyle::Json => {
                line.push_str("{\"timestamp\":");
                push_json_str(&mut line, &ts);
                line.push_str(",\"level\":\"");
                line.push_str(meta.level().as_str());
                line.push_str("\",\"fields\":{");
                line.push_str(&fields.buf);
                if fields.truncated {
                    line.push_str(",\"_truncated\":true");
                }
                line.push_str("},\"target\":");
                push_json_str(&mut line, meta.target());
                line.push_str(",\"spans\":[");
                for (i, (name, f)) in spans.iter().enumerate() {
                    if i > 0 {
                        line.push(',');
                    }
                    line.push_str("{\"name\":");
                    push_json_str(&mut line, name);
                    if !f.is_empty() {
                        line.push(',');
                        line.push_str(f);
                    }
                    line.push('}');
                }
                line.push_str("]}\n");
            }
            LogStyle::Pretty => {
                let _ = write!(line, "{ts} {:>5} {}", meta.level().as_str(), meta.target());
                for (name, f) in &spans {
                    let _ = write!(line, " {name}{{{f}}}");
                }
                line.push_str(": ");
                line.push_str(&fields.buf);
                if fields.truncated {
                    line.push_str(" _truncated=true");
                }
                line.push('\n');
            }
        }
        // ek hi write_all: lines interleave nahi hoti
        let _ = self.writer.make_writer().write_all(line.as_bytes());
    }
}
