//! Application error model. HTTP mapping (problem+json) lives in `api`; here only the kinds.

use std::borrow::Cow;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppErrorKind {
    BadRequest,
    Unauthenticated,
    Forbidden,
    NotFound,
    Conflict,
    PreconditionFailed,
    FeatureDisabled,
    StepUpRequired,
    QuotaExceeded,
    RateLimited {
        retry_after_s: u32,
    },
    PayloadTooLarge,
    Unavailable {
        retry_after_s: u32,
    },
    /// Expected write did not persist (e.g. 0 rows affected). Never a silent success.
    NotPersisted,
    Internal,
}

impl AppErrorKind {
    /// Suggested HTTP status (plain number; `common` has no HTTP dependency).
    #[must_use]
    pub const fn status_code(&self) -> u16 {
        match self {
            Self::BadRequest => 400,
            Self::Unauthenticated => 401,
            Self::Forbidden | Self::FeatureDisabled | Self::StepUpRequired => 403,
            Self::NotFound => 404,
            Self::Conflict => 409,
            Self::PreconditionFailed => 412,
            Self::PayloadTooLarge => 413,
            Self::QuotaExceeded => 422,
            Self::RateLimited { .. } => 429,
            Self::Unavailable { .. } => 503,
            Self::NotPersisted | Self::Internal => 500,
        }
    }
}

/// One invalid request field. `message` must not echo user-supplied values (PII).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct FieldError {
    pub field: Cow<'static, str>,
    pub code: &'static str,
    pub message: Cow<'static, str>,
}

impl FieldError {
    #[must_use]
    pub fn new(
        field: impl Into<Cow<'static, str>>,
        code: &'static str,
        message: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            field: field.into(),
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug)]
pub struct AppError {
    pub kind: AppErrorKind,
    /// Stable machine-readable code, e.g. `"cursor_invalid"`.
    pub code: &'static str,
    /// Human-readable, client-safe text (no secrets, no PII).
    pub detail: Cow<'static, str>,
    pub fields: Vec<FieldError>,
    /// Internal cause; logged, never sent to the client.
    pub source: Option<anyhow::Error>,
}

impl AppError {
    #[must_use]
    pub fn new(
        kind: AppErrorKind,
        code: &'static str,
        detail: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            kind,
            code,
            detail: detail.into(),
            fields: Vec::new(),
            source: None,
        }
    }

    #[must_use]
    pub fn bad_request(code: &'static str, detail: impl Into<Cow<'static, str>>) -> Self {
        Self::new(AppErrorKind::BadRequest, code, detail)
    }

    #[must_use]
    pub fn not_found(code: &'static str, detail: impl Into<Cow<'static, str>>) -> Self {
        Self::new(AppErrorKind::NotFound, code, detail)
    }

    #[must_use]
    pub fn internal(source: impl Into<anyhow::Error>) -> Self {
        Self {
            kind: AppErrorKind::Internal,
            code: "internal",
            detail: Cow::Borrowed("internal error"),
            fields: Vec::new(),
            source: Some(source.into()),
        }
    }

    #[must_use]
    pub fn with_field(mut self, f: FieldError) -> Self {
        self.fields.push(f);
        self
    }

    #[must_use]
    pub fn with_source(mut self, source: impl Into<anyhow::Error>) -> Self {
        self.source = Some(source.into());
        self
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| {
            let r: &(dyn std::error::Error + 'static) = e.as_ref();
            r
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn status_codes() {
        assert_eq!(AppErrorKind::BadRequest.status_code(), 400);
        assert_eq!(
            AppErrorKind::RateLimited { retry_after_s: 3 }.status_code(),
            429
        );
        assert_eq!(
            AppErrorKind::Unavailable { retry_after_s: 1 }.status_code(),
            503
        );
        assert_eq!(AppErrorKind::NotPersisted.status_code(), 500);
        assert_eq!(AppErrorKind::StepUpRequired.status_code(), 403);
    }

    #[test]
    fn builders_and_display() {
        let e = AppError::bad_request("bad_email", "email is invalid").with_field(FieldError::new(
            "email",
            "invalid",
            "not a valid email",
        ));
        assert_eq!(e.kind, AppErrorKind::BadRequest);
        assert_eq!(e.fields.len(), 1);
        assert_eq!(e.to_string(), "bad_email: email is invalid");
        assert!(e.source().is_none());
    }

    #[test]
    fn internal_keeps_source_but_hides_it_from_detail() {
        let e = AppError::internal(anyhow::anyhow!("db password=hunter2 failed"));
        assert_eq!(e.kind, AppErrorKind::Internal);
        assert!(!e.to_string().contains("hunter2"));
        assert!(e.source().is_some());
    }

    #[test]
    fn field_error_serialises() {
        let f = FieldError::new("limit", "range", "must be 1..=200");
        let v = serde_json::to_value(&f).expect("ser");
        assert_eq!(v["field"], "limit");
        assert_eq!(v["code"], "range");
    }
}
