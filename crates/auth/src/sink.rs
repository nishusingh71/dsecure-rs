//! Audit / metrics hand-off for auth events. The `audit` crate is built in parallel; it (or the api)
//! implements [`AuthEventSink`] and forwards to `audit::AuditSink::record` + metrics. Events never
//! carry email, IP, token, password or hash material: only ids and a reason code.

use common::{SessionId, TenantId, UserId};
use time::OffsetDateTime;

use crate::error::Rejection;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthEventKind {
    LoginSucceeded,
    /// Reason codes: `unknown_user`, `bad_email`, `wrong_password`, `locked`, `bad_stored_hash`,
    /// `user_inactive`, `email_unverified`, `no_membership`, `unsupported_audience`, `not_staff`,
    /// plus [`Rejection::label`] values from the live state check.
    LoginFailed(&'static str),
    /// Account just got (re)locked.
    LockedOut,
    PasswordRehashed,
    RefreshRotated,
    RefreshFailed(&'static str),
    /// A used refresh token came back: family + session revoked (SECURITY.md §5 `auth.refresh_reuse`).
    RefreshReuseDetected,
    StepUpGranted,
    StepUpFailed(&'static str),
    /// Second factor accepted at login / step-up.
    MfaVerified,
    /// Wrong / replayed TOTP or recovery code, failed enrolment confirm.
    MfaFailed(&'static str),
    Logout,
    /// Token or live-state rejection on a request.
    RequestRejected(Rejection),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthEvent {
    pub kind: AuthEventKind,
    pub user: Option<UserId>,
    pub tenant: Option<TenantId>,
    pub session: Option<SessionId>,
    pub at: OffsetDateTime,
}

/// Must not block (bounded channel inside the implementation).
pub trait AuthEventSink: Send + Sync {
    fn record(&self, ev: AuthEvent);
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoopSink;

impl AuthEventSink for NoopSink {
    fn record(&self, _ev: AuthEvent) {}
}

/// Emits a structured tracing event (ids + reason only).
#[derive(Clone, Copy, Debug, Default)]
pub struct TracingSink;

impl AuthEventSink for TracingSink {
    fn record(&self, ev: AuthEvent) {
        tracing::info!(
            target: "auth_event",
            kind = ?ev.kind,
            user = ?ev.user,
            tenant = ?ev.tenant,
            session = ?ev.session,
            "auth event"
        );
    }
}
