//! Errors. Rule: Display/`code()` sab generic hain; detailed [`Rejection`] sirf audit/metrics sink ke
//! liye (client ko kabhi nahi). Koi token, email, password ya hash error mein nahi aata.

use common::TenantId;

/// Internal reason a token / principal was rejected (audit + metrics only).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Rejection {
    // token layer
    Malformed,
    BadAlgorithm,
    UnknownKid,
    BadSignature,
    WrongIssuer,
    WrongAudience,
    RealmMismatch,
    KindMismatch,
    Expired,
    NotYetValid,
    IssuedInFuture,
    LifetimeTooLong,
    MissingClaim,
    // live state layer
    SessionMissing,
    SessionRevoked,
    SessionExpired,
    UserInactive,
    EmailUnverified,
    TokensRevoked,
    MembershipInactive,
    TenantInactive,
    StaffRevoked,
    CredentialRevoked,
    OperatorInactive,
    StateMismatch,
    Locked,
    /// Staff session without a completed second factor (fail closed until MFA lands, P0-11).
    MfaRequired,
    /// Staff session idle longer than `STAFF_SESSION_IDLE`.
    SessionIdle,
    /// Wrong / replayed TOTP or recovery code.
    MfaInvalid,
}

impl Rejection {
    /// Stable metric label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::BadAlgorithm => "bad_alg",
            Self::UnknownKid => "unknown_kid",
            Self::BadSignature => "bad_signature",
            Self::WrongIssuer => "wrong_issuer",
            Self::WrongAudience => "wrong_audience",
            Self::RealmMismatch => "realm_mismatch",
            Self::KindMismatch => "kind_mismatch",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
            Self::IssuedInFuture => "issued_in_future",
            Self::LifetimeTooLong => "lifetime_too_long",
            Self::MissingClaim => "missing_claim",
            Self::SessionMissing => "session_missing",
            Self::SessionRevoked => "session_revoked",
            Self::SessionExpired => "session_expired",
            Self::UserInactive => "user_inactive",
            Self::EmailUnverified => "email_unverified",
            Self::TokensRevoked => "tokens_revoked",
            Self::MembershipInactive => "membership_inactive",
            Self::TenantInactive => "tenant_inactive",
            Self::StaffRevoked => "staff_revoked",
            Self::CredentialRevoked => "credential_revoked",
            Self::OperatorInactive => "operator_inactive",
            Self::StateMismatch => "state_mismatch",
            Self::Locked => "locked",
            Self::MfaRequired => "mfa_required",
            Self::SessionIdle => "session_idle",
            Self::MfaInvalid => "mfa_invalid",
        }
    }
}

/// Token / principal errors. API: `Unauthenticated` = 401, `Unavailable` = 503, `Internal` = 500
/// (still a deny).
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("unauthenticated")]
    Unauthenticated(Rejection),
    #[error("authentication service unavailable")]
    Unavailable,
    #[error("internal authentication error")]
    Internal(&'static str),
    /// Authenticated but not allowed (staff grant missing / read-only grant on a write): 403.
    #[error("forbidden")]
    Forbidden(&'static str),
}

impl AuthError {
    /// Internal reason (sink only).
    #[must_use]
    pub const fn rejection(&self) -> Option<Rejection> {
        match self {
            Self::Unauthenticated(r) => Some(*r),
            _ => None,
        }
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Unauthenticated(_) => "auth.unauthenticated",
            Self::Unavailable => "service.unavailable",
            Self::Internal(_) => "internal",
            Self::Forbidden(_) => "authz.forbidden",
        }
    }

    pub(crate) fn from_db(e: &db::DbError) -> Self {
        use db::DbError as D;
        match e {
            D::Unavailable | D::Timeout | D::Transient { .. } | D::CommitUnknown => {
                Self::Unavailable
            }
            D::TenantMismatch => Self::Internal("row tenant mismatch"),
            D::ReadOnly => Self::Forbidden("read_only"),
            D::Forbidden(_) => Self::Forbidden("forbidden"),
            D::Corrupt(_) => Self::Internal("corrupt auth state"),
            _ => Self::Internal("database error"),
        }
    }
}

/// Login / refresh / step-up outcome for callers. `Failed` is the ONE generic failure (wrong email,
/// wrong password, locked, inactive, unverified, no membership, reused refresh token ...).
#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    #[error("invalid credentials")]
    Failed,
    /// Password was correct and the user has several active tenants: client must pick one.
    #[error("tenant choice required")]
    TenantChoiceRequired(Vec<TenantId>),
    /// Password was correct and the account has MFA (or is staff): the client must send a code.
    #[error("second factor required")]
    MfaRequired,
    /// Password hashing capacity busy (API: 503 + Retry-After).
    #[error("authentication busy")]
    Busy,
    #[error("authentication service unavailable")]
    Unavailable,
}

impl LoginError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Failed => "auth.invalid_credentials",
            Self::TenantChoiceRequired(_) => "auth.tenant_choice_required",
            Self::MfaRequired => "auth.mfa_required",
            Self::Busy => "auth.busy",
            Self::Unavailable => "service.unavailable",
        }
    }
}
