//! Access token claims and audiences (SECURITY.md §5, RBAC.md §6.2).

use common::{DeviceId, MembershipId, SessionId, TenantId, UserId};
use serde::{Deserialize, Serialize};

use crate::error::Rejection;

/// Token audience = which API surface the token is for. Each audience belongs to exactly one
/// [`Realm`] (signing key family).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Audience {
    /// Dashboard (member).
    #[serde(rename = "dsecure-web")]
    Web,
    /// Desktop apps logged in as a member.
    #[serde(rename = "dsecure-app")]
    App,
    /// Enrolled device credential (minimal scopes).
    #[serde(rename = "dsecure-device")]
    Device,
    /// Platform staff console.
    #[serde(rename = "dsecure-platform")]
    Platform,
    /// System Cleaner accounts.
    #[serde(rename = "dsecure-cleaner")]
    Cleaner,
}

impl Audience {
    pub const ALL: [Self; 5] = [
        Self::Web,
        Self::App,
        Self::Device,
        Self::Platform,
        Self::Cleaner,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Web => "dsecure-web",
            Self::App => "dsecure-app",
            Self::Device => "dsecure-device",
            Self::Platform => "dsecure-platform",
            Self::Cleaner => "dsecure-cleaner",
        }
    }

    /// The only principal kind a token of this audience may carry.
    #[must_use]
    pub const fn kind(self) -> PrincipalKind {
        match self {
            Self::Web | Self::App => PrincipalKind::Member,
            Self::Device => PrincipalKind::Device,
            Self::Platform => PrincipalKind::Staff,
            Self::Cleaner => PrincipalKind::Cleaner,
        }
    }

    /// Signing key family.
    #[must_use]
    pub const fn realm(self) -> Realm {
        match self {
            Self::Web | Self::App | Self::Device => Realm::Member,
            Self::Platform => Realm::Staff,
            Self::Cleaner => Realm::Cleaner,
        }
    }
}

/// Key family: member/device key A, staff key B, cleaner key C (RBAC.md §6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Realm {
    Member,
    Staff,
    Cleaner,
}

/// `typ` claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    Member,
    Device,
    Staff,
    Cleaner,
}

/// Authentication methods (RFC 8176 subset).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Amr {
    Pwd,
    Mfa,
    /// Device credential exchange.
    Dev,
}

/// Access token payload. Unknown claims are rejected (`deny_unknown_fields`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessClaims {
    pub iss: String,
    /// User id (member/staff/cleaner) or device id (device tokens).
    pub sub: uuid::Uuid,
    pub aud: Audience,
    pub exp: i64,
    pub nbf: i64,
    pub iat: i64,
    pub jti: uuid::Uuid,
    pub typ: PrincipalKind,
    /// Tenant (member, device).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tid: Option<TenantId>,
    /// Membership (member) or owning operator membership (device).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mid: Option<MembershipId>,
    /// Session (member, staff, cleaner).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<SessionId>,
    /// Device credential id (device tokens).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dcid: Option<uuid::Uuid>,
    /// `authz_version` the token was issued with (cache key part; live state always wins).
    pub av: u64,
    pub amr: Vec<Amr>,
    pub auth_time: i64,
}

impl AccessClaims {
    #[must_use]
    pub const fn user(&self) -> UserId {
        UserId(self.sub)
    }

    #[must_use]
    pub const fn device(&self) -> DeviceId {
        DeviceId(self.sub)
    }

    /// Required claims per principal kind; `typ` must match the audience.
    ///
    /// # Errors
    /// `KindMismatch`, `MissingClaim`.
    pub fn check_shape(&self) -> Result<(), Rejection> {
        if self.aud.kind() != self.typ {
            return Err(Rejection::KindMismatch);
        }
        if self.sub.is_nil() || self.jti.is_nil() {
            return Err(Rejection::MissingClaim);
        }
        let ok = match self.typ {
            PrincipalKind::Member => {
                self.tid.is_some()
                    && self.mid.is_some()
                    && self.sid.is_some()
                    && self.dcid.is_none()
            }
            PrincipalKind::Device => {
                self.tid.is_some()
                    && self.mid.is_some()
                    && self.dcid.is_some()
                    && self.sid.is_none()
            }
            PrincipalKind::Staff | PrincipalKind::Cleaner => {
                self.sid.is_some()
                    && self.tid.is_none()
                    && self.mid.is_none()
                    && self.dcid.is_none()
            }
        };
        if ok {
            Ok(())
        } else {
            Err(Rejection::MissingClaim)
        }
    }
}

/// Claims of a token that `Es256Verifier` verified (signature, kid, realm, issuer, audience, kind,
/// times, shape). Only the verifier constructs it (no `Deserialize`, no public constructor), and every
/// state loader / step-up / logout entry point takes `&VerifiedClaims`, so unverified claims cannot
/// reach them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedClaims {
    claims: AccessClaims,
    kid: String,
}

impl VerifiedClaims {
    pub(crate) const fn new(claims: AccessClaims, kid: String) -> Self {
        Self { claims, kid }
    }

    /// Read-only view of the verified payload.
    #[must_use]
    pub const fn claims(&self) -> &AccessClaims {
        &self.claims
    }

    /// `kid` of the verifying key.
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    #[must_use]
    pub const fn user(&self) -> UserId {
        self.claims.user()
    }

    #[must_use]
    pub const fn device(&self) -> DeviceId {
        self.claims.device()
    }

    #[must_use]
    pub const fn audience(&self) -> Audience {
        self.claims.aud
    }

    #[must_use]
    pub const fn kind(&self) -> PrincipalKind {
        self.claims.typ
    }

    #[must_use]
    pub const fn tenant(&self) -> Option<TenantId> {
        self.claims.tid
    }

    #[must_use]
    pub const fn membership(&self) -> Option<MembershipId> {
        self.claims.mid
    }

    #[must_use]
    pub const fn session(&self) -> Option<SessionId> {
        self.claims.sid
    }

    #[must_use]
    pub const fn credential(&self) -> Option<uuid::Uuid> {
        self.claims.dcid
    }

    #[must_use]
    pub const fn authz_version(&self) -> u64 {
        self.claims.av
    }

    #[must_use]
    pub const fn iat(&self) -> i64 {
        self.claims.iat
    }

    #[must_use]
    pub const fn exp(&self) -> i64 {
        self.claims.exp
    }

    #[must_use]
    pub const fn auth_time(&self) -> i64 {
        self.claims.auth_time
    }

    #[must_use]
    pub fn amr(&self) -> &[Amr] {
        &self.claims.amr
    }
}
