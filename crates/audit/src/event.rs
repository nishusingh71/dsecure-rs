//! Audit event model (PHASE0_SPEC §3.6, SECURITY.md §10): typed action catalogue, actor/target refs and a
//! typed, PII-checked, size-capped metadata bag.
//!
//! PII rule: emails and IPs never appear in clear. The caller supplies `ip_hmac` (HMAC/blind index) and, for
//! emails, a blind-index value (hex). Metadata keys are `&'static str` (never user data), values are
//! strings / integers / bools, and string values that look like an email or an IP address are rejected.

use common::{DeviceId, GrantId, MembershipId, RequestId, TenantId, UserId};
use std::collections::BTreeMap;
use std::net::IpAddr;

/// Serialised metadata cap (DATABASE.md: app cap 2 KB).
pub const MAX_META_BYTES: usize = 2048;
const MAX_META_KEYS: usize = 16;
const MAX_KEY_LEN: usize = 32;
const MAX_VALUE_LEN: usize = 256;

/// Errors of the audit crate (value-free).
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("invalid audit input: {0}")]
    Invalid(&'static str),
    #[error("audit event tenant differs from the transaction tenant")]
    TenantMismatch,
    #[error(transparent)]
    Db(#[from] db::DbError),
    #[error(transparent)]
    Storage(#[from] storage::StorageError),
    /// The block is not old enough to seal (late commits could still land in it).
    #[error("block is not sealable yet")]
    TooEarly,
    /// Chain structure problem found while sealing (gap, unsealed older events, ...).
    #[error("audit chain: {0}")]
    Chain(&'static str),
}

macro_rules! actions {
    ($($variant:ident => $name:literal,)+) => {
        /// Catalogue of audited actions (stable wire names, max 64 bytes, `area.thing.verb`).
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum AuditAction { $($variant,)+ }

        impl AuditAction {
            /// Every action (tests, docs, dashboards).
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];

            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $name,)+ }
            }

            #[must_use]
            pub fn parse(s: &str) -> Option<Self> {
                match s { $($name => Some(Self::$variant),)+ _ => None }
            }
        }
    };
}

actions! {
    // auth
    AuthLoginSuccess => "auth.login.success",
    AuthLoginFailure => "auth.login.failure",
    AuthLockout => "auth.lockout",
    AuthLogout => "auth.logout",
    AuthRefreshReuse => "auth.refresh_reuse",
    AuthPasswordChange => "auth.password.change",
    AuthPasswordResetRequest => "auth.password.reset_request",
    AuthPasswordReset => "auth.password.reset",
    AuthMfaEnable => "auth.mfa.enable",
    AuthMfaDisable => "auth.mfa.disable",
    AuthMfaRecoveryUsed => "auth.mfa.recovery_used",
    AuthStepUpSuccess => "auth.step_up.success",
    AuthStepUpFailure => "auth.step_up.failure",
    AuthSessionRevoke => "auth.session.revoke",
    AuthzDenied => "authz.denied",
    // members / groups
    MemberCreate => "member.create",
    MemberDelete => "member.delete",
    MemberTransfer => "member.transfer",
    MemberStatusChange => "member.status_change",
    MemberInvite => "member.invite",
    GroupCreate => "group.create",
    GroupAdminGrant => "group.admin.grant",
    GroupAdminRevoke => "group.admin.revoke",
    OwnershipTransfer => "tenant.ownership_transfer",
    TenantClose => "tenant.close",
    // roles / capabilities
    RoleChange => "role.change",
    CapabilityGrant => "capability.grant",
    CapabilityRevoke => "capability.revoke",
    // toggles / quotas
    FeatureToggle => "platform.feature.toggle",
    QuotaChange => "platform.quota.change",
    TenantSuspend => "platform.tenant.suspend",
    // keys
    KeyRotate => "key.rotate",
    KeyCreate => "key.create",
    KeyDeactivate => "key.deactivate",
    CryptoDecryptFailed => "crypto.decrypt_failed",
    // staff access
    StaffAccessOpen => "staff.access.open",
    StaffAccessClose => "staff.access.close",
    StaffAccessRequest => "staff.access.request",
    StaffAccessDenied => "staff.access.denied",
    // remote wipe
    RemoteWipeRequested => "device.remote_wipe.requested",
    RemoteWipeDispatched => "device.remote_wipe.dispatched",
    RemoteWipeConfirmed => "device.remote_wipe.confirmed",
    // licences
    LicenseIssue => "license.issue",
    LicenseActivate => "license.activate",
    LicenseRevoke => "license.revoke",
    LicenseTransfer => "license.transfer",
    // credits
    CreditIssue => "credit.issue",
    CreditConsume => "credit.consume",
    CreditRefund => "credit.refund",
    CreditAdjust => "credit.adjust",
    // exports
    ExportRequest => "export.request",
    ExportDownload => "export.download",
    TenantDataExport => "tenant.data_export",
    // integrations
    WebhookVerifyFailed => "webhook.verify_failed",
    PrivateCloudChange => "private_cloud.change",
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Success,
    Denied,
    Failed,
}

impl Outcome {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Denied => "denied",
            Self::Failed => "failed",
        }
    }
}

/// Who did it. Kinds match the `audit_events.actor_kind` comment (member|device|staff|cleaner|system|anonymous).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActorRef {
    Member(MembershipId),
    Device(DeviceId),
    Staff(UserId),
    Cleaner(uuid::Uuid),
    System,
    Anonymous,
}

impl ActorRef {
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Member(_) => "member",
            Self::Device(_) => "device",
            Self::Staff(_) => "staff",
            Self::Cleaner(_) => "cleaner",
            Self::System => "system",
            Self::Anonymous => "anonymous",
        }
    }

    #[must_use]
    pub const fn id(&self) -> Option<uuid::Uuid> {
        match self {
            Self::Member(m) => Some(m.0),
            Self::Device(d) => Some(d.0),
            Self::Staff(u) => Some(u.0),
            Self::Cleaner(c) => Some(*c),
            Self::System | Self::Anonymous => None,
        }
    }
}

/// Kind of the thing acted on (`audit_events.target_type`, max 32 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetKind {
    Tenant,
    User,
    Membership,
    Group,
    Department,
    Session,
    Device,
    License,
    CreditLot,
    Report,
    Key,
    Feature,
    Quota,
    Export,
    Grant,
    Webhook,
}

impl TargetKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tenant => "tenant",
            Self::User => "user",
            Self::Membership => "membership",
            Self::Group => "group",
            Self::Department => "department",
            Self::Session => "session",
            Self::Device => "device",
            Self::License => "license",
            Self::CreditLot => "credit_lot",
            Self::Report => "report",
            Self::Key => "key",
            Self::Feature => "feature",
            Self::Quota => "quota",
            Self::Export => "export",
            Self::Grant => "grant",
            Self::Webhook => "webhook",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetRef {
    pub kind: TargetKind,
    pub id: uuid::Uuid,
}

impl TargetRef {
    #[must_use]
    pub const fn new(kind: TargetKind, id: uuid::Uuid) -> Self {
        Self { kind, id }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum MetaValue {
    Str(String),
    Int(i64),
    Bool(bool),
}

/// Typed metadata bag: static keys, scalar values, <= 2 KB serialised, no PII.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditMeta(BTreeMap<&'static str, MetaValue>);

const SENSITIVE_KEY_PARTS: &[&str] = &[
    "email", "phone", "password", "passwd", "secret", "token", "cookie", "address", "ssn", "otp",
];

fn key_ok(key: &str) -> bool {
    if key.is_empty() || key.len() > MAX_KEY_LEN {
        return false;
    }
    if !key
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return false;
    }
    // `ip` only as a whole `_`-segment (so `ip_hmac_hex` is also refused, `zip_count` is not).
    !SENSITIVE_KEY_PARTS.iter().any(|p| key.contains(p)) && !key.split('_').any(|s| s == "ip")
}

/// Does this string look like an email address or contain an IP address?
fn looks_like_pii(s: &str) -> bool {
    if s.contains('@') {
        return true;
    }
    s.split(|c: char| !(c.is_ascii_hexdigit() || c == '.' || c == ':'))
        .filter(|t| t.contains('.') || t.contains(':'))
        .any(|t| {
            t.trim_matches(['.', ':']).parse::<IpAddr>().is_ok() || t.parse::<IpAddr>().is_ok()
        })
}

impl AuditMeta {
    #[must_use]
    pub const fn new() -> Self {
        Self(BTreeMap::new())
    }

    fn put(mut self, key: &'static str, v: MetaValue) -> Result<Self, AuditError> {
        if !key_ok(key) {
            return Err(AuditError::Invalid("metadata key not allowed"));
        }
        if self.0.len() >= MAX_META_KEYS && !self.0.contains_key(key) {
            return Err(AuditError::Invalid("too many metadata keys"));
        }
        self.0.insert(key, v);
        Ok(self)
    }

    /// Short enum-like text (reason codes, plan names). Email-/IP-looking values are rejected.
    ///
    /// # Errors
    /// `Invalid` for a bad key, a too long value or a value that looks like PII.
    pub fn with_str(self, key: &'static str, value: &str) -> Result<Self, AuditError> {
        if value.len() > MAX_VALUE_LEN {
            return Err(AuditError::Invalid("metadata value too long"));
        }
        if looks_like_pii(value) {
            return Err(AuditError::Invalid("metadata value looks like PII"));
        }
        self.put(key, MetaValue::Str(value.to_owned()))
    }

    /// # Errors
    /// `Invalid` for a bad key or an integer outside +-2^53 (JSON-safe).
    pub fn with_int(self, key: &'static str, value: i64) -> Result<Self, AuditError> {
        if value.unsigned_abs() > (1u64 << 53) {
            return Err(AuditError::Invalid("metadata integer out of range"));
        }
        self.put(key, MetaValue::Int(value))
    }

    /// # Errors
    /// `Invalid` for a bad key.
    pub fn with_bool(self, key: &'static str, value: bool) -> Result<Self, AuditError> {
        self.put(key, MetaValue::Bool(value))
    }

    /// Id as hyphenated text.
    ///
    /// # Errors
    /// `Invalid` for a bad key.
    pub fn with_id(self, key: &'static str, id: uuid::Uuid) -> Result<Self, AuditError> {
        self.put(key, MetaValue::Str(id.hyphenated().to_string()))
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// JSON object (`None` when empty), checked against the 2 KB cap.
    ///
    /// # Errors
    /// `Invalid` when the serialised size exceeds `MAX_META_BYTES`.
    pub fn to_json(&self) -> Result<Option<serde_json::Value>, AuditError> {
        if self.0.is_empty() {
            return Ok(None);
        }
        let mut m = serde_json::Map::new();
        for (k, v) in &self.0 {
            let jv = match v {
                MetaValue::Str(s) => serde_json::Value::String(s.clone()),
                MetaValue::Int(i) => serde_json::Value::from(*i),
                MetaValue::Bool(b) => serde_json::Value::Bool(*b),
            };
            m.insert((*k).to_owned(), jv);
        }
        let v = serde_json::Value::Object(m);
        let len = serde_json::to_vec(&v)
            .map_err(|_| AuditError::Invalid("metadata not serialisable"))?
            .len();
        if len >= MAX_META_BYTES {
            return Err(AuditError::Invalid("metadata larger than 2 KB"));
        }
        Ok(Some(v))
    }
}

/// One audit event (PHASE0_SPEC §3.6).
#[derive(Clone, Debug)]
pub struct AuditEvent {
    pub action: AuditAction,
    pub outcome: Outcome,
    pub actor: ActorRef,
    pub tenant: Option<TenantId>,
    pub staff_grant: Option<GrantId>,
    pub target: Option<TargetRef>,
    pub request_id: RequestId,
    /// HMAC of the client IP (supplied by the caller; never a raw IP).
    pub ip_hmac: Option<[u8; 32]>,
    pub metadata: AuditMeta,
}

impl AuditEvent {
    #[must_use]
    pub const fn new(
        action: AuditAction,
        outcome: Outcome,
        actor: ActorRef,
        request_id: RequestId,
    ) -> Self {
        Self {
            action,
            outcome,
            actor,
            tenant: None,
            staff_grant: None,
            target: None,
            request_id,
            ip_hmac: None,
            metadata: AuditMeta::new(),
        }
    }

    #[must_use]
    pub const fn tenant(mut self, t: TenantId) -> Self {
        self.tenant = Some(t);
        self
    }

    #[must_use]
    pub const fn staff_grant(mut self, g: GrantId) -> Self {
        self.staff_grant = Some(g);
        self
    }

    #[must_use]
    pub const fn target(mut self, t: TargetRef) -> Self {
        self.target = Some(t);
        self
    }

    #[must_use]
    pub const fn ip_hmac(mut self, h: [u8; 32]) -> Self {
        self.ip_hmac = Some(h);
        self
    }

    #[must_use]
    pub fn metadata(mut self, m: AuditMeta) -> Self {
        self.metadata = m;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn catalogue_is_unique_parsable_and_fits_the_column() {
        let mut seen = HashSet::new();
        for a in AuditAction::ALL {
            let s = a.as_str();
            assert!(s.len() <= 64, "{s}");
            assert!(
                s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'.' || b == b'_'),
                "{s}"
            );
            assert!(seen.insert(s), "duplicate {s}");
            assert_eq!(AuditAction::parse(s), Some(*a));
        }
        assert_eq!(AuditAction::parse("nope"), None);
        // Areas the docs require (SECURITY.md §10 audited actions).
        for needle in [
            "auth.",
            "member.",
            "role.",
            "platform.feature",
            "key.",
            "staff.access",
            "remote_wipe",
            "license.",
            "credit.",
            "export.",
        ] {
            assert!(
                AuditAction::ALL.iter().any(|a| a.as_str().contains(needle)),
                "missing area {needle}"
            );
        }
    }

    #[test]
    fn pii_values_and_keys_are_rejected() {
        for bad in [
            "alice@example.com",
            "10.1.2.3",
            "client 192.168.0.1 failed",
            "::1",
            "2001:db8::ff00:42:8329",
        ] {
            assert!(AuditMeta::new().with_str("reason", bad).is_err(), "{bad}");
        }
        for key in [
            "email",
            "user_email",
            "client_ip",
            "ip",
            "password_hash",
            "x y",
            "",
        ] {
            assert!(AuditMeta::new().with_bool(key, true).is_err(), "{key}");
        }
        let ok = AuditMeta::new()
            .with_str("reason", "wrong_password")
            .and_then(|m| m.with_int("attempts", 3))
            .and_then(|m| m.with_str("at", "2026-10-20T10:00:00Z"))
            .and_then(|m| m.with_id("block", uuid::Uuid::now_v7()));
        assert!(ok.is_ok());
    }

    #[test]
    fn metadata_is_capped_below_2kb() {
        let mut m = AuditMeta::new();
        let long = "a".repeat(200);
        let keys = [
            "k01", "k02", "k03", "k04", "k05", "k06", "k07", "k08", "k09", "k10", "k11", "k12",
        ];
        let mut failed = false;
        for k in keys {
            match m.clone().with_str(k, &long) {
                Ok(n) => m = n,
                Err(_) => failed = true,
            }
        }
        assert!(!failed, "12 x 200 B fits the key limit");
        assert!(m.to_json().is_err(), "2.4 KB must be refused");
        let small = AuditMeta::new().with_str("reason", "x").unwrap();
        assert!(small.to_json().unwrap().is_some());
        assert!(AuditMeta::new().to_json().unwrap().is_none());
    }
}
