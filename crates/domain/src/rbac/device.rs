//! Device / app principal scopes (RBAC.md §4.11). Alag, minimal; operator ke permissions ka subset.
//! Device token kisi dashboard/admin/member/platform route par valid nahi: yahan sirf mapped perms hain.

use common::{DeviceId, MembershipId, TenantId};
use smallvec::SmallVec;

use super::caps::Capabilities;
use super::decide::{Decision, DenyReason, Subject, Target, decide};
use super::hierarchy::ActorState;
use super::matrix::required_features;
use super::perm::Perm;
use super::roles::{FeatureSet, Scope};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DeviceScope {
    ReportsReserve,
    CreditsConsume,
    ReportsUpload,
    LicensesActivate,
    Heartbeat,
    LicensesOffline,
    CreditsOfflineGrantRead,
    FreezeAgent,
    AutopilotCheck,
}

impl DeviceScope {
    pub const ALL: [Self; 9] = [
        Self::ReportsReserve,
        Self::CreditsConsume,
        Self::ReportsUpload,
        Self::LicensesActivate,
        Self::Heartbeat,
        Self::LicensesOffline,
        Self::CreditsOfflineGrantRead,
        Self::FreezeAgent,
        Self::AutopilotCheck,
    ];

    /// Wire name, e.g. `device:reports.reserve` (RBAC.md §4.11).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ReportsReserve => "device:reports.reserve",
            Self::CreditsConsume => "device:credits.consume",
            Self::ReportsUpload => "device:reports.upload",
            Self::LicensesActivate => "device:licenses.activate",
            Self::Heartbeat => "device:heartbeat",
            Self::LicensesOffline => "device:licenses.offline",
            Self::CreditsOfflineGrantRead => "device:credits.offline_grant.read",
            Self::FreezeAgent => "device:freeze.agent",
            Self::AutopilotCheck => "device:autopilot.check",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|d| d.name() == s)
    }

    /// Tenant permissions this scope may exercise. Heartbeat maps to none (device-only endpoint).
    /// Reserve/upload: the three apps that have device flows (drive, diag, file); upload also covers
    /// the offline (device-signed) upload.
    #[must_use]
    pub const fn perms(self) -> &'static [Perm] {
        match self {
            Self::ReportsReserve => &[
                Perm::ReportsDriveCreate,
                Perm::ReportsDiagCreate,
                Perm::ReportsFileCreate,
            ],
            Self::ReportsUpload => &[
                Perm::ReportsDriveCreate,
                Perm::ReportsDiagCreate,
                Perm::ReportsFileCreate,
                Perm::ReportsDriveOfflineUpload,
                Perm::ReportsDiagOfflineUpload,
                Perm::ReportsFileOfflineUpload,
            ],
            Self::CreditsConsume => &[Perm::CreditsConsume],
            Self::LicensesActivate | Self::LicensesOffline => &[Perm::LicensesActivate],
            Self::CreditsOfflineGrantRead => &[Perm::CreditsRead],
            // Freeze agent: upload freeze reports, chat as `endpoint` (register/heartbeat is
            // device-only, like Heartbeat).
            Self::FreezeAgent => &[
                Perm::ReportsFreezeCreate,
                Perm::FreezeChatSend,
                Perm::FreezeChatRead,
            ],
            // Autopilot tool: check-status / upload devices for its tenant.
            Self::AutopilotCheck => &[Perm::AutopilotDevicesImport, Perm::AutopilotRecheck],
            Self::Heartbeat => &[],
        }
    }
}

/// Is `perm` reachable with any of the device's scopes?
#[must_use]
pub fn device_allows(scopes: &[DeviceScope], perm: Perm) -> bool {
    scopes.iter().any(|s| s.perms().contains(&perm))
}

/// Device principal state.
///
/// NOTE for the API layer: `decide_device` binds a device to itself and its owning member only.
/// It cannot know which device created a row, so handlers MUST also bind resource rows to the acting
/// device id (e.g. a report reserved by device A cannot be uploaded by device B, even when both belong
/// to the same member).
/// `operator` = the member who enrolled the app (if any); then the device
/// can do only what the operator could (operator disabled/demoted = device denied).
#[derive(Clone, Debug)]
pub struct DeviceActor {
    pub tenant: TenantId,
    /// The device itself (resource binding).
    pub device: DeviceId,
    /// Member owning the device when there is no operator (`operator` wins when present).
    pub owner: Option<MembershipId>,
    pub scopes: SmallVec<[DeviceScope; 5]>,
    pub operator: Option<ActorState>,
}

impl DeviceActor {
    fn owning_membership(&self) -> Option<MembershipId> {
        self.operator.as_ref().map(|o| o.membership).or(self.owner)
    }
}

/// Device authorisation: tenant, device scope, feature, resource binding, then (if present) the
/// operator's own `decide`. A device may act on `Collection` (its own tenant-level call), on itself
/// (`Subject::Device(own id)`) or on resources of its owning member. Anything else (other members,
/// groups, unowned pool, other devices) is denied. Success yields `Scope::SelfOnly`.
#[must_use]
pub fn decide_device(
    device: &DeviceActor,
    perm: Perm,
    features: &FeatureSet,
    caps: &Capabilities,
    target: &Target,
) -> Decision {
    if target.tenant != device.tenant {
        return Decision::Denied(DenyReason::CrossTenant);
    }
    if let Subject::Member(m) = &target.subject
        && m.tenant != device.tenant
    {
        return Decision::Denied(DenyReason::CrossTenant);
    }
    if !device_allows(&device.scopes, perm) {
        return Decision::Denied(DenyReason::NoPermission);
    }
    for f in required_features(perm).iter().flatten() {
        if !features.has(*f) {
            return Decision::Denied(DenyReason::FeatureDisabled(*f));
        }
    }
    let subject = match &target.subject {
        Subject::Collection => Subject::Collection,
        Subject::Device(id) if *id == device.device => Subject::Device(*id),
        Subject::Member(m) if device.owning_membership() == Some(m.membership) => {
            Subject::Member(m.clone())
        }
        _ => return Decision::Denied(DenyReason::OutOfScope),
    };
    match &device.operator {
        None => Decision::Allowed(Scope::SelfOnly),
        Some(op) if op.tenant != device.tenant => Decision::Denied(DenyReason::CrossTenant),
        Some(op) => {
            // The device's own row belongs to the operator.
            let subject = match subject {
                Subject::Device(_) => Subject::Member(op.as_member()),
                other => other,
            };
            let t = Target {
                subject,
                ..target.clone()
            };
            match decide(op, perm, features, caps, &t) {
                Decision::Allowed(_) => Decision::Allowed(Scope::SelfOnly),
                denied @ Decision::Denied(_) => denied,
            }
        }
    }
}
