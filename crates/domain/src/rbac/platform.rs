//! Staff (platform) matrix, RBAC.md §3.2 and §4.10. Alag realm: tenant roles yahan aate hi nahi.

use common::{GrantId, TenantId};

use super::decide::DenyReason;
use super::hierarchy::{MemberChange, MemberChangeError, MemberState, validate_lifecycle};
use super::perm::PlatformPerm;
use super::roles::StaffRole;

/// Conditions attached to a staff grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlatformGrant {
    /// Ticket reference mandatory (support toggling features).
    pub ticket_required: bool,
    /// Needs the owner (Mr. W) approval record (key rotation, tenant erase).
    pub owner_approval: bool,
    /// Commerce fields only (billing) / metadata only (auditor).
    pub restricted_view: bool,
}

/// Columns: superadmin, support, billing, auditor. `Y` yes, `T` yes + ticket, `R` yes + restricted
/// view, `A` yes + owner approval, `-` no.
struct PRow {
    perm: PlatformPerm,
    cells: [u8; 4],
}

const fn p(perm: PlatformPerm, c: &[u8; 4]) -> PRow {
    PRow { perm, cells: *c }
}

/// Order MUST equal `PlatformPerm::ALL` (test pins it).
static PROWS: &[PRow] = &[
    p(PlatformPerm::TenantsRead, b"YYRR"),
    p(PlatformPerm::TenantsSuspend, b"Y---"),
    p(PlatformPerm::FeaturesToggle, b"YT--"),
    p(PlatformPerm::QuotasUpdate, b"Y-Y-"),
    p(PlatformPerm::StaffAccessOpen, b"YY--"),
    p(PlatformPerm::MembersSupport, b"YY--"),
    p(PlatformPerm::LicensesIssue, b"Y-Y-"),
    p(PlatformPerm::CreditsAdjust, b"Y-Y-"),
    p(PlatformPerm::Refunds, b"Y-Y-"),
    p(PlatformPerm::CheckoutLinksManage, b"Y-Y-"),
    p(PlatformPerm::WebhooksManage, b"Y-Y-"),
    p(PlatformPerm::LeadsRead, b"YYY-"),
    p(PlatformPerm::LeadsManage, b"YYY-"),
    p(PlatformPerm::ReleasesManage, b"Y---"),
    p(PlatformPerm::AuditRead, b"Y--Y"),
    p(PlatformPerm::KeysRotate, b"A---"),
    p(PlatformPerm::TenantErase, b"A---"),
    p(PlatformPerm::StaffManage, b"Y---"),
    // 4.12 additions (`platform.leads.manage` is listed again there with identical cells).
    p(PlatformPerm::CleanerCodesMint, b"Y-Y-"),
    p(PlatformPerm::AutopilotCredits, b"Y-Y-"),
    p(PlatformPerm::ProviderProductsManage, b"Y-Y-"),
    p(PlatformPerm::EmailLogsRead, b"YY-Y"),
    p(PlatformPerm::DownloadsRead, b"YYY-"),
    p(PlatformPerm::ReportsRevoke, b"YT--"),
    p(PlatformPerm::HealthDetailed, b"YY--"),
];

fn prow(perm: PlatformPerm) -> Option<&'static PRow> {
    PROWS.get(perm as usize).filter(|r| r.perm == perm)
}

/// Staff matrix cell. `None` = not granted.
#[must_use]
pub fn platform_grants(role: StaffRole, perm: PlatformPerm) -> Option<PlatformGrant> {
    let r = prow(perm)?;
    let idx = match role {
        StaffRole::Superadmin => 0,
        StaffRole::Support => 1,
        StaffRole::Billing => 2,
        StaffRole::Auditor => 3,
    };
    let plain = PlatformGrant {
        ticket_required: false,
        owner_approval: false,
        restricted_view: false,
    };
    match r.cells[idx] {
        b'Y' => Some(plain),
        b'T' => Some(PlatformGrant {
            ticket_required: true,
            ..plain
        }),
        b'R' => Some(PlatformGrant {
            restricted_view: true,
            ..plain
        }),
        b'A' => Some(PlatformGrant {
            owner_approval: true,
            ..plain
        }),
        _ => None,
    }
}

/// Request context for conditional staff grants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlatformContext {
    pub ticket_ref_present: bool,
    pub owner_approval_present: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlatformDenyReason {
    NoPermission,
    TicketRequired,
    OwnerApprovalRequired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlatformDecision {
    Allowed { restricted_view: bool },
    Denied(PlatformDenyReason),
}

/// Staff authorisation (MFA, session and tenant-data grant are handled by `auth`/`api`).
#[must_use]
pub fn decide_platform(
    role: StaffRole,
    perm: PlatformPerm,
    ctx: PlatformContext,
) -> PlatformDecision {
    let Some(g) = platform_grants(role, perm) else {
        return PlatformDecision::Denied(PlatformDenyReason::NoPermission);
    };
    if g.ticket_required && !ctx.ticket_ref_present {
        return PlatformDecision::Denied(PlatformDenyReason::TicketRequired);
    }
    if g.owner_approval && !ctx.owner_approval_present {
        return PlatformDecision::Denied(PlatformDenyReason::OwnerApprovalRequired);
    }
    PlatformDecision::Allowed {
        restricted_view: g.restricted_view,
    }
}

/// May this staff role read tenant data (reports, members...) at all? Only superadmin and support, and
/// only with an active, unexpired access grant. Billing sees commerce data and auditor audit metadata
/// through platform perms, never customer content.
#[must_use]
pub const fn staff_tenant_data_access(role: StaffRole, active_grant: bool) -> bool {
    matches!(role, StaffRole::Superadmin | StaffRole::Support) && active_grant
}

/// Proof that a staff member may act on ONE tenant's members right now: role has
/// `platform.members.support` and an access grant for that tenant is active. Only built through
/// `StaffScope::new` from a `VerifiedStaffGrant`. The REAL gate is the db layer's grant check
/// (`db::staff_grant`: grant active, unexpired, same tenant); domain only checks the role here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StaffScope {
    role: StaffRole,
    tenant: TenantId,
    grant: GrantId,
}

/// An access grant that the db layer has verified (active, unexpired, for `tenant`). Domain cannot
/// verify it (no IO), so this type only marks the hand-over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedStaffGrant {
    role: StaffRole,
    tenant: TenantId,
    grant: GrantId,
}

impl VerifiedStaffGrant {
    /// MUST only be called by `db::staff_grant` after it has checked that the grant exists, is active
    /// and unexpired and belongs to `tenant`. Any other caller defeats the staff access control.
    #[doc(hidden)]
    #[must_use]
    pub const fn __from_verified_grant(role: StaffRole, tenant: TenantId, grant: GrantId) -> Self {
        Self {
            role,
            tenant,
            grant,
        }
    }
}

impl StaffScope {
    /// `None` when the role lacks `platform.members.support`.
    #[must_use]
    pub fn new(proof: &VerifiedStaffGrant) -> Option<Self> {
        platform_grants(proof.role, PlatformPerm::MembersSupport)?;
        Some(Self {
            role: proof.role,
            tenant: proof.tenant,
            grant: proof.grant,
        })
    }

    #[must_use]
    pub const fn role(&self) -> StaffRole {
        self.role
    }

    #[must_use]
    pub const fn grant(&self) -> GrantId {
        self.grant
    }
}

/// Staff lifecycle validation (disable / delete a member): the actor-independent rules (explicit
/// `transfer_to`, last owner). The actor-free `validate_lifecycle` is crate-private on purpose, so a
/// tenant handler cannot use it to skip `decide()`.
///
/// # Errors
/// `Denied(CrossTenant)` when `target` is not in the scope's tenant, else see `MemberChangeError`.
pub fn validate_staff_member_change(
    scope: &StaffScope,
    target: &MemberState,
    change: MemberChange<'_>,
    active_owner_count: u32,
) -> Result<(), MemberChangeError> {
    if target.tenant != scope.tenant {
        return Err(MemberChangeError::Denied(DenyReason::CrossTenant));
    }
    validate_lifecycle(target, change, active_owner_count)
}

/// Rendered staff matrix for the snapshot test.
#[must_use]
pub fn render_platform_matrix() -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "{:<34} SA SUP BIL AUD", "platform permission");
    for r in PROWS {
        let mut cols: Vec<&str> = Vec::new();
        for role in StaffRole::ALL {
            cols.push(match platform_grants(role, r.perm) {
                None => "-",
                Some(g) if g.owner_approval => "A",
                Some(g) if g.ticket_required => "T",
                Some(g) if g.restricted_view => "R",
                Some(_) => "Y",
            });
        }
        let _ = writeln!(
            out,
            "{:<34} {:<2} {:<3} {:<3} {}",
            r.perm.name(),
            cols[0],
            cols[1],
            cols[2],
            cols[3]
        );
    }
    out
}
