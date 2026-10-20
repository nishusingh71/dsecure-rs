//! RBAC.md §4 role x permission matrix as one const table (one row per `Perm`, same order as
//! `Perm::ALL`). Cell letters: T tenant, G group, S self, `-` none. Column order: Owner Admin GA
//! Member Viewer. Lookup failure (row missing / misaligned) = no grant (fail closed); a test pins
//! the alignment.

use std::fmt::Write as _;

use super::caps::CapabilityKind;
use super::perm::Perm;
use super::roles::{Feature, Product, Scope, TenantRole};

/// What kind of effect a permission has (for the "viewer can never write" invariant).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// Reads / exports.
    Read,
    /// Mutates tenant data or acts on a device/licence/credit.
    Write,
    /// Own account hygiene (profile, password, MFA, own sessions): every role incl. viewer.
    SelfService,
}

/// Extra per-target rule applied by `decide` on top of the scope (hierarchy).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    /// Scope check only.
    Free,
    /// Target member must be visible: self, strictly lower rank (owner: any), GA: own group + rank < 60.
    ReadMember,
    /// `can_manage(actor, target)` (strictly lower rank, GA own group, never self).
    ManageMember,
    /// Needs `new_role`; `can_grant(actor, new_role)`.
    NewMember,
    /// `ManageMember` + `can_grant(actor, new_role)`.
    AssignRole,
    /// `members.create` but the new role must be exactly `member` (autopilot donor accounts).
    NewMemberOnly,
    /// Only owner/admin; needs `Target::group` (same tenant); target must be an active
    /// `member`-role membership.
    GrantGroupAdmin,
    /// Add/remove a member to/from a group. Needs `Target::group` + `Target::group_op` + a member
    /// subject. ADD is owner/admin only (a GA can never add, ruling on review item 8); REMOVE by a
    /// GA only for a member of its own group. Always `can_manage` on the member.
    GroupMembership,
}

#[derive(Clone, Copy, Debug)]
pub struct Row {
    pub perm: Perm,
    /// Owner, Admin, GA, Member, Viewer.
    pub cells: [Option<Scope>; 5],
    /// Hard gates (all must be ON): feature OFF = denied even for Owner (E14).
    pub features: [Option<Feature>; 2],
    /// Soft gate: feature OFF = scope narrowed to `SelfOnly` (audit.read_actions, erasure metrics).
    pub narrowed_by: Option<Feature>,
    /// Member-level data gate (D-65): with the feature OFF only `Collection` (aggregate, no member
    /// identity) or the actor itself is allowed; another member's data is `FeatureDisabled`.
    pub member_gate: Option<Feature>,
    /// Accepts `Subject::Aggregate` (org totals, no member identity). Every other perm refuses it.
    pub aggregate_ok: bool,
    pub cap: Option<CapabilityKind>,
    pub rule: Rule,
    pub access: Access,
    pub step_up: bool,
    /// Explicit confirmation in the request (remote wipe, Intune delete).
    pub confirm: bool,
    /// D-63: with the capability OFF the actor may still do this for ITSELF (scope self).
    pub cap_self_ok: bool,
    /// GA may use it only for group membership, not name/dept (members.update). API enforces fields.
    pub ga_limited: bool,
}

const fn cell(b: u8) -> Option<Scope> {
    match b {
        b'T' => Some(Scope::Tenant),
        b'G' => Some(Scope::Group),
        b'S' => Some(Scope::SelfOnly),
        _ => None,
    }
}

// Default access = Write (safe default: a forgotten `.read()` shows up in the viewer test).
const fn row(perm: Perm, c: &[u8; 5]) -> Row {
    Row {
        perm,
        cells: [cell(c[0]), cell(c[1]), cell(c[2]), cell(c[3]), cell(c[4])],
        features: [None, None],
        narrowed_by: None,
        member_gate: None,
        aggregate_ok: false,
        cap: None,
        rule: Rule::Free,
        access: Access::Write,
        step_up: false,
        confirm: false,
        cap_self_ok: false,
        ga_limited: false,
    }
}

impl Row {
    const fn read(self) -> Self {
        Self {
            access: Access::Read,
            ..self
        }
    }
    const fn selfservice(self) -> Self {
        Self {
            access: Access::SelfService,
            ..self
        }
    }
    /// Adds a hard feature gate (at most two; a third is a compile-time const panic).
    const fn feat(self, f: Feature) -> Self {
        let features = if self.features[0].is_none() {
            [Some(f), None]
        } else {
            assert!(self.features[1].is_none(), "max two feature gates");
            [self.features[0], Some(f)]
        };
        Self { features, ..self }
    }
    const fn confirm(self) -> Self {
        Self {
            confirm: true,
            ..self
        }
    }
    const fn cap_self_ok(self) -> Self {
        Self {
            cap_self_ok: true,
            ..self
        }
    }
    const fn narrow(self, f: Feature) -> Self {
        Self {
            narrowed_by: Some(f),
            ..self
        }
    }
    const fn member_gate(self, f: Feature) -> Self {
        Self {
            member_gate: Some(f),
            ..self
        }
    }
    const fn aggregate(self) -> Self {
        Self {
            aggregate_ok: true,
            ..self
        }
    }
    const fn cap(self, c: CapabilityKind) -> Self {
        Self {
            cap: Some(c),
            ..self
        }
    }
    const fn rule(self, r: Rule) -> Self {
        Self { rule: r, ..self }
    }
    const fn step(self) -> Self {
        Self {
            step_up: true,
            ..self
        }
    }
    const fn ga_limited(self) -> Self {
        Self {
            ga_limited: true,
            ..self
        }
    }
}

use CapabilityKind::{AssignLicenses, ManageMachines, ViewReports};
use Feature::{Groups, PrivateCloud, Subusers, UserActivity};
use Rule::NewMemberOnly;
use Rule::{AssignRole, GrantGroupAdmin, GroupMembership, ManageMember, NewMember, ReadMember};

/// The matrix. Order MUST equal `Perm::ALL` (test `rows_align_with_catalogue`).
pub static ROWS: &[Row] = &[
    // 4.1 Account / self
    row(Perm::ProfileReadSelf, b"SSSSS").selfservice(),
    row(Perm::ProfileUpdateSelf, b"SSSSS").selfservice(),
    row(Perm::ProfileUpdateTimezone, b"SSSSS").selfservice(),
    row(Perm::PasswordChangeSelf, b"SSSSS").selfservice(),
    row(Perm::MfaManageSelf, b"SSSSS").selfservice(),
    row(Perm::SessionsReadSelf, b"SSSSS").selfservice(),
    row(Perm::SessionsRevokeSelf, b"SSSSS").selfservice(),
    row(Perm::MembersPreferencesManageSelf, b"SSSSS").selfservice(),
    row(Perm::ActivityReadSelf, b"SSSSS").read(),
    row(Perm::DownloadsHistoryReadSelf, b"SSSSS").read(),
    // 4.2 Members
    row(Perm::MembersRead, b"TTGSS")
        .read()
        .feat(Subusers)
        .rule(ReadMember),
    row(Perm::MembersReadRolesCatalogue, b"TTGSS").read(),
    row(Perm::MembersCreate, b"TT---")
        .feat(Subusers)
        .rule(NewMember),
    row(Perm::MembersUpdate, b"TTG--")
        .feat(Subusers)
        .rule(ManageMember)
        .ga_limited(),
    row(Perm::MembersAssignRole, b"TT---")
        .feat(Subusers)
        .rule(AssignRole),
    row(Perm::MembersSetCapabilities, b"TT---")
        .feat(Subusers)
        .rule(ManageMember),
    row(Perm::MembersDisable, b"TT---")
        .feat(Subusers)
        .rule(ManageMember),
    row(Perm::MembersEnable, b"TT---")
        .feat(Subusers)
        .rule(ManageMember),
    row(Perm::MembersDelete, b"TT---")
        .feat(Subusers)
        .rule(ManageMember)
        .step(),
    row(Perm::MembersResetPassword, b"TT---")
        .feat(Subusers)
        .rule(ManageMember),
    row(Perm::MembersBulkAssignDepartment, b"TT---")
        .feat(Subusers)
        .feat(Groups)
        .rule(ManageMember),
    // Spec cell is plain T for Admin; we still apply ManageMember (rank < 80) so an admin cannot move
    // the resources of a peer admin or the owner (stricter than the spec on purpose: moving someone's
    // devices/reports/credits is an act on that member, E4).
    row(Perm::MembersTransferResources, b"TTG--")
        .feat(Subusers)
        .rule(ManageMember),
    row(Perm::TenantOwnershipTransfer, b"T----")
        .rule(ManageMember)
        .step(),
    // 4.3 Groups / departments
    row(Perm::GroupsRead, b"TTGSS").read().feat(Groups),
    row(Perm::GroupsCreate, b"TT---").feat(Groups),
    row(Perm::GroupsUpdate, b"TT---").feat(Groups),
    row(Perm::GroupsDelete, b"TT---").feat(Groups),
    // GA cell G = REMOVE only, within own groups; ADD is owner/admin (rule `GroupMembership`).
    row(Perm::GroupsManageMembers, b"TTG--")
        .feat(Groups)
        .rule(GroupMembership),
    row(Perm::GroupsAssignAdmin, b"TT---")
        .feat(Groups)
        .rule(GrantGroupAdmin),
    row(Perm::DepartmentsRead, b"TTGSS").read().feat(Groups),
    row(Perm::DepartmentsManage, b"TT---").feat(Groups),
    // 4.4 Activity / sessions / performance
    row(Perm::ActivityReadMembers, b"TTG--")
        .read()
        .feat(UserActivity)
        .rule(ReadMember),
    row(Perm::SessionsRevokeMembers, b"TT---")
        .feat(UserActivity)
        .rule(ManageMember),
    // D-65: org-level performance is always visible to owner/admin; the `user_activity` toggle gates
    // only per-member data (`activity.read_members`, `audit.read_actions`), not this perm.
    row(Perm::PerformanceRead, b"TTGSS")
        .read()
        .member_gate(UserActivity)
        .aggregate(),
    row(Perm::AuditReadActions, b"TTGS-")
        .read()
        .narrow(UserActivity)
        .rule(ReadMember),
    // D-65: org-level metric, not narrowed by `user_activity` (per-member data is `audit.read_actions`
    // / `activity.read_members`).
    row(Perm::PerformanceErasureMetricsRead, b"TTGSS")
        .read()
        .member_gate(UserActivity)
        .aggregate(),
    // 4.5 Devices
    row(Perm::DevicesRead, b"TTGSS").read(),
    // D-63: own device needs no `can_manage_machines`; registering for others does.
    row(Perm::DevicesRegister, b"TTGS-")
        .cap(ManageMachines)
        .cap_self_ok(),
    row(Perm::DevicesUpdate, b"TTG--").cap(ManageMachines),
    row(Perm::DevicesAssign, b"TTG--")
        .cap(ManageMachines)
        .feat(Subusers),
    row(Perm::DevicesRemoteCommand, b"TTG--").cap(ManageMachines),
    row(Perm::DevicesRemoteWipe, b"TT---").step().confirm(),
    row(Perm::DevicesDelete, b"TT---"),
    row(Perm::DevicesReadLicenseStatus, b"TTGSS").read(),
    row(Perm::DevicesTransfer, b"TTG--").cap(ManageMachines),
    row(Perm::DevicesStatisticsRead, b"TTGS-").read(),
    // 4.6 Licences / credits / billing
    row(Perm::LicensesRead, b"TTGSS").read(),
    row(Perm::LicensesActivate, b"TTGS-"),
    row(Perm::LicensesAllocate, b"TTG--").cap(AssignLicenses),
    row(Perm::LicensesDeactivateDevice, b"TTG--"),
    row(Perm::LicensesTransfer, b"TTG--").cap(AssignLicenses),
    row(Perm::LicensesSync, b"TTGS-"),
    row(Perm::LicensesRenew, b"TTGS-"),
    row(Perm::LicensesRevoke, b"TT---"),
    row(Perm::LicensesExport, b"TTG--").read(),
    row(Perm::CreditsRead, b"TTGSS").read(),
    row(Perm::CreditsConsume, b"TTGS-"),
    row(Perm::CreditsOfflineGrant, b"TTGS-"),
    row(Perm::OrdersRead, b"TT---").read(),
    row(Perm::InvoicesRead, b"TT---").read(),
    row(Perm::OrdersInvoiceDownload, b"TT---").read(),
    row(Perm::BillingManage, b"T----"),
    // 4.7 Reports (per product)
    row(Perm::ReportsDriveRead, b"TTGSS")
        .read()
        .cap(ViewReports),
    row(Perm::ReportsDriveCreate, b"TTGS-"),
    row(Perm::ReportsDiagRead, b"TTGSS").read().cap(ViewReports),
    row(Perm::ReportsDiagCreate, b"TTGS-"),
    row(Perm::ReportsFileRead, b"TTGSS").read().cap(ViewReports),
    row(Perm::ReportsFileCreate, b"TTGS-"),
    row(Perm::ReportsCleanerRead, b"TTGSS")
        .read()
        .cap(ViewReports),
    row(Perm::ReportsCleanerCreate, b"TTGS-"),
    row(Perm::ReportsFreezeRead, b"TTGSS")
        .read()
        .cap(ViewReports),
    row(Perm::ReportsFreezeCreate, b"TTGS-"),
    row(Perm::ReportsAutopilotRead, b"TTGSS")
        .read()
        .cap(ViewReports),
    row(Perm::ReportsAutopilotCreate, b"TTGS-"),
    row(Perm::ReportsExport, b"TTGSS").read().cap(ViewReports),
    row(Perm::ReportsBrandingManage, b"TT---"),
    row(Perm::ReportsTransfer, b"TTG--"),
    row(Perm::ReportsArchive, b"TT---"),
    row(Perm::ReportsDriveOfflineUpload, b"TTGS-"),
    row(Perm::ReportsDiagOfflineUpload, b"TTGS-"),
    row(Perm::ReportsFileOfflineUpload, b"TTGS-"),
    row(Perm::ReportsCleanerOfflineUpload, b"TTGS-"),
    row(Perm::ReportsFreezeOfflineUpload, b"TTGS-"),
    row(Perm::ReportsAutopilotOfflineUpload, b"TTGS-"),
    row(Perm::ReportsDriveStatisticsRead, b"TTGSS")
        .read()
        .cap(ViewReports),
    row(Perm::ReportsDiagStatisticsRead, b"TTGSS")
        .read()
        .cap(ViewReports),
    row(Perm::ReportsFileStatisticsRead, b"TTGSS")
        .read()
        .cap(ViewReports),
    row(Perm::ReportsCleanerStatisticsRead, b"TTGSS")
        .read()
        .cap(ViewReports),
    row(Perm::ReportsFreezeStatisticsRead, b"TTGSS")
        .read()
        .cap(ViewReports),
    row(Perm::ReportsAutopilotStatisticsRead, b"TTGSS")
        .read()
        .cap(ViewReports),
    row(Perm::ReportsDriveFacetsRead, b"TTGSS")
        .read()
        .cap(ViewReports),
    row(Perm::ReportsDiagFacetsRead, b"TTGSS")
        .read()
        .cap(ViewReports),
    row(Perm::ReportsFileFacetsRead, b"TTGSS")
        .read()
        .cap(ViewReports),
    row(Perm::ReportsCleanerFacetsRead, b"TTGSS")
        .read()
        .cap(ViewReports),
    row(Perm::ReportsFreezeFacetsRead, b"TTGSS")
        .read()
        .cap(ViewReports),
    row(Perm::ReportsAutopilotFacetsRead, b"TTGSS")
        .read()
        .cap(ViewReports),
    row(Perm::ReportsDriveSubjectsRead, b"TTGSS").read(),
    row(Perm::ReportsExportBatch, b"TTGSS")
        .read()
        .cap(ViewReports),
    row(Perm::ReportsBrandingRead, b"TTGSS").read(),
    // 4.8 Autopilot (DSAM)
    row(Perm::AutopilotDevicesRead, b"TTGSS").read(),
    row(Perm::AutopilotDevicesImport, b"TTGS-"),
    row(Perm::AutopilotDevicesDelete, b"TT---"),
    row(Perm::AutopilotRecheck, b"TTGS-"),
    row(Perm::AutopilotConnectionManage, b"TT---").step(),
    row(Perm::AutopilotUnlockCredentialsSubmit, b"TT---"),
    row(Perm::AutopilotSettingsManage, b"TT---"),
    row(Perm::AutopilotCustomFieldsUpdate, b"TTGS-"),
    row(Perm::AutopilotSchedulesRead, b"TTGSS").read(),
    row(Perm::AutopilotSchedulesManage, b"TT---"),
    row(Perm::AutopilotUemRecheckRun, b"TT---"),
    row(Perm::AutopilotUemRecheckRead, b"TTGSS").read(),
    row(Perm::AutopilotIntuneDeleteDevice, b"TT---").confirm(),
    row(Perm::AutopilotDonorsCreate, b"TT---")
        .feat(Subusers)
        .rule(NewMemberOnly),
    // 4.8 Freeze (DSFZ)
    row(Perm::FreezeEndpointsRead, b"TTGSS").read(),
    row(Perm::FreezeEndpointsManage, b"TTG--"),
    row(Perm::FreezeChatRead, b"TTGSS").read(),
    row(Perm::FreezeChatSend, b"TTGS-"),
    row(Perm::FreezeEndpointsDelete, b"TT---"),
    row(Perm::FreezeReportsRead, b"TTGSS").read(),
    row(Perm::FreezeReportsArchive, b"TT---"),
    // 4.8 System Cleaner (DSSC)
    row(Perm::CleanerRun, b"TT-S-"),
    row(Perm::CleanerRedeem, b"TT-S-"),
    row(Perm::CleanerReportsRead, b"TT-SS").read(),
    row(Perm::CleanerTransactionsRead, b"TT-SS").read(),
    // 4.8 Downloads, private cloud
    row(Perm::DownloadsRead, b"TT---").read(),
    row(Perm::PrivateCloudRead, b"TT---")
        .read()
        .feat(PrivateCloud),
    row(Perm::PrivateCloudManage, b"T----")
        .feat(PrivateCloud)
        .step(),
    // 4.9 Tenant administration
    row(Perm::TenantSettingsRead, b"TT---").read(),
    row(Perm::TenantSettingsUpdate, b"T----"),
    row(Perm::TenantAuditRead, b"TT---").read(),
    row(Perm::TenantExportData, b"T----").step(),
    row(Perm::TenantClose, b"T----").step(),
];

/// Row for `perm`; `None` if the table is misaligned (then every query below denies).
#[must_use]
pub fn row_of(perm: Perm) -> Option<&'static Row> {
    ROWS.get(perm as usize).filter(|r| r.perm == perm)
}

/// Matrix cell for a tenant role (base role only; GA is `ga_grants`).
#[must_use]
pub fn grants(role: TenantRole, perm: Perm) -> Option<Scope> {
    let r = row_of(perm)?;
    match role {
        TenantRole::Owner => r.cells[0],
        TenantRole::Admin => r.cells[1],
        TenantRole::Member => r.cells[3],
        TenantRole::Viewer => r.cells[4],
    }
}

/// GroupAdmin column (extra grant inside own groups, on top of the base `member` role).
#[must_use]
pub fn ga_grants(perm: Perm) -> Option<Scope> {
    row_of(perm)?.cells[2]
}

/// Hard feature gate (OFF = denied, owner included).
#[must_use]
pub fn required_feature(perm: Perm) -> Option<Feature> {
    row_of(perm)?.features[0]
}

/// All hard feature gates of `perm` (up to two, e.g. `members.bulk_assign_department`).
#[must_use]
pub fn required_features(perm: Perm) -> [Option<Feature>; 2] {
    row_of(perm).map_or([None, None], |r| r.features)
}

/// Needs an explicit confirmation in the request (remote wipe, Intune delete).
/// Unknown perm = `true` (fail closed).
#[must_use]
pub fn requires_confirm(perm: Perm) -> bool {
    row_of(perm).is_none_or(|r| r.confirm)
}

/// Soft gate: feature OFF narrows to self only (audit.read_actions, erasure metrics).
#[must_use]
pub fn narrowing_feature(perm: Perm) -> Option<Feature> {
    row_of(perm)?.narrowed_by
}

/// Capability mask that narrows this permission.
#[must_use]
pub fn required_capability(perm: Perm) -> Option<CapabilityKind> {
    row_of(perm)?.cap
}

/// RBAC.md §6.6: remote wipe and the other destructive actions need a step-up token.
/// Unknown perm = `true` (fail closed). Bulk licence revoke: see `requires_step_up_bulk`.
#[must_use]
pub fn requires_step_up(perm: Perm) -> bool {
    row_of(perm).is_none_or(|r| r.step_up)
}

/// `licenses.transfer` bulk > 10 items also needs step-up (§6.6).
pub const BULK_STEP_UP_THRESHOLD: u32 = 10;

#[must_use]
pub fn requires_step_up_bulk(perm: Perm, items: u32) -> bool {
    requires_step_up(perm)
        || (matches!(perm, Perm::LicensesTransfer | Perm::LicensesRevoke)
            && items > BULK_STEP_UP_THRESHOLD)
}

#[must_use]
pub fn access_of(perm: Perm) -> Option<Access> {
    row_of(perm).map(|r| r.access)
}

#[must_use]
pub fn rule_of(perm: Perm) -> Option<Rule> {
    row_of(perm).map(|r| r.rule)
}

/// Product entitlement (check #2 part 2) the caller must verify; domain has no licence data.
/// `reports.<p>.*` -> p; `autopilot.*`, `freeze.*`, `cleaner.*` -> that product.
#[must_use]
pub fn required_product(perm: Perm) -> Option<Product> {
    let mut parts = perm.name().split('.');
    match (parts.next()?, parts.next()) {
        ("reports", Some(p)) => Product::parse(p),
        ("autopilot", _) => Some(Product::Autopilot),
        ("freeze", _) => Some(Product::Freeze),
        ("cleaner", _) => Some(Product::Cleaner),
        _ => None,
    }
}

/// GA uses `members.update` only for group membership (API must restrict fields).
#[must_use]
pub fn ga_field_limited(perm: Perm) -> bool {
    row_of(perm).is_some_and(|r| r.ga_limited)
}

fn cell_char(c: Option<Scope>) -> char {
    c.map_or('-', Scope::letter)
}

/// Stable text rendering of the whole matrix (snapshot test compares it with RBAC.md §4).
#[must_use]
pub fn render_matrix() -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:<36} O A G M V  {:<14} {:<14} {:<15} {:<15} {:<12} STEP",
        "permission", "feature", "narrowed_by", "cap", "rule", "access"
    );
    for r in ROWS {
        let feat = {
            let names: Vec<&str> = r.features.iter().flatten().map(|f| f.as_str()).collect();
            if names.is_empty() {
                "-".to_owned()
            } else {
                names.join("+")
            }
        };
        let narrow = r.narrowed_by.map_or("-", Feature::as_str);
        let cap = r.cap.map_or_else(|| "-".to_owned(), |c| format!("{c:?}"));
        let rule = format!("{:?}", r.rule);
        let access = format!("{:?}", r.access);
        let mut tail = String::from(if r.step_up { "step-up" } else { "-" });
        if r.confirm {
            tail.push_str(" confirm");
        }
        if r.aggregate_ok {
            tail.push_str(" aggregate-ok");
        }
        if let Some(f) = r.member_gate {
            tail.push_str(" member-gate:");
            tail.push_str(f.as_str());
        }
        if r.cap_self_ok {
            tail.push_str(" self-ok-without-cap");
        }
        if r.ga_limited {
            tail.push_str(" GA-limited");
        }
        let _ = writeln!(
            out,
            "{:<36} {} {} {} {} {}  {:<14} {:<14} {:<15} {:<15} {:<12} {}",
            r.perm.name(),
            cell_char(r.cells[0]),
            cell_char(r.cells[1]),
            cell_char(r.cells[2]),
            cell_char(r.cells[3]),
            cell_char(r.cells[4]),
            feat,
            narrow,
            cap,
            rule,
            access,
            tail,
        );
    }
    out
}
