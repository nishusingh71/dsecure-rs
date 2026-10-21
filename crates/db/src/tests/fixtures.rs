//! Test fixtures (fake encrypted blobs: these tests exercise the data layer, not crypto).

use crate::pool::Db;
use crate::repo::memberships::{self, MembershipKind, MembershipStatus, NewMember};
use crate::repo::tenants::{self, NewOwner, NewTenant, TenantKind};
use crate::repo::users::{self, NewUser, UserStatus};
use common::{GroupId, MembershipId, TenantId, UserId};
use domain::rbac::{TenantRole, TenantScope, Visibility};
use smallvec_shim::groups;
use time::OffsetDateTime;

/// DATETIME(6) precision (microseconds) so round trips compare equal.
pub(crate) fn now() -> OffsetDateTime {
    let n = OffsetDateTime::now_utc();
    n.replace_nanosecond(n.nanosecond() / 1000 * 1000)
        .unwrap_or(n)
}

pub(crate) const CURSOR_KEY: &[u8] = b"0123456789abcdef0123456789abcdef";

/// Every fixture tenant carries this marker (shared TiDB test DB: fixture data is recognisable).
pub(crate) const TEST_TENANT_MARKER: &[u8] = b"TEST-FIXTURE:dsecure-rs-db-tests";

/// Unique job kind per test (shared DB: tests never see each other's jobs).
pub(crate) fn uniq_kind(prefix: &str) -> &'static str {
    let s = uuid::Uuid::now_v7().simple().to_string();
    Box::leak(format!("{prefix}.{}", &s[s.len() - 12..]).into_boxed_str())
}

pub(crate) fn scope(tenant: TenantId, actor: MembershipId) -> TenantScope {
    TenantScope::for_tests(tenant, actor, Visibility::Tenant, None)
}

pub(crate) fn scope_with(tenant: TenantId, actor: MembershipId, v: Visibility) -> TenantScope {
    TenantScope::for_tests(tenant, actor, v, None)
}

pub(crate) fn group_vis(gs: &[GroupId]) -> Visibility {
    Visibility::Groups(groups(gs))
}

pub(crate) async fn new_user(db: &Db) -> UserId {
    let mut bidx = [0u8; 32];
    bidx[..16].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
    bidx[16..].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
    let mut tx = db.identity_tx().await.expect("identity tx");
    let id = users::insert(
        &mut tx,
        &NewUser {
            id: UserId::new(),
            email_bidx: bidx,
            email_enc: vec![1, 2, 3],
            name_enc: None,
            status: UserStatus::Active,
        },
        now(),
    )
    .await
    .expect("insert user");
    tx.commit().await.expect("commit");
    id
}

pub(crate) struct TenantFx {
    pub(crate) tenant: TenantId,
    pub(crate) owner: MembershipId,
}

impl TenantFx {
    pub(crate) fn scope(&self) -> TenantScope {
        scope(self.tenant, self.owner)
    }
}

pub(crate) async fn new_tenant(db: &Db) -> TenantFx {
    let user = new_user(db).await;
    let mut tx = db.system_tx().await.expect("system tx");
    let c = tenants::create(
        &mut tx,
        &NewTenant {
            id: TenantId::new(),
            kind: TenantKind::Organization,
            display_name_enc: TEST_TENANT_MARKER.to_vec(),
        },
        &NewOwner {
            membership_id: MembershipId::new(),
            user_id: user,
            display_name_enc: None,
        },
        now(),
    )
    .await
    .expect("create tenant");
    tx.commit().await.expect("commit");
    TenantFx {
        tenant: c.tenant,
        owner: c.owner,
    }
}

pub(crate) fn new_member(user: UserId, role: TenantRole) -> NewMember {
    NewMember {
        id: MembershipId::new(),
        user_id: user,
        role,
        kind: MembershipKind::Primary,
        status: MembershipStatus::Active,
        parent_membership_id: None,
        department_id: None,
        display_name_enc: None,
    }
}

pub(crate) async fn add_member(db: &Db, t: &TenantFx, role: TenantRole) -> MembershipId {
    let user = new_user(db).await;
    let mut tx = db.tenant_tx(&t.scope()).await.expect("tenant tx");
    let id = memberships::insert(&mut tx, &new_member(user, role), now())
        .await
        .expect("insert member");
    tx.commit().await.expect("commit");
    id
}

/// `SmallVec` construction without a direct smallvec dependency (via domain's `GroupIds`).
mod smallvec_shim {
    use common::GroupId;
    use domain::rbac::GroupIds;

    pub(crate) fn groups(gs: &[GroupId]) -> GroupIds {
        gs.iter().copied().collect()
    }
}

/// Staff user + support grant on `tenant` (expires at `expires_at`), verified at `now()`.
/// Audit row for a platform-admin action by `actor` (dummy hash; hashing belongs to the audit crate).
pub(crate) fn admin_audit(
    actor: UserId,
    kind: &str,
    action: &str,
) -> crate::repo::audit::AuditRowRecord {
    crate::repo::audit::AuditRowRecord {
        id: uuid::Uuid::now_v7(),
        occurred_at: now(),
        tenant_id: None,
        actor_kind: kind.into(),
        actor_id: Some(actor.0),
        staff_grant_id: None,
        action: action.into(),
        outcome: "success".into(),
        target_type: None,
        target_id: None,
        request_id: None,
        ip_hmac: None,
        metadata: None,
        row_hash: vec![0u8; 32],
    }
}

async fn active_superadmin(db: &Db) -> Option<UserId> {
    let mut tx = db.system_tx().await.expect("tx");
    let row = tx
        .inner
        .fetch_optional(crate::sql::dynamic(String::from(
            "SELECT user_id FROM platform_staff WHERE role = 'platform_superadmin' AND revoked_at IS NULL LIMIT 1",
        )))
        .await
        .expect("q");
    tx.rollback().await;
    row.map(|r| UserId(crate::sql::uuid_col(&r, "user_id").expect("id")))
}

/// The scratch DB's superadmin (bootstrapped on first use through the platform-admin path).
///
/// Bounded: a `bootstrap_done` conflict means another test's bootstrap won (shared TiDB DB) and is
/// committed or about to be, so it re-reads a few times. It used to recurse without limit, which
/// overflowed the stack when the singleton marker existed WITHOUT any superadmin row (CI run #9).
pub(crate) async fn superadmin(db: &Db) -> UserId {
    const ATTEMPTS: u32 = 20;
    for _ in 0..ATTEMPTS {
        if let Some(u) = active_superadmin(db).await {
            return u;
        }
        let u = new_user(db).await;
        match crate::platform_admin::PlatformAdminDb::for_tests(db.clone())
            .bootstrap_first_superadmin(u, &admin_audit(u, "system", "staff.bootstrap"), now())
            .await
        {
            Ok(()) => return u,
            // Another test (shared DB) bootstrapped first: read its superadmin on the next round.
            Err(crate::DbError::Conflict("staff.bootstrap_done")) => {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(e) => panic!("bootstrap: {e}"),
        }
    }
    panic!(
        "superadmin fixture: bootstrap refused (marker/staff exist) but no active platform_superadmin          row after {ATTEMPTS} attempts"
    )
}

/// Support staff + grant (`scope`) on `tenant`, opened by the superadmin via the platform-admin path.
pub(crate) async fn staff_grant_scoped(
    db: &Db,
    tenant: TenantId,
    expires_at: OffsetDateTime,
    scope: crate::staff_grant::GrantScope,
) -> crate::staff_grant::VerifiedGrant {
    use crate::staff_grant;
    use domain::rbac::PlatformPerm;
    let admin = crate::platform_admin::PlatformAdminDb::for_tests(db.clone());
    let sa = superadmin(db).await;
    let staff = new_user(db).await;
    let mut tx = admin
        .admin_tx(
            sa,
            PlatformPerm::StaffManage,
            &admin_audit(sa, "staff", "staff.create"),
            now(),
        )
        .await
        .expect("admin tx");
    staff_grant::insert_staff(&mut tx, staff, domain::rbac::StaffRole::Support, now())
        .await
        .expect("staff");
    tx.commit().await.expect("c");
    let mut tx = admin
        .admin_tx(
            sa,
            PlatformPerm::StaffAccessOpen,
            &admin_audit(sa, "staff", "staff_access.open"),
            now(),
        )
        .await
        .expect("admin tx");
    let g = staff_grant::open_grant(
        &mut tx,
        staff,
        tenant,
        "ticket work",
        Some("T-1"),
        scope,
        expires_at,
        now(),
    )
    .await
    .expect("grant");
    tx.commit().await.expect("c");
    let mut tx = db.system_tx().await.expect("tx");
    let at = now();
    let v = match staff_grant::verify(&mut tx, staff, g, tenant, at).await {
        Ok(v) => v,
        Err(e) => {
            panic!("verify valid grant failed: {e:?} (verify at {at}, expires_at {expires_at})")
        }
    };
    tx.rollback().await;
    v
}

pub(crate) async fn staff_grant_until(
    db: &Db,
    tenant: TenantId,
    expires_at: OffsetDateTime,
) -> crate::staff_grant::VerifiedGrant {
    staff_grant_scoped(
        db,
        tenant,
        expires_at,
        crate::staff_grant::GrantScope::SupportWrite,
    )
    .await
}

pub(crate) async fn staff_grant(db: &Db, tenant: TenantId) -> crate::staff_grant::VerifiedGrant {
    staff_grant_until(db, tenant, now() + time::Duration::hours(1)).await
}

/// Audit row matching a staff grant (row_hash is a dummy; hashing belongs to the audit crate).
pub(crate) fn staff_audit(
    g: &crate::staff_grant::VerifiedGrant,
    action: &str,
) -> crate::repo::audit::AuditRowRecord {
    crate::repo::audit::AuditRowRecord {
        id: uuid::Uuid::now_v7(),
        occurred_at: now(),
        tenant_id: Some(g.tenant().0),
        actor_kind: "staff".into(),
        actor_id: Some(g.staff_user().0),
        staff_grant_id: Some(g.grant().0),
        action: action.into(),
        outcome: "success".into(),
        target_type: None,
        target_id: None,
        request_id: None,
        ip_hmac: None,
        metadata: None,
        row_hash: vec![0u8; 32],
    }
}
