//! Minimal `groups` / `group_memberships` (Phase 0: parent checks + Visibility::Groups fixtures;
//! full CRUD is Phase 1).

use crate::error::DbError;
use crate::queries::{GROUP_MEMBERSHIPS_INSERT, GROUPS_EXISTS, GROUPS_INSERT, MEMBERSHIPS_EXISTS};
use crate::repo::counters::{self, Counter};
use crate::repo::memberships;
use crate::sql;
use crate::tx::TenantTx;
use crate::write_guard::WriteOutcome;
use common::{GroupId, MembershipId};
use domain::rbac::Visibility;
use time::OffsetDateTime;

/// Name normalisation for uniqueness (trim + lowercase). Full NFKC rule lives with the Phase 1 repo.
fn norm(name: &str) -> String {
    name.trim().to_lowercase()
}

/// Create a group in the tx tenant; `parent` must be a group of the same tenant.
///
/// # Errors
/// `Invalid` (empty/long name), `ScopeMissing` (no actor), `NotFound("parent group")`,
/// `Conflict("groups.name_taken")`, server errors.
pub async fn create(
    tx: &mut TenantTx,
    id: GroupId,
    name: &str,
    parent: Option<GroupId>,
    now: OffsetDateTime,
) -> Result<GroupId, DbError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 128 {
        return Err(DbError::Invalid("group name must be 1..=128 chars"));
    }
    let actor = tx.require_actor()?;
    let tid = tx.tid();
    if let Some(p) = parent
        && !tx
            .inner
            .exists(sql::q(GROUPS_EXISTS).bind(tid).bind(p.0))
            .await?
    {
        return Err(DbError::NotFound("parent group"));
    }
    let n = norm(name);
    let r = tx
        .inner
        .execute(
            sql::q(GROUPS_INSERT)
                .bind(tid)
                .bind(id.0)
                .bind(parent.map(|p| p.0))
                .bind(name)
                .bind(n.as_str())
                .bind(n.as_str())
                .bind(actor.0)
                .bind(now),
        )
        .await;
    match r {
        Ok(rows) => rows.expect_one()?,
        Err(e) if e.is_duplicate_of("ux_groups_name") => {
            return Err(DbError::Conflict("groups.name_taken"));
        }
        Err(e) => return Err(e),
    }
    let tenant = tx.tenant();
    counters::add(&mut tx.inner, tenant, Counter::Groups, 1, now).await?;
    Ok(id)
}

/// Add `membership` to `group`; both must belong to the tx tenant (cross-tenant = NotFound).
///
/// # Errors
/// `NotFound`, `Conflict("groups.already_member")`, `ScopeMissing`, server errors.
pub async fn add_member(
    tx: &mut TenantTx,
    group: GroupId,
    membership: MembershipId,
    now: OffsetDateTime,
) -> Result<(), DbError> {
    let actor = tx.require_actor()?;
    // Visibility (review F8): the group must be inside the caller's scope, and so must the target
    // member. Invisible = NotFound (same answer as a cross-tenant id).
    let group_visible = match tx.visibility() {
        Visibility::Tenant => true,
        Visibility::Groups(gs) => gs.contains(&group),
        Visibility::SelfOnly => false,
    };
    if !group_visible {
        return Err(DbError::NotFound("group"));
    }
    if memberships::get(tx, membership).await?.is_none() {
        return Err(DbError::NotFound("membership"));
    }
    let tid = tx.tid();
    if !tx
        .inner
        .exists(sql::q(GROUPS_EXISTS).bind(tid).bind(group.0))
        .await?
    {
        return Err(DbError::NotFound("group"));
    }
    if !tx
        .inner
        .exists(sql::q(MEMBERSHIPS_EXISTS).bind(tid).bind(membership.0))
        .await?
    {
        return Err(DbError::NotFound("membership"));
    }
    match tx
        .inner
        .execute(
            sql::q(GROUP_MEMBERSHIPS_INSERT)
                .bind(tid)
                .bind(group.0)
                .bind(membership.0)
                .bind(actor.0)
                .bind(now),
        )
        .await
    {
        Ok(n) => n.expect_one(),
        Err(e) if e.is_duplicate_of("PRIMARY") => Err(DbError::Conflict("groups.already_member")),
        Err(e) => Err(e),
    }
}
