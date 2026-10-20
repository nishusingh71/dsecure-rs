//! db: TiDB/MySQL data layer (DATABASE.md, PHASE0_SPEC §3.5).
//!
//! Tenant isolation without RLS (DATABASE.md §2.2), as enforced in this crate:
//! - L1 type level: tenant-class repository fns take `&mut TenantTx` and never a tenant id; the tenant
//!   comes from a `domain::rbac::TenantScope` (nil tenant/actor refused) or a re-verified job row.
//! - L2/L4: all SQL lives in `queries/**/*.sql` (+ a few engine/session consts); only `sql.rs` calls
//!   `sqlx::query` (single `#[allow(clippy::disallowed_methods)]`).
//! - L6: every tenant row mapper checks `row.tenant_id == tx.tenant` first (`TenantMismatch`, fail closed).
//! - Composite references: parent checks in the same tx (cross-tenant parent = `NotFound`); MySQL shadow
//!   FKs in CI (D-55).
//! - L8: the app DB user has no DELETE/DDL (`docs/ops/db_users.sql`).
//!
//! ```compile_fail
//! // L1: a tenant repository cannot be called with a non-tenant transaction.
//! async fn f(tx: &mut db::IdentityTx, id: common::MembershipId) {
//!     let _ = db::repo::memberships::get(tx, id).await;
//! }
//! ```

pub mod engine;
pub mod epochs;
pub mod error;
pub mod grants;
pub mod idempotency;
pub mod jobs;
pub mod keyset;
pub mod migrate;
mod migration_files;
pub mod options;
pub mod outbox;
pub mod platform_admin;
pub mod pool;
mod queries;
mod queries_internal;
pub mod repo;
pub mod retry;
mod sql;
pub mod staff_grant;
pub mod table_classes;
#[cfg(any(test, feature = "test-fixtures"))]
pub mod testing;
pub mod tx;
pub mod write_guard;

/// Reserved platform pseudo-tenant (migration `0100_0021`): owner of platform-scope rows that need a
/// tenant id (platform DEKs, audit anchor blobs). Status `platform`: never loginable, refused by
/// `Db::tenant_tx*`, excluded from tenant lists.
pub const PLATFORM_TENANT_ID: common::TenantId = common::TenantId(uuid::Uuid::from_u128(
    0x0000_0000_0000_7000_8000_0000_0000_0001,
));

pub use engine::Engine;
pub use epochs::{EpochMap, bump_epoch};
pub use error::DbError;
pub use jobs::{ClaimedJob, Enqueued, NewJob, Reaped};
pub use options::DbOptions;
pub use outbox::{OutboxEvent, outbox_insert, outbox_insert_system};
pub use pool::Db;
pub use repo::keys::DbDekStore;
pub use staff_grant::VerifiedGrant;
pub use table_classes::{TABLE_CLASSES, TableClass};
pub use tx::{
    IdentityTx, JobTx, PlatformTx, SystemJobTx, SystemTx, TenantTx, TxOrigin, assert_row_tenant,
};
pub use write_guard::WriteOutcome;

#[cfg(test)]
mod tests;
