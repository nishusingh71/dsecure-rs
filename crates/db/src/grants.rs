//! Least-privilege DB grants generated from `TABLE_CLASSES` (DATABASE.md §2.5, L8; review F5).
//! `docs/ops/db_users.sql` is produced from [`grant_statements`] (a test keeps the doc in sync), and
//! the local grant test applies the same statements to a scratch database.
//!
//! Rules:
//! - app: S/I/U on tenant, identity, directory and infra tables; audit tables S/I only (append-only);
//!   `data_keys`, `signing_keys` S/I (lazy tenant DEK); `platform_staff`, `staff_access_grants` SELECT
//!   only (creating staff/grants = platform-admin path). Never DELETE, never DDL.
//! - worker: what jobs need: tenant tables S/I/U, identity/directory S, jobs/outbox S/I/U, audit S/I,
//!   `data_keys` S/I (lazy tenant DEK), no staff tables, no idempotency keys.
//! - readonly: SELECT everywhere.
//! - platform_admin (`db::platform_admin`): S/I + COLUMN-level UPDATE on `platform_staff(role,
//!   revoked_at)`, `staff_access_grants(closed_at)`, `data_keys(status, active_marker, rotated_at,
//!   destroyed_at, destroyed_by_approval)`, `signing_keys(status, not_after)`; S/I on `audit_events`;
//!   S on `tenants`. Never `wrapped_dek`, `kek_ref`, `staff_user_id`, `tenant_id`.

use crate::table_classes::{TABLE_CLASSES, TableClass};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DbRole {
    App,
    Worker,
    Readonly,
    PlatformAdmin,
}

const SIU: &str = "SELECT, INSERT, UPDATE";
const SI: &str = "SELECT, INSERT";
const SU: &str = "SELECT, UPDATE";
const S: &str = "SELECT";

const AUDIT: &[&str] = &["audit_events", "audit_chain_blocks"];
const STAFF: &[&str] = &["platform_staff", "staff_access_grants"];
const KEYS: &[&str] = &["data_keys", "signing_keys"];

/// Privileges of `role` on `table` (`None` = no grant at all).
#[must_use]
pub fn privileges(role: DbRole, table: &str, class: TableClass) -> Option<&'static str> {
    let audit = AUDIT.contains(&table);
    let staff = STAFF.contains(&table);
    let keys = KEYS.contains(&table);
    match role {
        DbRole::Readonly => Some(S),
        // R1: no INSERT/UPDATE on staff tables for the app (platform-admin path only).
        DbRole::App => Some(if staff || table == "signing_keys" {
            S
        } else if audit || keys {
            SI
        } else {
            SIU
        }),
        DbRole::Worker => match (class, table) {
            _ if audit => Some(SI),
            _ if staff => None,
            (_, "data_keys") => Some(SI),
            (_, "signing_keys" | "tenants") => Some(S),
            (_, "idempotency_keys") => None,
            (_, "authz_epochs") => Some(SU),
            (TableClass::Identity | TableClass::Directory, _) => Some(S),
            _ => Some(SIU),
        },
        // R5: column-level UPDATE only; never wrapped_dek / kek_ref / staff_user_id / tenant_id.
        DbRole::PlatformAdmin => match table {
            "platform_staff" => Some("SELECT, INSERT, UPDATE (role, revoked_at)"),
            "staff_access_grants" => Some("SELECT, INSERT, UPDATE (closed_at)"),
            "data_keys" => Some(
                "SELECT, INSERT, UPDATE (status, active_marker, rotated_at, destroyed_at, destroyed_by_approval)",
            ),
            "signing_keys" => Some("SELECT, INSERT, UPDATE (status, not_after)"),
            "audit_events" => Some(SI),
            "tenants" => Some(S),
            _ => None,
        },
    }
}

fn ident_ok(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// `GRANT ... ON \`db\`.\`table\` TO <grantee>;` for every classified table (+ SELECT on the sqlx
/// bookkeeping table for app/worker/readonly readiness checks). `grantee` is a literal like
/// `'dsecure_app'@'%'` (caller-controlled, never user input).
///
/// # Panics
/// Never (invalid identifiers yield an empty list).
#[must_use]
pub fn grant_statements(role: DbRole, database: &str, grantee: &str) -> Vec<String> {
    if !ident_ok(database) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (table, class) in TABLE_CLASSES {
        if let Some(p) = privileges(role, table, *class) {
            out.push(format!("GRANT {p} ON `{database}`.`{table}` TO {grantee};"));
        }
    }
    if role != DbRole::PlatformAdmin {
        out.push(format!(
            "GRANT SELECT ON `{database}`.`_sqlx_migrations` TO {grantee};"
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_delete_or_ddl_ever_and_audit_append_only() {
        for role in [
            DbRole::App,
            DbRole::Worker,
            DbRole::Readonly,
            DbRole::PlatformAdmin,
        ] {
            for g in grant_statements(role, "d", "'u'@'%'") {
                for bad in [
                    "DELETE",
                    "DROP",
                    "CREATE",
                    "ALTER",
                    "ALL",
                    "INDEX",
                    "GRANT OPTION",
                ] {
                    assert!(!g[6..].contains(bad), "{role:?}: {g}");
                }
            }
        }
        for (t, c) in TABLE_CLASSES {
            let app = privileges(DbRole::App, t, *c).unwrap_or("");
            if [
                "audit_events",
                "audit_chain_blocks",
                "platform_staff",
                "staff_access_grants",
                "data_keys",
            ]
            .contains(t)
            {
                assert!(!app.contains("UPDATE"), "{t}");
            }
        }
        assert!(privileges(DbRole::Worker, "staff_access_grants", TableClass::Platform).is_none());
        for t in ["platform_staff", "staff_access_grants"] {
            assert_eq!(
                privileges(DbRole::App, t, TableClass::Platform),
                Some("SELECT")
            );
        }
        for (_, p) in TABLE_CLASSES
            .iter()
            .filter_map(|(t, c)| privileges(DbRole::PlatformAdmin, t, *c).map(|p| (t, p)))
        {
            if p.contains("UPDATE") {
                assert!(p.contains("UPDATE ("), "column-level only: {p}");
            }
            for col in ["wrapped_dek", "kek_ref", "staff_user_id", "tenant_id"] {
                assert!(!p.contains(col), "{p}");
            }
        }
        assert!(grant_statements(DbRole::App, "bad name;", "x").is_empty());
    }

    /// `docs/ops/db_users.sql` must contain exactly what the generator produces for production.
    #[test]
    fn ops_doc_matches_generator() {
        let doc = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/ops/db_users.sql"),
        )
        .expect("docs/ops/db_users.sql");
        for (role, grantee) in [
            (DbRole::App, "'dsecure_app'@'%'"),
            (DbRole::Worker, "'dsecure_worker'@'%'"),
            (DbRole::Readonly, "'dsecure_readonly'@'%'"),
            (DbRole::PlatformAdmin, "'dsecure_platform_admin'@'%'"),
        ] {
            for g in grant_statements(role, "dsecure_prod", grantee) {
                assert!(doc.contains(&g), "missing in db_users.sql: {g}");
            }
        }
        assert!(!doc.contains("ON `dsecure_prod`.* TO 'dsecure_app'"));
    }

    /// Prints the generated block (used to refresh the doc): `cargo test -p db print_grants -- --ignored --nocapture`.
    #[test]
    #[ignore = "doc generation helper"]
    fn print_grants() {
        for (role, grantee) in [
            (DbRole::App, "'dsecure_app'@'%'"),
            (DbRole::Worker, "'dsecure_worker'@'%'"),
            (DbRole::Readonly, "'dsecure_readonly'@'%'"),
            (DbRole::PlatformAdmin, "'dsecure_platform_admin'@'%'"),
        ] {
            println!("-- {role:?}");
            for g in grant_statements(role, "dsecure_prod", grantee) {
                println!("{g}");
            }
        }
    }
}
