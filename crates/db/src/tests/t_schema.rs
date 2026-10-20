//! Local schema check (subset of P0-20 `xtask schema-check`): every table is classified; tenant
//! tables have `tenant_id` leading the PK and every index; utf8mb4_bin everywhere; query files carry
//! the header and tenant-class queries bind `tenant_id`.

use super::harness::with_db;
use crate::queries::ALL;
use crate::sql;
use crate::table_classes::{TABLE_CLASSES, TOOLING_TABLES, TableClass, class_of};
use std::collections::{BTreeMap, BTreeSet};

#[tokio::test]
async fn schema_matches_table_classes() {
    with_db("schema", |db, _| async move {
        let mut tx = db.system_tx().await.expect("tx");
        let tables = tx
            .inner
            .fetch_all(sql::dynamic(String::from(
                "SELECT TABLE_NAME AS t, TABLE_COLLATION AS c FROM information_schema.TABLES \
                 WHERE TABLE_SCHEMA = DATABASE()",
            )))
            .await
            .expect("tables");
        let mut found = BTreeSet::new();
        for r in &tables {
            let t: String = sql::col(r, "t").expect("t");
            if TOOLING_TABLES.contains(&t.as_str()) {
                continue;
            }
            let c: String = sql::col(r, "c").expect("c");
            assert_eq!(c, "utf8mb4_bin", "{t}");
            assert!(class_of(&t).is_some(), "unclassified table {t}");
            found.insert(t);
        }
        let registry: BTreeSet<String> = TABLE_CLASSES.iter().map(|(t, _)| (*t).to_owned()).collect();
        assert_eq!(found, registry);

        let idx = tx
            .inner
            .fetch_all(sql::dynamic(String::from(
                "SELECT TABLE_NAME AS t, INDEX_NAME AS i, COLUMN_NAME AS c FROM information_schema.STATISTICS \
                 WHERE TABLE_SCHEMA = DATABASE() AND SEQ_IN_INDEX = 1",
            )))
            .await
            .expect("stats");
        let mut first_cols: BTreeMap<(String, String), String> = BTreeMap::new();
        for r in &idx {
            first_cols.insert(
                (sql::col(r, "t").expect("t"), sql::col(r, "i").expect("i")),
                sql::col(r, "c").expect("c"),
            );
        }
        for ((t, i), c) in &first_cols {
            // InnoDB auto-creates a helper index named after a shadow FK when no index starts with
            // the FK columns (e.g. `memberships.fk_m_user` on `user_id`). Shadow FKs exist only in the
            // MySQL CI run (never on TiDB), so those helper indexes are exempt.
            if class_of(t) == Some(TableClass::Tenant) && !i.starts_with("fk_") {
                assert_eq!(c, "tenant_id", "{t}.{i} is not tenant-leading");
            }
        }
        tx.rollback().await;
    })
    .await;
}

#[test]
fn query_files_have_headers_and_tenant_binds() {
    for (name, text) in ALL {
        assert!(text.starts_with("-- class: "), "{name} header");
        assert!(text.contains("params:"), "{name} params");
        let class = text
            .trim_start_matches("-- class: ")
            .split(|c: char| !c.is_ascii_alphabetic())
            .next()
            .unwrap_or("");
        let code: String = text
            .lines()
            .filter(|l| !l.trim_start().starts_with("--"))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(!code.contains("SELECT *"), "{name}: explicit columns only");
        assert!(
            !code.to_ascii_uppercase().contains(" OFFSET "),
            "{name}: keyset only"
        );
        assert!(
            !code.to_ascii_uppercase().contains("DELETE "),
            "{name}: no DELETE"
        );
        if class == "tenant" {
            let has_tenant_bind = code.contains("tenant_id = ?")
                || code.contains("INSERT INTO") && code.contains("tenant_id");
            assert!(
                has_tenant_bind,
                "{name}: tenant query without tenant_id bind"
            );
        }
    }
}
