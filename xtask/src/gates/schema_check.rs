//! `cargo xtask schema-check` (DATABASE.md §2.2 L5, T-DB7): migrated DB ka `information_schema` check.
//!
//! - har table `TABLE_CLASSES` mein (ya tooling table); registry ki har table DB mein,
//! - tenant-class: PK ka pehla column `tenant_id`, aur har secondary index ka pehla column `tenant_id`
//!   (`fk_*` index names MySQL par exempt: FK shadow indexes), TiDB par PK `CLUSTERED` (`TIDB_PK_TYPE`),
//! - `*_enc` columns `VARBINARY` hon (encrypted payloads binary rehte hain).
//!
//! Default: fresh scratch DB (`db::testing::ScratchDb`) banao, migrate, check, drop.
//! `--database-url-env NAME`: already-migrated DB ka URL env var `NAME` se (read-only; TiDB nightly ke liye).

use super::classes::{Class, parse_table_classes, parse_tooling_tables};
use super::scratch::{Scratch, runtime, short};
use super::{Violation, finish, repo_root, say};
use anyhow::{Context, Result, anyhow, bail};
use sqlx::Connection as _;
use sqlx::Row as _;
use sqlx::mysql::MySqlConnection;
use std::collections::{HashMap, HashSet};

pub const GATE: &str = "schema-check";

#[derive(Default, Debug)]
pub struct SchemaFacts {
    pub tables: Vec<String>,
    /// (table, column, data_type lowercase)
    pub columns: Vec<(String, String, String)>,
    /// (table, index_name, seq_in_index, column)
    pub indexes: Vec<(String, String, i64, Option<String>)>,
    /// TiDB only: table -> CLUSTERED / NONCLUSTERED / INT_HANDLE
    pub pk_types: Option<HashMap<String, String>>,
}

/// Pure check over already-fetched facts.
pub fn check_schema(
    facts: &SchemaFacts,
    classes: &HashMap<String, Class>,
    tooling: &[String],
) -> Vec<Violation> {
    let mut out = Vec::new();
    let loc = |t: &str| format!("table `{t}`");
    let present: HashSet<&str> = facts.tables.iter().map(String::as_str).collect();

    for t in &facts.tables {
        if tooling.iter().any(|x| x == t) {
            continue;
        }
        if !classes.contains_key(t) {
            out.push(Violation::new(
                GATE,
                loc(t),
                "table is not in TABLE_CLASSES (register it with a class)",
            ));
        }
    }
    let mut registered: Vec<&String> = classes.keys().collect();
    registered.sort();
    for t in registered {
        if !present.contains(t.as_str()) {
            out.push(Violation::new(
                GATE,
                loc(t),
                "listed in TABLE_CLASSES but missing from the migrated schema",
            ));
        }
    }

    for (t, c, ty) in &facts.columns {
        if c.ends_with("_enc") && ty != "varbinary" {
            out.push(Violation::new(
                GATE,
                format!("{}.{c}", loc(t)),
                format!("encrypted column must be VARBINARY, found {ty}"),
            ));
        }
    }

    for (t, class) in classes {
        if *class != Class::Tenant || !present.contains(t.as_str()) {
            continue;
        }
        let mut by_index: HashMap<&str, Vec<(i64, Option<&str>)>> = HashMap::new();
        for (it, name, seq, col) in &facts.indexes {
            if it == t {
                by_index
                    .entry(name.as_str())
                    .or_default()
                    .push((*seq, col.as_deref()));
            }
        }
        match by_index.get("PRIMARY") {
            Some(cols) => {
                let first = cols.iter().find(|(s, _)| *s == 1).and_then(|(_, c)| *c);
                if first != Some("tenant_id") {
                    out.push(Violation::new(
                        GATE,
                        loc(t),
                        format!(
                            "tenant table PRIMARY KEY must start with tenant_id (starts with {})",
                            first.unwrap_or("?")
                        ),
                    ));
                }
            }
            None => out.push(Violation::new(
                GATE,
                loc(t),
                "tenant table has no PRIMARY KEY",
            )),
        }
        let mut names: Vec<&str> = by_index
            .keys()
            .copied()
            .filter(|n| *n != "PRIMARY")
            .collect();
        names.sort();
        for name in names {
            if name.to_ascii_lowercase().starts_with("fk_") {
                continue;
            }
            let first = by_index
                .get(name)
                .and_then(|c| c.iter().find(|(s, _)| *s == 1))
                .and_then(|(_, c)| *c);
            if first != Some("tenant_id") {
                out.push(Violation::new(
                    GATE,
                    format!("{} index `{name}`", loc(t)),
                    format!(
                        "tenant table index must start with tenant_id (starts with {})",
                        first.unwrap_or("?")
                    ),
                ));
            }
        }
        if let Some(pk) = &facts.pk_types
            && let Some(kind) = pk.get(t)
            && !kind.eq_ignore_ascii_case("CLUSTERED")
        {
            out.push(Violation::new(
                GATE,
                loc(t),
                format!("tenant table PK must be CLUSTERED on TiDB (TIDB_PK_TYPE = {kind})"),
            ));
        }
    }
    out.sort_by(|a, b| a.location.cmp(&b.location).then(a.message.cmp(&b.message)));
    out
}

// xtask tooling: static information_schema reads only (no user input in the SQL), not app code.
#[allow(clippy::disallowed_methods)]
async fn fetch(conn: &mut MySqlConnection) -> Result<SchemaFacts> {
    let mut facts = SchemaFacts::default();
    let rows = sqlx::query(
        "SELECT CAST(table_name AS CHAR) FROM information_schema.tables \
         WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'",
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| anyhow!("information_schema.tables: {}", short(&e)))?;
    for r in rows {
        facts.tables.push(r.try_get::<String, _>(0)?);
    }
    let rows = sqlx::query(
        "SELECT CAST(table_name AS CHAR), CAST(column_name AS CHAR), CAST(data_type AS CHAR) \
         FROM information_schema.columns WHERE table_schema = DATABASE()",
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| anyhow!("information_schema.columns: {}", short(&e)))?;
    for r in rows {
        facts.columns.push((
            r.try_get::<String, _>(0)?,
            r.try_get::<String, _>(1)?,
            r.try_get::<String, _>(2)?.to_ascii_lowercase(),
        ));
    }
    let rows = sqlx::query(
        "SELECT CAST(table_name AS CHAR), CAST(index_name AS CHAR), CAST(seq_in_index AS SIGNED), \
         CAST(column_name AS CHAR) FROM information_schema.statistics WHERE table_schema = DATABASE()",
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| anyhow!("information_schema.statistics: {}", short(&e)))?;
    for r in rows {
        facts.indexes.push((
            r.try_get::<String, _>(0)?,
            r.try_get::<String, _>(1)?,
            r.try_get::<i64, _>(2)?,
            r.try_get::<Option<String>, _>(3)?,
        ));
    }
    let version: String = sqlx::query("SELECT CAST(VERSION() AS CHAR)")
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| anyhow!("VERSION(): {}", short(&e)))?
        .try_get(0)?;
    if version.to_ascii_lowercase().contains("tidb") {
        let rows = sqlx::query(
            "SELECT CAST(table_name AS CHAR), CAST(tidb_pk_type AS CHAR) FROM information_schema.tables \
             WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'",
        )
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| anyhow!("TIDB_PK_TYPE: {}", short(&e)))?;
        let mut m = HashMap::new();
        for r in rows {
            m.insert(r.try_get::<String, _>(0)?, r.try_get::<String, _>(1)?);
        }
        facts.pk_types = Some(m);
    }
    Ok(facts)
}

pub fn run(args: impl Iterator<Item = String>) -> Result<()> {
    let mut url_env: Option<String> = None;
    let mut args = args;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--database-url-env" => {
                url_env = Some(
                    args.next()
                        .context("--database-url-env needs a variable name")?,
                );
            }
            other => {
                bail!("unknown argument `{other}`; usage: schema-check [--database-url-env NAME]")
            }
        }
    }
    let root = repo_root()?;
    let src = std::fs::read_to_string(root.join("crates/db/src/table_classes.rs"))
        .context("crates/db/src/table_classes.rs not readable")?;
    let classes = parse_table_classes(&src)?;
    let tooling = parse_tooling_tables(&src);
    let rt = runtime()?;
    let facts = rt.block_on(async {
        if let Some(var) = url_env {
            // Process env var, else the dev env file (URL never printed).
            let url = super::scratch::url_from_env_or_file(&root, &var)?;
            let mut conn = MySqlConnection::connect(secrecy::ExposeSecret::expose_secret(&url))
                .await
                .map_err(|e| anyhow!("cannot connect via `{var}`: {}", short(&e)))?;
            let facts = fetch(&mut conn).await;
            let _ = conn.close().await;
            say!("schema-check: checking the database from `{var}` (read-only)");
            facts
        } else {
            let mut s = Scratch::open().await?;
            say!("schema-check: scratch database {} migrated", s.name());
            let facts = fetch(&mut s.conn).await;
            s.close().await?;
            facts
        }
    })?;
    let v = check_schema(&facts, &classes, &tooling);
    finish(GATE, &v, facts.tables.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classes() -> HashMap<String, Class> {
        [("groups", Class::Tenant), ("users", Class::Identity)]
            .into_iter()
            .map(|(t, c)| (t.to_owned(), c))
            .collect()
    }

    fn good() -> SchemaFacts {
        let ix =
            |t: &str, n: &str, s: i64, c: &str| (t.to_owned(), n.to_owned(), s, Some(c.to_owned()));
        SchemaFacts {
            tables: vec!["groups".into(), "users".into(), "_sqlx_migrations".into()],
            columns: vec![
                ("groups".into(), "name_enc".into(), "varbinary".into()),
                ("users".into(), "email_enc".into(), "varbinary".into()),
            ],
            indexes: vec![
                ix("groups", "PRIMARY", 1, "tenant_id"),
                ix("groups", "PRIMARY", 2, "id"),
                ix("groups", "ix_g_parent", 1, "tenant_id"),
                ix("groups", "ix_g_parent", 2, "parent_id"),
                ix("groups", "fk_g_parent", 1, "parent_id"),
                ix("users", "PRIMARY", 1, "id"),
            ],
            pk_types: None,
        }
    }

    fn msgs(f: &SchemaFacts) -> Vec<String> {
        check_schema(f, &classes(), &["_sqlx_migrations".to_owned()])
            .into_iter()
            .map(|v| format!("{} {}", v.location, v.message))
            .collect()
    }

    #[test]
    fn good_schema_passes() {
        let v = msgs(&good());
        assert!(v.is_empty(), "{v:?}");
    }

    #[test]
    fn non_tenant_leading_index_is_caught() {
        let mut f = good();
        f.indexes.push((
            "groups".into(),
            "ix_bad".into(),
            1,
            Some("created_at".into()),
        ));
        let v = msgs(&f);
        assert!(
            v.iter()
                .any(|m| m.contains("ix_bad") && m.contains("start with tenant_id")),
            "{v:?}"
        );
    }

    #[test]
    fn pk_not_leading_with_tenant_id_is_caught() {
        let mut f = good();
        f.indexes.retain(|i| !(i.0 == "groups" && i.1 == "PRIMARY"));
        f.indexes
            .push(("groups".into(), "PRIMARY".into(), 1, Some("id".into())));
        let v = msgs(&f);
        assert!(
            v.iter()
                .any(|m| m.contains("PRIMARY KEY must start with tenant_id")),
            "{v:?}"
        );
    }

    #[test]
    fn unclassified_and_missing_tables_are_caught() {
        let mut f = good();
        f.tables.push("mystery".into());
        f.tables.retain(|t| t != "users");
        let v = msgs(&f);
        assert!(
            v.iter()
                .any(|m| m.contains("`mystery`") && m.contains("not in TABLE_CLASSES")),
            "{v:?}"
        );
        assert!(
            v.iter()
                .any(|m| m.contains("`users`") && m.contains("missing from the migrated schema")),
            "{v:?}"
        );
    }

    #[test]
    fn non_varbinary_encrypted_column_is_caught() {
        let mut f = good();
        f.columns
            .push(("users".into(), "phone_enc".into(), "varchar".into()));
        let v = msgs(&f);
        assert!(
            v.iter()
                .any(|m| m.contains("phone_enc") && m.contains("VARBINARY")),
            "{v:?}"
        );
    }

    #[test]
    fn tidb_non_clustered_tenant_pk_is_caught() {
        let mut f = good();
        f.pk_types = Some(
            [("groups".to_owned(), "NONCLUSTERED".to_owned())]
                .into_iter()
                .collect(),
        );
        let v = msgs(&f);
        assert!(v.iter().any(|m| m.contains("CLUSTERED")), "{v:?}");
    }

    /// The checked database is only READ: every statement in this file is a SELECT (no DDL/DML).
    #[test]
    fn schema_check_issues_only_selects() {
        let src = include_str!("schema_check.rs");
        let re = regex::Regex::new(r#"sqlx::query\(\s*"([A-Za-z]+)"#).expect("re");
        let mut n = 0;
        for c in re.captures_iter(src) {
            n += 1;
            assert_eq!(
                c[1].to_ascii_uppercase(),
                "SELECT",
                "non-SELECT statement in schema-check"
            );
        }
        assert!(n >= 4, "expected the information_schema queries, found {n}");
        for bad in [format!("raw_{}(", "sql"), format!(".{}(", "execute")] {
            assert!(
                !src.contains(&bad),
                "schema-check must not execute statements: {bad}"
            );
        }
    }
}
