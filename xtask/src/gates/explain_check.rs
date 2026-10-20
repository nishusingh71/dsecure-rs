//! `cargo xtask explain-check [--all]` (DATABASE.md §9.2, T-DB13): `EXPLAIN` har "hot" query file par.
//!
//! Hot = query file ke header mein ek line `-- hot` (ya `-- hot: <reason>`). `--all` = saari query files.
//! Fail: tenant-class table par full table scan (MySQL `type = ALL`, `type = index`; TiDB `TableFullScan`,
//! `IndexFullScan`).
//!
//! Local MySQL scratch DB khali hai, isliye optimizer chhote/khali tables par kabhi `ALL` chun sakta hai:
//! yeh gate local par sanity hai. Asli gate nightly TiDB job (seeded >= 10k users, 50k sessions) par chalega:
//! TiDB ka EXPLAIN alag format hai, yahan uska parser (`analyze_tidb`) tayyar hai par TiDB par chalaya nahi gaya.

use super::classes::Class;
use super::scratch::{Scratch, runtime, short};
use super::sql_lint::{hot_files, load_ctx, parse_header, top_level_occurrences};
use super::{Violation, finish, repo_root, say};
use anyhow::{Result, anyhow, bail};
use sqlx::Row as _;
use std::collections::HashMap;

pub const GATE: &str = "explain-check";

/// `?` -> literal for EXPLAIN. LIMIT/OFFSET get `1`; everything else a string literal that compares
/// cleanly with BINARY/BIGINT/VARCHAR/DATETIME columns without defeating index use. Quoted strings untouched.
pub fn substitute_placeholders(sql: &str) -> String {
    let sql = sql.replace("/*GROUP_IDS*/", "?");
    let mut out = String::with_capacity(sql.len());
    let mut chars = sql.chars().peekable();
    let mut quote: Option<char> = None;
    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                out.push(c);
                if c == q {
                    quote = None;
                }
            }
            None => match c {
                '\'' | '"' | '`' => {
                    quote = Some(c);
                    out.push(c);
                }
                '-' if chars.peek() == Some(&'-') => {
                    // line comment: copy through newline
                    out.push(c);
                    for n in chars.by_ref() {
                        out.push(n);
                        if n == '\n' {
                            break;
                        }
                    }
                }
                '?' => {
                    let prev = out
                        .trim_end()
                        .rsplit(char::is_whitespace)
                        .next()
                        .unwrap_or("");
                    if prev.eq_ignore_ascii_case("limit") || prev.eq_ignore_ascii_case("offset") {
                        out.push('1');
                    } else {
                        out.push_str("'2026-01-01 00:00:00'");
                    }
                }
                _ => out.push(c),
            },
        }
    }
    out
}

/// One MySQL EXPLAIN row (only what the gate needs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MyPlanRow {
    pub select_type: Option<String>,
    pub table: Option<String>,
    pub access_type: Option<String>,
}

fn tenant_by_alias(
    alias: &str,
    alias_to_table: &HashMap<String, String>,
    classes: &HashMap<String, Class>,
) -> Option<String> {
    let table = alias_to_table
        .get(alias)
        .map_or(alias, String::as_str)
        .to_owned();
    (classes.get(&table) == Some(&Class::Tenant)).then_some(table)
}

pub fn analyze_mysql(
    rows: &[MyPlanRow],
    alias_to_table: &HashMap<String, String>,
    classes: &HashMap<String, Class>,
) -> Vec<String> {
    let mut out = Vec::new();
    for r in rows {
        // INSERT-target row (select_type INSERT) is a write, not a scan.
        if r.select_type
            .as_deref()
            .is_some_and(|s| s.eq_ignore_ascii_case("INSERT"))
        {
            continue;
        }
        let (Some(t), Some(ty)) = (&r.table, &r.access_type) else {
            continue;
        };
        if (ty.eq_ignore_ascii_case("ALL") || ty.eq_ignore_ascii_case("index"))
            && let Some(table) = tenant_by_alias(&t.to_ascii_lowercase(), alias_to_table, classes)
        {
            out.push(format!(
                "full {} on tenant table `{table}` (type = {ty})",
                if ty.eq_ignore_ascii_case("ALL") {
                    "table scan"
                } else {
                    "index scan"
                }
            ));
        }
    }
    out
}

/// TiDB `EXPLAIN FORMAT='brief'` rows: (operator id, access object like `table:users, index:ix(a)`).
// Nightly TiDB job (not wired yet): scratch DB local MySQL hai, isliye abhi sirf tests use karte hain.
#[cfg_attr(not(test), allow(dead_code))]
pub fn analyze_tidb(rows: &[(String, String)], classes: &HashMap<String, Class>) -> Vec<String> {
    let mut out = Vec::new();
    for (id, access) in rows {
        if !(id.contains("TableFullScan") || id.contains("IndexFullScan")) {
            continue;
        }
        let table = access
            .split(',')
            .find_map(|p| p.trim().strip_prefix("table:"))
            .map(str::to_ascii_lowercase);
        if let Some(t) = table
            && classes.get(&t) == Some(&Class::Tenant)
        {
            out.push(format!(
                "{} on tenant table `{t}`",
                id.split('_').next().unwrap_or(id)
            ));
        }
    }
    out
}

// xtask tooling: EXPLAIN of static query files (placeholders substituted), local scratch DB only.
#[allow(clippy::disallowed_methods)]
async fn explain_mysql(
    conn: &mut sqlx::mysql::MySqlConnection,
    sql: String,
) -> Result<Vec<MyPlanRow>> {
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!("EXPLAIN {sql}")))
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| anyhow!("{}", short(&e)))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(MyPlanRow {
            select_type: r.try_get::<Option<String>, _>("select_type").ok().flatten(),
            table: r.try_get::<Option<String>, _>("table").ok().flatten(),
            access_type: r.try_get::<Option<String>, _>("type").ok().flatten(),
        });
    }
    Ok(out)
}

pub fn run(args: impl Iterator<Item = String>) -> Result<()> {
    let mut all = false;
    for a in args {
        match a.as_str() {
            "--all" => all = true,
            other => bail!("unknown argument `{other}`; usage: explain-check [--all]"),
        }
    }
    let root = repo_root()?;
    let ctx = load_ctx(&root)?;
    let files = hot_files(&root, all)?;
    if files.is_empty() {
        say!("explain-check: no query file is marked `-- hot` (use --all to check every file)");
        return finish(GATE, &[], 0);
    }
    let rt = runtime()?;
    let violations = rt.block_on(async {
        let mut s = Scratch::open().await?;
        let mut violations = Vec::new();
        for (path, text) in &files {
            let alias_to_table: HashMap<String, String> = top_level_occurrences(text)
                .into_iter()
                .map(|o| (o.alias, o.table))
                .collect();
            let header_class = parse_header(text).class;
            let _ = header_class;
            match explain_mysql(&mut s.conn, substitute_placeholders(text)).await {
                Ok(rows) => {
                    for m in analyze_mysql(&rows, &alias_to_table, &ctx.classes) {
                        violations.push(Violation::new(GATE, path.clone(), m));
                    }
                }
                Err(e) => violations.push(Violation::new(
                    GATE,
                    path.clone(),
                    format!("EXPLAIN failed: {e}"),
                )),
            }
        }
        s.close().await?;
        Ok::<_, anyhow::Error>(violations)
    })?;
    finish(GATE, &violations, files.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classes() -> HashMap<String, Class> {
        [("groups", Class::Tenant), ("jobs", Class::Infra)]
            .into_iter()
            .map(|(t, c)| (t.to_owned(), c))
            .collect()
    }

    #[test]
    fn placeholders_are_substituted_outside_quotes_only() {
        let s = substitute_placeholders(
            "-- hdr ? here\nSELECT id FROM t WHERE a = ? AND b = '?' LIMIT ?",
        );
        assert!(s.contains("-- hdr ? here"));
        assert!(s.contains("a = '2026-01-01 00:00:00'"));
        assert!(s.contains("b = '?'"));
        assert!(s.trim_end().ends_with("LIMIT 1"), "{s}");
        let s = substitute_placeholders("SELECT 1 WHERE id IN (/*GROUP_IDS*/)");
        assert!(!s.contains('?'), "{s}");
    }

    #[test]
    fn mysql_full_scan_on_tenant_table_is_caught() {
        let alias: HashMap<String, String> = [("g".to_owned(), "groups".to_owned())]
            .into_iter()
            .collect();
        let rows = vec![MyPlanRow {
            select_type: None,
            table: Some("g".into()),
            access_type: Some("ALL".into()),
        }];
        let v = analyze_mysql(&rows, &alias, &classes());
        assert_eq!(v.len(), 1, "{v:?}");
        let rows = vec![MyPlanRow {
            select_type: None,
            table: Some("g".into()),
            access_type: Some("index".into()),
        }];
        assert_eq!(analyze_mysql(&rows, &alias, &classes()).len(), 1);
    }

    #[test]
    fn insert_target_row_is_not_a_scan() {
        let rows = vec![MyPlanRow {
            select_type: Some("INSERT".into()),
            table: Some("groups".into()),
            access_type: Some("ALL".into()),
        }];
        assert!(analyze_mysql(&rows, &HashMap::new(), &classes()).is_empty());
    }

    #[test]
    fn mysql_index_access_and_non_tenant_scans_pass() {
        let alias = HashMap::new();
        let ok = vec![
            MyPlanRow {
                select_type: None,
                table: Some("groups".into()),
                access_type: Some("ref".into()),
            },
            MyPlanRow {
                select_type: None,
                table: Some("groups".into()),
                access_type: Some("const".into()),
            },
            MyPlanRow {
                select_type: None,
                table: Some("jobs".into()),
                access_type: Some("ALL".into()),
            },
            MyPlanRow {
                select_type: None,
                table: None,
                access_type: None,
            },
        ];
        assert!(analyze_mysql(&ok, &alias, &classes()).is_empty());
    }

    #[test]
    fn tidb_full_scans_on_tenant_tables_are_caught() {
        let rows = vec![
            ("TableFullScan_5".to_owned(), "table:groups".to_owned()),
            (
                "IndexRangeScan_6".to_owned(),
                "table:groups, index:ix(a)".to_owned(),
            ),
            ("TableFullScan_7".to_owned(), "table:jobs".to_owned()),
        ];
        let v = analyze_tidb(&rows, &classes());
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(v[0].contains("groups"));
    }
}
