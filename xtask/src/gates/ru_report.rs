//! `cargo xtask ru-report --database-url-env NAME` (P0-22): `EXPLAIN ANALYZE` of every `-- hot` query
//! file on an already-migrated database, with a small fixture seed, written to `docs/RU_REPORT.md`.
//!
//! - URL from the process env var `NAME`, else the same key in `.dev/dev.env` (never printed).
//! - Seed: one test-marked fixture tenant (`RU_TENANT`, `display_name_enc = 'TEST-FIXTURE:ru-report'`)
//!   with <= 300 rows per table; inserted only if that tenant row does not exist yet. Nothing is
//!   deleted or updated; no DDL; no other database is referenced.
//! - SELECT files: `EXPLAIN ANALYZE` (executes the SELECT). Non-SELECT files: plain `EXPLAIN` (never
//!   executed). Placeholders get literals of the seeded fixture rows by parameter name.
//! - RU: parsed from TiDB `execution info` (`RU:` / `ru:`) when present; else `n/a` with the reason.
//!   MySQL: always `n/a (MySQL)`.

use super::scratch::{runtime, short, url_from_env_or_file};
use super::sql_lint::{hot_files, parse_header};
use super::{repo_root, say};
use anyhow::{Context, Result, anyhow, bail};
use regex::Regex;
use secrecy::ExposeSecret as _;
use sqlx::Connection as _;
use sqlx::Row as _;
use sqlx::mysql::{MySqlConnection, MySqlRow};
use std::fmt::Write as _;

pub const GATE: &str = "ru-report";

/// Fixture tenant (test-marked, fixed): `00000000-0000-7000-8000-00000000f1f0`.
pub const RU_TENANT_HEX: &str = "0000000000007000800000000000F1F0";
const MARKER: &str = "TEST-FIXTURE:ru-report";
const USERS: usize = 100;
const SESSIONS: usize = 300;
const JOBS: usize = 200;
const OUTBOX: usize = 200;
const GROUPS: usize = 10;

fn hex16(prefix: u8, i: usize) -> String {
    // Deterministic fixture ids: 0x<prefix>..<i> (UUIDv7-shaped version nibble, unique per table).
    format!("{prefix:02X}{i:010X}70008000{i:012X}")
}

fn hex32(prefix: u8, i: usize) -> String {
    format!("{}{}", hex16(prefix, i), hex16(prefix ^ 0x80, i))
}

// xtask tooling: explicit statements of this tool only (seed inserts under the fixture tenant,
// EXPLAIN of repo query files). No DDL, no DELETE.
#[allow(clippy::disallowed_methods)]
async fn exec(conn: &mut MySqlConnection, sql: String) -> Result<u64> {
    sqlx::query(sqlx::AssertSqlSafe(sql))
        .execute(&mut *conn)
        .await
        .map(|r| r.rows_affected())
        .map_err(|e| anyhow!("{}", short(&e)))
}

#[allow(clippy::disallowed_methods)]
async fn fetch(conn: &mut MySqlConnection, sql: String) -> Result<Vec<MySqlRow>> {
    sqlx::query(sqlx::AssertSqlSafe(sql))
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| anyhow!("{}", short(&e)))
}

fn col_str(r: &MySqlRow, i: usize) -> String {
    r.try_get::<String, _>(i)
        .or_else(|_| {
            r.try_get::<Vec<u8>, _>(i)
                .map(|b| String::from_utf8_lossy(&b).into_owned())
        })
        .unwrap_or_default()
}

async fn insert_batches(conn: &mut MySqlConnection, head: &str, rows: Vec<String>) -> Result<u64> {
    let mut n = 0;
    for chunk in rows.chunks(50) {
        n += exec(conn, format!("{head} VALUES {}", chunk.join(", "))).await?;
    }
    Ok(n)
}

const NOW: &str = "'2026-10-20 12:00:00.000000'";

/// Seed the fixture tenant once. Returns rows inserted (0 = already seeded).
async fn seed(conn: &mut MySqlConnection) -> Result<u64> {
    let t = RU_TENANT_HEX;
    let exists = fetch(conn, format!("SELECT 1 FROM tenants WHERE id = X'{t}'")).await?;
    if !exists.is_empty() {
        return Ok(0);
    }
    let mut n = 0;
    n += exec(
        conn,
        format!(
            "INSERT INTO tenants (id, kind, display_name_enc, status, data_region, created_at, updated_at, version) \
             VALUES (X'{t}', 'organization', '{MARKER}', 'active', 'default', {NOW}, {NOW}, 1)"
        ),
    )
    .await?;
    n += exec(
        conn,
        format!(
            "INSERT INTO authz_epochs (tenant_id, epoch, updated_at) VALUES (X'{t}', 1, {NOW})"
        ),
    )
    .await?;
    n += exec(conn, format!("INSERT INTO tenant_counters (tenant_id, members_active, updated_at) VALUES (X'{t}', {USERS}, {NOW})")).await?;
    let users = (0..USERS)
        .map(|i| {
            format!(
                "(X'{}', X'{}', '{MARKER}', 'active', {NOW}, {NOW})",
                hex16(0xA1, i),
                hex32(0xB1, i)
            )
        })
        .collect();
    n += insert_batches(
        conn,
        "INSERT INTO users (id, email_bidx, email_enc, status, created_at, updated_at)",
        users,
    )
    .await?;
    let members = (0..USERS)
        .map(|i| {
            format!(
                "(X'{t}', X'{}', X'{}', 'member', 40, 'primary', 'active', {NOW}, {NOW})",
                hex16(0xA2, i),
                hex16(0xA1, i)
            )
        })
        .collect();
    n += insert_batches(conn, "INSERT INTO memberships (tenant_id, id, user_id, role, role_rank, kind, status, created_at, updated_at)", members).await?;
    let dir = (0..USERS)
        .map(|i| {
            format!(
                "(X'{}', X'{t}', X'{}', 'active', 'member', {NOW})",
                hex16(0xA1, i),
                hex16(0xA2, i)
            )
        })
        .collect();
    n += insert_batches(conn, "INSERT INTO membership_directory (user_id, tenant_id, membership_id, status, role, updated_at)", dir).await?;
    let groups = (0..GROUPS)
        .map(|i| {
            format!(
                "(X'{t}', X'{}', 'g{i}', 'g{i}', 'g{i}', X'{}', {NOW})",
                hex16(0xA3, i),
                hex16(0xA2, 0)
            )
        })
        .collect();
    n += insert_batches(conn, "INSERT INTO `groups` (tenant_id, id, name, name_norm, name_active, created_by_membership, created_at)", groups).await?;
    let gm = (0..USERS / 2)
        .map(|i| {
            format!(
                "(X'{t}', X'{}', X'{}', X'{}', {NOW})",
                hex16(0xA3, i % GROUPS),
                hex16(0xA2, i),
                hex16(0xA2, 0)
            )
        })
        .collect();
    n += insert_batches(
        conn,
        "INSERT INTO group_memberships (tenant_id, group_id, membership_id, added_by, added_at)",
        gm,
    )
    .await?;
    let sessions = (0..SESSIONS)
        .map(|i| {
            format!(
                "(X'{}', X'{}', X'{t}', X'{}', 'member', 'web', {NOW}, {NOW}, '2027-01-01 00:00:00')",
                hex16(0xA4, i),
                hex16(0xA1, i % USERS),
                hex16(0xA2, i % USERS)
            )
        })
        .collect();
    n += insert_batches(conn, "INSERT INTO sessions (id, user_id, tenant_id, membership_id, principal_kind, client_kind, created_at, last_seen_at, expires_at)", sessions).await?;
    let rts = (0..SESSIONS)
        .map(|i| {
            format!(
                "(X'{}', X'{}', X'{}', X'{}', {NOW}, '2027-01-01 00:00:00')",
                hex16(0xA5, i),
                hex16(0xA4, i),
                hex16(0xA6, i / 3),
                hex32(0xC1, i)
            )
        })
        .collect();
    n += insert_batches(
        conn,
        "INSERT INTO refresh_tokens (id, session_id, family_id, token_hash, issued_at, expires_at)",
        rts,
    )
    .await?;
    // Finished jobs / published outbox only: no worker will ever pick them up.
    let jobs = (0..JOBS)
        .map(|i| {
            format!(
                "(X'{}', 'ru.seed', 'ru-seed-{i}', X'{t}', '{{}}', 'succeeded', {NOW}, 1, {NOW}, {NOW})",
                hex16(0xA7, i)
            )
        })
        .collect();
    n += insert_batches(conn, "INSERT INTO jobs (id, kind, job_key, tenant_id, payload, status, run_after, attempts, created_at, finished_at)", jobs).await?;
    let ob = (0..OUTBOX)
        .map(|i| {
            format!(
                "(X'{}', X'{t}', 'ru.seed', 'fixture', X'{}', '{{}}', {NOW}, {NOW})",
                hex16(0xA8, i),
                hex16(0xA2, i % USERS)
            )
        })
        .collect();
    n += insert_batches(conn, "INSERT INTO outbox_events (id, tenant_id, event_type, aggregate_type, aggregate_id, payload, created_at, published_at)", ob).await?;
    Ok(n)
}

/// Literal for a named placeholder of a hot query (seeded fixture values).
fn literal(file: &str, param: &str) -> String {
    let p = param.trim().trim_end_matches("...");
    let t = format!("X'{RU_TENANT_HEX}'");
    match p {
        "tenant_id" | "scope_key" => t,
        "after_id" => "X'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'".into(),
        "after_tenant_id" => "X'00000000000000000000000000000000'".into(),
        "limit" => "50".into(),
        "membership_id" | "actor_id" => format!("X'{}'", hex16(0xA2, 1)),
        "user_id" => format!("X'{}'", hex16(0xA1, 1)),
        "family_id" => format!("X'{}'", hex16(0xA6, 1)),
        "token_hash" => format!("X'{}'", hex32(0xC1, 1)),
        "email_bidx" => format!("X'{}'", hex32(0xB1, 1)),
        "group_id" => format!("X'{}'", hex16(0xA3, 1)),
        "kind" => "'ru.seed'".into(),
        "purpose" => "'jwt_member'".into(),
        "kid" => "'ru-none'".into(),
        "id" if file.contains("sessions/") => format!("X'{}'", hex16(0xA4, 1)),
        "id" if file.contains("memberships/") => format!("X'{}'", hex16(0xA2, 1)),
        "id" => format!("X'{}'", hex16(0xA2, 1)),
        _ => NOW.into(),
    }
}

/// Replace `?` (outside quotes/comments) in order with the literals for `params`.
fn bind_literals(file: &str, sql: &str, params: &[String]) -> Option<String> {
    let sql = sql.replace("/*GROUP_IDS*/", "?");
    let mut out = String::with_capacity(sql.len());
    let mut it = params.iter();
    let mut quote: Option<char> = None;
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            out.push(c);
            if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' | '`' => {
                quote = Some(c);
                out.push(c);
            }
            '-' if chars.peek() == Some(&'-') => {
                for n in chars.by_ref() {
                    if n == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            '?' => out.push_str(&literal(file, it.next()?)),
            _ => out.push(c),
        }
    }
    it.next().is_none().then_some(out)
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PlanFacts {
    pub summary: String,
    pub indexes: Vec<String>,
    pub full_scan: bool,
    pub ru: Option<String>,
}

/// TiDB: rows (id, estRows, actRows?, task, access object, execution info, ...) as strings.
pub fn analyze_tidb(rows: &[Vec<String>], header: &[String]) -> PlanFacts {
    let idx = |name: &str| header.iter().position(|h| h.eq_ignore_ascii_case(name));
    let (id_i, acc_i, exe_i) = (idx("id"), idx("access object"), idx("execution info"));
    let ru_re = Regex::new(r"(?i)\bRU:\s*([0-9]+(?:\.[0-9]+)?)").ok();
    let mut f = PlanFacts::default();
    let mut ops = Vec::new();
    for r in rows {
        let id = id_i.and_then(|i| r.get(i)).cloned().unwrap_or_default();
        let op = id.trim_start_matches(['└', '├', '─', '│', ' ']).to_owned();
        if op.contains("TableFullScan") || op.contains("IndexFullScan") {
            f.full_scan = true;
        }
        ops.push(op.split('_').next().unwrap_or("").to_owned());
        if let Some(a) = acc_i.and_then(|i| r.get(i))
            && !a.is_empty()
        {
            f.indexes.push(a.clone());
        }
        if f.ru.is_none()
            && let (Some(re), Some(e)) = (&ru_re, exe_i.and_then(|i| r.get(i)))
            && let Some(c) = re.captures(e)
        {
            f.ru = c.get(1).map(|m| m.as_str().to_owned());
        }
    }
    f.summary = ops.join(" > ");
    f
}

/// MySQL: one tree text (EXPLAIN ANALYZE) or tabular EXPLAIN rows (`type`, `key`).
pub fn analyze_mysql_tree(tree: &str) -> PlanFacts {
    let mut f = PlanFacts::default();
    if let Ok(re) = Regex::new(r"using ([A-Za-z0-9_]+)") {
        for c in re.captures_iter(tree) {
            if let Some(m) = c.get(1) {
                let s = m.as_str().to_owned();
                if !f.indexes.contains(&s) {
                    f.indexes.push(s);
                }
            }
        }
    }
    f.full_scan = tree.contains("Table scan on") || tree.contains("Index scan on");
    f.summary = tree
        .lines()
        .map(|l| l.trim().trim_start_matches("-> "))
        .map(|l| l.split(" (").next().unwrap_or(l).to_owned())
        .take(4)
        .collect::<Vec<_>>()
        .join(" > ");
    f
}

/// §10.1 hot path + estimate a query file belongs to.
pub fn estimate_for(file: &str) -> (&'static str, &'static str) {
    if file.contains("users/find_by_email_bidx") || file.contains("membership_directory/by_user") {
        ("Login (whole flow)", "~10-25")
    } else if file.contains("refresh_tokens/") {
        ("Login / refresh (part of)", "~10-25 (flow)")
    } else if file.contains("memberships/get") || file.contains("sessions/get") {
        ("Request auth, cache miss", "~2-4 (3-4 point gets)")
    } else if file.contains("memberships/list")
        || file.contains("sessions/list")
        || file.contains("visible_in_groups")
    {
        ("Dashboard list (50 rows)", "~5-15")
    } else if file.contains("tenant_counters/") {
        ("Dashboard summary", "~2-5")
    } else if file.contains("signing_keys/") {
        ("Token sign/verify key lookup", "not in §10.1 (cached)")
    } else {
        ("Background (jobs/outbox/epochs)", "not in §10.1")
    }
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
                )
            }
            other => bail!("unknown argument `{other}`; usage: ru-report --database-url-env NAME"),
        }
    }
    let var = url_env
        .context("usage: ru-report --database-url-env NAME (an already-migrated database)")?;
    let root = repo_root()?;
    let files = hot_files(&root, false)?;
    let rt = runtime()?;
    let (engine, version, db_name, seeded, rows) = rt.block_on(async {
        let url = url_from_env_or_file(&root, &var)?;
        let mut conn = MySqlConnection::connect(url.expose_secret())
            .await
            .map_err(|e| anyhow!("cannot connect via `{var}`: {}", short(&e)))?;
        let v = fetch(
            &mut conn,
            "SELECT CAST(VERSION() AS CHAR), CAST(DATABASE() AS CHAR)".into(),
        )
        .await?;
        let version = v.first().map(|r| col_str(r, 0)).unwrap_or_default();
        let db_name = v.first().map(|r| col_str(r, 1)).unwrap_or_default();
        if db_name.eq_ignore_ascii_case("Cloud_Erase__App")
            || db_name.to_ascii_lowercase().starts_with("cloud_erase")
        {
            bail!("refusing to run against a legacy database");
        }
        let tidb = version.to_ascii_lowercase().contains("tidb");
        let seeded = seed(&mut conn).await.context("fixture seed")?;
        let mut rows = Vec::new();
        for (file, text) in &files {
            let h = parse_header(text);
            let params = h.params.clone().unwrap_or_default();
            let params: Vec<String> = params.into_iter().filter(|p| p != "none").collect();
            let body: String = text
                .lines()
                .filter(|l| !l.trim_start().starts_with("--"))
                .collect::<Vec<_>>()
                .join("\n");
            let Some(sql) = bind_literals(file, &body, &params) else {
                rows.push((
                    file.clone(),
                    PlanFacts {
                        summary: "params header does not match placeholders".into(),
                        ..PlanFacts::default()
                    },
                    "skipped".to_owned(),
                ));
                continue;
            };
            let is_select = sql.trim_start().to_ascii_uppercase().starts_with("SELECT");
            let explain = if is_select {
                "EXPLAIN ANALYZE"
            } else {
                "EXPLAIN"
            };
            let res = fetch(&mut conn, format!("{explain} {sql}")).await;
            let (facts, mode) = match res {
                Err(e) => (
                    PlanFacts {
                        summary: format!("EXPLAIN failed: {e}"),
                        ..PlanFacts::default()
                    },
                    explain.to_owned(),
                ),
                Ok(rs) if tidb => {
                    let header: Vec<String> = rs
                        .first()
                        .map(|r| {
                            use sqlx::Column as _;
                            r.columns().iter().map(|c| c.name().to_owned()).collect()
                        })
                        .unwrap_or_default();
                    let table: Vec<Vec<String>> = rs
                        .iter()
                        .map(|r| (0..header.len()).map(|i| col_str(r, i)).collect())
                        .collect();
                    (analyze_tidb(&table, &header), explain.to_owned())
                }
                Ok(rs) => {
                    let tree: String = if is_select {
                        rs.iter()
                            .map(|r| col_str(r, 0))
                            .collect::<Vec<_>>()
                            .join("\n")
                    } else {
                        // tabular EXPLAIN: key column + type
                        use sqlx::Column as _;
                        rs.iter()
                            .map(|r| {
                                let names: Vec<String> =
                                    r.columns().iter().map(|c| c.name().to_owned()).collect();
                                let get = |n: &str| {
                                    names
                                        .iter()
                                        .position(|x| x == n)
                                        .map(|i| col_str(r, i))
                                        .unwrap_or_default()
                                };
                                let ty = get("type");
                                let key = get("key");
                                let scan = if ty == "ALL" {
                                    "Table scan on t"
                                } else if ty == "index" {
                                    "Index scan on t"
                                } else {
                                    ""
                                };
                                format!("{} {} using {} {}", get("select_type"), ty, key, scan)
                            })
                            .collect::<Vec<_>>()
                            .join("\n")
                    };
                    (analyze_mysql_tree(&tree), explain.to_owned())
                }
            };
            rows.push((file.clone(), facts, mode));
        }
        let _ = conn.close().await;
        Ok::<_, anyhow::Error>((
            if tidb { "TiDB" } else { "MySQL" },
            version,
            db_name,
            seeded,
            rows,
        ))
    })?;

    let mut md = String::new();
    let _ = writeln!(md, "# RU report (P0-22)\n");
    let _ = writeln!(
        md,
        "Generated by `cargo xtask ru-report --database-url-env {var}`. Engine: **{engine}** (`{version}`), database `{db_name}`."
    );
    let _ = writeln!(
        md,
        "Fixture: tenant `{RU_TENANT_HEX}` (marked `{MARKER}`), <= {SESSIONS} rows per table; rows inserted this run: {seeded} (0 = seed already present).\n"
    );
    let _ = writeln!(
        md,
        "RU source: TiDB `EXPLAIN ANALYZE` execution info (`RU:`). `n/a` = not reported: MySQL has no RU; on TiDB, a version/plan that prints no RU in execution info (then read `statements_summary` RU columns on the cluster, not done by this tool). Non-SELECT files use plain `EXPLAIN` (not executed, no RU).\n"
    );
    let _ = writeln!(
        md,
        "| Query file | Mode | Plan (top operators) | Index / access | Full scan | RU | DATABASE.md §10.1 path | §10.1 estimate |"
    );
    let _ = writeln!(md, "|---|---|---|---|---|---|---|---|");
    let mut full = 0;
    for (file, f, mode) in &rows {
        let ru = match (&f.ru, engine) {
            (_, "MySQL") => "n/a (MySQL)".to_owned(),
            (Some(r), _) => r.clone(),
            (None, _) if mode == "EXPLAIN" => "n/a (not executed)".to_owned(),
            (None, _) => "n/a (not in execution info)".to_owned(),
        };
        if f.full_scan {
            full += 1;
        }
        let (path, est) = estimate_for(file);
        let short_file = file
            .trim_start_matches("crates/db/queries/")
            .replace('\\', "/");
        let _ = writeln!(
            md,
            "| `{short_file}` | {mode} | {} | {} | {} | {ru} | {path} | {est} |",
            f.summary.replace('|', "/"),
            f.indexes.join("; ").replace('|', "/"),
            if f.full_scan { "**YES**" } else { "no" }
        );
    }
    let _ = writeln!(
        md,
        "\nHot queries: {}; with a full scan: {full}. Seed is tiny, so a full scan on a small table can be an optimizer choice; the TiDB nightly with >= 10k rows (DATABASE.md §9.2) is the real gate.",
        rows.len()
    );
    let out = root.join("docs/RU_REPORT.md");
    std::fs::write(&out, md).context("write docs/RU_REPORT.md")?;
    say!(
        "{GATE}: {} hot queries, {full} with full scan, report written to docs/RU_REPORT.md",
        rows.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_and_binding() {
        let sql = "SELECT 1 FROM m WHERE m.tenant_id = ? AND m.id < ? LIMIT ?";
        let p: Vec<String> = ["tenant_id", "after_id", "limit"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let out =
            bind_literals("crates/db/queries/memberships/list_tenant.sql", sql, &p).expect("bind");
        assert!(out.contains(RU_TENANT_HEX) && out.contains("FFFF") && out.ends_with("LIMIT 50"));
        assert!(
            bind_literals("x", "SELECT ?", &[]).is_none(),
            "count mismatch detected"
        );
    }

    #[test]
    fn tidb_plan_parsing() {
        let header: Vec<String> = ["id", "estRows", "task", "access object", "execution info"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let rows = vec![
            vec![
                "Projection_4".into(),
                "1".into(),
                "root".into(),
                String::new(),
                "time:1ms, RU:2.35".into(),
            ],
            vec![
                "└─Point_Get_5".into(),
                "1".into(),
                "root".into(),
                "table:users, index:ux_users_email_bidx(email_bidx)".into(),
                "time:1ms".into(),
            ],
        ];
        let f = analyze_tidb(&rows, &header);
        assert_eq!(f.ru.as_deref(), Some("2.35"));
        assert!(!f.full_scan);
        assert!(f.indexes[0].contains("ux_users_email_bidx"));
        let rows = vec![vec![
            "TableFullScan_1".into(),
            "1".into(),
            "cop".into(),
            "table:jobs".into(),
            String::new(),
        ]];
        assert!(analyze_tidb(&rows, &header).full_scan);
    }

    #[test]
    fn mysql_tree_parsing() {
        let t = "-> Limit: 50 row(s)  (cost=1 rows=1)\n    -> Index range scan on m using PRIMARY over (...)";
        let f = analyze_mysql_tree(t);
        assert_eq!(f.indexes, vec!["PRIMARY".to_owned()]);
        assert!(!f.full_scan);
        assert!(analyze_mysql_tree("-> Table scan on jobs").full_scan);
    }
}
