//! `cargo xtask db-reset` (DATABASE.md §9.3, PHASE0_SPEC §7): lokal dev database ko drop + recreate, migrate,
//! generated grants lagana. SIRF `.dev/dev.env` ke `DATABASE_URL` mein named database (`dsecure_dev`).
//!
//! Refuse (kuch bhi change hone se pehle):
//! - `DSECURE_ENV` != `dev` (process env, warna dev.env),
//! - host `localhost` / `127.0.0.1` / `::1` ke alawa,
//! - database naam `dsecure_dev` ke alawa koi bhi; `cloud_erase*` (kisi bhi case mein) alag, saaf message,
//! - TiDB server (`VERSION()` mein tidb).
//!
//! Local root password dev.env ke `LOCAL_MYSQL_ROOT_PASSWORD` se; kabhi print nahi hota. Grants:
//! `db::grants::grant_statements(App, ...)` DATABASE_URL ke user ko (host `mysql.user` se; user na ho to
//! DATABASE_URL ke password se banta hai).

use super::scratch::{apply_migrations, exec, read_env_map, runtime, short};
use super::{repo_root, say};
use anyhow::{Context, Result, anyhow, bail};
use db::grants::{DbRole, grant_statements};
use sqlx::Connection as _;
use sqlx::Row as _;
use sqlx::mysql::MySqlConnection;

/// The only database this command may ever drop.
pub const DEV_DB: &str = "dsecure_dev";

#[derive(Debug, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub database: String,
}

/// Pure refusal logic. `env` = value of DSECURE_ENV.
pub fn validate_target(env: Option<&str>, database_url: &str) -> Result<Target> {
    if env != Some("dev") {
        bail!("db-reset refuses: DSECURE_ENV must be `dev`");
    }
    let rest = database_url
        .strip_prefix("mysql://")
        .ok_or_else(|| anyhow!("db-reset refuses: DATABASE_URL is not a mysql:// URL"))?;
    let (auth_host, path) = rest.split_once('/').unwrap_or((rest, ""));
    let database = path.split('?').next().unwrap_or("").to_owned();
    let (userinfo, hostport) = auth_host.rsplit_once('@').unwrap_or(("", auth_host));
    let (user, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
    let (host, port) = if let Some(h) = hostport.strip_prefix('[') {
        let (h, p) = h.split_once(']').unwrap_or((h, ""));
        (h.to_owned(), p.trim_start_matches(':').to_owned())
    } else {
        let (h, p) = hostport.split_once(':').unwrap_or((hostport, ""));
        (h.to_owned(), p.to_owned())
    };
    if !matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1") {
        bail!("db-reset refuses: host is not localhost / 127.0.0.1");
    }
    if database.to_ascii_lowercase().starts_with("cloud_erase") {
        bail!("db-reset refuses: production database names (cloud_erase*) are never touched");
    }
    if database != DEV_DB {
        bail!("db-reset refuses: the database must be exactly `{DEV_DB}`");
    }
    if user.is_empty() {
        bail!("db-reset refuses: DATABASE_URL has no user");
    }
    Ok(Target {
        host,
        port: port.parse().unwrap_or(3306),
        user: user.to_owned(),
        password: password.to_owned(),
        database,
    })
}

fn pct(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// Identifier-safe single-quoted SQL string.
fn sql_str(s: &str) -> String {
    format!("'{}'", s.replace('\\', "\\\\").replace('\'', "''"))
}

pub fn run(args: impl Iterator<Item = String>) -> Result<()> {
    if let Some(a) = args.into_iter().next() {
        bail!("unknown argument `{a}`; usage: db-reset");
    }
    let root = repo_root()?;
    let env = read_env_map(&root)?;
    // xtask tooling: DSECURE_ENV from the process wins over dev.env.
    #[allow(clippy::disallowed_methods)]
    let env_name = std::env::var("DSECURE_ENV")
        .ok()
        .or_else(|| env.get("DSECURE_ENV").cloned());
    let url = env
        .get("DATABASE_URL")
        .ok_or_else(|| anyhow!("DATABASE_URL missing in the dev env file"))?;
    let t = validate_target(env_name.as_deref(), url)?;
    let root_pw = env
        .get("LOCAL_MYSQL_ROOT_PASSWORD")
        .ok_or_else(|| anyhow!("LOCAL_MYSQL_ROOT_PASSWORD missing in the dev env file"))?;
    let rt = runtime()?;
    rt.block_on(async {
        let root_url = format!("mysql://root:{}@{}:{}/", pct(root_pw), t.host, t.port);
        let mut c = MySqlConnection::connect(&root_url)
            .await
            .map_err(|e| anyhow!("cannot connect as local root: {}", short(&e)))?;
        let r = reset(&mut c, &t, &root, &root_url).await;
        let _ = c.close().await;
        r
    })
}

// xtask tooling: static queries + DDL for the validated dev database name only.
#[allow(clippy::disallowed_methods)]
async fn reset(
    c: &mut MySqlConnection,
    t: &Target,
    repo: &std::path::Path,
    root_url: &str,
) -> Result<()> {
    let version: String = sqlx::query("SELECT CAST(VERSION() AS CHAR)")
        .fetch_one(&mut *c)
        .await
        .map_err(|e| anyhow!("VERSION(): {}", short(&e)))?
        .try_get(0)?;
    if version.to_ascii_lowercase().contains("tidb") {
        bail!("db-reset refuses: TiDB server (db-reset is for the local MySQL stand-in only)");
    }
    let db = &t.database;
    exec(c, format!("DROP DATABASE IF EXISTS `{db}`")).await?;
    exec(
        c,
        format!("CREATE DATABASE `{db}` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"),
    )
    .await?;
    let mut dbc = MySqlConnection::connect(&format!("{root_url}{db}"))
        .await
        .map_err(|e| anyhow!("cannot connect to {db}: {}", short(&e)))?;
    let m = apply_migrations(&mut dbc, repo).await;
    let _ = dbc.close().await;
    m?;
    let host: Option<String> =
        sqlx::query("SELECT CAST(host AS CHAR) FROM mysql.user WHERE user = ? LIMIT 1")
            .bind(&t.user)
            .fetch_optional(&mut *c)
            .await
            .map_err(|e| anyhow!("mysql.user: {}", short(&e)))?
            .map(|r| r.try_get(0))
            .transpose()?;
    let host = match host {
        Some(h) => h,
        None => {
            exec(
                c,
                format!(
                    "CREATE USER {}@'localhost' IDENTIFIED BY {}",
                    sql_str(&t.user),
                    sql_str(&t.password)
                ),
            )
            .await
            .context("CREATE USER for the DATABASE_URL user")?;
            "localhost".to_owned()
        }
    };
    let grantee = format!("{}@{}", sql_str(&t.user), sql_str(&host));
    let stmts = grant_statements(DbRole::App, db, &grantee);
    for g in &stmts {
        exec(c, g.clone()).await.context("grant")?;
    }
    say!(
        "db-reset: `{db}` dropped, recreated, migrated; {} grant statements applied (role App)",
        stmts.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_url() -> &'static str {
        "mysql://dsecure_app:pw@127.0.0.1:3307/dsecure_dev"
    }

    #[test]
    fn accepts_the_local_dev_database() {
        let t = validate_target(Some("dev"), ok_url()).unwrap();
        assert_eq!(t.host, "127.0.0.1");
        assert_eq!(t.port, 3307);
        assert_eq!(t.database, DEV_DB);
        assert_eq!(t.user, "dsecure_app");
        assert!(validate_target(Some("dev"), "mysql://u:p@localhost/dsecure_dev?x=1").is_ok());
    }

    #[test]
    fn refuses_other_environments() {
        for e in [
            None,
            Some("test"),
            Some("staging"),
            Some("production"),
            Some("DEV"),
        ] {
            assert!(validate_target(e, ok_url()).is_err(), "{e:?}");
        }
    }

    #[test]
    fn refuses_non_local_hosts() {
        for h in [
            "10.0.0.5",
            "db.example.com",
            "127.0.0.1.evil.com",
            "gateway01.tidbcloud.com",
        ] {
            let url = format!("mysql://u:p@{h}:4000/dsecure_dev");
            assert!(validate_target(Some("dev"), &url).is_err(), "{h}");
        }
    }

    #[test]
    fn refuses_other_names_and_cloud_erase_in_any_case() {
        for n in ["dsecure_test", "dsecure_dev2", "mysql", "", "Dsecure_Dev"] {
            let url = format!("mysql://u:p@127.0.0.1:3307/{n}");
            assert!(validate_target(Some("dev"), &url).is_err(), "{n}");
        }
        for n in ["Cloud_Erase__App", "cloud_erase", "CLOUD_ERASE_X"] {
            let url = format!("mysql://u:p@127.0.0.1:3307/{n}");
            let e = validate_target(Some("dev"), &url).unwrap_err().to_string();
            assert!(e.contains("cloud_erase"), "{n}: {e}");
        }
    }

    #[test]
    fn refuses_a_userinfo_trick_host() {
        // real host is evil.com, "127.0.0.1" is only the user name
        assert!(validate_target(Some("dev"), "mysql://127.0.0.1:x@evil.com/dsecure_dev").is_err());
    }
}
