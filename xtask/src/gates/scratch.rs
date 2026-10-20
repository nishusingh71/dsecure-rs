//! Scratch-DB helper for the DB-backed gates (`schema-check`, `explain-check`).
//!
//! Sirf local MySQL: credentials `.dev/dev.env` se (override `DSECURE_DEV_ENV_FILE`, same file jo
//! `db::testing` padhta hai), `TEST_DATABASE_URL` ka user. `dsecure_t_<16 hex>` scratch database banata hai (db::testing wala prefix: migrator user ke grants isi pattern par hain),
//! `crates/db/migrations` + `migrations_shadow` file-order mein chalata hai (ek statement per file), aur close
//! par SIRF wahi database drop karta hai (naam regex se validate). Credentials/URLs kabhi print nahi hote;
//! `Cloud_Erase__App` ko yeh kabhi nahi chhuta.
//!
//! `db` crate par dependency jaan-bujh kar nahi hai: db engineers ka mid-edit code xtask ka build/clippy
//! na tode, aur gates source files par chalte hain.

use super::{repo_root, walk};
use anyhow::{Context, Result, anyhow, bail};
use regex::Regex;
use secrecy::{ExposeSecret as _, SecretString};
use sqlx::Connection as _;
use sqlx::mysql::MySqlConnection;
use std::path::PathBuf;

/// Open scratch DB + one connection to it.
pub struct Scratch {
    name: String,
    admin: MySqlConnection,
    pub conn: MySqlConnection,
}

/// Replace the database (path) of a mysql URL, keeping `?query` params.
pub fn with_database(url: &str, db: &str) -> String {
    let start = url.find("://").map_or(0, |i| i + 3);
    let host_from = url[start..]
        .find('/')
        .map_or(url.len(), |i| start + i)
        .min(url.len());
    // '@' can only appear before the first '/' after the scheme (credentials), so cut at that '/'.
    let slash = host_from;
    let end = url[slash..].find('?').map_or(url.len(), |i| slash + i);
    format!("{}/{}{}", &url[..slash], db, &url[end..])
}

/// `dsecure_t_<16 hex>`: the only database names this tool will ever drop.
pub fn valid_scratch(name: &str) -> bool {
    Regex::new(r"^dsecure_t_[0-9a-f]{16}$").is_ok_and(|r| r.is_match(name))
}

fn scratch_name() -> String {
    let s = uuid::Uuid::now_v7().simple().to_string();
    format!("dsecure_t_{}", s.get(16..).unwrap_or("0000000000000000"))
}

fn env_file_path(root: &std::path::Path) -> PathBuf {
    // xtask tooling: explicit override var, same name as db::testing uses.
    #[allow(clippy::disallowed_methods)]
    match std::env::var("DSECURE_DEV_ENV_FILE") {
        Ok(p) if !p.is_empty() => PathBuf::from(p),
        _ => root.join(".dev/dev.env"),
    }
}

/// URL from the process env var `name`, else the same key in the dev env file (never printed).
pub fn url_from_env_or_file(root: &std::path::Path, name: &str) -> Result<SecretString> {
    // xtask tooling: explicit, caller-named env var.
    #[allow(clippy::disallowed_methods)]
    if let Ok(v) = std::env::var(name)
        && !v.is_empty()
    {
        return Ok(SecretString::from(v));
    }
    let text = std::fs::read_to_string(env_file_path(root))
        .map_err(|_| anyhow!("`{name}` not set and the dev env file is not readable"))?;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=')
            && k.trim() == name
        {
            return Ok(SecretString::from(
                v.trim().trim_matches('"').trim_matches('\'').to_owned(),
            ));
        }
    }
    bail!("`{name}` is neither set nor in the dev env file")
}

/// `TEST_DATABASE_URL` from the dev env file (value-free errors).
fn test_url(root: &std::path::Path) -> Result<SecretString> {
    let text = std::fs::read_to_string(env_file_path(root))
        .map_err(|_| anyhow!("dev env file not readable (.dev/dev.env)"))?;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=')
            && k.trim() == "TEST_DATABASE_URL"
        {
            return Ok(SecretString::from(
                v.trim().trim_matches('"').trim_matches('\'').to_owned(),
            ));
        }
    }
    bail!("TEST_DATABASE_URL missing in the dev env file")
}

// xtask tooling: runs migration files of this repo / DDL for the validated scratch name only.
#[allow(clippy::disallowed_methods)]
pub async fn exec(conn: &mut MySqlConnection, sql: String) -> Result<()> {
    sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
        .execute(&mut *conn)
        .await
        .map_err(|e| anyhow!("{}", short(&e)))?;
    Ok(())
}

/// `crates/db/migrations` then `migrations_shadow`, file order, one statement per file.
pub async fn apply_migrations(conn: &mut MySqlConnection, root: &std::path::Path) -> Result<()> {
    for dir in ["crates/db/migrations", "crates/db/migrations_shadow"] {
        let d = root.join(dir);
        if !d.is_dir() {
            continue;
        }
        for f in walk(&d, "sql")? {
            let text = std::fs::read_to_string(&f)?;
            exec(conn, text)
                .await
                .with_context(|| format!("migration {}", super::rel(root, &f)))?;
        }
    }
    Ok(())
}

/// KEY=VALUE pairs of the dev env file (values never printed by callers).
pub fn read_env_map(root: &std::path::Path) -> Result<std::collections::HashMap<String, String>> {
    let text = std::fs::read_to_string(env_file_path(root))
        .map_err(|_| anyhow!("dev env file not readable (.dev/dev.env)"))?;
    let mut m = std::collections::HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            m.insert(
                k.trim().to_owned(),
                v.trim().trim_matches('"').trim_matches('\x27').to_owned(),
            );
        }
    }
    Ok(m)
}

impl Scratch {
    pub async fn open() -> Result<Self> {
        let root = repo_root()?;
        let url = test_url(&root)?;
        let mut admin = MySqlConnection::connect(url.expose_secret())
            .await
            .map_err(|e| anyhow!("cannot connect to local MySQL: {}", short(&e)))?;
        let name = scratch_name();
        if !valid_scratch(&name) {
            bail!("internal: bad scratch name");
        }
        exec(
            &mut admin,
            format!("CREATE DATABASE {name} CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"),
        )
        .await
        .context("CREATE DATABASE (scratch)")?;
        let conn = match MySqlConnection::connect(&with_database(url.expose_secret(), &name)).await
        {
            Ok(c) => c,
            Err(e) => {
                let _ = exec(&mut admin, format!("DROP DATABASE IF EXISTS {name}")).await;
                bail!("cannot connect to the scratch database: {}", short(&e));
            }
        };
        let mut me = Self { name, admin, conn };
        if let Err(e) = me.migrate(&root).await {
            let _ = me.close().await;
            return Err(e);
        }
        Ok(me)
    }

    async fn migrate(&mut self, root: &std::path::Path) -> Result<()> {
        apply_migrations(&mut self.conn, root).await
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Close the connection and drop ONLY the scratch database.
    pub async fn close(self) -> Result<()> {
        let Self {
            name,
            mut admin,
            conn,
        } = self;
        let _ = conn.close().await;
        if !valid_scratch(&name) {
            bail!("refusing to drop a database that is not a scratch name");
        }
        let r = exec(&mut admin, format!("DROP DATABASE IF EXISTS {name}")).await;
        let _ = admin.close().await;
        r.context("scratch database drop failed")
    }
}

/// Error text without the connection string.
pub fn short(e: &sqlx::Error) -> String {
    match e {
        sqlx::Error::Database(d) => d.message().to_owned(),
        sqlx::Error::Io(_) => "io error (is local MySQL up on 127.0.0.1:3307?)".to_owned(),
        _ => "connection error".to_owned(),
    }
}

/// Current-thread tokio runtime for the sync xtask main.
pub fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_database_replaces_the_path_and_keeps_params() {
        assert_eq!(
            with_database(
                "mysql://u:p%40w@127.0.0.1:3307/old?ssl-mode=disabled",
                "dsecure_t_1"
            ),
            "mysql://u:p%40w@127.0.0.1:3307/dsecure_t_1?ssl-mode=disabled"
        );
        assert_eq!(
            with_database("mysql://u:p@host:3306", "d"),
            "mysql://u:p@host:3306/d"
        );
    }

    #[test]
    fn only_scratch_names_are_droppable() {
        assert!(valid_scratch("dsecure_t_0123456789abcdef"));
        assert!(!valid_scratch("Cloud_Erase__App"));
        assert!(!valid_scratch("dsecure_test"));
        assert!(!valid_scratch("dsecure_t_0123456789abcdef; DROP"));
        assert!(valid_scratch(&scratch_name()));
    }
}
