//! L8 grants.
//! 1) The real local app user (DATABASE_URL): no DELETE/DDL grants, DELETE refused (1142).
//! 2) Least privilege from `grants::grant_statements` (F5): applied by local root to a scratch DB for a
//!    dedicated scratch user `dsecure_t_grants`; UPDATE on audit/staff/key tables and DELETE are
//!    refused (1142). Cleanup = REVOKE ALL (the user keeps only USAGE; nothing is dropped except the
//!    scratch database). Local MySQL only; the root password is read from `.dev/dev.env`, never printed.

use super::harness::{cfg, connect_failed, dev_env, unavailable, with_db};
use crate::error::DbError;
use crate::grants::{DbRole, grant_statements};
use crate::pool::Db;
use crate::sql;
use config::{DbEngine, Environment};
use futures_util::FutureExt as _;
use secrecy::ExposeSecret as _;
use sqlx::mysql::{MySqlConnectOptions, MySqlConnection};
use sqlx::{ConnectOptions as _, Connection as _, Row as _};
use std::panic::AssertUnwindSafe;
use std::str::FromStr as _;

const SCRATCH_USER: &str = "dsecure_t_grants";

#[tokio::test]
async fn app_user_cannot_delete_or_ddl() {
    if super::harness::tidb_skip(
        "app_user_cannot_delete_or_ddl",
        "replaced in tidb mode by app_user_cannot_delete_shared",
    ) {
        return;
    }
    let Some(env) = dev_env("app_user_grants") else {
        return;
    };
    let db = match Db::connect(&cfg(&env.app_url, DbEngine::MySql), Environment::Test).await {
        Ok(db) => db,
        Err(e) => return connect_failed("app_user_grants", &e),
    };
    let rows = sql::dynamic(String::from("SHOW GRANTS"))
        .fetch_all(db.pool())
        .await
        .expect("show grants");
    assert!(!rows.is_empty());
    for r in &rows {
        let g: String = r.try_get(0).expect("grant line");
        let up = g.to_ascii_uppercase();
        let privs = up.split(" ON ").next().unwrap_or("");
        for bad in [
            "DELETE",
            "ALL PRIVILEGES",
            "DROP",
            "CREATE",
            "ALTER",
            "INDEX",
            "REFERENCES",
        ] {
            assert!(!privs.contains(bad), "app user holds {bad}");
        }
    }
    let e = sql::dynamic(String::from("DELETE FROM jobs WHERE id = ?"))
        .bind(uuid::Uuid::now_v7())
        .execute(db.pool())
        .await
        .map_err(sql::map_err)
        .expect_err("DELETE must be refused");
    assert!(
        matches!(e, DbError::PermissionDenied { number: 1142 }),
        "expected 1142, got {e:?}"
    );
    db.close().await;
}

async fn exec(conn: &mut MySqlConnection, stmt: String) -> Result<u64, DbError> {
    sql::dynamic(stmt)
        .execute(&mut *conn)
        .await
        .map(|r| r.rows_affected())
        .map_err(sql::map_err)
}

fn host_ok(h: &str) -> bool {
    !h.is_empty()
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'%' | b'_' | b'-' | b':'))
}

#[tokio::test]
async fn least_privilege_grants_refuse_audit_update_and_delete() {
    if super::harness::tidb_skip(
        "least_privilege_grants_refuse_audit_update_and_delete",
        "needs local root to create scratch users",
    ) {
        return;
    }
    with_db("least_privilege", |db, env| async move {
        let Some(root_pw) = env.root_password.as_ref() else {
            return unavailable(
                "least_privilege",
                "LOCAL_MYSQL_ROOT_PASSWORD missing",
                false,
            );
        };
        let base = MySqlConnectOptions::from_str(&env.test_url).expect("test url");
        let mut tx = db.system_tx().await.expect("tx");
        let row = tx
            .inner
            .fetch_optional(sql::dynamic(String::from("SELECT DATABASE() AS d")))
            .await
            .expect("q")
            .expect("row");
        let scratch: String = sql::col(&row, "d").expect("db");
        tx.rollback().await;
        assert!(scratch.starts_with("dsecure_t_"), "only scratch databases");

        let mut root = base
            .clone()
            .username("root")
            .password(root_pw.expose_secret())
            .database(&scratch)
            .connect()
            .await
            .expect("root connect (local only)");
        let who: String = sql::dynamic(String::from("SELECT USER() AS u"))
            .fetch_one(&mut root)
            .await
            .expect("user()")
            .try_get("u")
            .expect("u");
        let host = who
            .rsplit_once('@')
            .map_or("localhost", |(_, h)| h)
            .to_owned();
        assert!(host_ok(&host));
        let grantee = format!("'{SCRATCH_USER}'@'{host}'");
        let pw = uuid::Uuid::now_v7().simple().to_string(); // random hex, never printed
        exec(
            &mut root,
            format!("CREATE USER IF NOT EXISTS {grantee} IDENTIFIED BY '{pw}'"),
        )
        .await
        .expect("create scratch user");
        exec(
            &mut root,
            format!("ALTER USER {grantee} IDENTIFIED BY '{pw}'"),
        )
        .await
        .expect("set password");
        let stmts = grant_statements(DbRole::App, &scratch, &grantee);
        assert!(!stmts.is_empty());

        let outcome = AssertUnwindSafe(async {
            for g in &stmts {
                exec(&mut root, g.clone()).await.expect("grant");
            }
            let mut app = base
                .clone()
                .username(SCRATCH_USER)
                .password(&pw)
                .database(&scratch)
                .connect()
                .await
                .expect("scratch user connect");
            sql::dynamic(String::from("SELECT COUNT(*) FROM memberships"))
                .fetch_one(&mut app)
                .await
                .expect("select allowed");
            sql::dynamic(String::from(
                "UPDATE memberships SET version = version WHERE tenant_id = ?",
            ))
            .bind(uuid::Uuid::now_v7())
            .execute(&mut app)
            .await
            .expect("update tenant table allowed");
            for stmt in [
                "UPDATE audit_events SET outcome = 'x' WHERE id = ?",
                "UPDATE audit_chain_blocks SET sealed_at = sealed_at WHERE first_id = ?",
                "UPDATE platform_staff SET role = 'x' WHERE user_id = ?",
                "UPDATE staff_access_grants SET closed_at = NULL WHERE id = ?",
                "UPDATE data_keys SET status = 'x' WHERE tenant_id = ?",
                "DELETE FROM jobs WHERE id = ?",
                "DELETE FROM memberships WHERE tenant_id = ?",
                // R1: the app user cannot create staff or grants.
                "INSERT INTO staff_access_grants (id) VALUES (?)",
                "INSERT INTO platform_staff (user_id) VALUES (?)",
            ] {
                let e = sql::dynamic(stmt.to_owned())
                    .bind(uuid::Uuid::now_v7())
                    .execute(&mut app)
                    .await
                    .map_err(sql::map_err)
                    .expect_err(stmt);
                assert!(
                    matches!(e, DbError::PermissionDenied { number: 1142 }),
                    "{stmt}: {e:?}"
                );
            }
            let _ = app.close().await;

            // R5: platform-admin grants are column-level.
            exec(
                &mut root,
                format!("REVOKE ALL PRIVILEGES, GRANT OPTION FROM {grantee}"),
            )
            .await
            .expect("revoke app grants");
            for g in grant_statements(DbRole::PlatformAdmin, &scratch, &grantee) {
                exec(&mut root, g).await.expect("grant platform admin");
            }
            let mut padm = base
                .clone()
                .username(SCRATCH_USER)
                .password(&pw)
                .database(&scratch)
                .connect()
                .await
                .expect("platform admin connect");
            for ok in [
                "UPDATE data_keys SET status = status, active_marker = active_marker WHERE kid = ?",
                "UPDATE staff_access_grants SET closed_at = closed_at WHERE id = ?",
                // Locking reads of the platform-admin path need UPDATE (column-level is enough).
                "SELECT user_id FROM platform_staff WHERE user_id = ? FOR UPDATE",
            ] {
                sql::dynamic(ok.to_owned())
                    .bind(uuid::Uuid::now_v7())
                    .execute(&mut padm)
                    .await
                    .expect(ok);
            }
            for (stmt, number) in [
                (
                    "UPDATE data_keys SET wrapped_dek = wrapped_dek WHERE kid = ?",
                    1143,
                ),
                ("UPDATE data_keys SET kek_ref = kek_ref WHERE kid = ?", 1143),
                (
                    "UPDATE staff_access_grants SET staff_user_id = staff_user_id WHERE id = ?",
                    1143,
                ),
                (
                    "UPDATE memberships SET version = version WHERE tenant_id = ?",
                    1142,
                ),
                ("DELETE FROM data_keys WHERE kid = ?", 1142),
            ] {
                let e = sql::dynamic(stmt.to_owned())
                    .bind(uuid::Uuid::now_v7())
                    .execute(&mut padm)
                    .await
                    .map_err(sql::map_err)
                    .expect_err(stmt);
                assert!(
                    matches!(e, DbError::PermissionDenied { number: n } if n == number),
                    "{stmt}: {e:?}"
                );
            }
            let _ = padm.close().await;
        })
        .catch_unwind()
        .await;
        let _ = exec(
            &mut root,
            format!("REVOKE ALL PRIVILEGES, GRANT OPTION FROM {grantee}"),
        )
        .await;
        let _ = root.close().await;
        if let Err(p) = outcome {
            std::panic::resume_unwind(p);
        }
    })
    .await;
}

/// Dev tool (ignored; run explicitly, LOCAL MySQL only): migrate `dsecure_dev` + `dsecure_test` with the
/// migrator user and replace the local app user's DB-level `SELECT, INSERT, UPDATE` with the generated
/// per-table App grants (root). `cargo test -p db apply_local_dev_schema_and_grants -- --ignored`
#[tokio::test]
#[ignore = "mutates the local dev/test databases and the local app user's grants (run explicitly)"]
async fn apply_local_dev_schema_and_grants() {
    if super::harness::tidb_skip(
        "apply_local_dev_schema_and_grants",
        "local dev tool (root, local DBs only)",
    ) {
        return;
    }
    let env = crate::testing::load_env().expect("dev env");
    let file = std::fs::read_to_string(crate::testing::env_file_path()).expect("env file");
    let migrator_url = file
        .lines()
        .find_map(|l| l.trim().strip_prefix("MIGRATOR_DATABASE_URL="))
        .map(|v| v.trim().trim_matches('"').to_owned())
        .unwrap_or_else(|| env.test_url.expose_secret().to_owned());
    let app_user = MySqlConnectOptions::from_str(env.app_url.expose_secret())
        .expect("app url")
        .get_username()
        .to_owned();
    assert!(
        app_user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    );
    for dbname in ["dsecure_dev", "dsecure_test"] {
        let url = crate::testing::with_database(&migrator_url, dbname);
        let db = Db::connect(
            &crate::testing::test_config(&secrecy::SecretString::from(url)),
            Environment::Test,
        )
        .await
        .expect("migrator connect");
        crate::migrate::run(&db).await.expect("migrate");
        db.close().await;

        let mut root = crate::testing::root_connection(&env, dbname)
            .await
            .expect("root (local)");
        let hosts: Vec<String> = sql::dynamic(String::from(
            "SELECT host AS h FROM mysql.user WHERE user = ?",
        ))
        .bind(app_user.as_str())
        .fetch_all(&mut root)
        .await
        .expect("hosts")
        .iter()
        .map(|r| r.try_get::<String, _>("h").expect("h"))
        .collect();
        assert!(!hosts.is_empty(), "app user exists");
        for host in hosts {
            assert!(host_ok(&host));
            let grantee = format!("'{app_user}'@'{host}'");
            // 1141 = no such grant (already per-table): fine.
            match exec(
                &mut root,
                format!("REVOKE SELECT, INSERT, UPDATE ON `{dbname}`.* FROM {grantee}"),
            )
            .await
            {
                Ok(_) | Err(DbError::Database { number: 1141, .. }) => {}
                Err(e) => panic!("revoke: {e}"),
            }
            // Re-apply from scratch so removed privileges (R1) really disappear.
            for (t, _) in crate::TABLE_CLASSES {
                match exec(
                    &mut root,
                    format!("REVOKE ALL PRIVILEGES ON `{dbname}`.`{t}` FROM {grantee}"),
                )
                .await
                {
                    Ok(_) | Err(DbError::Database { number: 1147, .. }) => {}
                    Err(e) => panic!("revoke table: {e}"),
                }
            }
            for g in grant_statements(DbRole::App, dbname, &grantee) {
                exec(&mut root, g).await.expect("grant");
            }
        }
        let _ = root.close().await;
    }
}

/// Read-only dev tool: which applied migration versions differ from the embedded files (versions only).
#[tokio::test]
#[ignore = "diagnostic, read-only"]
async fn diag_applied_migrations() {
    if super::harness::tidb_skip("diag_applied_migrations", "local dev tool (root)") {
        return;
    }
    use sha2_shim::checksum;
    let env = crate::testing::load_env().expect("dev env");
    for dbname in ["dsecure_dev", "dsecure_test"] {
        let mut root = crate::testing::root_connection(&env, dbname)
            .await
            .expect("root (local)");
        let rows = sql::dynamic(String::from(
            "SELECT version AS v, checksum AS c FROM _sqlx_migrations ORDER BY version",
        ))
        .fetch_all(&mut root)
        .await;
        let Ok(rows) = rows else {
            println!("{dbname}: no _sqlx_migrations table");
            continue;
        };
        let ours: std::collections::HashMap<i64, Vec<u8>> = crate::migration_files::MAIN
            .iter()
            .map(|(n, t)| (crate::migrate::parse_name(n).expect("n").0, checksum(t)))
            .collect();
        let mut diff = Vec::new();
        for r in &rows {
            let v: i64 = r.try_get("v").expect("v");
            let c: Vec<u8> = r.try_get("c").expect("c");
            if ours.get(&v) != Some(&c) {
                diff.push(v);
            }
        }
        println!("{dbname}: applied={} differing={diff:?}", rows.len());
        let _ = root.close().await;
    }
}

mod sha2_shim {
    pub(super) fn checksum(sql_text: &str) -> Vec<u8> {
        sqlx::migrate::Migration::new(
            0,
            std::borrow::Cow::Borrowed("x"),
            sqlx::migrate::MigrationType::Simple,
            sqlx::SqlSafeStr::into_sql_str(sqlx::AssertSqlSafe(sql_text.to_owned())),
            false,
        )
        .checksum
        .into_owned()
    }
}

/// TiDB mode: the shared app user (`TIDB_DEV_APP_URL`) cannot DELETE (1142) and holds no DDL grant.
#[tokio::test]
async fn app_user_cannot_delete_shared() {
    if !super::harness::tidb_mode() {
        return;
    }
    let env = crate::testing::load_env().expect("dev env");
    let scratch = crate::testing::ScratchDb::create(&env)
        .await
        .expect("shared db");
    let app = scratch.app().expect("app pool").clone();
    let e = sql::dynamic(String::from("DELETE FROM jobs WHERE id = ?"))
        .bind(uuid::Uuid::now_v7())
        .execute(app.pool())
        .await
        .map_err(sql::map_err)
        .expect_err("DELETE must be refused");
    assert!(
        matches!(e, DbError::PermissionDenied { number: 1142 }),
        "expected 1142, got {e:?}"
    );
    scratch.drop_db(&env).await.expect("close");
}
