//! `dsecure-api migrate [--status]` (B1): the release step from DATABASE.md §11.1, run by the owner
//! BEFORE a deploy (schema first). Uses ONLY `MIGRATOR_DATABASE_URL` (required here, no fallback to
//! the app URL), the config validation done at load time and `db::migrate` (lock row + heartbeat).
//! Output: versions only (no URLs, no user names, no values).

use std::io::Write;

use config::AppConfig;
use db::DbError;

use super::{EXIT_CONFIG, EXIT_FAILURE, EXIT_OK, EXIT_PENDING, EXIT_TEMPFAIL};

/// `1000001` -> `0100_0001` (migration file prefix).
#[must_use]
pub fn version_label(v: i64) -> String {
    format!("{:04}_{:04}", v / 10_000, v % 10_000)
}

/// Exit code for a db error of the migrate command.
#[must_use]
pub fn exit_code(e: &DbError) -> u8 {
    match e {
        DbError::Config(_) | DbError::EngineMismatch { .. } => EXIT_CONFIG,
        DbError::Conflict("migrate.busy") => EXIT_TEMPFAIL,
        _ => EXIT_FAILURE,
    }
}

fn list(out: &mut dyn Write, verb: &str, versions: &[i64]) {
    for v in versions {
        let _ = writeln!(out, "  {verb} {}", version_label(*v));
    }
}

/// Run the command. `out` gets the report, `err` the (value-free) refusal reasons.
pub async fn run(
    cfg: &AppConfig,
    status_only: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    if cfg.db.migrator_url.is_none() {
        let _ = writeln!(
            err,
            "migrate refused: MIGRATOR_DATABASE_URL is not set (the migrator user runs migrations; \
             never the app user)"
        );
        return EXIT_CONFIG;
    }
    let env = cfg.environment;
    if status_only {
        return match db::migrate::pending_from_config(&cfg.db, env).await {
            Ok(p) if p.is_empty() => {
                let _ = writeln!(out, "migrate --status: up to date (0 pending)");
                EXIT_OK
            }
            Ok(p) => {
                let _ = writeln!(out, "migrate --status: {} pending", p.len());
                list(out, "pending", &p);
                EXIT_PENDING
            }
            Err(e) => {
                tracing::error!(error = %e, "migrate --status failed");
                let _ = writeln!(err, "migrate --status failed: {e}");
                exit_code(&e)
            }
        };
    }
    match db::migrate::run_from_config(&cfg.db, env).await {
        Ok(r) if r.applied.is_empty() => {
            let _ = writeln!(out, "migrate: up to date (0 applied)");
            EXIT_OK
        }
        Ok(r) => {
            tracing::info!(applied = r.applied.len(), "migrations applied");
            let _ = writeln!(out, "migrate: applied {}", r.applied.len());
            list(out, "applied", &r.applied);
            EXIT_OK
        }
        Err(e) => {
            tracing::error!(error = %e, "migrate failed");
            let hint = if matches!(e, DbError::Conflict("migrate.busy")) {
                " (another migrator holds the lock; retry later)"
            } else {
                ""
            };
            let _ = writeln!(err, "migrate failed: {e}{hint}");
            exit_code(&e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_and_exit_codes() {
        assert_eq!(version_label(1_000_001), "0100_0001");
        assert_eq!(version_label(8_700_001), "0870_0001");
        assert_eq!(exit_code(&DbError::Config("x")), EXIT_CONFIG);
        assert_eq!(exit_code(&DbError::Conflict("migrate.busy")), EXIT_TEMPFAIL);
        assert_eq!(exit_code(&DbError::Migrate("x".into())), EXIT_FAILURE);
    }
}
