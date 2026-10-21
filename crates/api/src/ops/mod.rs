//! Operator subcommands of the `dsecure-api` binary (Render staging blockers B1/B2).
//!
//! - `dsecure-api` (no arguments) or `dsecure-api serve`: the server, unchanged.
//! - `dsecure-api migrate`: release step (DATABASE.md §11.1), migrator user from
//!   `MIGRATOR_DATABASE_URL` only. `migrate --status` (alias `--dry-run`) lists pending versions and
//!   writes nothing. Migrations NEVER run implicitly on server start (ARCHITECTURE.md, DATABASE.md:
//!   "migrations kabhi app startup par nahi").
//! - `dsecure-api staff-bootstrap --email <addr> --password-env <NAME>`: first platform superadmin
//!   ([`staff_bootstrap`]). The password is read from the environment variable NAMED by the flag,
//!   never from the command line.
//!
//! Every command loads and validates the full `AppConfig` first (same rules as the server: legacy DB
//! refusal, TLS `VERIFY_IDENTITY` + CA outside dev/test, `DB_EXPECT_ENGINE`, dev-key refusal).

pub mod migrate;
pub mod staff_bootstrap;

use std::ffi::OsString;

use common::config_util::Env;
use config::AppConfig;

/// Success.
pub const EXIT_OK: u8 = 0;
/// Database / server error, or a migration failed.
pub const EXIT_FAILURE: u8 = 1;
/// `migrate --status`: at least one version is pending (nothing was written).
pub const EXIT_PENDING: u8 = 3;
/// `staff-bootstrap`: refused, platform staff already exists (nothing was written).
pub const EXIT_ALREADY_BOOTSTRAPPED: u8 = 4;
/// sysexits `EX_USAGE`: bad arguments, or a required interactive terminal is missing.
pub const EXIT_USAGE: u8 = 64;
/// sysexits `EX_DATAERR`: invalid operator input (email, password, TOTP code, email taken).
pub const EXIT_DATAERR: u8 = 65;
/// sysexits `EX_TEMPFAIL`: another migrator holds the migration lock (`migrate.busy`); retry later.
pub const EXIT_TEMPFAIL: u8 = 75;
/// sysexits `EX_CONFIG`: configuration refused (same as server startup).
pub const EXIT_CONFIG: u8 = crate::startup::EXIT_CONFIG;

pub const USAGE: &str = "usage:
  dsecure-api                       run the server (RUN_MODE api|workers|all)
  dsecure-api migrate               apply pending migrations (MIGRATOR_DATABASE_URL)
  dsecure-api migrate --status      list pending migrations, write nothing (alias --dry-run)
  dsecure-api staff-bootstrap --email <address> --password-env <ENV_VAR_NAME>
                                    create the first platform superadmin (interactive terminal;
                                    needs DATABASE_URL = app user and PLATFORM_ADMIN_DATABASE_URL)
exit codes: 0 ok, 1 failure, 3 migrations pending (--status), 4 staff already exists,
            64 usage, 65 invalid input, 75 migration lock busy, 78 configuration refused";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Serve,
    Help,
    Migrate { status_only: bool },
    StaffBootstrap(BootstrapArgs),
}

/// `staff-bootstrap` flags. Only the NAME of the password variable is ever on the command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootstrapArgs {
    pub email: String,
    pub password_env: String,
}

fn env_name_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        && !s.as_bytes()[0].is_ascii_digit()
}

/// Parse the arguments after the program name. Error = value-free usage message.
///
/// # Errors
/// Unknown command/flag, missing value, non-UTF-8 argument, a password literal.
pub fn parse_args<I: IntoIterator<Item = OsString>>(args: I) -> Result<Command, String> {
    let mut it = args.into_iter().map(|a| {
        a.into_string()
            .map_err(|_| String::from("arguments must be valid UTF-8"))
    });
    let Some(first) = it.next().transpose()? else {
        return Ok(Command::Serve);
    };
    let rest: Vec<String> = it.collect::<Result<_, _>>()?;
    match first.as_str() {
        "serve" if rest.is_empty() => Ok(Command::Serve),
        "help" | "--help" | "-h" if rest.is_empty() => Ok(Command::Help),
        "migrate" => match rest.as_slice() {
            [] => Ok(Command::Migrate { status_only: false }),
            [f] if f == "--status" || f == "--dry-run" => {
                Ok(Command::Migrate { status_only: true })
            }
            _ => Err(String::from("migrate takes only --status / --dry-run")),
        },
        "staff-bootstrap" => parse_bootstrap(&rest).map(Command::StaffBootstrap),
        _ => Err(String::from("unknown command or extra arguments")),
    }
}

fn parse_bootstrap(rest: &[String]) -> Result<BootstrapArgs, String> {
    let mut email = None;
    let mut password_env = None;
    let mut i = 0;
    while i < rest.len() {
        let flag = rest[i].as_str();
        if flag == "--password" || flag.starts_with("--password=") {
            return Err(String::from(
                "a password is never accepted on the command line; use --password-env <ENV_VAR_NAME>",
            ));
        }
        let (name, value) = match flag.split_once('=') {
            Some((n, v)) => (n, Some(v.to_owned())),
            None => (flag, None),
        };
        let value = match value {
            Some(v) => v,
            None => {
                i += 1;
                rest.get(i)
                    .cloned()
                    .ok_or_else(|| format!("{name} needs a value"))?
            }
        };
        let slot = match name {
            "--email" => &mut email,
            "--password-env" => &mut password_env,
            _ => return Err(String::from("staff-bootstrap: unknown flag")),
        };
        if slot.replace(value).is_some() {
            return Err(format!("{name} given twice"));
        }
        i += 1;
    }
    let email = email.ok_or("staff-bootstrap needs --email <address>")?;
    let password_env = password_env.ok_or("staff-bootstrap needs --password-env <ENV_VAR_NAME>")?;
    if !env_name_ok(&password_env) {
        return Err(String::from(
            "--password-env must be an environment variable NAME (A-Z, 0-9, _)",
        ));
    }
    Ok(BootstrapArgs {
        email,
        password_env,
    })
}

/// Run a non-server command (config already loaded and valid). Returns the exit code.
pub async fn run_command(cfg: &AppConfig, env: &Env, cmd: &Command) -> u8 {
    match cmd {
        Command::Serve | Command::Help => EXIT_USAGE,
        Command::Migrate { status_only } => {
            let mut out = std::io::stdout();
            let mut err = std::io::stderr();
            migrate::run(cfg, *status_only, &mut out, &mut err).await
        }
        Command::StaffBootstrap(a) => staff_bootstrap::run_cli(cfg, env, a).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(a: &[&str]) -> Result<Command, String> {
        parse_args(a.iter().map(OsString::from))
    }

    #[test]
    fn server_is_the_default_and_unknown_is_refused() {
        assert_eq!(p(&[]), Ok(Command::Serve));
        assert_eq!(p(&["serve"]), Ok(Command::Serve));
        assert_eq!(p(&["--help"]), Ok(Command::Help));
        assert!(p(&["serve", "x"]).is_err());
        assert!(p(&["migrat"]).is_err());
        assert!(p(&["--port", "1"]).is_err());
    }

    #[test]
    fn migrate_flags() {
        assert_eq!(p(&["migrate"]), Ok(Command::Migrate { status_only: false }));
        assert_eq!(
            p(&["migrate", "--status"]),
            Ok(Command::Migrate { status_only: true })
        );
        assert_eq!(
            p(&["migrate", "--dry-run"]),
            Ok(Command::Migrate { status_only: true })
        );
        // No URL on the command line, ever.
        assert!(p(&["migrate", "--db-url", "mysql://x"]).is_err());
        assert!(p(&["migrate", "--status", "--status"]).is_err());
    }

    #[test]
    fn bootstrap_flags_and_password_literal_refused() {
        let ok = Command::StaffBootstrap(BootstrapArgs {
            email: "ops@dsecure.test".into(),
            password_env: "DSECURE_BOOTSTRAP_PW".into(),
        });
        assert_eq!(
            p(&[
                "staff-bootstrap",
                "--email",
                "ops@dsecure.test",
                "--password-env",
                "DSECURE_BOOTSTRAP_PW"
            ]),
            Ok(ok.clone())
        );
        assert_eq!(
            p(&[
                "staff-bootstrap",
                "--password-env=DSECURE_BOOTSTRAP_PW",
                "--email=ops@dsecure.test"
            ]),
            Ok(ok)
        );
        for bad in [
            &["staff-bootstrap", "--email", "a@b.test", "--password", "x"][..],
            &["staff-bootstrap", "--email", "a@b.test", "--password=x"][..],
            &["staff-bootstrap", "--email", "a@b.test"][..],
            &["staff-bootstrap", "--password-env", "PW"][..],
            &[
                "staff-bootstrap",
                "--email",
                "a@b.test",
                "--password-env",
                "pw lower",
            ][..],
            &[
                "staff-bootstrap",
                "--email",
                "a@b.test",
                "--password-env",
                "1PW",
            ][..],
            &["staff-bootstrap", "--email", "a@b.test", "--password-env"][..],
            &[
                "staff-bootstrap",
                "--email",
                "a",
                "--email",
                "b",
                "--password-env",
                "P",
            ][..],
            &["staff-bootstrap", "--role", "x"][..],
        ] {
            let e = p(bad).expect_err("refused");
            assert!(!e.contains("a@b.test"), "usage errors never echo values");
        }
        let e = p(&["staff-bootstrap", "--password=hunter2hunter2"]).expect_err("literal");
        assert!(!e.contains("hunter2"));
    }
}
