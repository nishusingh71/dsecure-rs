//! P0-20 data-layer gates (`cargo xtask <gate>`). Har gate ka detection logic pure function hai
//! (text in, `Vec<Violation>` out) taaki fixtures se test ho sake; disk/DB wala hissa patla wrapper hai.
//!
//! Gates sirf REPORT karte hain: koi gate kisi crate ki file nahi badalta.

pub mod classes;
pub mod db_reset;
pub mod explain_check;
pub mod migrate_lint;
pub mod route_policies;
pub mod ru_report;
pub mod schema_check;
pub mod scratch;
pub mod sql_lint;
pub mod src_scan;

use anyhow::{Context, Result, bail};
use std::fmt;
use std::path::{Path, PathBuf};

// `print_stdout` workspace mein deny hai; xtask ka human output stderr par jaata hai.
macro_rules! say {
    ($($arg:tt)*) => { eprintln!($($arg)*) };
}
pub(crate) use say;

/// Ek gate finding. `location` = repo-relative path (+ `:line` jahan pata ho).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    pub gate: &'static str,
    pub location: String,
    pub message: String,
}

impl Violation {
    pub fn new(
        gate: &'static str,
        location: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            gate,
            location: location.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.gate, self.location, self.message)
    }
}

/// Workspace root (`xtask/..`).
pub fn repo_root() -> Result<PathBuf> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("xtask has no parent directory")?;
    Ok(p.to_path_buf())
}

/// Repo-relative display path with forward slashes.
pub fn rel(root: &Path, p: &Path) -> String {
    p.strip_prefix(root)
        .unwrap_or(p)
        .to_string_lossy()
        .replace('\\', "/")
}

/// All files under `dir` (recursive) with the given extension, sorted. `target/` and hidden dirs skipped.
pub fn walk(dir: &Path, ext: &str) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    walk_into(dir, ext, &mut out)?;
    out.sort();
    Ok(out)
}

fn walk_into(dir: &Path, ext: &str, out: &mut Vec<PathBuf>) -> Result<()> {
    let rd = std::fs::read_dir(dir).with_context(|| format!("cannot read {}", dir.display()))?;
    for entry in rd {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if entry.file_type()?.is_dir() {
            if name == "target" || name.starts_with('.') {
                continue;
            }
            walk_into(&path, ext, out)?;
        } else if path.extension().is_some_and(|e| e == ext) {
            out.push(path);
        }
    }
    Ok(())
}

/// Print violations and fail when there are any.
pub fn finish(gate: &str, violations: &[Violation], checked: usize) -> Result<()> {
    for v in violations {
        say!("{v}");
    }
    if violations.is_empty() {
        say!("xtask {gate}: OK ({checked} checked)");
        Ok(())
    } else {
        bail!(
            "xtask {gate}: {} violation(s) in {checked} checked item(s)",
            violations.len()
        )
    }
}

fn run_sql_lint() -> Result<()> {
    let root = repo_root()?;
    let (v, n) = sql_lint::run_on_repo(&root)?;
    finish(sql_lint::GATE, &v, n)
}

fn run_migrate_lint() -> Result<()> {
    let root = repo_root()?;
    let (v, n) = migrate_lint::run_on_repo(&root)?;
    finish(migrate_lint::GATE, &v, n)
}

fn run_no_raw_sql() -> Result<()> {
    let root = repo_root()?;
    let (raw, _, n) = src_scan::run_on_repo(&root)?;
    finish(src_scan::GATE_RAW, &raw, n)
}

fn run_sealed() -> Result<()> {
    let root = repo_root()?;
    let (_, sealed, n) = src_scan::run_on_repo(&root)?;
    finish(src_scan::GATE_SEALED, &sealed, n)
}

/// Dispatch a gate subcommand; `None` = not a gate.
pub fn dispatch(cmd: &str, args: impl Iterator<Item = String>) -> Option<Result<()>> {
    Some(match cmd {
        "sql-lint" => run_sql_lint(),
        "migrate-lint" => run_migrate_lint(),
        "no-raw-sql" => run_no_raw_sql(),
        "sealed-ctor-gate" => run_sealed(),
        "schema-check" => schema_check::run(args),
        "explain-check" => explain_check::run(args),
        "ru-report" => ru_report::run(args),
        "route-policies" => route_policies::run(args),
        "db-reset" => db_reset::run(args),
        "gates" => run_all(args),
        _ => return None,
    })
}

/// `gates [--db]`: every static gate, continue after a failure, fail at the end if any failed.
/// `--db` adds `schema-check` and `explain-check` (needs the local MySQL).
fn run_all(args: impl Iterator<Item = String>) -> Result<()> {
    let mut db = false;
    for a in args {
        match a.as_str() {
            "--db" => db = true,
            other => bail!("unknown argument `{other}`; usage: gates [--db]"),
        }
    }
    let mut steps: Vec<(&str, Result<()>)> = vec![
        ("sql-lint", run_sql_lint()),
        ("migrate-lint", run_migrate_lint()),
        ("no-raw-sql", run_no_raw_sql()),
        ("sealed-ctor-gate", run_sealed()),
        (
            "route-policies",
            route_policies::run(["--check".to_owned()].into_iter()),
        ),
    ];
    if db {
        steps.push(("schema-check", schema_check::run(std::iter::empty())));
        steps.push(("explain-check", explain_check::run(std::iter::empty())));
    }
    let mut failed = Vec::new();
    for (name, r) in &steps {
        match r {
            Ok(()) => say!("== {name}: PASS"),
            Err(e) => {
                say!("== {name}: FAIL ({e:#})");
                failed.push(*name);
            }
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        bail!("gates failed: {}", failed.join(", "))
    }
}
