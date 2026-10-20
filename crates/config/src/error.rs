//! Value-free problem list + the single process-exit helper.

use std::fmt;

use common::config_util::Env;

use crate::model::AppConfig;

/// sysexits `EX_CONFIG`.
pub const EXIT_CONFIG: i32 = 78;

/// One problem: the key (or rule name) and a static-ish description. Never contains a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigProblem {
    pub key: String,
    pub problem: String,
}

impl ConfigProblem {
    #[must_use]
    pub fn new(key: impl Into<String>, problem: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            problem: problem.into(),
        }
    }
}

impl fmt::Display for ConfigProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.key, self.problem)
    }
}

/// All problems found (never empty when returned as an `Err`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigErrors(pub Vec<ConfigProblem>);

impl ConfigErrors {
    #[must_use]
    pub fn problems(&self) -> &[ConfigProblem] {
        &self.0
    }

    #[must_use]
    pub fn has_key(&self, key: &str) -> bool {
        self.0.iter().any(|p| p.key == key)
    }
}

impl fmt::Display for ConfigErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid configuration ({} problem(s))", self.0.len())?;
        for p in &self.0 {
            write!(f, "; {p}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigErrors {}

/// Process exit code for a failed validation (always 78).
#[must_use]
pub const fn exit_code_for(_errors: &ConfigErrors) -> i32 {
    EXIT_CONFIG
}

/// Load + validate; on failure print value-free messages to stderr and return exit code 78.
/// Split from [`load_or_exit`] so the failure mapping is testable without exiting.
///
/// # Errors
/// The process exit code (always [`EXIT_CONFIG`]).
#[allow(clippy::print_stderr)]
pub fn load_or_exit_code(env: &Env, extra: &[&dyn crate::ConfigCheck]) -> Result<AppConfig, i32> {
    AppConfig::load_with(env, extra).map_err(|errors| {
        eprintln!("startup aborted: {errors}");
        exit_code_for(&errors)
    })
}

/// Load + validate, or terminate the process with code 78.
/// This is the ONLY function in the crate that terminates the process.
pub fn load_or_exit(env: &Env, extra: &[&dyn crate::ConfigCheck]) -> AppConfig {
    match load_or_exit_code(env, extra) {
        Ok(cfg) => cfg,
        Err(code) => std::process::exit(code),
    }
}
