//! config: typed `AppConfig` loaded from `common::config_util::Env` + fail-closed startup validation.
//!
//! Rules: secrets are `SecretString` (Debug redacted); every problem message names the KEY only,
//! never a value; `load` reports ALL problems at once; exit code on invalid config is 78 (EX_CONFIG).

pub mod dburl;
mod endpoint;
mod error;
mod load;
mod model;
mod validate;

pub use endpoint::Endpoint;
pub use error::{
    ConfigErrors, ConfigProblem, EXIT_CONFIG, exit_code_for, load_or_exit, load_or_exit_code,
};
pub use model::{
    AppConfig, Argon2Config, BlobBackend, BlobConfig, DbConfig, DbEngine, Environment, HttpConfig,
    JwtConfig, KekConfig, KekProvider, LimitsConfig, LogFormat, RateLimitConfig, RateLimitStore,
    RunMode, TelemetryConfig, WorkersConfig,
};
pub use validate::ConfigCheck;

#[cfg(test)]
mod tests;
