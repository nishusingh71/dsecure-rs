//! DB integration tests against the LOCAL MySQL 8.4 (127.0.0.1:3307) only.
//!
//! Credentials come from `.dev/dev.env` (gitignored) and are never printed. Every test gets its own
//! scratch database `dsecure_t_<random>` (created + dropped via the migrator user); nothing else is
//! ever dropped. If the env file or the server is missing, tests FAIL unless `DSECURE_DB_TESTS=skip`.
//! These are in-crate tests so fault injection (raw rows of another tenant) can use crate internals.

mod fixtures;
mod harness;

mod t_bootstrap;
mod t_concurrency;
mod t_engine;
mod t_epochs;
mod t_grants;
mod t_isolation;
mod t_jobs;
mod t_keys;
mod t_last_owner;
mod t_migrate;
mod t_misc;
mod t_pagination;
mod t_parents;
mod t_schema;
mod t_signing;
mod t_staff;
mod t_worker_api;
