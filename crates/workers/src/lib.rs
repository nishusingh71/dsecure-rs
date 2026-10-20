//! workers (P0-13): lease-based job runner + outbox relay (DATABASE.md 8.4, ARCHITECTURE.md 9).
//!
//! Bounded by design: at most `WORKER_CONCURRENCY` jobs in flight (one semaphore permit per job,
//! every task goes through [`task::bounded_spawn`]); no unbounded queues.

pub mod jobs;
pub mod registry;
pub mod runner;
pub mod startup;
pub mod task;

pub use registry::{JobContext, JobError, JobHandler, JobRegistry};
pub use runner::{Runner, RunnerConfig, RunnerStats, ShutdownHandle};
