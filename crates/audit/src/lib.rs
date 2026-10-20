//! audit: typed audit events, same-transaction sink, hash chain of sealed hourly blocks anchored to the blob
//! store (PHASE0_SPEC §3.6 / P0-12, SECURITY.md §10, DATABASE.md §8).
//!
//! - [`event`]: `AuditAction` catalogue, `Outcome`, `ActorRef`, `TargetRef`, PII-checked `AuditMeta` (< 2 KB).
//! - [`sink_db`]: `AuditSink` / `DbAuditSink` (`record_in_tx` same tx; `record` bounded channel + sync fallback).
//! - [`chain`]: `row_hash`, Merkle blocks, `seal_block` / `seal_due` (worker job body), `verify_chain`.
//!
//! The app DB user is INSERT-only on `audit_events` / `audit_chain_blocks` in production (no UPDATE/DELETE
//! grants; see `docs/ops/db_users.sql`): nothing in this crate updates or deletes an audit row.

pub mod chain;
pub mod event;
pub mod sink_db;

pub use chain::{
    Failure, FailureKind, SealConfig, SealOutcome, VerifyReport, hour_floor, next_block_start,
    seal_block, seal_due, verify_chain,
};
pub use event::{
    ActorRef, AuditAction, AuditError, AuditEvent, AuditMeta, MAX_META_BYTES, Outcome, TargetKind,
    TargetRef,
};
pub use sink_db::{
    AuditSink, AuditTx, DbAuditSink, METRIC_OVERFLOW, METRIC_WRITE_FAILED, SinkOptions,
};
