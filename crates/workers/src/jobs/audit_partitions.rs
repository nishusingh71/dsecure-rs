//! `audit_partitions`: audit chain sealing / partition upkeep. Phase 0 = injectable hook.
//! The audit crate does not expose `seal_block` yet; `LogOnlyAuditHook` logs and returns Ok.
//! When it lands, implement [`AuditHook`] over it in `startup` (no change needed here).

use crate::registry::{JobContext, JobError, JobHandler};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;

#[async_trait]
pub trait AuditHook: Send + Sync {
    async fn run(&self, now: OffsetDateTime) -> Result<(), JobError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LogOnlyAuditHook;

#[async_trait]
impl AuditHook for LogOnlyAuditHook {
    async fn run(&self, now: OffsetDateTime) -> Result<(), JobError> {
        tracing::info!(at = %now, "audit_partitions: no seal hook wired yet");
        Ok(())
    }
}

pub struct AuditPartitionsJob {
    hook: Arc<dyn AuditHook>,
    clock: Arc<dyn common::Clock>,
}

impl AuditPartitionsJob {
    pub const KIND: &'static str = "audit_partitions";

    #[must_use]
    pub fn new(hook: Arc<dyn AuditHook>, clock: Arc<dyn common::Clock>) -> Self {
        Self { hook, clock }
    }
}

#[async_trait]
impl JobHandler for AuditPartitionsJob {
    fn kind(&self) -> &'static str {
        Self::KIND
    }

    fn completes_in_tx(&self) -> bool {
        true
    }

    fn max_concurrency(&self) -> usize {
        1
    }

    fn schedule(&self) -> Option<Duration> {
        Some(Duration::from_secs(3600))
    }

    async fn handle(&self, ctx: &JobContext) -> Result<(), JobError> {
        self.hook.run(self.clock.now()).await?;
        ctx.complete_system().await
    }
}
