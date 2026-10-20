//! Startup wiring: config load (with `DevKeyCheck`), runner config, job registry.

use crate::jobs::{
    AuditHook, AuditPartitionsJob, IdempotencyStore, IdempotencySweepJob, LogOnlyAuditHook,
    LoggingPublisher, OutboxPublisher, OutboxRelayJob, OutboxStore,
};
use crate::registry::JobRegistry;
use crate::runner::RunnerConfig;
use common::Clock;
use common::config_util::Env;
use config::AppConfig;
use std::sync::Arc;

/// Load + validate config; staging/production refuse dev KEKs and dev signing keys.
/// `Err(code)` is the process exit code (78) after a value-free message on stderr.
///
/// # Errors
/// Exit code 78 on any config problem.
pub fn load_config(env: &Env) -> Result<AppConfig, i32> {
    config::load_or_exit_code(env, &[&crypto::DevKeyCheck])
}

/// `WORKER_CONCURRENCY` (default 2) -> runner settings.
#[must_use]
pub fn runner_config(cfg: &AppConfig, worker_id: String) -> RunnerConfig {
    RunnerConfig::new(
        worker_id,
        usize::try_from(cfg.workers.concurrency).unwrap_or(2),
    )
}

/// Storage back ends that exist. `None` = the db crate has no API for it yet; the job is then
/// not registered (and a warning is logged) instead of pretending to work.
#[derive(Default)]
pub struct JobDeps {
    pub outbox_store: Option<Arc<dyn OutboxStore>>,
    pub outbox_publisher: Option<Arc<dyn OutboxPublisher>>,
    pub idempotency_store: Option<Arc<dyn IdempotencyStore>>,
    pub audit_hook: Option<Arc<dyn AuditHook>>,
}

#[must_use]
pub fn build_registry(deps: JobDeps, clock: &Arc<dyn Clock>, worker_id: &str) -> JobRegistry {
    let mut reg = JobRegistry::new();
    match deps.outbox_store {
        Some(store) => {
            let publisher = deps
                .outbox_publisher
                .unwrap_or_else(|| Arc::new(LoggingPublisher));
            reg.register(Arc::new(OutboxRelayJob::new(
                store,
                publisher,
                Arc::clone(clock),
                worker_id.to_owned(),
            )));
        }
        None => tracing::warn!("outbox_relay not registered: no outbox store (db API missing)"),
    }
    match deps.idempotency_store {
        Some(store) => reg.register(Arc::new(IdempotencySweepJob::new(store, Arc::clone(clock)))),
        None => tracing::warn!("idempotency_sweep not registered: no store (db API missing)"),
    }
    let hook = deps
        .audit_hook
        .unwrap_or_else(|| Arc::new(LogOnlyAuditHook));
    reg.register(Arc::new(AuditPartitionsJob::new(hook, Arc::clone(clock))));
    reg
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::devkeys::{dev_kek_id, generate_kek_b64};

    fn env(environment: &str, kek_id: &str) -> Env {
        let kek = generate_kek_b64().expect("kek");
        let mut p: Vec<(String, String)> = [
            ("DSECURE_ENV", environment),
            (
                "DATABASE_URL",
                "mysql://app:pw@db.example.com:4000/x?ssl-mode=VERIFY_IDENTITY",
            ),
            ("DB_TLS_CA", "/etc/ssl/ca.pem"),
            ("KEK_PROVIDER", "env"),
            ("KEK_ENV_ACTIVE_ID", kek_id),
            ("JWT_ISSUER", "https://dsecure.test"),
            ("JWT_SIGNING_KID_MEMBER", "member-2026a"),
            ("JWT_SIGNING_KID_STAFF", "staff-2026a"),
            ("TRUSTED_PROXY_HOPS", "1"),
            ("TRUSTED_PROXY_CIDRS", "10.0.0.0/8"),
            ("BLOB_BACKEND", "fs"),
            ("BLOB_FS_ROOT", "/tmp/blobs"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        p.push((format!("KEK_ENV_{kek_id}"), (*kek).clone()));
        Env::from_pairs(p)
    }

    #[test]
    fn staging_with_dev_kek_exits_78() {
        let id = dev_kek_id().expect("dev kek id");
        assert_eq!(load_config(&env("staging", &id)).err(), Some(78));
    }

    #[test]
    fn staging_with_real_kek_loads_and_default_concurrency_is_two() {
        let cfg = load_config(&env("staging", "real_2026a")).expect("valid");
        assert_eq!(runner_config(&cfg, "w1".into()).concurrency, 2);
    }

    #[test]
    fn registry_skips_jobs_without_a_store() {
        let clock: Arc<dyn Clock> = Arc::new(common::SystemClock);
        let reg = build_registry(JobDeps::default(), &clock, "w1");
        assert_eq!(reg.kinds(), vec!["audit_partitions"]);
    }
}
