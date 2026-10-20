//! dsecure-workers: runs the job runner (P0-13). Exit code 78 on config errors.

use common::config_util::Env;
use std::process::ExitCode;
use std::sync::Arc;
use workers::jobs::{DbIdempotencyStore, DbOutboxStore};
use workers::startup::{JobDeps, build_registry, load_config, runner_config};
use workers::{Runner, ShutdownHandle};

fn main() -> ExitCode {
    let cfg = match load_config(&Env::process()) {
        Ok(c) => c,
        Err(code) => return ExitCode::from(u8::try_from(code).unwrap_or(78)),
    };
    let _telemetry = telemetry::init(&cfg.telemetry);
    if cfg.run_mode == config::RunMode::Api {
        tracing::info!("RUN_MODE=api: the job runner is not started by this binary");
        return ExitCode::SUCCESS;
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cfg.http.tokio_worker_threads.max(1))
        .max_blocking_threads(cfg.http.tokio_max_blocking_threads.max(1))
        .enable_all()
        .build();
    let rt = match rt {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %e, "tokio runtime failed");
            return ExitCode::FAILURE;
        }
    };
    rt.block_on(async move {
        let db = match db::Db::connect(&cfg.db, cfg.environment).await {
            Ok(db) => db,
            Err(e) => {
                tracing::error!(error = %e, "database connect failed");
                // Config-class refusals (legacy DB, TLS, URL, engine mismatch) exit 78 like api.
                return if matches!(
                    e,
                    db::DbError::Config(_) | db::DbError::EngineMismatch { .. }
                ) {
                    ExitCode::from(78)
                } else {
                    ExitCode::FAILURE
                };
            }
        };
        let clock: Arc<dyn common::Clock> = Arc::new(common::SystemClock);
        let worker_id = format!("w-{}", &uuid::Uuid::now_v7().simple().to_string()[16..]);
        let deps = JobDeps {
            outbox_store: Some(Arc::new(DbOutboxStore::new(db.clone()))),
            idempotency_store: Some(Arc::new(DbIdempotencyStore::new(db.clone()))),
            ..JobDeps::default()
        };
        let registry = build_registry(deps, &clock, &worker_id);
        let runner = Runner::new(db.clone(), registry, clock, runner_config(&cfg, worker_id));
        let signal = wait_for_signal(runner.shutdown_handle());
        let _ = tokio::join!(runner.run(), signal);
        db.close().await;
        ExitCode::SUCCESS
    })
}

/// Resolves after the first stop signal (SIGINT/ctrl-c, SIGTERM on unix) and triggers shutdown.
async fn wait_for_signal(handle: ShutdownHandle) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            handle.trigger();
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
    handle.trigger();
}
