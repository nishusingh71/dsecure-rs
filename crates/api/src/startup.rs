//! Process startup (fail closed) + graceful shutdown.
//!
//! Order: config (+ `crypto::DevKeyCheck`, exit 78) -> telemetry -> tokio runtime (config-sized) ->
//! DB pool (TLS / legacy-db / engine checks inside `db`) -> platform KeyRing (fail closed) -> blob
//! temp sweep (fs backend) -> `RUN_MODE`: api server (+ loopback metrics listener + authz epoch
//! poller), job runner, or both -> SIGINT/SIGTERM -> graceful stop -> pool close.
//!
//! No `tokio::spawn`: every long-running piece is one future joined in `serve_all` (fixed count).

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;

use auth::{
    AuthDeps, AuthService, AuthSettings, DbPrincipalLoader, Es256Issuer, Es256Verifier, KeySet,
    RefreshHasher, TracingSink,
};
use common::config_util::Env;
use common::{Clock, SystemClock};
use config::{AppConfig, BlobBackend, ConfigProblem, Environment, KekProvider, RunMode};
use crypto::{
    Argon2Params, Argon2idHasher, EnvKeyProvider, HmacBlindIndexer, KeyProvider, KeyPurpose,
    KeyRing, ParamPolicy,
};
use tokio::sync::watch;

use crate::app::{HttpSettings, RouteOptions, assemble, build_routes};
use crate::authn::LiveAuthenticator;
use crate::authz::GateDeps;
use crate::ratelimit::{PreAuthLimiter, Rules};
use crate::state::{AppState, AuthHttp, cursor_key_from};

/// HKDF label of the refresh/step-up token HMAC subkey (platform `Secrets` DEK). Stable across
/// restarts and instances; a rotation of that DEK invalidates outstanding refresh and step-up
/// tokens (users log in again; documented trade-off).
pub const REFRESH_KEY_LABEL: &str = "api-refresh-hmac";
/// Max wait for an Argon2 slot before 503 (ARCHITECTURE.md §12.1: 2 s).
pub const LOGIN_HASH_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// sysexits `EX_CONFIG`.
pub const EXIT_CONFIG: u8 = 78;

/// Loopback-only Prometheus listener (not in `config` yet: api-local key, PHASE0_PROGRESS item 6
/// style follow-up). Decision: separate localhost port instead of a staff-policy route, because
/// (a) staff login needs MFA (P0-11) so a staff route would be unusable now, (b) a loopback bind is
/// unreachable from the internet with zero auth code, (c) an in-container collector/sidecar scrapes
/// it. Non-loopback values are refused (exit 78).
pub const METRICS_ADDR_KEY: &str = "METRICS_ADDR";
pub const DEFAULT_METRICS_ADDR: &str = "127.0.0.1:9464";

/// Trace head-sampling (PHASE0_PROGRESS item 6): config has no field yet, so a local constant.
pub const TRACE_SAMPLE_LOCAL: f64 = 1.0;
pub const TRACE_SAMPLE_DEPLOYED: f64 = 0.1;

#[must_use]
pub const fn trace_sample_ratio(env: Environment) -> f64 {
    if env.is_local() {
        TRACE_SAMPLE_LOCAL
    } else {
        TRACE_SAMPLE_DEPLOYED
    }
}

/// api-only settings that `config::AppConfig` does not carry yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApiExtras {
    pub metrics_addr: SocketAddr,
}

impl ApiExtras {
    /// # Errors
    /// Value-free problem (key name only).
    pub fn load(env: &Env) -> Result<Self, ConfigProblem> {
        let raw = env
            .optional(METRICS_ADDR_KEY)
            .map_err(|_| ConfigProblem::new(METRICS_ADDR_KEY, "not valid unicode"))?
            .unwrap_or_else(|| DEFAULT_METRICS_ADDR.to_owned());
        let addr: SocketAddr = raw
            .trim()
            .parse()
            .map_err(|_| ConfigProblem::new(METRICS_ADDR_KEY, "expected ip:port"))?;
        if !addr.ip().is_loopback() {
            return Err(ConfigProblem::new(
                METRICS_ADDR_KEY,
                "metrics listener must bind a loopback address",
            ));
        }
        Ok(Self { metrics_addr: addr })
    }
}

/// Load + validate (value-free messages on stderr).
///
/// # Errors
/// Exit code 78.
#[allow(clippy::print_stderr)]
pub fn load(env: &Env) -> Result<(AppConfig, ApiExtras), u8> {
    let cfg = AppConfig::load_with(env, &[&crypto::DevKeyCheck]).map_err(|errors| {
        eprintln!("startup aborted: {errors}");
        EXIT_CONFIG
    })?;
    let extras = ApiExtras::load(env).map_err(|p| {
        eprintln!("startup aborted: invalid configuration; {p}");
        EXIT_CONFIG
    })?;
    Ok((cfg, extras))
}

/// Binary entry: `dsecure-api` (server), `dsecure-api migrate [--status]` (release step, B1),
/// `dsecure-api staff-bootstrap ...` (first platform superadmin, B2). See `crate::ops`.
#[must_use]
#[allow(clippy::print_stderr)]
pub fn main_entry() -> ExitCode {
    let cmd = match crate::ops::parse_args(std::env::args_os().skip(1)) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!(
                "dsecure-api: {msg}

{}",
                crate::ops::USAGE
            );
            return ExitCode::from(crate::ops::EXIT_USAGE);
        }
    };
    if cmd == crate::ops::Command::Help {
        eprintln!("{}", crate::ops::USAGE);
        return ExitCode::SUCCESS;
    }
    let env = Env::process();
    let (cfg, extras) = match load(&env) {
        Ok(v) => v,
        Err(code) => return ExitCode::from(code),
    };
    let _telemetry = telemetry::init_with(
        &cfg.telemetry,
        &telemetry::otlp::OtlpOptions {
            sample_ratio: trace_sample_ratio(cfg.environment),
            ..telemetry::otlp::OtlpOptions::default()
        },
    );
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
    match cmd {
        crate::ops::Command::Serve | crate::ops::Command::Help => rt.block_on(run(cfg, extras)),
        other => ExitCode::from(rt.block_on(crate::ops::run_command(&cfg, &env, &other))),
    }
}

async fn run(cfg: AppConfig, extras: ApiExtras) -> ExitCode {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let db = match db::Db::connect(&cfg.db, cfg.environment).await {
        Ok(db) => db,
        Err(e) => {
            tracing::error!(error = %e, "database connect refused");
            return match e {
                db::DbError::Config(_) | db::DbError::EngineMismatch { .. } => {
                    ExitCode::from(EXIT_CONFIG)
                }
                _ => ExitCode::FAILURE,
            };
        }
    };
    let code = serve_all(&cfg, extras, db.clone(), clock).await;
    db.close().await;
    code
}

/// KEK provider from config (fail closed: dev KEK refused outside dev/test). Error = exit code 78.
pub(crate) fn kek_provider(cfg: &AppConfig) -> Result<Arc<dyn KeyProvider>, u8> {
    let provider: Arc<dyn KeyProvider> = match cfg.kek.provider {
        Some(KekProvider::Env) => {
            let (Some(id), Some(key)) = (&cfg.kek.env_active_id, &cfg.kek.env_active_key) else {
                tracing::error!("KEK_ENV_ACTIVE_ID / KEK_ENV_<id> missing");
                return Err(EXIT_CONFIG);
            };
            match EnvKeyProvider::new(id, [(id.clone(), key.clone())]) {
                Ok(p) => Arc::new(p),
                Err(e) => {
                    tracing::error!(error = %e, "KEK provider refused");
                    return Err(EXIT_CONFIG);
                }
            }
        }
        Some(KekProvider::AzureKv) => {
            tracing::error!("KEK_PROVIDER=azure-kv is not built yet (D-03 / P0-06)");
            return Err(EXIT_CONFIG);
        }
        None => {
            tracing::error!("KEK_PROVIDER missing");
            return Err(EXIT_CONFIG);
        }
    };
    if provider.is_dev() && !cfg.environment.is_local() {
        tracing::error!("dev KEK refused outside dev/test");
        return Err(EXIT_CONFIG);
    }
    Ok(provider)
}

/// Platform KeyRing (fail closed). Dev/test only: missing platform DEKs are created first.
async fn load_keyring(cfg: &AppConfig, db: &db::Db) -> Result<Arc<KeyRing>, ExitCode> {
    let provider = kek_provider(cfg).map_err(ExitCode::from)?;
    let store = Arc::new(db::DbDekStore::new(db.clone()));
    if cfg.environment.is_local() {
        match KeyRing::ensure_platform_keys(provider.as_ref(), store.as_ref()).await {
            Ok(0) => {}
            Ok(n) => tracing::warn!(created = n, "dev/test: platform DEKs bootstrapped"),
            Err(e) => tracing::warn!(error = %e, "dev/test: platform DEK bootstrap failed"),
        }
    }
    KeyRing::load_platform_with(provider, store, cfg.limits.max_tenant_deks_cached)
        .await
        .map(Arc::new)
        .map_err(|e| {
            tracing::error!(error = %e, "platform keys could not be loaded (fail closed)");
            ExitCode::FAILURE
        })
}

/// JWT keys from `signing_keys` (fail closed, exit 78 when the configured kids are not usable).
/// Dev/test: missing member/staff keys are bootstrapped first with the migrator pool (the app user
/// has SELECT only on `signing_keys`).
async fn jwt_keys(
    cfg: &AppConfig,
    db: &db::Db,
    enc: &dyn crypto::FieldEncryptor,
) -> Result<(Es256Issuer, KeySet), ExitCode> {
    if cfg.environment.is_local() {
        match db::Db::connect_migrator(&cfg.db, cfg.environment).await {
            Ok(mig) => {
                match crate::keys::dev_bootstrap(
                    &mig,
                    cfg.environment,
                    enc,
                    &cfg.jwt.signing_kid_member,
                    &cfg.jwt.signing_kid_staff,
                )
                .await
                {
                    Ok(0) => {}
                    Ok(n) => tracing::warn!(created = n, "dev/test: JWT signing keys bootstrapped"),
                    Err(e) => tracing::warn!(error = %e, "dev/test: JWT key bootstrap failed"),
                }
                mig.close().await;
            }
            Err(e) => tracing::warn!(error = %e, "dev/test: migrator pool unavailable"),
        }
    }
    crate::keys::load_jwt(
        db,
        enc,
        &cfg.jwt.signing_kid_member,
        &cfg.jwt.signing_kid_staff,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "JWT signing keys refused (fail closed)");
        match e {
            crate::keys::JwtKeyError::Db(_) => ExitCode::FAILURE,
            _ => ExitCode::from(EXIT_CONFIG),
        }
    })
}

async fn subkey(ring: &KeyRing, label: &'static str) -> Result<[u8; 32], ExitCode> {
    ring.derive_subkey(KeyPurpose::Secrets, None, label)
        .await
        .map(|k| *k)
        .map_err(|e| {
            tracing::error!(error = %e, "subkey derivation failed (fail closed)");
            ExitCode::FAILURE
        })
}

/// Argon2id hasher from config (production parameter floor outside dev/test). Error = exit 78.
pub(crate) fn hasher(cfg: &AppConfig) -> Result<Argon2idHasher, u8> {
    let policy = if cfg.environment.is_local() {
        ParamPolicy::Relaxed
    } else {
        ParamPolicy::Production
    };
    Argon2idHasher::new(
        Argon2Params {
            m_kib: cfg.argon2.m_kib,
            t: cfg.argon2.t,
            p: cfg.argon2.p,
        },
        usize::try_from(cfg.argon2.login_hash_concurrency).unwrap_or(1),
        LOGIN_HASH_WAIT,
        policy,
    )
    .map_err(|e| {
        tracing::error!(error = %e, "argon2 parameters refused");
        EXIT_CONFIG
    })
}

async fn sweep_blobs(cfg: &AppConfig) {
    if cfg.blob.backend != BlobBackend::Fs {
        return;
    }
    let Some(root) = cfg.blob.fs_root.as_deref() else {
        tracing::warn!("BLOB_FS_ROOT unset: temp sweep skipped");
        return;
    };
    match storage::FsBlobStore::new(root) {
        Ok(store) => match store.sweep_stale_temp(storage::fs::MIN_SWEEP_AGE).await {
            Ok(n) => tracing::info!(removed = n, "blob temp sweep done"),
            Err(e) => tracing::warn!(error = %e, "blob temp sweep failed"),
        },
        Err(e) => tracing::warn!(error = %e, "blob store unavailable: temp sweep skipped"),
    }
}

fn build_runner(cfg: &AppConfig, db: &db::Db, clock: &Arc<dyn Clock>) -> workers::Runner {
    use workers::jobs::{DbIdempotencyStore, DbOutboxStore};
    use workers::startup::{JobDeps, build_registry, runner_config};
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let worker_id = format!("api-{}", suffix.get(16..).unwrap_or("0"));
    let deps = JobDeps {
        outbox_store: Some(Arc::new(DbOutboxStore::new(db.clone()))),
        idempotency_store: Some(Arc::new(DbIdempotencyStore::new(db.clone()))),
        ..JobDeps::default()
    };
    let registry = build_registry(deps, clock, &worker_id);
    workers::Runner::new(
        db.clone(),
        registry,
        Arc::clone(clock),
        runner_config(cfg, worker_id),
    )
}

struct ApiParts {
    app: axum::Router,
    db: db::Db,
    clock: Arc<dyn Clock>,
    epoch_poll: std::time::Duration,
}

async fn build_api(
    cfg: &AppConfig,
    db: &db::Db,
    clock: &Arc<dyn Clock>,
) -> Result<ApiParts, ExitCode> {
    let keys = load_keyring(cfg, db).await?;
    let fields: Arc<dyn crypto::FieldEncryptor> =
        Arc::new(crypto::AesGcmFieldEncryptor::new(Arc::clone(&keys)));
    let (issuer, verify_set) = jwt_keys(cfg, db, fields.as_ref()).await?;
    let verifier = Es256Verifier::new(
        verify_set,
        cfg.jwt.issuer.clone(),
        Arc::clone(clock),
        auth::tokens::MAX_LEEWAY_SECS,
    );
    let settings = AuthSettings::from_config(cfg);
    let loader = Arc::new(DbPrincipalLoader::new(
        db.clone(),
        Arc::clone(clock),
        &settings,
    ));
    let indexer: Arc<dyn crypto::BlindIndexer> = Arc::new(HmacBlindIndexer::new(Arc::clone(&keys)));
    let refresh_key = subkey(&keys, REFRESH_KEY_LABEL).await?;
    let service = AuthService::new(AuthDeps {
        db: db.clone(),
        hasher: Arc::new(hasher(cfg).map_err(ExitCode::from)?),
        indexer: Arc::clone(&indexer),
        issuer: Arc::new(issuer),
        refresh: RefreshHasher::new(&refresh_key),
        fields,
        sink: Arc::new(TracingSink),
        clock: Arc::clone(clock),
        loader: Arc::clone(&loader),
        settings: settings.clone(),
    })
    .await
    .map(Arc::new)
    .map_err(|e| {
        tracing::error!(code = e.code(), "auth service failed");
        ExitCode::FAILURE
    })?;
    let limiter = PreAuthLimiter::in_memory(Rules::default()).map_err(|_| ExitCode::FAILURE)?;
    let gate = GateDeps {
        authn: Arc::new(LiveAuthenticator::new(Arc::new(verifier), loader)),
        clock: Arc::clone(clock),
        db: Some(db.clone()),
        auth: Some(Arc::clone(&service)),
    };
    let http = HttpSettings::from_config(cfg).map_err(|e| {
        tracing::error!(error = %e, "trusted proxy config refused");
        ExitCode::from(EXIT_CONFIG)
    })?;
    let cursor = cursor_key_from(&keys).await.map_err(|e| {
        tracing::error!(error = %e, "cursor key derivation failed (fail closed)");
        ExitCode::FAILURE
    })?;
    let state =
        AppState::new(cfg.environment, db.clone(), Some(keys), cursor).with_auth(AuthHttp {
            service,
            limiter: Arc::new(limiter),
            indexer,
        });
    let (app, table) = assemble(
        build_routes(&RouteOptions::from_config(cfg)),
        state,
        gate,
        &http,
    )
    .map_err(|problems| {
        for p in &problems {
            tracing::error!(problem = %p, "route table refused");
        }
        ExitCode::from(EXIT_CONFIG)
    })?;
    tracing::info!(routes = table.len(), "route table built");
    Ok(ApiParts {
        app,
        db: db.clone(),
        clock: Arc::clone(clock),
        epoch_poll: settings.epoch_poll,
    })
}

async fn wait_stop(mut rx: watch::Receiver<bool>) {
    let _ = rx.wait_for(|stop| *stop).await;
}

/// First SIGINT/ctrl-c (or SIGTERM on unix).
async fn os_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

async fn serve(
    addr: &str,
    app: axum::Router,
    stop: watch::Receiver<bool>,
) -> Result<(), &'static str> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|_| "bind failed")?;
    crate::server::serve(
        listener,
        app,
        crate::server::ServerLimits::default(),
        wait_stop(stop),
    )
    .await;
    Ok(())
}

async fn serve_all(
    cfg: &AppConfig,
    extras: ApiExtras,
    db: db::Db,
    clock: Arc<dyn Clock>,
) -> ExitCode {
    let api = if cfg.run_mode == RunMode::Workers {
        None
    } else {
        match build_api(cfg, &db, &clock).await {
            Ok(p) => Some(p),
            Err(code) => return code,
        }
    };
    if cfg.run_mode == RunMode::Workers {
        // Workers mode still refuses broken keys (jobs decrypt/encrypt too).
        if let Err(code) = load_keyring(cfg, &db).await {
            return code;
        }
    }
    sweep_blobs(cfg).await;
    let runner = matches!(cfg.run_mode, RunMode::Workers | RunMode::All)
        .then(|| build_runner(cfg, &db, &clock));

    let (stop_tx, stop_rx) = watch::channel(false);
    let stop_tx = &stop_tx;

    let api_fut = async {
        let Some(p) = &api else { return Ok(()) };
        tracing::info!("api listening");
        let r = serve(&cfg.http.addr, p.app.clone(), stop_rx.clone()).await;
        if let Err(e) = r {
            tracing::error!(problem = e, "api server stopped");
            stop_tx.send_replace(true);
        }
        r
    };
    let metrics_fut = async {
        if api.is_none() {
            return;
        }
        let addr = extras.metrics_addr.to_string();
        if let Err(e) = serve(&addr, crate::router::metrics_router(), stop_rx.clone()).await {
            // Metrics are not worth taking the API down for.
            tracing::warn!(problem = e, "metrics listener stopped");
        }
    };
    let poller_fut = async {
        if let Some(p) = &api {
            auth::run_epoch_poller(
                p.db.clone(),
                Arc::clone(&p.clock),
                p.epoch_poll,
                wait_stop(stop_rx.clone()),
            )
            .await;
        }
    };
    let workers_fut = async {
        if let Some(r) = &runner {
            let handle = r.shutdown_handle();
            let stop = wait_stop(stop_rx.clone());
            tokio::join!(r.run(), async move {
                stop.await;
                handle.trigger();
            });
        }
    };
    let signal_fut = async {
        tokio::select! {
            () = os_signal() => tracing::info!("shutdown signal received"),
            () = wait_stop(stop_rx.clone()) => {}
        }
        stop_tx.send_replace(true);
    };
    let (api_res, (), (), (), ()) =
        tokio::join!(api_fut, metrics_fut, poller_fut, workers_fut, signal_fut);
    tracing::info!("shutdown complete");
    if api_res.is_err() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::devkeys::{dev_kek_id, generate_kek_b64};

    fn env(environment: &str, kek_id: &str, extra: &[(&str, &str)]) -> Env {
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
        .iter()
        .chain(extra.iter())
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
        p.push((format!("KEK_ENV_{kek_id}"), (*kek).clone()));
        Env::from_pairs(p)
    }

    #[test]
    fn production_refuses_dev_kek_with_exit_78() {
        let id = dev_kek_id().expect("dev kek id");
        assert_eq!(load(&env("production", &id, &[])).err(), Some(78));
        assert_eq!(load(&env("staging", &id, &[])).err(), Some(78));
    }

    #[test]
    fn real_kek_loads_with_default_metrics_addr() {
        let (cfg, extras) = load(&env("staging", "real_2026a", &[])).expect("valid");
        assert_eq!(cfg.environment, Environment::Staging);
        assert!(extras.metrics_addr.ip().is_loopback());
    }

    #[test]
    fn metrics_addr_must_be_loopback() {
        let e = env("staging", "real_2026a", &[("METRICS_ADDR", "0.0.0.0:9464")]);
        assert_eq!(load(&e).err(), Some(78));
        let e = env("staging", "real_2026a", &[("METRICS_ADDR", "[::1]:9000")]);
        assert!(load(&e).is_ok());
    }

    #[test]
    fn missing_required_key_is_78() {
        let e = Env::from_pairs([("DSECURE_ENV", "dev")]);
        assert_eq!(load(&e).err(), Some(78));
    }

    #[test]
    fn sampling_defaults() {
        assert!((trace_sample_ratio(Environment::Dev) - 1.0).abs() < f64::EPSILON);
        assert!((trace_sample_ratio(Environment::Production) - 0.1).abs() < f64::EPSILON);
    }
}
