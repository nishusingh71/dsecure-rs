//! Env -> `AppConfig`. Collects every parse/missing problem instead of stopping at the first.

use std::str::FromStr;

use common::config_util::{ConfigError, Env};
use secrecy::SecretString;

use crate::endpoint::Endpoint;
use crate::error::{ConfigErrors, ConfigProblem};
use crate::model::{
    AppConfig, Argon2Config, BlobBackend, BlobConfig, DbConfig, DbEngine, Environment, HttpConfig,
    JwtConfig, KekConfig, KekProvider, LimitsConfig, LogFormat, RateLimitConfig, RateLimitStore,
    RunMode, TelemetryConfig, WorkersConfig,
};
use crate::validate::{ConfigCheck, validate_problems};

const DEFAULT_MALLOC_CONF: &str =
    "background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:1000,narenas:2";

struct Loader<'a> {
    env: &'a Env,
    problems: Vec<ConfigProblem>,
}

impl Loader<'_> {
    fn note(&mut self, e: &ConfigError) {
        // `ConfigError` Display names the key and never the value.
        let key = match e {
            ConfigError::Missing { key }
            | ConfigError::NotUnicode { key }
            | ConfigError::Invalid { key, .. } => key.clone(),
        };
        self.problems.push(ConfigProblem::new(key, e.to_string()));
    }

    fn opt(&mut self, key: &str) -> Option<String> {
        match self.env.optional(key) {
            Ok(v) => v,
            Err(e) => {
                self.note(&e);
                None
            }
        }
    }

    fn secret(&mut self, key: &str) -> Option<SecretString> {
        self.opt(key).map(SecretString::from)
    }

    /// Parsed number or default. A set-but-unparsable value is recorded as a problem
    /// (no silent fallback: `load` fails) and the default is used only to finish building.
    fn num<T: FromStr + Copy>(&mut self, key: &str, default: T, expected: &'static str) -> T {
        match self.env.parse_or(key, default, expected) {
            Ok(v) => v,
            Err(e) => {
                self.note(&e);
                default
            }
        }
    }

    fn flag(&mut self, key: &str, default: bool) -> bool {
        match self.env.bool_or(key, default) {
            Ok(v) => v,
            Err(e) => {
                self.note(&e);
                default
            }
        }
    }

    fn list(&mut self, key: &str) -> Vec<String> {
        self.opt(key)
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn choice<T: Copy>(
        &mut self,
        key: &str,
        default: T,
        parse: fn(&str) -> Option<T>,
        expected: &'static str,
    ) -> T {
        match self.opt(key) {
            None => default,
            Some(v) => parse(&v).unwrap_or_else(|| {
                self.note(&ConfigError::Invalid {
                    key: key.to_owned(),
                    expected,
                });
                default
            }),
        }
    }
}

fn parse_rate_store(s: &str) -> Option<RateLimitStore> {
    match s.trim() {
        "memory" => Some(RateLimitStore::Memory),
        "redis" => Some(RateLimitStore::Redis),
        _ => None,
    }
}

fn parse_log_format(s: &str) -> Option<LogFormat> {
    match s.trim() {
        "json" => Some(LogFormat::Json),
        "pretty" => Some(LogFormat::Pretty),
        _ => None,
    }
}

fn parse_blob_backend(s: &str) -> Option<BlobBackend> {
    match s.trim() {
        "fs" => Some(BlobBackend::Fs),
        "s3" => Some(BlobBackend::S3),
        _ => None,
    }
}

fn parse_engine(s: &str) -> Option<DbEngine> {
    match s.trim() {
        "mysql" => Some(DbEngine::MySql),
        "tidb" => Some(DbEngine::TiDb),
        _ => None,
    }
}

fn parse_kek_provider(s: &str) -> Option<KekProvider> {
    match s.trim() {
        "env" => Some(KekProvider::Env),
        "azure-kv" => Some(KekProvider::AzureKv),
        _ => None,
    }
}

impl AppConfig {
    /// Load from env, then validate. Returns ALL problems at once.
    ///
    /// # Errors
    /// `ConfigErrors` listing every missing/invalid key and every violated startup rule.
    pub fn load(env: &Env) -> Result<Self, ConfigErrors> {
        Self::load_with(env, &[])
    }

    /// Like [`AppConfig::load`] plus extra checks (e.g. crypto's dev-key fingerprint check).
    ///
    /// # Errors
    /// See [`AppConfig::load`].
    pub fn load_with(env: &Env, extra: &[&dyn ConfigCheck]) -> Result<Self, ConfigErrors> {
        let (cfg, mut problems) = Self::build(env);
        problems.extend(validate_problems(&cfg, extra));
        if problems.is_empty() {
            Ok(cfg)
        } else {
            Err(ConfigErrors(problems))
        }
    }

    #[allow(clippy::too_many_lines)]
    fn build(env: &Env) -> (Self, Vec<ConfigProblem>) {
        let mut l = Loader {
            env,
            problems: Vec::new(),
        };

        // Fail closed: unknown/missing environment is treated as production for defaults.
        let environment = match l.opt("DSECURE_ENV") {
            None => {
                l.note(&ConfigError::Missing {
                    key: "DSECURE_ENV".to_owned(),
                });
                Environment::Production
            }
            Some(v) => Environment::parse(&v).unwrap_or_else(|| {
                l.note(&ConfigError::Invalid {
                    key: "DSECURE_ENV".to_owned(),
                    expected: "dev, test, staging or production",
                });
                Environment::Production
            }),
        };
        let run_mode = l.choice(
            "RUN_MODE",
            RunMode::Api,
            RunMode::parse,
            "api, workers or all",
        );

        let http = HttpConfig {
            addr: l
                .opt("HTTP_ADDR")
                .unwrap_or_else(|| "0.0.0.0:8080".to_owned()),
            trusted_proxy_hops_set: env.optional("TRUSTED_PROXY_HOPS").ok().flatten().is_some(),
            trusted_proxy_cidrs_set: env.optional("TRUSTED_PROXY_CIDRS").ok().flatten().is_some(),
            trusted_proxy_hops: l.num("TRUSTED_PROXY_HOPS", 0_u8, "an integer 0..=255"),
            trusted_proxy_cidrs: l.list("TRUSTED_PROXY_CIDRS"),
            cors_allowed_origins: l.list("CORS_ALLOWED_ORIGINS"),
            openapi_public: l.flag("OPENAPI_PUBLIC", !environment.is_production()),
            tokio_worker_threads: l.num("TOKIO_WORKER_THREADS", 2_usize, "a positive integer"),
            tokio_max_blocking_threads: l.num(
                "TOKIO_MAX_BLOCKING_THREADS",
                4_usize,
                "a positive integer",
            ),
            malloc_conf: l
                .opt("_RJEM_MALLOC_CONF")
                .unwrap_or_else(|| DEFAULT_MALLOC_CONF.to_owned()),
        };

        let default_conns = if matches!(run_mode, RunMode::Workers) {
            4_u32
        } else {
            8_u32
        };
        let db = DbConfig {
            url: l
                .secret("DATABASE_URL")
                .unwrap_or_else(|| SecretString::from(String::new())),
            tls_ca: l.secret("DB_TLS_CA"),
            expect_engine: l.choice(
                "DB_EXPECT_ENGINE",
                if environment.is_local() {
                    DbEngine::MySql
                } else {
                    DbEngine::TiDb
                },
                parse_engine,
                "mysql or tidb",
            ),
            max_connections: l.num("DB_MAX_CONNECTIONS", default_conns, "a positive integer"),
            acquire_timeout_ms: l.num("DB_ACQUIRE_TIMEOUT_MS", 2000_u64, "milliseconds"),
            tx_timeout_ms: l.num("DB_TX_TIMEOUT_MS", 5000_u64, "milliseconds"),
            max_execution_ms: l.num("DB_MAX_EXECUTION_MS", 3000_u64, "milliseconds"),
            lock_wait_timeout_s: l.num("DB_LOCK_WAIT_TIMEOUT_S", 5_u32, "seconds"),
            retry_max_attempts: l.num("DB_RETRY_MAX_ATTEMPTS", 3_u32, "an attempt count"),
            retry_base_delay_ms: l.num("DB_RETRY_BASE_DELAY_MS", 20_u64, "milliseconds"),
            statement_cache_capacity: l.num(
                "DB_STATEMENT_CACHE_CAPACITY",
                64_usize,
                "an entry count",
            ),
            migrator_url: l.secret("MIGRATOR_DATABASE_URL"),
        };

        let provider = match l.opt("KEK_PROVIDER") {
            None => None,
            Some(v) => {
                let p = parse_kek_provider(&v);
                if p.is_none() {
                    l.note(&ConfigError::Invalid {
                        key: "KEK_PROVIDER".to_owned(),
                        expected: "env or azure-kv",
                    });
                }
                p
            }
        };
        let env_active_id = l.opt("KEK_ENV_ACTIVE_ID");
        // Only the active id is read (Env cannot enumerate); id charset is checked in validate.
        let env_active_key = match &env_active_id {
            Some(id) if id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') => {
                l.secret(&format!("KEK_ENV_{id}"))
            }
            _ => None,
        };
        let kek = KekConfig {
            provider,
            env_active_id,
            env_active_key,
            azure_keyvault_uri: l.opt("AZURE_KEYVAULT_URI").map(Endpoint::new),
            azure_keyvault_kek_name: l.opt("AZURE_KEYVAULT_KEK_NAME"),
            azure_tenant_id: l.opt("AZURE_TENANT_ID"),
            azure_client_id: l.opt("AZURE_CLIENT_ID"),
            azure_client_secret: l.secret("AZURE_CLIENT_SECRET"),
        };

        let jwt = JwtConfig {
            issuer: l.opt("JWT_ISSUER").unwrap_or_default(),
            signing_kid_member: l.opt("JWT_SIGNING_KID_MEMBER").unwrap_or_default(),
            signing_kid_staff: l.opt("JWT_SIGNING_KID_STAFF").unwrap_or_default(),
            access_token_ttl_secs: l.num("ACCESS_TOKEN_TTL_SECS", 900_u32, "seconds"),
            refresh_ttl_web_days: l.num("REFRESH_TTL_WEB_DAYS", 30_u32, "days"),
            refresh_ttl_app_days: l.num("REFRESH_TTL_APP_DAYS", 90_u32, "days"),
            cursor_hmac_purpose: l.opt("CURSOR_HMAC_PURPOSE"),
        };

        let limits = LimitsConfig {
            max_inflight_requests: l.num("MAX_INFLIGHT_REQUESTS", 128_u32, "a positive integer"),
            max_json_body_bytes: l.num("MAX_JSON_BODY_BYTES", 65_536_usize, "bytes"),
            max_tenant_deks_cached: l.num("MAX_TENANT_DEKS_CACHED", 5000_u64, "an entry count"),
            authz_cache_entries: l.num("AUTHZ_CACHE_ENTRIES", 10_000_u64, "an entry count"),
        };

        let argon2 = Argon2Config {
            m_kib: l.num("ARGON2_M_KIB", 19_456_u32, "KiB"),
            t: l.num("ARGON2_T", 2_u32, "iterations"),
            p: l.num("ARGON2_P", 1_u32, "lanes"),
            login_hash_concurrency: l.num("LOGIN_HASH_CONCURRENCY", 3_u32, "a positive integer"),
        };

        let rate_limit = RateLimitConfig {
            store: l.choice(
                "RATE_LIMIT_STORE",
                RateLimitStore::Memory,
                parse_rate_store,
                "memory or redis",
            ),
            redis_url: l.secret("REDIS_URL"),
        };

        let telemetry = TelemetryConfig {
            otlp_endpoint: l.opt("OTEL_EXPORTER_OTLP_ENDPOINT").map(Endpoint::new),
            service_name: l.opt("OTEL_SERVICE_NAME"),
            log_level: l.opt("LOG_LEVEL").unwrap_or_else(|| "info".to_owned()),
            log_format: l.choice(
                "LOG_FORMAT",
                LogFormat::Json,
                parse_log_format,
                "json or pretty",
            ),
        };

        let blob = BlobConfig {
            backend: l.choice(
                "BLOB_BACKEND",
                BlobBackend::Fs,
                parse_blob_backend,
                "fs or s3",
            ),
            fs_root: l.opt("BLOB_FS_ROOT"),
            s3_endpoint: l.opt("S3_ENDPOINT").map(Endpoint::new),
            s3_bucket: l.opt("S3_BUCKET"),
            s3_access_key_id: l.secret("S3_ACCESS_KEY_ID"),
            s3_secret_access_key: l.secret("S3_SECRET_ACCESS_KEY"),
        };

        let workers = WorkersConfig {
            concurrency: l.num("WORKER_CONCURRENCY", 2_u32, "a positive integer"),
        };

        let cfg = Self {
            environment,
            run_mode,
            http,
            db,
            kek,
            jwt,
            limits,
            argon2,
            rate_limit,
            telemetry,
            blob,
            workers,
        };
        (cfg, l.problems)
    }
}
