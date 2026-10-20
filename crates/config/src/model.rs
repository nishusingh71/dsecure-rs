//! Typed config. Secrets are `SecretString` so `Debug` never prints them.

use secrecy::SecretString;

use crate::endpoint::Endpoint;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Dev,
    Test,
    Staging,
    Production,
}

impl Environment {
    #[must_use]
    pub const fn is_production(self) -> bool {
        matches!(self, Self::Production)
    }

    /// dev and test are the only "relaxed" environments.
    #[must_use]
    pub const fn is_local(self) -> bool {
        matches!(self, Self::Dev | Self::Test)
    }

    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "dev" => Some(Self::Dev),
            "test" => Some(Self::Test),
            "staging" => Some(Self::Staging),
            "production" => Some(Self::Production),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunMode {
    Api,
    Workers,
    All,
}

impl RunMode {
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "api" => Some(Self::Api),
            "workers" => Some(Self::Workers),
            "all" => Some(Self::All),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KekProvider {
    Env,
    AzureKv,
}

/// Engine the db crate must see at connect time (e.g. `VERSION()` contains `TiDB`).
/// The db crate enforces it; config only carries and validates the setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbEngine {
    MySql,
    TiDb,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitStore {
    Memory,
    Redis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobBackend {
    Fs,
    S3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Pretty,
}

#[derive(Debug)]
pub struct HttpConfig {
    pub addr: String,
    pub trusted_proxy_hops: u8,
    /// Raw CIDR strings (syntax checked by `validate`).
    pub trusted_proxy_cidrs: Vec<String>,
    /// Were the `TRUSTED_PROXY_*` keys explicitly set (prod requires it)?
    pub trusted_proxy_hops_set: bool,
    pub trusted_proxy_cidrs_set: bool,
    pub cors_allowed_origins: Vec<String>,
    pub openapi_public: bool,
    pub tokio_worker_threads: usize,
    pub tokio_max_blocking_threads: usize,
    pub malloc_conf: String,
}

#[derive(Debug)]
pub struct DbConfig {
    pub url: SecretString,
    /// CA bundle (path or PEM) for server-cert verification; required outside dev/test.
    pub tls_ca: Option<SecretString>,
    /// Expected server engine, enforced by the db crate at connect time. Default `tidb` in
    /// staging/production (the only allowed value there), `mysql` in dev/test.
    pub expect_engine: DbEngine,
    pub max_connections: u32,
    pub acquire_timeout_ms: u64,
    /// Max wall time of one transaction (ms).
    pub tx_timeout_ms: u64,
    /// Per-statement execution limit (ms), e.g. `max_execution_time`.
    pub max_execution_ms: u64,
    /// `innodb_lock_wait_timeout` in seconds.
    pub lock_wait_timeout_s: u32,
    pub retry_max_attempts: u32,
    pub retry_base_delay_ms: u64,
    /// sqlx statement cache capacity (0 disables).
    pub statement_cache_capacity: usize,
    /// Optional separate URL for the migrator (same URL rules as `url`).
    pub migrator_url: Option<SecretString>,
}

#[derive(Debug)]
pub struct KekConfig {
    /// `None` = `KEK_PROVIDER` unset (validate reports it).
    pub provider: Option<KekProvider>,
    pub env_active_id: Option<String>,
    /// Value of `KEK_ENV_<active id>` (base64 32 bytes).
    pub env_active_key: Option<SecretString>,
    pub azure_keyvault_uri: Option<Endpoint>,
    pub azure_keyvault_kek_name: Option<String>,
    pub azure_tenant_id: Option<String>,
    pub azure_client_id: Option<String>,
    pub azure_client_secret: Option<SecretString>,
}

#[derive(Debug)]
pub struct JwtConfig {
    pub issuer: String,
    pub signing_kid_member: String,
    pub signing_kid_staff: String,
    pub access_token_ttl_secs: u32,
    pub refresh_ttl_web_days: u32,
    pub refresh_ttl_app_days: u32,
    pub cursor_hmac_purpose: Option<String>,
}

#[derive(Debug)]
pub struct LimitsConfig {
    pub max_inflight_requests: u32,
    pub max_json_body_bytes: usize,
    pub max_tenant_deks_cached: u64,
    pub authz_cache_entries: u64,
}

#[derive(Debug)]
pub struct Argon2Config {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    pub login_hash_concurrency: u32,
}

#[derive(Debug)]
pub struct RateLimitConfig {
    pub store: RateLimitStore,
    pub redis_url: Option<SecretString>,
}

#[derive(Debug)]
pub struct TelemetryConfig {
    pub otlp_endpoint: Option<Endpoint>,
    pub service_name: Option<String>,
    pub log_level: String,
    pub log_format: LogFormat,
}

#[derive(Debug)]
pub struct BlobConfig {
    pub backend: BlobBackend,
    pub fs_root: Option<String>,
    pub s3_endpoint: Option<Endpoint>,
    pub s3_bucket: Option<String>,
    pub s3_access_key_id: Option<SecretString>,
    pub s3_secret_access_key: Option<SecretString>,
}

#[derive(Debug)]
pub struct WorkersConfig {
    pub concurrency: u32,
}

#[derive(Debug)]
pub struct AppConfig {
    pub environment: Environment,
    pub run_mode: RunMode,
    pub http: HttpConfig,
    pub db: DbConfig,
    pub kek: KekConfig,
    pub jwt: JwtConfig,
    pub limits: LimitsConfig,
    pub argon2: Argon2Config,
    pub rate_limit: RateLimitConfig,
    pub telemetry: TelemetryConfig,
    pub blob: BlobConfig,
    pub workers: WorkersConfig,
}
