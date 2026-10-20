//! Startup validation (spec §5). Fail closed; returns every problem; messages never carry values.

use std::net::IpAddr;

use common::limits;
use secrecy::ExposeSecret;

use crate::dburl::{self, TlsCheck};
use crate::endpoint::Endpoint;
use crate::error::{ConfigErrors, ConfigProblem};
use crate::model::{AppConfig, BlobBackend, DbEngine, KekProvider, RateLimitStore};

/// Argon2id floor (OWASP minimum): m >= 19456 KiB, t >= 2, p >= 1.
pub const ARGON2_MIN_M_KIB: u32 = 19_456;
pub const ARGON2_MIN_T: u32 = 2;
pub const ARGON2_MIN_P: u32 = 1;
pub const MAX_JSON_BODY_CAP: usize = 1024 * 1024;

/// Extension hook: other crates (e.g. crypto's dev-key fingerprint check) add their own rules.
pub trait ConfigCheck {
    /// Push problems (key + value-free text) into `out`.
    fn check(&self, cfg: &AppConfig, out: &mut Vec<ConfigProblem>);
}

impl AppConfig {
    /// Run all built-in startup rules.
    ///
    /// # Errors
    /// Every violated rule, at once.
    pub fn validate(&self) -> Result<(), ConfigErrors> {
        self.validate_with(&[])
    }

    /// Built-in rules plus `extra` checks.
    ///
    /// # Errors
    /// Every violated rule, at once.
    pub fn validate_with(&self, extra: &[&dyn ConfigCheck]) -> Result<(), ConfigErrors> {
        let problems = validate_problems(self, extra);
        if problems.is_empty() {
            Ok(())
        } else {
            Err(ConfigErrors(problems))
        }
    }
}

fn range<T: PartialOrd>(out: &mut Vec<ConfigProblem>, key: &str, v: T, lo: T, hi: T, what: &str) {
    if v < lo || v > hi {
        out.push(ConfigProblem::new(
            key,
            format!("out of range (allowed {what})"),
        ));
    }
}

fn missing(out: &mut Vec<ConfigProblem>, key: &str) {
    out.push(ConfigProblem::new(
        key,
        format!("missing required key `{key}`"),
    ));
}

fn blank_ep(s: Option<&Endpoint>) -> bool {
    s.is_none_or(Endpoint::is_blank)
}

fn blank(s: Option<&String>) -> bool {
    s.is_none_or(|v| v.trim().is_empty())
}

fn valid_cidr(s: &str) -> bool {
    let (ip, prefix) = match s.split_once('/') {
        Some((ip, p)) => (ip, Some(p)),
        None => (s, None),
    };
    let Ok(addr) = ip.parse::<IpAddr>() else {
        return false;
    };
    let max = if addr.is_ipv4() { 32_u8 } else { 128_u8 };
    prefix.is_none_or(|p| p.parse::<u8>().is_ok_and(|n| n <= max))
}

pub(crate) fn validate_problems(cfg: &AppConfig, extra: &[&dyn ConfigCheck]) -> Vec<ConfigProblem> {
    let mut out = Vec::new();
    let prod = cfg.environment.is_production();
    let local = cfg.environment.is_local();

    check_db(cfg, local, &mut out);
    check_kek(cfg, prod, &mut out);
    check_jwt(cfg, &mut out);
    check_argon2(cfg, local, &mut out);
    check_limits(cfg, &mut out);
    check_http(cfg, prod, local, &mut out);
    check_rate_limit_and_blob(cfg, prod, local, &mut out);

    for c in extra {
        c.check(cfg, &mut out);
    }
    out
}

/// Same rules for the app URL and the migrator URL (valid name, no legacy DB, TLS outside dev/test).
fn check_db_url(key: &str, url: &str, local: bool, out: &mut Vec<ConfigProblem>) {
    if !dburl::is_mysql_url(url) {
        out.push(ConfigProblem::new(
            key,
            "must be a valid mysql:// URL with a plain database name and no cert/socket keys",
        ));
    }
    if dburl::targets_legacy_db(url) {
        out.push(ConfigProblem::new(
            key,
            "must not point at the legacy database (refused in every environment)",
        ));
    }
    if !local {
        match dburl::tls_check(url) {
            TlsCheck::Verified => {}
            TlsCheck::NotVerified => out.push(ConfigProblem::new(
                key,
                "staging/production require exactly one ssl-mode=VERIFY_IDENTITY",
            )),
            TlsCheck::Ambiguous => out.push(ConfigProblem::new(
                key,
                "ambiguous TLS settings (duplicate or mis-cased ssl-mode key, or a #fragment)",
            )),
        }
    }
}

fn check_db(cfg: &AppConfig, local: bool, out: &mut Vec<ConfigProblem>) {
    let url = cfg.db.url.expose_secret();
    if url.trim().is_empty() {
        missing(out, "DATABASE_URL");
    } else {
        check_db_url("DATABASE_URL", url, local, out);
    }
    if let Some(m) = &cfg.db.migrator_url {
        check_db_url("MIGRATOR_DATABASE_URL", m.expose_secret(), local, out);
    }
    if !local {
        if cfg
            .db
            .tls_ca
            .as_ref()
            .is_none_or(|s| s.expose_secret().trim().is_empty())
        {
            missing(out, "DB_TLS_CA");
        }
        if cfg.db.expect_engine != DbEngine::TiDb {
            out.push(ConfigProblem::new(
                "DB_EXPECT_ENGINE",
                "must be `tidb` in staging/production",
            ));
        }
    }
    range(
        out,
        "DB_MAX_CONNECTIONS",
        cfg.db.max_connections,
        1,
        32,
        "1..=32",
    );
    range(
        out,
        "DB_ACQUIRE_TIMEOUT_MS",
        cfg.db.acquire_timeout_ms,
        100,
        30_000,
        "100..=30000",
    );
    range(
        out,
        "DB_TX_TIMEOUT_MS",
        cfg.db.tx_timeout_ms,
        100,
        60_000,
        "100..=60000",
    );
    range(
        out,
        "DB_MAX_EXECUTION_MS",
        cfg.db.max_execution_ms,
        100,
        60_000,
        "100..=60000",
    );
    range(
        out,
        "DB_LOCK_WAIT_TIMEOUT_S",
        cfg.db.lock_wait_timeout_s,
        1,
        50,
        "1..=50",
    );
    range(
        out,
        "DB_RETRY_MAX_ATTEMPTS",
        cfg.db.retry_max_attempts,
        1,
        10,
        "1..=10",
    );
    range(
        out,
        "DB_RETRY_BASE_DELAY_MS",
        cfg.db.retry_base_delay_ms,
        1,
        1000,
        "1..=1000",
    );
    range(
        out,
        "DB_STATEMENT_CACHE_CAPACITY",
        cfg.db.statement_cache_capacity,
        0,
        512,
        "0..=512",
    );
}

fn check_kek(cfg: &AppConfig, prod: bool, out: &mut Vec<ConfigProblem>) {
    let k = &cfg.kek;
    match k.provider {
        None => missing(out, "KEK_PROVIDER"),
        Some(KekProvider::Env) => {
            if prod {
                out.push(ConfigProblem::new(
                    "KEK_PROVIDER",
                    "`env` provider is not allowed in production (use azure-kv)",
                ));
            }
            match k.env_active_id.as_deref() {
                None => missing(out, "KEK_ENV_ACTIVE_ID"),
                Some(id) => {
                    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                        out.push(ConfigProblem::new(
                            "KEK_ENV_ACTIVE_ID",
                            "must be non-empty and contain only letters, digits or underscore",
                        ));
                    } else if k.env_active_key.is_none() {
                        missing(out, &format!("KEK_ENV_{id}"));
                    }
                }
            }
        }
        Some(KekProvider::AzureKv) => {
            for (key, val) in [
                ("AZURE_KEYVAULT_KEK_NAME", &k.azure_keyvault_kek_name),
                ("AZURE_TENANT_ID", &k.azure_tenant_id),
                ("AZURE_CLIENT_ID", &k.azure_client_id),
            ] {
                if blank(val.as_ref()) {
                    missing(out, key);
                }
            }
            if blank_ep(k.azure_keyvault_uri.as_ref()) {
                missing(out, "AZURE_KEYVAULT_URI");
            }
            if k.azure_client_secret.is_none() {
                missing(out, "AZURE_CLIENT_SECRET");
            }
        }
    }
}

fn check_jwt(cfg: &AppConfig, out: &mut Vec<ConfigProblem>) {
    let j = &cfg.jwt;
    for (key, val) in [
        ("JWT_ISSUER", &j.issuer),
        ("JWT_SIGNING_KID_MEMBER", &j.signing_kid_member),
        ("JWT_SIGNING_KID_STAFF", &j.signing_kid_staff),
    ] {
        if val.trim().is_empty() {
            missing(out, key);
        }
    }
    range(
        out,
        "ACCESS_TOKEN_TTL_SECS",
        j.access_token_ttl_secs,
        60,
        3600,
        "60..=3600",
    );
    range(
        out,
        "REFRESH_TTL_WEB_DAYS",
        j.refresh_ttl_web_days,
        1,
        365,
        "1..=365",
    );
    range(
        out,
        "REFRESH_TTL_APP_DAYS",
        j.refresh_ttl_app_days,
        1,
        365,
        "1..=365",
    );
}

fn check_argon2(cfg: &AppConfig, local: bool, out: &mut Vec<ConfigProblem>) {
    let a = &cfg.argon2;
    // Floor applies to staging + production. dev/test may go lower (fast tests) but never degenerate.
    let (min_m, min_t, min_p) = if local {
        (8, 1, 1)
    } else {
        (ARGON2_MIN_M_KIB, ARGON2_MIN_T, ARGON2_MIN_P)
    };
    if a.m_kib < min_m {
        out.push(ConfigProblem::new(
            "ARGON2_M_KIB",
            format!("below the floor ({min_m} KiB)"),
        ));
    }
    if a.t < min_t {
        out.push(ConfigProblem::new(
            "ARGON2_T",
            format!("below the floor ({min_t})"),
        ));
    }
    if a.p < min_p {
        out.push(ConfigProblem::new(
            "ARGON2_P",
            format!("below the floor ({min_p})"),
        ));
    }
    // Shared caps/budget (common::limits): crypto constructor bhi yahi use karta hai.
    range(
        out,
        "ARGON2_M_KIB",
        a.m_kib,
        0,
        limits::ARGON2_MAX_M_KIB,
        "<= 262144 KiB",
    );
    range(out, "ARGON2_T", a.t, 0, limits::ARGON2_MAX_T, "<= 10");
    range(out, "ARGON2_P", a.p, 0, limits::ARGON2_MAX_P, "<= 4");
    range(
        out,
        "LOGIN_HASH_CONCURRENCY",
        a.login_hash_concurrency,
        1,
        limits::LOGIN_HASH_CONCURRENCY_MAX,
        "1..=16",
    );
    if !limits::argon2_budget_ok(a.m_kib, a.login_hash_concurrency) {
        out.push(ConfigProblem::new(
            "LOGIN_HASH_CONCURRENCY",
            "ARGON2_M_KIB x LOGIN_HASH_CONCURRENCY exceeds the 128 MiB hashing memory budget",
        ));
    }
}

fn check_limits(cfg: &AppConfig, out: &mut Vec<ConfigProblem>) {
    let l = &cfg.limits;
    range(
        out,
        "MAX_JSON_BODY_BYTES",
        l.max_json_body_bytes,
        1,
        MAX_JSON_BODY_CAP,
        "1..=1048576",
    );
    range(
        out,
        "MAX_INFLIGHT_REQUESTS",
        l.max_inflight_requests,
        1,
        10_000,
        "1..=10000",
    );
    range(
        out,
        "MAX_TENANT_DEKS_CACHED",
        l.max_tenant_deks_cached,
        1,
        1_000_000,
        "1..=1000000",
    );
    range(
        out,
        "AUTHZ_CACHE_ENTRIES",
        l.authz_cache_entries,
        1,
        1_000_000,
        "1..=1000000",
    );
    range(
        out,
        "TOKIO_WORKER_THREADS",
        cfg.http.tokio_worker_threads,
        1,
        64,
        "1..=64",
    );
    range(
        out,
        "TOKIO_MAX_BLOCKING_THREADS",
        cfg.http.tokio_max_blocking_threads,
        1,
        512,
        "1..=512",
    );
    range(
        out,
        "WORKER_CONCURRENCY",
        cfg.workers.concurrency,
        1,
        64,
        "1..=64",
    );
}

fn check_http(cfg: &AppConfig, prod: bool, local: bool, out: &mut Vec<ConfigProblem>) {
    let h = &cfg.http;
    if h.addr.parse::<std::net::SocketAddr>().is_err() {
        out.push(ConfigProblem::new(
            "HTTP_ADDR",
            "must be host:port (socket address)",
        ));
    }
    if prod && h.openapi_public {
        out.push(ConfigProblem::new(
            "OPENAPI_PUBLIC",
            "must not be true in production",
        ));
    }
    for c in &h.trusted_proxy_cidrs {
        if !valid_cidr(c) {
            out.push(ConfigProblem::new(
                "TRUSTED_PROXY_CIDRS",
                "contains an invalid CIDR entry",
            ));
            break;
        }
    }
    // Every non-local environment (staging too): hops > 0 needs the proxy ranges.
    if !local && h.trusted_proxy_hops > 0 && h.trusted_proxy_cidrs.is_empty() {
        out.push(ConfigProblem::new(
            "TRUSTED_PROXY_CIDRS",
            "must list the proxy ranges when TRUSTED_PROXY_HOPS > 0",
        ));
    }
    if prod {
        if !h.trusted_proxy_hops_set {
            missing(out, "TRUSTED_PROXY_HOPS");
        }
        if !h.trusted_proxy_cidrs_set {
            missing(out, "TRUSTED_PROXY_CIDRS");
        }
        if h.cors_allowed_origins.iter().any(|o| o == "*") {
            out.push(ConfigProblem::new(
                "CORS_ALLOWED_ORIGINS",
                "wildcard origin is not allowed in production",
            ));
        }
    }
}

fn check_rate_limit_and_blob(
    cfg: &AppConfig,
    prod: bool,
    local: bool,
    out: &mut Vec<ConfigProblem>,
) {
    if cfg.rate_limit.store == RateLimitStore::Redis && cfg.rate_limit.redis_url.is_none() {
        missing(out, "REDIS_URL");
    }
    let b = &cfg.blob;
    match b.backend {
        BlobBackend::Fs => {
            if prod {
                out.push(ConfigProblem::new(
                    "BLOB_BACKEND",
                    "`fs` backend is not allowed in production (use s3)",
                ));
            }
            if !local && blank(b.fs_root.as_ref()) {
                missing(out, "BLOB_FS_ROOT");
            }
        }
        BlobBackend::S3 => {
            if blank_ep(b.s3_endpoint.as_ref()) {
                missing(out, "S3_ENDPOINT");
            }
            if blank(b.s3_bucket.as_ref()) {
                missing(out, "S3_BUCKET");
            }
            if b.s3_access_key_id.is_none() {
                missing(out, "S3_ACCESS_KEY_ID");
            }
            if b.s3_secret_access_key.is_none() {
                missing(out, "S3_SECRET_ACCESS_KEY");
            }
        }
    }
}
