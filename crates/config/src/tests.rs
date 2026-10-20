use common::config_util::Env;

use crate::{
    AppConfig, BlobBackend, ConfigCheck, ConfigErrors, ConfigProblem, DbEngine, EXIT_CONFIG,
    Endpoint, Environment, KekProvider, LogFormat, RateLimitStore, RunMode, dburl, exit_code_for,
    load_or_exit_code,
};

const SECRET_DB: &str =
    "mysql://app:hunter2-db-pass@db.example.com:4000/x?ssl-mode=VERIFY_IDENTITY";

fn dev_pairs() -> Vec<(String, String)> {
    [
        ("DSECURE_ENV", "dev"),
        ("DATABASE_URL", SECRET_DB),
        ("KEK_PROVIDER", "env"),
        ("KEK_ENV_ACTIVE_ID", "k1"),
        ("KEK_ENV_k1", "c2VjcmV0LWtlay1rZXktdmFsdWUtMzItYnl0ZXMhIQ=="),
        ("JWT_ISSUER", "https://dsecure.test"),
        ("JWT_SIGNING_KID_MEMBER", "m1"),
        ("JWT_SIGNING_KID_STAFF", "s1"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect()
}

fn prod_pairs() -> Vec<(String, String)> {
    let mut p = dev_pairs();
    p.retain(|(k, _)| !k.starts_with("KEK_ENV") && k != "DSECURE_ENV" && k != "KEK_PROVIDER");
    for (k, v) in [
        ("DSECURE_ENV", "production"),
        ("KEK_PROVIDER", "azure-kv"),
        ("AZURE_KEYVAULT_URI", "https://kv.example.net"),
        ("AZURE_KEYVAULT_KEK_NAME", "kek"),
        ("AZURE_TENANT_ID", "tenant"),
        ("AZURE_CLIENT_ID", "client"),
        ("AZURE_CLIENT_SECRET", "azure-secret-value"),
        ("DB_TLS_CA", "/etc/ssl/ca-secret-path.pem"),
        ("TRUSTED_PROXY_HOPS", "1"),
        ("TRUSTED_PROXY_CIDRS", "10.0.0.0/8, 2001:db8::/32"),
        ("BLOB_BACKEND", "s3"),
        ("S3_ENDPOINT", "https://s3.example.net"),
        ("S3_BUCKET", "b"),
        ("S3_ACCESS_KEY_ID", "s3-key-id-value"),
        ("S3_SECRET_ACCESS_KEY", "s3-secret-value"),
    ] {
        p.push((k.to_owned(), v.to_owned()));
    }
    p
}

fn with(mut base: Vec<(String, String)>, over: &[(&str, &str)]) -> Env {
    for (k, v) in over {
        base.retain(|(bk, _)| bk != k);
        base.push(((*k).to_owned(), (*v).to_owned()));
    }
    Env::from_pairs(base)
}

fn without(mut base: Vec<(String, String)>, keys: &[&str]) -> Env {
    base.retain(|(k, _)| !keys.contains(&k.as_str()));
    Env::from_pairs(base)
}

fn err(env: &Env) -> ConfigErrors {
    AppConfig::load(env).expect_err("must be rejected")
}

#[test]
fn dev_defaults_applied() {
    let cfg = AppConfig::load(&Env::from_pairs(dev_pairs())).expect("dev config valid");
    assert_eq!(cfg.environment, Environment::Dev);
    assert_eq!(cfg.run_mode, RunMode::Api);
    assert_eq!(cfg.http.addr, "0.0.0.0:8080");
    assert_eq!(cfg.http.tokio_worker_threads, 2);
    assert_eq!(cfg.http.tokio_max_blocking_threads, 4);
    assert_eq!(cfg.http.trusted_proxy_hops, 0);
    assert!(cfg.http.trusted_proxy_cidrs.is_empty());
    assert!(cfg.http.openapi_public, "non-prod default is public spec");
    assert_eq!(cfg.db.max_connections, 8);
    assert_eq!(cfg.db.acquire_timeout_ms, 2000);
    assert_eq!(cfg.kek.provider, Some(KekProvider::Env));
    assert_eq!(cfg.jwt.access_token_ttl_secs, 900);
    assert_eq!(cfg.jwt.refresh_ttl_web_days, 30);
    assert_eq!(cfg.jwt.refresh_ttl_app_days, 90);
    assert_eq!(cfg.limits.max_inflight_requests, 128);
    assert_eq!(cfg.limits.max_json_body_bytes, 65_536);
    assert_eq!(cfg.limits.max_tenant_deks_cached, 5000);
    assert_eq!(cfg.limits.authz_cache_entries, 10_000);
    assert_eq!(cfg.argon2.m_kib, 19_456);
    assert_eq!(cfg.argon2.t, 2);
    assert_eq!(cfg.argon2.p, 1);
    assert_eq!(cfg.argon2.login_hash_concurrency, 3);
    assert_eq!(cfg.rate_limit.store, RateLimitStore::Memory);
    assert_eq!(cfg.telemetry.log_level, "info");
    assert_eq!(cfg.telemetry.log_format, LogFormat::Json);
    assert!(cfg.telemetry.otlp_endpoint.is_none());
    assert_eq!(cfg.blob.backend, BlobBackend::Fs);
    assert_eq!(cfg.workers.concurrency, 2);
    assert!(cfg.http.malloc_conf.starts_with("background_thread:true"));
}

#[test]
fn workers_mode_defaults_to_four_connections() {
    let cfg = AppConfig::load(&with(dev_pairs(), &[("RUN_MODE", "workers")])).expect("valid");
    assert_eq!(cfg.db.max_connections, 4);
}

#[test]
fn valid_production_config_loads() {
    let cfg = AppConfig::load(&Env::from_pairs(prod_pairs())).expect("prod valid");
    assert_eq!(cfg.environment, Environment::Production);
    assert!(!cfg.http.openapi_public, "prod default is private spec");
    assert_eq!(cfg.http.trusted_proxy_cidrs.len(), 2);
}

#[test]
fn missing_required_keys_all_reported_at_once() {
    let e = err(&Env::from_pairs([("RUN_MODE", "api")]));
    for key in [
        "DSECURE_ENV",
        "DATABASE_URL",
        "KEK_PROVIDER",
        "JWT_ISSUER",
        "JWT_SIGNING_KID_MEMBER",
        "JWT_SIGNING_KID_STAFF",
    ] {
        assert!(e.has_key(key), "expected problem for {key}: {e}");
    }
}

#[test]
fn env_provider_requires_active_id_and_key() {
    let e = err(&without(dev_pairs(), &["KEK_ENV_ACTIVE_ID", "KEK_ENV_k1"]));
    assert!(e.has_key("KEK_ENV_ACTIVE_ID"));
    let e = err(&without(dev_pairs(), &["KEK_ENV_k1"]));
    assert!(e.has_key("KEK_ENV_k1"));
}

#[test]
fn azure_provider_requires_its_keys() {
    let e = err(&without(
        prod_pairs(),
        &["AZURE_KEYVAULT_URI", "AZURE_CLIENT_SECRET"],
    ));
    assert!(e.has_key("AZURE_KEYVAULT_URI"));
    assert!(e.has_key("AZURE_CLIENT_SECRET"));
}

#[test]
fn production_rejects_env_kek_provider() {
    let e = err(&with(
        prod_pairs(),
        &[
            ("KEK_PROVIDER", "env"),
            ("KEK_ENV_ACTIVE_ID", "k1"),
            ("KEK_ENV_k1", "x"),
        ],
    ));
    assert!(e.has_key("KEK_PROVIDER"));
}

#[test]
fn staging_may_use_env_kek_provider() {
    let mut p = dev_pairs();
    p.retain(|(k, _)| k != "DSECURE_ENV");
    p.push(("DSECURE_ENV".into(), "staging".into()));
    p.push(("BLOB_FS_ROOT".into(), "/data/blobs".into()));
    p.push(("DB_TLS_CA".into(), "/etc/ca.pem".into()));
    p.push(("DB_EXPECT_ENGINE".into(), "tidb".into()));
    AppConfig::load(&Env::from_pairs(p)).expect("staging with env kek ok");
}

#[test]
fn production_requires_verified_tls() {
    for url in [
        "mysql://u:p@h:4000/db",
        "mysql://u:p@h:4000/db?ssl-mode=REQUIRED",
        "mysql://u:p@h:4000/db?ssl-mode=VERIFY_CA",
        "mysql://u:p@h:4000/db?ssl-mode=DISABLED",
    ] {
        let e = err(&with(prod_pairs(), &[("DATABASE_URL", url)]));
        assert!(e.has_key("DATABASE_URL"), "{url}");
    }
    // sslmode alias + case-insensitive value accepted.
    AppConfig::load(&with(
        prod_pairs(),
        &[(
            "DATABASE_URL",
            "mysql://u:p@h:4000/db?sslmode=VERIFY_IDENTITY",
        )],
    ))
    .expect("verified tls ok");
    // dev may be plain.
    AppConfig::load(&with(
        dev_pairs(),
        &[("DATABASE_URL", "mysql://u:p@localhost:3306/db")],
    ))
    .expect("dev plain ok");
}

#[test]
fn database_url_must_be_mysql() {
    let e = err(&with(
        dev_pairs(),
        &[("DATABASE_URL", "postgres://u:p@h/db")],
    ));
    assert!(e.has_key("DATABASE_URL"));
}

#[test]
fn argon2_floor_enforced_outside_local_envs() {
    for (k, v) in [
        ("ARGON2_M_KIB", "19455"),
        ("ARGON2_T", "1"),
        ("ARGON2_P", "0"),
    ] {
        let e = err(&with(prod_pairs(), &[(k, v)]));
        assert!(e.has_key(k), "{k}");
    }
    // staging too.
    let e = err(&with(
        prod_pairs(),
        &[("DSECURE_ENV", "staging"), ("ARGON2_T", "1")],
    ));
    assert!(e.has_key("ARGON2_T"));
    // dev may be cheap, but not zero.
    AppConfig::load(&with(
        dev_pairs(),
        &[("ARGON2_M_KIB", "64"), ("ARGON2_T", "1")],
    ))
    .expect("cheap dev argon ok");
    assert!(err(&with(dev_pairs(), &[("ARGON2_P", "0")])).has_key("ARGON2_P"));
}

#[test]
fn argon2_caps_and_memory_budget_enforced() {
    // caps (ab sab environments mein, dev mein bhi)
    for (k, v) in [
        ("ARGON2_M_KIB", "262145"),
        ("ARGON2_T", "11"),
        ("ARGON2_P", "5"),
        ("LOGIN_HASH_CONCURRENCY", "17"),
    ] {
        let e = err(&with(dev_pairs(), &[(k, v)]));
        assert!(e.has_key(k), "{k}={v}");
    }
    // budget: 19456 KiB x 7 > 128 MiB
    let e = err(&with(prod_pairs(), &[("LOGIN_HASH_CONCURRENCY", "7")]));
    assert!(e.has_key("LOGIN_HASH_CONCURRENCY"));
    AppConfig::load(&with(prod_pairs(), &[("LOGIN_HASH_CONCURRENCY", "6")]))
        .expect("6 fits budget");
    // ek bada hash akela budget ke andar
    AppConfig::load(&with(
        prod_pairs(),
        &[("ARGON2_M_KIB", "131072"), ("LOGIN_HASH_CONCURRENCY", "1")],
    ))
    .expect("128 MiB x 1 fits");
    let e = err(&with(
        prod_pairs(),
        &[("ARGON2_M_KIB", "131072"), ("LOGIN_HASH_CONCURRENCY", "2")],
    ));
    assert!(e.has_key("LOGIN_HASH_CONCURRENCY"));
    // default (19456 x 3) valid
    AppConfig::load(&Env::from_pairs(dev_pairs())).expect("defaults ok");
}

#[test]
fn openapi_public_rejected_in_production() {
    let e = err(&with(prod_pairs(), &[("OPENAPI_PUBLIC", "true")]));
    assert!(e.has_key("OPENAPI_PUBLIC"));
}

#[test]
fn trusted_proxy_required_in_production() {
    let e = err(&without(prod_pairs(), &["TRUSTED_PROXY_HOPS"]));
    assert!(e.has_key("TRUSTED_PROXY_HOPS"));
    let e = err(&without(prod_pairs(), &["TRUSTED_PROXY_CIDRS"]));
    assert!(e.has_key("TRUSTED_PROXY_CIDRS"));
    let e = err(&with(
        prod_pairs(),
        &[("TRUSTED_PROXY_CIDRS", "10.0.0.0/33")],
    ));
    assert!(e.has_key("TRUSTED_PROXY_CIDRS"));
    let e = err(&with(
        prod_pairs(),
        &[("TRUSTED_PROXY_CIDRS", "not-a-cidr")],
    ));
    assert!(e.has_key("TRUSTED_PROXY_CIDRS"));
    // dev does not need them.
    AppConfig::load(&Env::from_pairs(dev_pairs())).expect("dev ok");
}

#[test]
fn limits_out_of_range_rejected() {
    for (k, v) in [
        ("DB_MAX_CONNECTIONS", "0"),
        ("DB_MAX_CONNECTIONS", "33"),
        ("MAX_JSON_BODY_BYTES", "1048577"),
        ("MAX_JSON_BODY_BYTES", "0"),
        ("MAX_INFLIGHT_REQUESTS", "0"),
        ("DB_ACQUIRE_TIMEOUT_MS", "5"),
        ("ACCESS_TOKEN_TTL_SECS", "86400"),
        ("LOGIN_HASH_CONCURRENCY", "0"),
        ("WORKER_CONCURRENCY", "0"),
    ] {
        let e = err(&with(dev_pairs(), &[(k, v)]));
        assert!(e.has_key(k), "{k}={v} should be rejected");
    }
    // boundaries accepted.
    AppConfig::load(&with(
        dev_pairs(),
        &[
            ("DB_MAX_CONNECTIONS", "32"),
            ("MAX_JSON_BODY_BYTES", "1048576"),
        ],
    ))
    .expect("edges ok");
}

#[test]
fn run_mode_and_enum_values_validated() {
    assert!(err(&with(dev_pairs(), &[("RUN_MODE", "both")])).has_key("RUN_MODE"));
    assert!(err(&with(dev_pairs(), &[("DSECURE_ENV", "prod")])).has_key("DSECURE_ENV"));
    assert!(err(&with(dev_pairs(), &[("KEK_PROVIDER", "vault")])).has_key("KEK_PROVIDER"));
    assert!(err(&with(dev_pairs(), &[("LOG_FORMAT", "xml")])).has_key("LOG_FORMAT"));
    for mode in ["api", "workers", "all"] {
        AppConfig::load(&with(dev_pairs(), &[("RUN_MODE", mode)])).expect("mode ok");
    }
}

#[test]
fn unparsable_number_is_a_problem_not_a_silent_default() {
    let e = err(&with(dev_pairs(), &[("DB_MAX_CONNECTIONS", "lots")]));
    assert!(e.has_key("DB_MAX_CONNECTIONS"));
    assert!(!e.to_string().contains("lots"));
}

#[test]
fn redis_and_s3_conditionals() {
    let e = err(&with(dev_pairs(), &[("RATE_LIMIT_STORE", "redis")]));
    assert!(e.has_key("REDIS_URL"));
    let e = err(&with(dev_pairs(), &[("BLOB_BACKEND", "s3")]));
    for k in [
        "S3_ENDPOINT",
        "S3_BUCKET",
        "S3_ACCESS_KEY_ID",
        "S3_SECRET_ACCESS_KEY",
    ] {
        assert!(e.has_key(k), "{k}");
    }
}

#[test]
fn production_with_dev_settings_is_rejected() {
    // T-C6 (config part): a dev-style config flipped to production must fail on many rules at once.
    let e = err(&with(dev_pairs(), &[("DSECURE_ENV", "production")]));
    for k in [
        "KEK_PROVIDER",
        "TRUSTED_PROXY_HOPS",
        "TRUSTED_PROXY_CIDRS",
        "BLOB_BACKEND",
    ] {
        assert!(e.has_key(k), "expected {k} in: {e}");
    }
    let e = err(&with(
        dev_pairs(),
        &[
            ("DSECURE_ENV", "production"),
            ("DATABASE_URL", "mysql://u:p@localhost:3306/db"),
            ("OPENAPI_PUBLIC", "true"),
            ("ARGON2_M_KIB", "64"),
            ("ARGON2_T", "1"),
        ],
    ));
    for k in ["DATABASE_URL", "OPENAPI_PUBLIC", "ARGON2_M_KIB", "ARGON2_T"] {
        assert!(e.has_key(k), "expected {k}");
    }
    // Unknown environment fails closed too.
    assert!(err(&without(dev_pairs(), &["DSECURE_ENV"])).has_key("DSECURE_ENV"));
}

#[test]
fn errors_never_contain_values() {
    let env = with(
        prod_pairs(),
        &[
            ("DATABASE_URL", "mysql://app:hunter2-db-pass@h:4000/db"),
            ("ARGON2_M_KIB", "12345"),
            ("OPENAPI_PUBLIC", "true"),
            ("KEK_PROVIDER", "env"),
            ("KEK_ENV_ACTIVE_ID", "k1"),
            ("KEK_ENV_k1", "kek-secret-value"),
            ("DB_MAX_CONNECTIONS", "abc-secret"),
        ],
    );
    let text = format!("{} {:?}", err(&env), err(&env));
    for needle in [
        "hunter2",
        "kek-secret-value",
        "azure-secret-value",
        "s3-secret-value",
        "abc-secret",
        "12345",
    ] {
        assert!(!text.contains(needle), "leaked {needle}");
    }
}

#[test]
fn debug_output_contains_no_secret_values() {
    let mut p = prod_pairs();
    p.push(("RATE_LIMIT_STORE".into(), "redis".into()));
    p.push((
        "REDIS_URL".into(),
        "redis://:redis-pass-value@r:6379".into(),
    ));
    let cfg = AppConfig::load(&Env::from_pairs(p)).expect("valid");
    let mut dev = dev_pairs();
    dev.push(("RATE_LIMIT_STORE".into(), "redis".into()));
    dev.push((
        "REDIS_URL".into(),
        "redis://:redis-pass-value@r:6379".into(),
    ));
    let dev_cfg = AppConfig::load(&Env::from_pairs(dev)).expect("valid");
    for c in [&cfg, &dev_cfg] {
        let dbg = format!("{c:?} {c:#?}");
        for secret in [
            "hunter2-db-pass",
            "azure-secret-value",
            "s3-key-id-value",
            "s3-secret-value",
            "redis-pass-value",
            "c2VjcmV0LWtlay1rZXktdmFsdWUt",
        ] {
            assert!(!dbg.contains(secret), "Debug leaked {secret}");
        }
        assert!(dbg.to_lowercase().contains("redacted"));
    }
}

struct DenyAll;
impl ConfigCheck for DenyAll {
    fn check(&self, _cfg: &AppConfig, out: &mut Vec<ConfigProblem>) {
        out.push(ConfigProblem::new("KEK_ENV_k1", "dev key fingerprint"));
    }
}

#[test]
fn extra_checks_run_and_combine() {
    let cfg = AppConfig::load(&Env::from_pairs(dev_pairs())).expect("valid");
    assert!(cfg.validate().is_ok());
    let e = cfg.validate_with(&[&DenyAll]).expect_err("hook rejects");
    assert!(e.has_key("KEK_ENV_k1"));
    let e = AppConfig::load_with(&Env::from_pairs(dev_pairs()), &[&DenyAll]).expect_err("rejected");
    assert_eq!(e.problems().len(), 1);
}

#[test]
fn exit_code_is_78() {
    let e = err(&Env::from_pairs([("X", "y")]));
    assert_eq!(exit_code_for(&e), 78);
    assert_eq!(EXIT_CONFIG, 78);
}

fn db_err(env_name: &str, url: &str) -> ConfigErrors {
    err(&with(
        prod_pairs(),
        &[("DSECURE_ENV", env_name), ("DATABASE_URL", url)],
    ))
}

#[test]
fn tls_bypass_forms_rejected() {
    let base = "mysql://u:p@h:4000/db";
    for q in [
        // (a) wrong-case key: sqlx ignores it and falls back to PREFERRED
        "?SSL-MODE=VERIFY_IDENTITY",
        "?Ssl-Mode=VERIFY_IDENTITY",
        // (b) duplicate key, one percent-encoded
        "?ssl-mode=VERIFY_IDENTITY&ssl%2Dmode=DISABLED",
        "?ssl-mode=VERIFY_IDENTITY&ssl-mode=DISABLED",
        "?ssl-mode=DISABLED&sslmode=VERIFY_IDENTITY",
        // (c) fragment hides a second key from the driver
        "?ssl-mode=DISABLED#&ssl-mode=VERIFY_IDENTITY",
        "?ssl-mode=VERIFY_IDENTITY#frag",
        // not strict enough
        "?ssl-mode=verify_identity",
        "?ssl-mode=VERIFY_CA",
        "",
    ] {
        let url = format!("{base}{q}");
        for env_name in ["production", "staging"] {
            assert!(
                db_err(env_name, &url).has_key("DATABASE_URL"),
                "{env_name} {q}"
            );
        }
    }
    assert!(!dburl::has_verified_tls(
        "mysql://u:p@h/db?SSL-MODE=VERIFY_IDENTITY"
    ));
    assert!(!dburl::has_verified_tls(
        "mysql://u:p@h/db?ssl-mode=DISABLED#&ssl-mode=VERIFY_IDENTITY"
    ));
}

#[test]
fn tls_valid_forms_accepted_in_prod_and_staging() {
    for q in [
        "?ssl-mode=VERIFY_IDENTITY",
        "?sslmode=VERIFY_IDENTITY",
        "?charset=utf8mb4&ssl-mode=VERIFY_IDENTITY",
        "?ssl%2Dmode=VERIFY_IDENTITY",
    ] {
        let url = format!("mysql://u:p@h:4000/db{q}");
        for env_name in ["production", "staging"] {
            let mut p = prod_pairs();
            p.retain(|(k, _)| k != "DSECURE_ENV" && k != "DATABASE_URL");
            p.push(("DSECURE_ENV".into(), env_name.into()));
            p.push(("DATABASE_URL".into(), url.clone()));
            AppConfig::load(&Env::from_pairs(p)).unwrap_or_else(|e| panic!("{env_name} {q}: {e}"));
        }
    }
}

#[test]
fn staging_enforces_tls_ca_and_engine() {
    assert!(db_err("staging", "mysql://u:p@h/db").has_key("DATABASE_URL"));
    let e = err(&with(
        without_vec(prod_pairs(), &["DB_TLS_CA"]),
        &[("DSECURE_ENV", "staging")],
    ));
    assert!(e.has_key("DB_TLS_CA"));
    for env_name in ["staging", "production"] {
        let e = err(&with(
            prod_pairs(),
            &[("DSECURE_ENV", env_name), ("DB_EXPECT_ENGINE", "mysql")],
        ));
        assert!(e.has_key("DB_EXPECT_ENGINE"));
    }
    let e = err(&with(dev_pairs(), &[("DB_EXPECT_ENGINE", "oracle")]));
    assert!(e.has_key("DB_EXPECT_ENGINE"));
}

fn without_vec(mut v: Vec<(String, String)>, keys: &[&str]) -> Vec<(String, String)> {
    v.retain(|(k, _)| !keys.contains(&k.as_str()));
    v
}

#[test]
fn db_engine_defaults_by_environment() {
    let dev = AppConfig::load(&Env::from_pairs(dev_pairs())).expect("dev");
    assert_eq!(dev.db.expect_engine, DbEngine::MySql);
    let dev_tidb =
        AppConfig::load(&with(dev_pairs(), &[("DB_EXPECT_ENGINE", "tidb")])).expect("dev");
    assert_eq!(dev_tidb.db.expect_engine, DbEngine::TiDb);
    let prod = AppConfig::load(&Env::from_pairs(prod_pairs())).expect("prod");
    assert_eq!(prod.db.expect_engine, DbEngine::TiDb);
}

#[test]
fn legacy_database_refused_in_every_environment() {
    for name in [
        "Cloud_Erase__App",
        "cloud_erase__app",
        "CLOUD_ERASE__APP",
        "Cloud%5FErase%5F%5FApp",
        "cloud%5ferase%5f%5fapp",
        "Cloud_Erase__App/",
        "Cloud%255FErase%255F%255FApp",
    ] {
        let url = format!("mysql://u:p@h:4000/{name}?ssl-mode=VERIFY_IDENTITY");
        for env_name in ["dev", "test", "staging", "production"] {
            assert!(
                db_err(env_name, &url).has_key("DATABASE_URL"),
                "{env_name} {name}"
            );
        }
    }
    // dev, plain URL.
    assert!(
        err(&with(
            dev_pairs(),
            &[("DATABASE_URL", "mysql://u:p@localhost/cloud_erase__app")]
        ))
        .has_key("DATABASE_URL")
    );
    // a different db is fine.
    AppConfig::load(&with(
        dev_pairs(),
        &[("DATABASE_URL", "mysql://u:p@localhost/dsecure_new")],
    ))
    .expect("other db ok");
}

#[test]
fn endpoint_debug_redacts_userinfo_and_query() {
    let mut p = prod_pairs();
    p.retain(|(k, _)| k != "S3_ENDPOINT" && k != "AZURE_KEYVAULT_URI");
    p.push((
        "S3_ENDPOINT".into(),
        "https://s3user:s3-endpoint-token@s3.example.net:9000/p?sig=qq-secret".into(),
    ));
    p.push((
        "AZURE_KEYVAULT_URI".into(),
        "https://kvuser:kv-endpoint-token@kv.example.net".into(),
    ));
    p.push((
        "OTEL_EXPORTER_OTLP_ENDPOINT".into(),
        "https://otlp-user:otlp-endpoint-token@otel.example.net:4318".into(),
    ));
    let cfg = AppConfig::load(&Env::from_pairs(p)).expect("valid");
    let dbg = format!("{cfg:?} {cfg:#?}");
    for leaked in [
        "s3-endpoint-token",
        "kv-endpoint-token",
        "otlp-endpoint-token",
        "s3user",
        "qq-secret",
    ] {
        assert!(!dbg.contains(leaked), "leaked {leaked}");
    }
    assert!(dbg.contains("s3.example.net:9000"));
    assert_eq!(format!("{:?}", Endpoint::new("not a url")), "[redacted]");
    // the real value is still reachable for the connecting code.
    assert!(
        cfg.blob
            .s3_endpoint
            .as_ref()
            .is_some_and(|e| e.as_str().contains("s3-endpoint-token"))
    );
}

#[test]
fn load_failure_maps_to_exit_code_78() {
    let bad = Env::from_pairs([("DSECURE_ENV", "production")]);
    assert_eq!(load_or_exit_code(&bad, &[]).err(), Some(78));
    assert!(load_or_exit_code(&Env::from_pairs(dev_pairs()), &[]).is_ok());
}

#[test]
fn db_tuning_defaults_and_bounds() {
    let cfg = AppConfig::load(&Env::from_pairs(dev_pairs())).expect("dev");
    assert_eq!(cfg.db.tx_timeout_ms, 5000);
    assert_eq!(cfg.db.max_execution_ms, 3000);
    assert_eq!(cfg.db.lock_wait_timeout_s, 5);
    assert_eq!(cfg.db.retry_max_attempts, 3);
    assert_eq!(cfg.db.retry_base_delay_ms, 20);
    assert_eq!(cfg.db.statement_cache_capacity, 64);
    assert!(cfg.db.migrator_url.is_none());
    for (k, lo, hi) in [
        ("DB_TX_TIMEOUT_MS", "100", "60000"),
        ("DB_MAX_EXECUTION_MS", "100", "60000"),
        ("DB_LOCK_WAIT_TIMEOUT_S", "1", "50"),
        ("DB_RETRY_MAX_ATTEMPTS", "1", "10"),
        ("DB_RETRY_BASE_DELAY_MS", "1", "1000"),
        ("DB_STATEMENT_CACHE_CAPACITY", "0", "512"),
    ] {
        AppConfig::load(&with(dev_pairs(), &[(k, lo)])).unwrap_or_else(|e| panic!("{k} lo: {e}"));
        AppConfig::load(&with(dev_pairs(), &[(k, hi)])).unwrap_or_else(|e| panic!("{k} hi: {e}"));
    }
    for (k, bad) in [
        ("DB_TX_TIMEOUT_MS", "99"),
        ("DB_TX_TIMEOUT_MS", "60001"),
        ("DB_MAX_EXECUTION_MS", "99"),
        ("DB_MAX_EXECUTION_MS", "60001"),
        ("DB_LOCK_WAIT_TIMEOUT_S", "0"),
        ("DB_LOCK_WAIT_TIMEOUT_S", "51"),
        ("DB_RETRY_MAX_ATTEMPTS", "0"),
        ("DB_RETRY_MAX_ATTEMPTS", "11"),
        ("DB_RETRY_BASE_DELAY_MS", "0"),
        ("DB_RETRY_BASE_DELAY_MS", "1001"),
        ("DB_STATEMENT_CACHE_CAPACITY", "513"),
    ] {
        assert!(err(&with(dev_pairs(), &[(k, bad)])).has_key(k), "{k}={bad}");
    }
}

#[test]
fn migrator_url_gets_same_checks() {
    const OK: &str = "mysql://m:p@h:4000/dsecure_new?ssl-mode=VERIFY_IDENTITY";
    let mut p = prod_pairs();
    p.push(("MIGRATOR_DATABASE_URL".into(), OK.into()));
    let cfg = AppConfig::load(&Env::from_pairs(p)).expect("valid migrator url");
    assert!(cfg.db.migrator_url.is_some());
    assert!(!format!("{cfg:?}").contains("m:p@h"));
    for bad in [
        "mysql://m:p@h:4000/dsecure_new",
        "mysql://m:p@h:4000/dsecure_new?ssl-mode=VERIFY_IDENTITY&ssl-mode=DISABLED",
        "mysql://m:p@h:4000/cloud_erase__app?ssl-mode=VERIFY_IDENTITY",
        "mysql://m:p@h:4000/Cloud_Erase__App%00?ssl-mode=VERIFY_IDENTITY",
        "mysql://m:p@h:4000/db%00x?ssl-mode=VERIFY_IDENTITY",
        "mysql://m:p@h:4000/db?ssl-mode=VERIFY_IDENTITY&ssl-ca=/x",
        "postgres://m:p@h/db",
    ] {
        let e = err(&with(prod_pairs(), &[("MIGRATOR_DATABASE_URL", bad)]));
        assert!(e.has_key("MIGRATOR_DATABASE_URL"), "{bad}");
        assert!(!e.has_key("DATABASE_URL"));
    }
    // dev: plain TLS ok, legacy db still refused.
    AppConfig::load(&with(
        dev_pairs(),
        &[("MIGRATOR_DATABASE_URL", "mysql://m:p@localhost/db")],
    ))
    .expect("dev plain ok");
    assert!(
        err(&with(
            dev_pairs(),
            &[(
                "MIGRATOR_DATABASE_URL",
                "mysql://m:p@localhost/CLOUD_ERASE__APP"
            )]
        ))
        .has_key("MIGRATOR_DATABASE_URL")
    );
}

#[test]
fn staging_hops_without_cidrs_refused() {
    let mut p = without_vec(prod_pairs(), &["TRUSTED_PROXY_CIDRS"]);
    p.retain(|(k, _)| k != "DSECURE_ENV");
    p.push(("DSECURE_ENV".into(), "staging".into()));
    let e = err(&Env::from_pairs(p.clone()));
    assert!(e.has_key("TRUSTED_PROXY_CIDRS"));
    // with CIDRs it loads; dev with hops and no CIDRs stays allowed.
    p.push(("TRUSTED_PROXY_CIDRS".into(), "10.0.0.0/8".into()));
    AppConfig::load(&Env::from_pairs(p)).expect("staging ok with cidrs");
    AppConfig::load(&with(dev_pairs(), &[("TRUSTED_PROXY_HOPS", "1")])).expect("dev ok");
}
