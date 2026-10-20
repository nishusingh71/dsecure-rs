# Phase 0 spec: Foundation (implementation-ready, draft v3, TiDB, 20 Oct 2026)

Owner: Mr. W. Author: architect. Status: **DRAFT v3, ready to build** (D-01 = TiDB and D-50 = 512 MB closed). Defaults: env KEK in dev (D-03 open), D-52 UUIDv7 + clustered `(tenant_id, id)`, D-53 MySQL 8 + TiDB containers, D-55 no DB FKs. Needs owner before P0-21: **D-51** (new TiDB non-prod cluster).

Goal: ek runnable, tested Rust workspace jo **bina kisi production secret** ke chale (dev keys local generate hoti hain, kabhi commit nahi), aur jisme baaki saare phases ke safety patterns locked hon: deny-by-default routing, 3-check authz, **tenant-scoped data access enforced in the data layer (TiDB has no RLS)**, field encryption, audit, bounded resources, observability, CI on MySQL + TiDB.

Out of scope: product features (members CRUD etc. Phase 1), importer, production deploy.

---

## 1. Workspace tree

```
dsecure-rs/
├─ Cargo.toml                    # [workspace] members, [workspace.dependencies], [workspace.lints]
├─ rust-toolchain.toml           # channel = "1.85" or newer stable (pin exact at start), components rustfmt, clippy
├─ rustfmt.toml  clippy.toml  deny.toml  .gitignore (.dev/, target/, .env*)
├─ .cargo/config.toml            # [alias] xtask = "run -p xtask --"
├─ .github/workflows/ci.yml
├─ docker/Dockerfile             # multi-stage, distroless/cc, non-root
├─ docker/compose.dev.yml        # mysql:8.0 (FK/CHECK shadow) + pingcap/tidb standalone (+ optional valkey); image tags pinned at start (not verified today)
├─ crates/
│  ├─ common/src/{lib.rs, ids.rs, redact.rs, error.rs, cursor.rs, clock.rs, config_util.rs}
│  ├─ crypto/src/{lib.rs, keys.rs, kek_env.rs, kek_azure.rs(feature "azure-kv"), keyring.rs,
│  │               field.rs, envelope_format.rs, blind_index.rs, password.rs, signing.rs, devkeys.rs}
│  ├─ domain/src/{lib.rs, rbac/{mod.rs, permissions.rs, roles.rs, rules.rs, features.rs}, tenant.rs}
│  ├─ auth/src/{lib.rs, principal.rs, token.rs, session.rs, stepup.rs, policy.rs, state.rs}
│  ├─ db/src/{lib.rs, pool.rs (MySqlPool + session init), engine.rs (TiDB|MySQL detect), tenant_tx.rs, identity_tx.rs,
│  │          platform_tx.rs, write_guard.rs, retry.rs, epochs.rs (authz epoch poller), table_classes.rs (registry),
│  │          repo/{tenants.rs, users.rs, memberships.rs, directory.rs, sessions.rs, keys.rs}, outbox.rs, jobs.rs (lease), idempotency.rs}
│  ├─ db/queries/<table>/<name>.sql   # ALL SQL; header `-- params: tenant_id, ...`; checked by sql-lint
│  ├─ db/migrations/0100_0001_tenants.sql ... (one DDL per file; DATABASE.md §4, §5, §8 sets 0100/0150/0200/0800)
│  ├─ db/migrations_shadow/*.sql      # MySQL-only FK statements for CI (D-55)
│  ├─ audit/src/{lib.rs, event.rs, sink_db.rs, chain.rs (hourly chain blocks)}
│  ├─ storage/src/{lib.rs, blob.rs, fs.rs, s3.rs(feature "s3"), stream_crypto.rs}
│  ├─ api/src/{main.rs, app.rs, router.rs (PolicyRouter), middleware/{request_id.rs, client_ip.rs, limits.rs,
│  │           authn.rs, authz.rs, idempotency.rs, errors.rs}, routes/{health.rs, auth.rs, me.rs, platform_dev.rs},
│  │           openapi.rs, telemetry.rs, alloc.rs}
│  ├─ workers/src/{main.rs, runner.rs (lease claim), jobs/{outbox_relay.rs, audit_chain_seal.rs, invariant_checks.rs}}   # purge jobs exist but disabled (D-56)
│  └─ testkit/src/{lib.rs, engines.rs (MySQL + TiDB containers), world.rs, principals.rs, matrix.rs, cross_tenant.rs}
├─ xtask/src/main.rs             # dev-keys | db-reset (dev only) | route-policies [--check] | sqlx-prepare | sql-lint | schema-check | migrate-lint | no-raw-sql | explain-check | ru-report | loadtest
├─ loadtest/k6/{phase0.js}
└─ docs/
```

Dependency direction: `ARCHITECTURE.md` §3 (no cycles; `domain` and `common` have no IO deps).

---

## 2. Workspace dependencies (major lines; pin exact versions at start — not verified today)

```toml
[workspace.dependencies]
tokio = { version = "1", features = ["rt-multi-thread", "macros", "signal", "time", "sync"] }
axum = "0.8"
tower = { version = "0.5", features = ["limit", "load-shed", "timeout", "util"] }
tower-http = { version = "0.6", features = ["trace", "cors", "request-id", "limit", "sensitive-headers", "catch-panic", "set-header"] }
hyper = "1"
sqlx = { version = "0.8", default-features = false, features = ["runtime-tokio", "tls-rustls", "mysql", "uuid", "time", "macros", "migrate", "json"] }   # TiDB via MySQL protocol
sqlparser = "*"           # xtask sql-lint (MySQL dialect); pin at start
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_jcs = "*"            # RFC 8785 canonical JSON: pick a maintained crate at start (not verified) or implement + test vectors
uuid = { version = "1", features = ["v7", "serde"] }
time = { version = "0.3", features = ["serde", "formatting", "parsing"] }
thiserror = "2"
anyhow = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["json", "env-filter"] }
opentelemetry = "*"; opentelemetry_sdk = "*"; opentelemetry-otlp = "*"; tracing-opentelemetry = "*"   # pin compatible set
aws-lc-rs = "1"
argon2 = "0.5"
bcrypt = "*"               # legacy hash verify only (pin at start)
jsonwebtoken = "*"         # ES256 only (pin at start; v9+)
secrecy = "0.10"
zeroize = { version = "1", features = ["derive"] }
figment = { version = "0.10", features = ["env"] }
moka = { version = "0.12", features = ["sync"] }
utoipa = { version = "5", features = ["axum_extras", "uuid", "time"] }
utoipa-axum = "*"
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "json", "stream"] }
tikv-jemallocator = "0.6"
tikv-jemalloc-ctl = "0.6"
base64 = "0.22"
async-trait = "0.1"
# dev
testcontainers = "*"; testcontainers-modules = { version = "*", features = ["mysql"] }   # TiDB via GenericImage("pingcap/tidb")
insta = { version = "1", features = ["json"] }
proptest = "1"
wiremock = "0.6"
```
(`"*"` = choose and pin at Phase 0 start; listed only where I am not sure of the current major.)

```toml
[workspace.lints.rust]
unsafe_code = "forbid"
[workspace.lints.clippy]
unwrap_used = "deny"; expect_used = "deny"; panic = "deny"; print_stdout = "deny"; dbg_macro = "deny"
todo = "deny"; disallowed_methods = "deny"; large_futures = "warn"
```
`clippy.toml` `disallowed-methods`: `axum::Router::route` (outside `api::router`), `sqlx::query`, `sqlx::query_as`, `sqlx::query_scalar`, `sqlx::raw_sql`, `sqlx::Executor::*` (outside `db` crate), `std::env::var` (outside config), `tokio::spawn` (use `bounded_spawn`). Macros (`query!`, `query_file!`) clippy se nahi pakde jaate → `xtask no-raw-sql` grep: `sqlx::` usage or `#[allow(clippy::disallowed_methods)]` outside `crates/db` = CI fail.

---

## 3. Public types and traits (contracts between crates)

### 3.1 `common`
```rust
macro_rules! id { ($n:ident) => { #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)] pub struct $n(pub uuid::Uuid); } }
id!(TenantId); id!(UserId); id!(MembershipId); id!(SessionId); id!(GroupId); id!(DeviceId); id!(GrantId); id!(RequestId);

pub struct Redacted<T>(T);            // Debug/Display = "[redacted]"; serde never serialises it to logs
pub struct Email(String);             // normalised (trim, NFKC, lowercase); Debug redacted

pub enum AppErrorKind { BadRequest, Unauthenticated, Forbidden, NotFound, Conflict, PreconditionFailed,
    FeatureDisabled, StepUpRequired, QuotaExceeded, RateLimited { retry_after_s: u32 }, PayloadTooLarge,
    Unavailable { retry_after_s: u32 }, NotPersisted, Internal }
pub struct AppError { pub kind: AppErrorKind, pub code: &'static str, pub detail: std::borrow::Cow<'static, str>,
                      pub fields: Vec<FieldError>, pub source: Option<anyhow::Error> }

pub struct Cursor { pub sort_key: time::OffsetDateTime, pub id: uuid::Uuid }   // opaque base64url + HMAC tag
pub struct Page { pub limit: u16 /* 1..=200 */, pub after: Option<Cursor> }
pub struct PageOut<T> { pub data: Vec<T>, pub next_cursor: Option<String> }
pub trait Clock: Send + Sync { fn now(&self) -> time::OffsetDateTime; }
```

### 3.2 `crypto`
```rust
pub enum KeyPurpose { Identity, Pii, Reports, Secrets, BidxEmail, BidxLicense, BidxTenant, Audit }
pub struct Kid(pub String);
pub struct Dek(zeroize::Zeroizing<[u8; 32]>);
pub struct WrappedDek { pub kek_ref: String, pub bytes: Vec<u8> }

#[async_trait::async_trait]
pub trait KeyProvider: Send + Sync {                         // KEK: env (dev/test) or Azure Key Vault (prod)
    fn active_kek_ref(&self) -> &str;
    async fn wrap(&self, dek: &Dek) -> Result<WrappedDek, CryptoError>;
    async fn unwrap(&self, w: &WrappedDek) -> Result<Dek, CryptoError>;
    fn is_dev(&self) -> bool;                               // production refuses dev providers
}

#[async_trait::async_trait]
pub trait DekStore: Send + Sync {                           // implemented in `db` (data_keys table)
    async fn active(&self, p: KeyPurpose, tenant: Option<TenantId>) -> Result<Option<(Kid, WrappedDek)>, CryptoError>;
    async fn by_kid(&self, kid: &Kid) -> Result<Option<(KeyPurpose, Option<TenantId>, WrappedDek)>, CryptoError>;
    async fn insert(&self, kid: &Kid, p: KeyPurpose, tenant: Option<TenantId>, w: &WrappedDek) -> Result<(), CryptoError>;
}

pub struct KeyRing { /* bounded moka cache Kid -> Dek (MAX_TENANT_DEKS_CACHED), platform DEKs pinned */ }
impl KeyRing {
    pub async fn load_platform(provider: Arc<dyn KeyProvider>, store: Arc<dyn DekStore>) -> Result<Self, CryptoError>; // fail closed
    pub async fn active(&self, p: KeyPurpose, tenant: Option<TenantId>) -> Result<(Kid, Arc<Dek>), CryptoError>; // creates tenant DEK lazily
    pub async fn get(&self, kid: &Kid) -> Result<Arc<Dek>, CryptoError>;
}

pub struct FieldContext<'a> { pub table: &'static str, pub column: &'static str,
                              pub tenant: Option<TenantId>, pub row_id: uuid::Uuid, pub purpose: KeyPurpose, pub _p: PhantomData<&'a ()> }
#[async_trait::async_trait]
pub trait FieldEncryptor: Send + Sync {
    async fn encrypt(&self, plaintext: &[u8], ctx: &FieldContext<'_>) -> Result<Vec<u8>, CryptoError>;  // format DATABASE.md §3
    async fn decrypt(&self, stored: &[u8], ctx: &FieldContext<'_>) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError>;
    fn kid_of(&self, stored: &[u8]) -> Result<Kid, CryptoError>;
}

pub enum BlindScope { Global, Tenant(TenantId) }
pub enum BlindKind { Email, LicenseKey, Serial, Mac, Fingerprint, Hwid }
pub trait BlindIndexer: Send + Sync {
    fn index(&self, kind: BlindKind, scope: BlindScope, raw: &str) -> Result<[u8; 32], CryptoError>;  // normalises per kind
}

pub enum VerifyOutcome { Valid { needs_rehash: bool }, Invalid }
#[async_trait::async_trait]
pub trait PasswordHasher: Send + Sync {        // Argon2id m=19456 KiB, t=2, p=1; semaphore LOGIN_HASH_CONCURRENCY; spawn_blocking
    async fn hash(&self, pw: secrecy::SecretString) -> Result<String, CryptoError>;              // PHC string
    async fn verify(&self, pw: secrecy::SecretString, phc_or_bcrypt: &str) -> Result<VerifyOutcome, CryptoError>; // bcrypt → needs_rehash
}

#[async_trait::async_trait]
pub trait Signer: Send + Sync {                 // Ed25519 (certificates, offline licences), ES256 (JWT)
    fn kid(&self) -> &str;
    fn alg(&self) -> SigAlg;
    async fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn public_key(&self) -> &[u8];
}
pub fn verify(alg: SigAlg, public_key: &[u8], msg: &[u8], sig: &[u8]) -> bool;
```

### 3.3 `domain::rbac`
```rust
pub enum TenantRole { Owner, Admin, Member, Viewer }           // rank 100/80/40/20
pub enum StaffRole { Superadmin, Support, Billing, Auditor }
pub enum Feature { Subusers, Groups, UserActivity, PrivateCloud }
pub enum Perm { ProfileReadSelf, ProfileUpdateSelf, PasswordChangeSelf, SessionsReadSelf, SessionsRevokeSelf,
                MembersRead, MembersCreate, MembersUpdate, MembersAssignRole, MembersSetCapabilities, MembersDisable,
                MembersDelete, MembersResetPassword, MembersTransferResources, GroupsRead, /* ... full RBAC.md §4 ... */ }
pub enum PlatformPerm { TenantsRead, TenantsSuspend, FeaturesToggle, QuotasUpdate, StaffAccessOpen, /* ... */ }
pub enum Scope { Tenant, Group, SelfOnly }
pub fn grants(role: TenantRole, perm: Perm) -> Option<Scope>;          // RBAC.md §4 matrix as code (const table)
pub fn ga_grants(perm: Perm) -> Option<Scope>;                          // group admin column
pub fn can_grant(actor: TenantRole, target: TenantRole) -> bool;       // target rank < actor rank
pub fn can_manage(actor: &ActorState, target: &MemberState) -> bool;
```
Phase 0 mein poora catalogue enum + matrix table + unit tests; endpoints Phase 1 mein.

### 3.4 `auth`
```rust
pub enum Principal { Member(MemberPrincipal), Device(DevicePrincipal), Staff(StaffPrincipal), Cleaner(CleanerPrincipal), Anonymous }
pub struct MemberPrincipal { pub user: UserId, pub tenant: TenantId, pub membership: MembershipId, pub session: SessionId,
                             pub role: TenantRole, pub ga_groups: SmallVec<[GroupId; 4]>, pub caps: Capabilities,
                             pub features: FeatureSet, pub authz_version: i64, pub mfa_at: Option<OffsetDateTime> }
pub struct StaffPrincipal { pub user: UserId, pub role: StaffRole, pub session: SessionId, pub grant: Option<ActiveGrant> }

pub enum Audience { Web, App, Device, Platform, Cleaner }
pub trait TokenIssuer: Send + Sync { fn issue_access(&self, c: &AccessClaims) -> Result<String, AuthError>; }
pub trait TokenVerifier: Send + Sync { fn verify(&self, token: &str, expected: &[Audience]) -> Result<AccessClaims, AuthError>; } // ES256 allowlist, kid lookup

#[async_trait::async_trait]
pub trait PrincipalStateLoader: Send + Sync {   // live state: one indexed query; moka cache keyed (membership, authz_version)
    async fn load_member(&self, claims: &AccessClaims) -> Result<MemberPrincipal, AuthError>;  // checks session, user, membership, tenant status
}
// Cache: moka keyed by session id; entry valid only while epoch_seen == db::epochs::current(tenant).
// Poller (AUTHZ_EPOCH_POLL_MS) refreshes epochs; poller stale > 10 s → bypass cache (live load), never deny-by-default.
// Policy::high_risk() routes always live-load.

pub struct TenantScope { pub tenant: TenantId, pub actor: MembershipId, pub visibility: Visibility, pub staff_grant: Option<GrantId> }
pub enum Visibility { Tenant, Groups(SmallVec<[GroupId; 4]>), SelfOnly }

pub struct Policy { /* principal kinds, perm, feature, product, step_up, idempotent, public_reason */ }
impl Policy {
    pub fn public(reason: &'static str) -> Self;
    pub fn member() -> Self; pub fn device() -> Self; pub fn member_or_device() -> Self; pub fn staff() -> Self;
    pub fn permission(self, p: Perm) -> Self; pub fn platform(self, p: PlatformPerm) -> Self;
    pub fn feature(self, f: Feature) -> Self; pub fn step_up(self, action: &'static str) -> Self; pub fn idempotent(self) -> Self;
    pub fn evaluate(&self, p: &Principal) -> Result<Authorized, Denied>;   // returns scope; any error = Denied
}
pub struct Authz<const P: u16>(pub TenantScope);   // extractor: only constructible by authz middleware after evaluate()
```

### 3.5 `db`
```rust
pub enum Engine { TiDb { version: String }, MySql { version: String } }   // detected at pool init (SELECT VERSION())
pub struct Db { pool: sqlx::MySqlPool, engine: Engine, epochs: Arc<EpochMap> }
pub struct TenantTx<'c> { tx: sqlx::Transaction<'c, sqlx::MySql>, tenant: TenantId, scope: TenantScope }  // no public ctor
pub struct IdentityTx<'c>;  pub struct PlatformTx<'c>;  pub struct SystemTx<'c>;  pub struct PublicVerifyTx<'c>;
impl Db {
    pub async fn tenant_tx(&self, authz: &Authorized) -> Result<TenantTx<'_>, DbError>;            // BEGIN (pessimistic on TiDB)
    pub async fn tenant_tx_for_job(&self, job: &ClaimedJob) -> Result<TenantTx<'_>, DbError>;      // tenant from job row
    pub async fn tenant_tx_for_staff(&self, grant: &ActiveGrant) -> Result<TenantTx<'_>, DbError>; // grant re-checked, audited
    pub async fn identity_tx(&self) -> Result<IdentityTx<'_>, DbError>;
    pub async fn platform_tx(&self, staff: &StaffPrincipal) -> Result<PlatformTx<'_>, DbError>;
    pub async fn system_tx(&self) -> Result<SystemTx<'_>, DbError>;                                // infra tables only
    pub async fn with_retry<T, F>(&self, f: F) -> Result<T, DbError> where F: FnMut(&mut TenantTx) -> BoxFuture<Result<T, DbError>>; // 1213/1205/9007/8028/... max 3
}
pub trait WriteOutcome { fn expect_one(self) -> Result<(), DbError>; fn expect_n(self, n: u64) -> Result<(), DbError>; } // else NotPersisted
pub fn assert_row_tenant(tx: &TenantTx<'_>, row_tenant: TenantId) -> Result<(), DbError>;   // L6; mismatch = Internal + alert
pub async fn outbox_insert(tx: &mut TenantTx<'_>, ev: OutboxEvent) -> Result<(), DbError>;
pub async fn bump_epoch(tx: &mut TenantTx<'_>) -> Result<(), DbError>;    // same tx as every authz change
pub struct JobQueue; // enqueue (job_key unique, max_pending per tenant/kind), claim (lease, DATABASE.md §8.4), heartbeat, complete, fail(backoff), reaper
```
Repository rule: har public fn ka pehla argument `&mut TenantTx` / `&mut IdentityTx` / `&mut PlatformTx` / `&mut SystemTx`; SQL sirf `queries/*.sql` se (`query_file_as!`); list functions `Page` lete hain aur `PageOut` lautate hain (keyset on `id`).
Session init per connection: `SET time_zone='+00:00'`, `SET SESSION max_execution_time=?`, `SET SESSION innodb_lock_wait_timeout=?`, TiDB only: `SET SESSION tidb_txn_mode='pessimistic'`.

### 3.6 `audit`
```rust
pub struct AuditEvent { pub action: AuditAction /* enum, catalogue */, pub outcome: Outcome,
    pub actor: ActorRef, pub tenant: Option<TenantId>, pub staff_grant: Option<GrantId>,
    pub target: Option<TargetRef>, pub request_id: RequestId, pub ip_hmac: Option<[u8; 32]>,
    pub metadata: AuditMeta /* typed struct per action, serialised < 2 KB, no PII */ }
#[async_trait::async_trait]
pub trait AuditSink: Send + Sync {
    async fn record_in_tx(&self, tx: &mut (dyn AuditTx + Send), ev: AuditEvent) -> Result<(), AuditError>; // same tx as business write
    async fn record(&self, ev: AuditEvent) -> Result<(), AuditError>;   // auth failures etc.; bounded channel, overflow → metric + sync fallback
}
```

### 3.7 `storage`
```rust
#[async_trait::async_trait]
pub trait BlobStore: Send + Sync {
    async fn put_stream(&self, key: &BlobKey, body: BoxStream<'static, Result<Bytes, io::Error>>, max_bytes: u64) -> Result<BlobMeta, StorageError>;
    async fn get_stream(&self, key: &BlobKey) -> Result<BoxStream<'static, Result<Bytes, io::Error>>, StorageError>;
}
// stream_crypto: encrypt/decrypt 64 KB STREAM chunks (SECURITY.md §3) — O(chunk) memory
```

---

## 4. Phase 0 HTTP surface

| Route | Policy | Purpose |
|---|---|---|
| `GET /health/live` | Public("liveness") | 200 `{"status":"ok"}` always if process up |
| `GET /health/ready` | Public("readiness") | 200/503 `{"status":"ok|degraded","checks":{"db":"ok","keys":"ok","migrations":"ok"}}` — no versions, no hostnames |
| `POST /api/v1/auth/login` | Public("login; rate limited") | email + password (+ optional `tenant_id` choice) → access + refresh; account state checks; lockout |
| `POST /api/v1/auth/refresh` | Public("refresh token") | rotation + reuse detection + full state re-check |
| `POST /api/v1/auth/logout` | member/staff | revoke session |
| `POST /api/v1/auth/step-up` | member/staff | password → step-up token |
| `GET /api/v1/me` | member, `ProfileReadSelf` | proves authn + live state |
| `GET /api/v1/me/sessions` | member, `SessionsReadSelf` | proves keyset pagination |
| `POST /api/v1/dev/fixtures` | **compiled only with feature `dev-fixtures`; route absent in release builds** | seed tenant/users for local testing |
| `GET /api/v1/openapi.json` | Public("api spec") in non-prod; staff in prod | spec |

---

## 5. Config keys (env)

| Key | Required | Default | Notes |
|---|---|---|---|
| `DSECURE_ENV` | yes | — | `dev` / `test` / `staging` / `production` |
| `HTTP_ADDR` | no | `0.0.0.0:8080` | Render `PORT` mapped |
| `RUN_MODE` | no | `api` | `api` / `workers` / `all` |
| `TOKIO_WORKER_THREADS` | no | `2` | |
| `TOKIO_MAX_BLOCKING_THREADS` | no | `4` | |
| `DATABASE_URL` | yes (secret) | — | `mysql://` TiDB Serverless endpoint; prod/staging: `ssl-mode=VERIFY_IDENTITY` enforced; never logged |
| `DB_TLS_CA` | prod/staging yes | — | CA bundle path for TiDB Cloud |
| `DB_EXPECT_ENGINE` | no | `tidb` in staging/prod, `any` in dev | startup fails if detected engine differs (prevents pointing prod at a MySQL) |
| `DB_TX_TIMEOUT_MS` | no | `5000` | app-side tx timeout |
| `DB_MAX_EXECUTION_TIME_MS` / `DB_LOCK_WAIT_TIMEOUT_S` | no | `5000` / `5` | session vars |
| `DB_RETRY_MAX` | no | `3` | conflict/deadlock retry |
| `AUTHZ_EPOCH_POLL_MS` | no | `2000` | epoch poller |
| `DB_MAX_CONNECTIONS` | no | `8` (api) / `4` (workers) | |
| `DB_ACQUIRE_TIMEOUT_MS` | no | `2000` | fail fast → 503 |
| `KEK_PROVIDER` | yes | — | `env` (dev/test/staging only unless D-03 says otherwise) / `azure-kv` |
| `KEK_ENV_ACTIVE_ID`, `KEK_ENV_<ID>` | if env | — | base64 32 bytes; dev generated by `xtask dev-keys` into `.dev/keys/` |
| `AZURE_KEYVAULT_URI`, `AZURE_KEYVAULT_KEK_NAME`, `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` | if azure-kv | — | secrets |
| `JWT_ISSUER` | yes | — | |
| `JWT_SIGNING_KID_MEMBER`, `JWT_SIGNING_KID_STAFF` | yes | — | refer to `signing_keys` rows (wrapped private keys) |
| `ACCESS_TOKEN_TTL_SECS` | no | `900` | |
| `REFRESH_TTL_WEB_DAYS` / `REFRESH_TTL_APP_DAYS` | no | `30` / `90` | D-40 |
| `CURSOR_HMAC_PURPOSE` | no | derived | cursor tamper protection (HKDF from platform DEK) |
| `TRUSTED_PROXY_HOPS` / `TRUSTED_PROXY_CIDRS` | prod yes | `0` / empty | |
| `CORS_ALLOWED_ORIGINS` | no | empty | |
| `MAX_INFLIGHT_REQUESTS` | no | `128` | |
| `MAX_JSON_BODY_BYTES` | no | `65536` | |
| `LOGIN_HASH_CONCURRENCY` | no | `3` | Argon2id memory bound |
| `ARGON2_M_KIB` / `ARGON2_T` / `ARGON2_P` | no | `19456` / `2` / `1` | prod lower bound enforced |
| `RATE_LIMIT_STORE` | no | `memory` | `memory` / `redis` (never DB: RU) |
| `REDIS_URL` | if redis | — | secret |
| `MAX_TENANT_DEKS_CACHED` | no | `5000` | |
| `AUTHZ_CACHE_ENTRIES` | no | `10000` | |
| `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME` | no | unset = stdout only | |
| `LOG_LEVEL`, `LOG_FORMAT` | no | `info`, `json` | |
| `OPENAPI_PUBLIC` | no | `false` in prod | |
| `BLOB_BACKEND` | no | `fs` (dev) | `fs` / `s3` |
| `BLOB_FS_ROOT` / `S3_ENDPOINT`, `S3_BUCKET`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY` | per backend | — | secrets |
| `WORKER_CONCURRENCY` | no | `2` | |
| `_RJEM_MALLOC_CONF` | no | `background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:1000,narenas:2` | jemalloc |

**Startup validation (fail closed, exit code 78):** missing required keys; `DSECURE_ENV=production` with `KEK_PROVIDER=env` (unless D-03 explicitly allows) or dev key fingerprints; DB TLS not `VERIFY_IDENTITY` in prod/staging; detected engine ≠ `DB_EXPECT_ENGINE`; `DATABASE_URL` database name equals the legacy database name (`Cloud_Erase__App`, compared case-insensitively) → refuse; KEK unwrap failure; JWT signing keys missing; Argon2 params below floor; `OPENAPI_PUBLIC=true` in prod. Logs show which key is missing, never values.

---

## 6. Phase 0 migrations
One DDL per file (`DATABASE.md` §11.1): sets `0100_tenancy_identity` (tenants, tenant_settings, tenant_features, tenant_feature_changes, tenant_quotas, authz_epochs, users, user_credentials, mfa_*, platform_staff, staff_access_grants, departments, `groups`, memberships, membership_directory, membership_capabilities, group_memberships, group_admin_grants, member_preferences), `0150_keys`, `0200_sessions`, `0800_audit_infra` (audit_events, audit_chain_blocks, outbox_events, jobs, idempotency_keys, tenant_counters, member_counters). `migrations_shadow/` FKs for MySQL CI. DB users/grants (`DATABASE.md` §2.5) are **not** a migration: `docs/ops/db_users.sql` draft, applied by owner/main session per environment. Dev: `cargo xtask db-reset` (refuses unless `DSECURE_ENV=dev` and host is localhost/127.0.0.1).

## 7. Tests to write (all must pass in CI)

| ID | Test | Crate |
|---|---|---|
| T-C1 | FieldEncryptor round trip; tamper (nonce/tag/kid/AAD table/column/tenant/row) → error; wrong tenant DEK → error; 10k nonces unique | crypto |
| T-C2 | Envelope format parse fuzz (proptest): never panics | crypto |
| T-C3 | BlindIndexer normalisation (email case/NFKC/whitespace; MAC separators) + scope separation (same value, different tenant → different index) | crypto |
| T-C4 | Argon2id verify + needs_rehash for bcrypt; semaphore bound (N+1th waits/503); prod param floor | crypto |
| T-C5 | Ed25519/ES256 sign-verify; wrong key fails | crypto |
| T-C6 | Startup refuses dev KEK in production config | crypto/api |
| T-D1 | `can_grant`/`can_manage` proptest (never target ≥ actor); matrix table = `RBAC.md` §4 snapshot | domain |
| T-A1 | Token: wrong aud, wrong kid, HS256-forged, `alg:none`, expired, nbf future, staff token on member audience → reject | auth |
| T-A2 | Account states (suspended, disabled, locked, unverified, membership disabled, tenant suspended) at login, refresh, request | auth+api |
| T-A3 | Refresh rotation + reuse detection revokes family | api |
| T-A4 | `authz_version` change → next request uses new role (no stale cache) | api |
| T-DB1 | Cross-tenant: for every Phase 0 repo fn, TenantTx(A) + B's ids → None / 0 rows / NotFound; insert with B's parent id → NotFound (generated by `testkit::cross_tenant`) — MySQL **and** TiDB | db |
| T-DB2 | App parent check prevents cross-tenant reference; MySQL shadow FKs: no orphan created by any test | db |
| T-DB3 | Last-owner app-tx guard (two concurrent demotions, tenant row mutex) — exactly one succeeds, on MySQL and TiDB | db |
| T-DB4 | `expect_one` on 0-row update → `NotPersisted` | db |
| T-DB5 | Job lease claim with 4 concurrent workers: each job runs once; lost lease → reaper requeues; heartbeat extends; no SKIP LOCKED used | db |
| T-DB6 | Keyset pagination stable under inserts; cursor tamper → 400 | db/api |
| T-AU1 | Audit row written in same tx (rollback → no audit row); chain block seal + verify; UPDATE/DELETE denied for app DB user (grant test on both engines) | audit |
| T-R1 | Router: route without policy → build error; `xtask route-policies --check` lists public routes = reviewed file | api |
| T-R2 | Authz matrix harness runs over Phase 0 routes with all fixture principals | testkit |
| T-L1 | Limits: body > limit → 413; inflight > limit → 503 + Retry-After; login hash queue timeout → 503 | api |
| T-O1 | Logs contain no email/IP/token for login flow (log capture scan for fixture values) | api |
| T-H1 | `/health/ready` 503 when DB down / keys not loaded | api |
| T-DB7 | `xtask schema-check` passes on fresh migrations (MySQL + TiDB); fails on a fixture table with a non-tenant-leading index or unclassified table | xtask |
| T-DB8 | `xtask sql-lint` fails on fixture query files missing `tenant_id = ?` (plain, JOIN, UPDATE, subquery) and passes on all real query files | xtask |
| T-DB9 | `with_retry`: injected 1213/9007 → retried ≤ 3, idempotent closure result once; non-retryable error surfaced | db |
| T-DB10 | Authz epoch: role change on pool A visible on pool B ≤ poll interval; high-risk policy live read sees it immediately; poller outage → cache bypass | auth/db |
| T-DB11 | Quota race on TiDB: `max_members`=5, 20 parallel inserts → exactly 5 (quota mutex, no gap locks) | db |
| T-DB12 | Row-tenant assert: fault-injected row with other tenant → `Internal` + metric, no data returned | db |
| T-DB13 | `explain-check`: every Phase 0 query file has no `TableFullScan`/`IndexFullScan` on seeded TiDB (≥ 10k users, 50k sessions) | xtask |
| T-DB14 | Startup refuses `DATABASE_URL` pointing at legacy database name; refuses engine mismatch | api |

---

## 8. Tasks (for the ledger; role = backend unless noted)

| ID | Task | Risk | Depends | Acceptance |
|---|---|---|---|---|
| P0-01 | Workspace skeleton, toolchain, lints, `clippy.toml` disallowed methods, `.gitignore`, Dockerfile | low | — | `cargo build --workspace` ok; clippy clean |
| P0-02 | `common` (ids, Redacted, AppError, Cursor/Page, Clock) | low | 01 | unit tests |
| P0-03 | Config loader + startup validation (§5) | medium | 02 | T-C6, missing-key tests |
| P0-04 | `crypto`: KeyProvider(env), KeyRing, FieldEncryptor, BlindIndexer, envelope format | high | 02 | T-C1..C3 |
| P0-05 | `crypto`: PasswordHasher (bounded), Signer (Ed25519, ES256), dev-keys xtask | medium | 04 | T-C4, T-C5; `.dev/` gitignored |
| P0-06 | `crypto`: Azure Key Vault KEK provider behind feature (wiremock tests) | medium | 04, D-03 | wrap/unwrap mocked |
| P0-07 | Migrations (sets 0100/0150/0200/0800, one DDL per file) + shadow FKs + `db` MySqlPool/session init/engine detect, TenantTx/IdentityTx/PlatformTx/SystemTx, query files, write guards, row-tenant assert, `with_retry` | high | 01 | T-DB1..DB4, T-DB9, T-DB12, T-DB14 on MySQL **and** TiDB |
| P0-08 | `domain::rbac` catalogue + matrix + rules | high | 02 | T-D1; matrix snapshot reviewed against `RBAC.md` |
| P0-09 | `auth`: tokens, PrincipalStateLoader (bounded cache + authz epoch poller), Policy (+ high_risk live read), Authz extractor | high | 05, 07, 08 | T-A1, T-A2, T-A4, T-DB10 |
| P0-10 | `api`: middleware stack (§ARCHITECTURE 5), PolicyRouter, problem+json, request id, client IP, limits, load-shed | high | 09 | T-R1, T-L1 |
| P0-11 | Auth endpoints (login/refresh/logout/step-up/me/me-sessions) + lockout + rate limits | high | 10 | T-A2, T-A3, T-DB6 |
| P0-12 | `audit` sink + hourly chain-block seal job + anchor to blob store | medium | 07, 14 | T-AU1 |
| P0-13 | Outbox + jobs runner (bounded, lease claim, reaper) + idempotency middleware | medium | 07 | T-DB5; idempotency replay test |
| P0-14 | `storage` BlobStore (fs + s3 feature) + STREAM crypto | medium | 04 | 50 MB stream with RSS delta < 5 MB |
| P0-15 | Telemetry: JSON logs, redaction layer, OTLP (bounded), metrics incl. jemalloc resident | medium | 10 | T-O1; metrics endpoint internal |
| P0-16 | `testkit` world fixtures + authz matrix harness | medium | 11 | T-R2 |
| P0-17 | Load test harness (k6) in 512 MB container; allocator benchmark jemalloc vs mimalloc vs system; Argon2 timing on target CPU | medium | 11 | Report: idle RSS, p95, spike behaviour; allocator choice confirmed |
| P0-18 | CI workflow (fmt, clippy, deny, audit, sqlx offline check, tests on **MySQL 8 + TiDB containers**, sql-lint, schema-check, migrate-lint, no-raw-sql, explain-check, route-policies, gitleaks, SBOM) | low | 01 | CI green on PR |
| P0-19 | (architect) Review: matrix snapshot vs `RBAC.md`; public route list; migration SQL; table class registry | — | 08, 10, 20 | Ledger decision recorded |
| P0-20 | `xtask` data-layer gates: `sql-lint` (sqlparser MySQL dialect), `schema-check` (information_schema + `TIDB_PK_TYPE`), `migrate-lint` (one statement per file), `no-raw-sql`, `explain-check` | high | 07 | T-DB7, T-DB8, T-DB13 |
| P0-21 | Nightly CI job on TiDB Serverless non-prod scratch DB (create → migrate → integration subset → RU report → drop scratch DB) | medium | 18, **D-51 owner approval**, D-54 | Job green; RU artifact per query digest; scratch DB removed |
| P0-22 | RU measurement + calibration: per route class RU from `statements_summary` (or Serverless equivalent; nv) vs `DATABASE.md` §10.1; update estimates | medium | 11, 21 | Report attached to ledger; estimates updated in DATABASE.md |
| P0-23 | `docs/ops/db_users.sql` draft (users + grants per env, no DELETE for app) for owner/main session | low | 07 | Reviewed by be-reviewer; not executed by agents |

Every task: be-reviewer (Opus) adversarial review for high-risk items (04, 07, 08, 09, 10, 11, 20); no commit/push without owner permission; no agent touches any TiDB cluster (main session/owner runs P0-21 setup and P0-23 SQL).

---

## 9. Acceptance criteria (Phase 0 exit)
1. `cargo build --workspace --release` succeeds; `cargo fmt --check` clean; `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean; `cargo deny check` and `cargo audit` clean (or documented exceptions).
2. All §7 tests pass locally and in CI on **both** MySQL 8 and TiDB standalone containers; nightly Serverless job green once D-51 is approved (otherwise recorded as pending, not as passed).
3. Fresh clone → `cargo xtask dev-keys && docker compose -f docker/compose.dev.yml up -d && cargo xtask db-reset && cargo run -p api` runs **without any production secret** (local MySQL or TiDB container); `/health/ready` = 200.
4. Production-mode start with dev keys or missing secrets exits non-zero with a clear (value-free) message.
5. Load test (P0-17) in `--memory=512m`: idle RSS ≤ 80 MB; 50 parallel logins RSS < 350 MB with 503s instead of OOM; `GET /me` p95 < 50 ms at 100 RPS.
6. Route-policy report shows only the reviewed public routes; no route without policy.
7. No secret, key, connection string or customer data in the repo (gitleaks clean).
8. `sql-lint`, `schema-check`, `explain-check` green; every Phase 0 tenant repository fn has a generated cross-tenant test.

## 10. Not verified
Exact crate versions/features (esp. OpenTelemetry set, JCS crate, jsonwebtoken major, sqlparser), Render CPU share, Azure Key Vault SDK choice for Rust (REST via reqwest is fallback), testcontainers on CI runner, `pingcap/tidb` image behaviour (unistore) vs Serverless, sqlx MySQL migrator partial-failure handling, TiDB error codes list (§3.5 retry), Serverless connection/idle limits.
