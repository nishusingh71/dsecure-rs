# DSecure Rust backend: Database design (draft v3, TiDB, 20 Oct 2026)

Owner: Mr. W. Author: architect. Status: **DRAFT**. Engine = **TiDB Cloud (MySQL-compatible)**, owner decision D-01 (*"Tidb"*). Naya, clean database (D-51: naya cluster, legacy `Cloud_Erase__App` kabhi nahi). .NET DB sirf data migration ka source hai.
Is doc mein koi secret/connection string nahi. Saare SQL **draft** hain: koi bhi DB par chalaya nahi gaya. Agents DB nahi chhoote; staging/production par schema owner/main session apply karega, **DB change pehle, code deploy baad mein**.

Saath: `ARCHITECTURE.md` §12 (budget), `RBAC.md` (model + enforcement), `SECURITY.md` (crypto), `PDF_TEMPLATES.md` (report render data).

**v3 mein kya badla:** PostgreSQL → TiDB. RLS, triggers, LISTEN/NOTIFY, `RETURNING`, partial indexes, `SKIP LOCKED`, sequences, partitions — sab hata ke TiDB-safe equivalents (§1). Saara DDL MySQL/TiDB dialect mein. DB-1 band (credit tables par `tenant_id`). Contracts reconcile karke naye tables (§13 coverage matrix).

---

## 1. TiDB: kya nahi milta, design kaise handle karta hai

### 1.1 Feature map
| Postgres-era control | TiDB status (my knowledge; "nv" = not verified on our Serverless version) | Design replacement |
|---|---|---|
| Row-Level Security | Nahi hai | **Data-layer enforcement** (§2.2): `TenantTx` + query files + SQL lint + schema check + row-tenant assert + negative tests + no-DELETE grants |
| Triggers / stored procedures | Nahi (TiDB triggers/SP support nahi karta) | Invariants app transaction mein `SELECT ... FOR UPDATE` mutex row ke saath (§4.3 last owner, §6.4 ledger); nightly invariant checks (bounded, keyset) |
| `LISTEN/NOTIFY` | Nahi | `authz_epochs` table: har authz change par tenant epoch +1; har instance 2 s mein changed epochs poll karta hai (ek indexed query) aur bounded cache entries drop karta hai (§4.4, `RBAC.md` §6.4) |
| `FOR UPDATE SKIP LOCKED` | **nv** (`SKIP LOCKED` aur `NOWAIT` dono ka Serverless support verify nahi kiya; design dono par depend nahi karta) | **Lease claim**: candidates snapshot read → per candidate `UPDATE jobs SET status='running', claimed_by=?, lease_until=? WHERE id=? AND status='queued'` → rows_affected=1 = claimed (§8.4). MySQL aur TiDB dono par sahi |
| `RETURNING` | Nahi (MySQL 8 mein bhi nahi) | App-generated ids (UUIDv7) insert se pehle; har write ka `rows_affected` check (`expect_one`); zarurat par same tx mein point read |
| Sequences | TiDB mein `CREATE SEQUENCE` hai, MySQL 8 mein nahi | Portable **block allocator** `report_number_blocks` (§6.6): instance 20 numbers ka block lock karke leta hai; gaps allowed (legacy mein bhi gaps the) |
| Partial indexes (`WHERE ...`) | Nahi | (a) Status column index mein include; (b) "unique-when-active" = nullable `*_active` column jo app archive/erase par NULL karta hai (unique index multiple NULL allow karta hai) |
| `NULLS LAST` ordering | Syntax MySQL/TiDB mein nahi | App-set non-null sort column (`expires_sort = COALESCE(expires_at, '9999-12-31')`) |
| Deferred constraint triggers (ledger sum = 0) | Nahi | Domain pure function postings validate karta hai (sum 0) + same tx insert + nightly invariant SQL |
| `CHECK` constraints | MySQL 8 enforce karta hai; TiDB v7.2+ mein sirf `tidb_enable_check_constraint=ON` par (default OFF; Serverless setting nv) | `CHECK` likhte hain (MySQL CI mein pakdega), par **bharosa sirf app validation par** (domain enums, `serde` strict) |
| Composite FKs | TiDB FK v6.6+ (Serverless version/maturity nv); har write par extra reads (RU) | **No DB FKs on TiDB** (D-55); app parent-check in TenantTx; MySQL CI "FK shadow" migration orphans pakadti hai; nightly orphan job |
| Native partitions for audit retention | TiDB range partitions hain, par PK mein partition column chahiye, DROP PARTITION = deletion | v1 non-partitioned; retention = owner-approved batch purge (D-56) |
| `jsonb` + `pg_column_size` checks | TiDB `JSON` type hai; direct index nahi (expression/multi-valued index alag feature); row/entry size limit `txn-entry-size-limit` (default 6 MB; Serverless nv) | JSON sirf non-query data; size cap app mein (e.g. 4-8 KB); query fields = real columns |
| `timestamptz` | Nahi | `DATETIME(6)` hamesha UTC; connection init `SET time_zone='+00:00'` |
| `SET LOCAL app.tenant_id` | Session vars hain par koi policy unhe enforce nahi karti | Use nahi; tenant har query ka bind parameter |
| Shared row locks (`FOR SHARE`) | TiDB mein default noop/error (`tidb_enable_noop_functions`) | Sirf `FOR UPDATE` use; shared lock kabhi nahi |
| Gap locks (MySQL RR) | TiDB mein gap locks nahi (snapshot isolation) | "Count then insert" invariants ke liye **hamesha parent mutex row lock** (tenant/quota/balance row `FOR UPDATE`); gap locks par kabhi depend nahi (MySQL aur TiDB alag behave karte) |
| `statement_timeout`, `idle_in_transaction_session_timeout` | MySQL `max_execution_time` (SELECT only; TiDB semantics nv), `innodb_lock_wait_timeout` (TiDB pessimistic mein supported) | Session init: `max_execution_time=5000`, `innodb_lock_wait_timeout=5`; app-side `tokio::time::timeout` har tx par (default 5 s) |

### 1.2 Transactions and retries
- TiDB naye clusters mein **pessimistic** default (Serverless nv). Connection init explicitly `SET SESSION tidb_txn_mode='pessimistic'` (sirf jab `SELECT VERSION()` mein `TiDB` ho; MySQL par skip).
- Isolation: TiDB REPEATABLE READ = snapshot isolation; `SELECT ... FOR UPDATE` pessimistic mode mein **latest committed** row padhta hai aur lock leta hai. Invariant reads hamesha `FOR UPDATE` se.
- **Retry wrapper** `db::with_retry(|tx| ...)`: sirf idempotent closures; max 3 attempts, jittered backoff 20-200 ms; retryable errors (codes from memory, P0 test mein confirm): `1213` deadlock, `1205` lock wait timeout, `9007` write conflict, `8028`/`8027` schema changed during tx, `9001`/`9002`/`9005` TiKV/PD busy/timeout, connection lost `2006`/`2013` (sirf agar commit bheja hi nahi). Commit ka result unknown (connection drop during COMMIT) → retry nahi; idempotency key se re-check.
- Transactions chhote: ek request = ek tx (max ~20 statements), kabhi external HTTP call tx ke andar nahi.
- Lock order rule (deadlock kam): tenant row → quota/balance rows → entity rows (id order) → counters → audit/outbox.

### 1.3 RU cost rules (TiDB Serverless bills Request Units)
1. Har query index se; full table scan sirf < 1k-row catalogue tables par. CI plan test (§9.2) `TableFullScan`/`IndexFullScan` par fail.
2. **Keyset pagination only** (`WHERE (tenant_id=?) AND id < ? ORDER BY id DESC LIMIT n`); offset kabhi nahi.
3. **Covering / clustered access**: tenant tables ka clustered PK `(tenant_id, id)` list "newest first" ko seedha PK range scan se serve karta hai (UUIDv7 = creation order), extra lookup nahi.
4. **Counter tables** (`tenant_counters`, `report_counters`, `report_facet_counters`, `report_subjects`, `credit_balances`) same tx mein maintain; dashboard par `COUNT(*)` nahi.
5. **Blobs DB ke bahar** (report JSON, render data, CSV, branding images) → object storage. TiDB write RU bytes ke proportional hai (§10).
6. Wide `SELECT *` nahi; har query file explicit columns.
7. Point gets by PK/unique key; `IN (...)` batch max 200 ids (N+1 ban).

### 1.4 Local dev / CI test DB and MySQL-vs-TiDB gaps (D-53, D-54)
| Env | Engine | Use |
|---|---|---|
| Local dev | MySQL 8.0 container **ya** `pingcap/tidb` standalone container (unistore, ek process) | Fast loop; `cargo xtask db-reset` sirf localhost |
| CI (har PR) | Dono: MySQL 8.0 (FK + CHECK shadow mode ON) **aur** TiDB standalone container | Integration + authz matrix + migrations |
| CI nightly + release candidate | TiDB Cloud Serverless `dsecure-rs-nonprod`, scratch database `ci_<run_id>` | Real TLS, real RU numbers (`statements_summary`), DDL behaviour |
| Optional | `tiup playground` (PD+TiKV+TiDB) | Pessimistic locking/region behaviour closer to real; heavier |

Gaps jinko tests cover karte hain (in sab par code **engine-neutral subset** use karta hai):
| Gap | MySQL 8 | TiDB | Rule |
|---|---|---|---|
| Gap/next-key locks | Hai (RR) | Nahi | Parent mutex row lock; test T-DB3/T-DB12 dono engines par |
| `CHECK` | Enforced | Optional (default off) | App validation; MySQL CI pakadta hai |
| FKs | Enforced (shadow migration) | Not relied on | App parent check; orphan job |
| Executable comments `/*T! ... */` | Comment (ignored) | Executed | TiDB-only options (clustered, SHARD_ROW_ID_BITS) isi syntax mein |
| AUTO_INCREMENT | Consecutive | Non-consecutive, per-node cache | AUTO_INCREMENT use hi nahi |
| AUTO_RANDOM, SEQUENCE, TTL | Nahi | Hai | Use nahi |
| Default collation | `utf8mb4_0900_ai_ci` (case-insensitive) | `utf8mb4_bin` | Har table/column explicit `utf8mb4_bin`; comparisons sirf normalised columns par |
| DDL | Mostly online; implicit commit | Online, DDL job queue, ek waqt ek DDL per table; ALTER se STORED generated column add nahi; clustered PK baad mein change nahi | One DDL per migration file (§11.1); PK create-time par final |
| Txn size | Large | Limit (`txn-total-size-limit`, Serverless nv) | Importer/batch jobs ≤ 1000 rows per tx |
| `max_execution_time` | SELECT only | nv | App timeout bhi |
| `LOCK IN SHARE MODE` | Works | Noop/error | Kabhi use nahi |
| `GET_LOCK` | Works | Limited (nv) | Use nahi |
| JSON functions | Full | Mostly compatible (nv per function) | DB mein JSON functions use nahi; app parse karta hai |

---

## 2. Conventions

### 2.1 Column conventions
| Item | Rule |
|---|---|
| Charset | Har table `ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin` |
| IDs | `BINARY(16)` UUIDv7, app-generated before insert (D-52). API mein hyphenated string |
| Tenant | Har tenant table: `tenant_id BINARY(16) NOT NULL` **pehla column of PK and of every index** |
| PK | Tenant tables: `PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */` |
| Time | `DATETIME(6)` UTC; `created_at`, `updated_at` app set karta hai (DB defaults par depend nahi) |
| Concurrency | `version INT UNSIGNED NOT NULL DEFAULT 1` on mutable rows; `UPDATE ... SET version=version+1 WHERE tenant_id=? AND id=? AND version=?` (ETag/If-Match) |
| Status/enums | `VARCHAR(24)` + `CHECK` (documentation + MySQL CI); values = Rust enum `as_str()` |
| Booleans | `BOOLEAN` (TINYINT(1)) |
| Encrypted columns | `<name>_enc VARBINARY(n)` (format §3); searchable = `<name>_bidx BINARY(32)` |
| Normalised search | `<name>_norm VARCHAR(n)` (trim + NFKC + lowercase) for non-PII names; `LOWER(col)` kabhi nahi |
| Unique-when-active | Nullable `<name>_active` column (value jab active, NULL jab archived/erased) + UNIQUE index |
| JSON | `JSON` sirf non-query data, app size cap |
| Soft state | `status` + `archived_at`/`deleted_at`; customer data par hard DELETE nahi (app DB user ke paas DELETE grant hi nahi, §2.5) |
| Counters | Summary tables same tx mein |

### 2.2 Tenant isolation without RLS (enforcement layers)
| # | Layer | Mechanism | Fails how |
|---|---|---|---|
| L1 | **Type-level** | `TenantTx<'_>` (holds `TenantId` from verified `TenantScope`) ke bina koi tenant repository function call nahi ho sakta. Repo fns ka pehla arg `&mut TenantTx`. `TenantId` sirf `auth` crate ka `Authorized` extractor ya worker job payload (job row se, verified) bana sakta hai | Compile error |
| L2 | **Query files** | Saara SQL `crates/db/queries/<table>/<name>.sql` mein, `sqlx::query_file_as!` se. Rust code mein inline SQL string nahi | Review + L3 |
| L3 | **SQL lint** (`cargo xtask sql-lint`, CI) | `sqlparser` (MySQL dialect) se har query file parse: har tenant-class table reference par `<alias>.tenant_id = ?` top-level AND conjunct (SELECT/UPDATE/DELETE), JOIN par bhi `a.tenant_id = b.tenant_id` + bind; INSERT mein `tenant_id` column; pehla bind param naam `tenant_id` (query file header comment `-- params: tenant_id, ...`). Allowlist sirf `directory`/`identity`/`platform`/`infra` class tables ke named queries | CI fail |
| L4 | **No raw SQL outside `db`** | `clippy.toml` `disallowed-methods`: `sqlx::query`, `sqlx::query_as`, `sqlx::query_scalar`, `sqlx::raw_sql`, `sqlx::Executor::*`, `sqlx::query_file*` (macros via `xtask no-raw-sql` grep) outside `crates/db`; `#[allow(clippy::disallowed_methods)]` outside `crates/db` = CI grep fail | CI fail |
| L5 | **Schema check** (`cargo xtask schema-check`, CI on MySQL+TiDB, aur staging release step) | `information_schema` se: har table `TABLE_CLASSES` registry (code) mein hona chahiye; tenant class: PK ka pehla column `tenant_id`, PK clustered (TiDB `TIDB_PK_TYPE`), **har** secondary index ka pehla column `tenant_id`; directory/identity/infra class ke liye apne rules; unknown table = fail | CI / release fail |
| L6 | **Row-tenant assert** | Har tenant row mapper `tenant_id` select karta hai aur `row.tenant_id == tx.tenant` check: mismatch = `AppError::Internal` + alert `db.tenant_mismatch` (kabhi data nahi lautata) | Runtime fail closed |
| L7 | **Negative tests** | `testkit` har repository function ke liye generated cross-tenant test: tenant A ka TenantTx + B ke ids → `None`/0 rows/404; har by-id route ke liye API matrix (`RBAC.md` §8) | CI fail |
| L8 | **DB grants** | `dsecure_app` user: tenant tables par sirf `SELECT, INSERT, UPDATE` (no DELETE, no DDL); staff/platform reads alag code path (PlatformTx + grant) | DB error |

Composite references: child row parent ka `(tenant_id, parent_id)` rakhta hai; insert/update se pehle repo same TenantTx mein `SELECT 1 FROM parent WHERE tenant_id=? AND id=? [FOR UPDATE]` karta hai (cross-tenant id = not found = 404). Isliye cross-tenant reference banana impossible hai bina L1-L3 tode.

### 2.3 ID strategy and hotspots (D-52)
- **UUIDv7** (48-bit ms timestamp + random): insert se pehle pata (AAD binding, audit target, outbox), time-ordered → `ORDER BY id DESC` = newest first (alag `created_at` index nahi chahiye). Migrated rows ka UUIDv7 legacy `created_at` timestamp se banta hai taaki order bana rahe.
- **Tenant tables**: clustered `(tenant_id, id)`. Writes alag tenants ke key ranges mein jaate hain (TiDB region split per range), ek tenant ke andar tail-append (ek tenant ka write rate chhota: ≤ 10/s expected).
- **Global append-heavy tables** (`audit_events`, `outbox_events`, `jobs`, `idempotency_keys`, `webhook_events`, `email_messages`, `download_events`): `PRIMARY KEY (id) /*T![clustered_index] NONCLUSTERED */` + table option `/*T! SHARD_ROW_ID_BITS=4 PRE_SPLIT_REGIONS=2 */` → row data scattered; PK index sequential rehta hai. Hamare volume (< 100 writes/s) par ye hotspot threshold se bahut neeche hai (estimate); Key Visualizer se monitor (risk DB-R2).
- AUTO_RANDOM / AUTO_INCREMENT use nahi (MySQL test DB par AUTO_RANDOM nahi chalta; AUTO_INCREMENT TiDB mein non-consecutive aur hot).
- Human-readable report numbers (`DS-ERASE-000123`): block allocator §6.6.

### 2.4 References and FKs (D-55)
- TiDB par DB FKs nahi. App parent check (§2.2). Delete hota hi nahi (soft), isliye cascade ki zarurat nahi.
- `db/migrations_shadow/` mein FK statements (MySQL-only) jo CI ke MySQL job mein lagte hain: integration tests mein orphan banana = test fail.
- Nightly `orphan-check` job (keyset batches 1000, RU-throttled) har reference edge par count report karta hai; > 0 = alert.

### 2.5 DB users (TiDB Serverless user names cluster prefix ke saath; exact naming nv)
| User | Grants | Use |
|---|---|---|
| `dsecure_migrator` | DDL on app database | Release step `dsecure-api migrate` (owner/main session) |
| `dsecure_app` | `SELECT, INSERT, UPDATE` on app tables; **no DELETE, no DDL** | API + in-process workers |
| `dsecure_worker` | Same as app | Separate worker service (D-02) |
| `dsecure_retention` | `SELECT, DELETE` sirf listed infra tables (`idempotency_keys`, `step_up_tokens`, `auth_challenges`, `outbox_events`, `jobs`, `download_events`, sessions/refresh after 90 days, ...) | Purge jobs; **disabled (no password set) jab tak owner har data class approve na kare** (D-17, D-56) |
| `dsecure_readonly` | `SELECT` | Reconciliation, support SELECTs (main session) |
Connection: TLS mandatory (`ssl-mode=VERIFY_IDENTITY`, CA from config), Serverless endpoint.

### 2.6 Table classes (schema-check registry)
| Class | Rule | Tables |
|---|---|---|
| `tenant` | PK `(tenant_id, id)` clustered (ya `(tenant_id, …)` natural key), har index `tenant_id`-leading, access sirf TenantTx | most tables |
| `identity` | Global human identity, key = user/session id from token; access `IdentityTx` named queries | `users`, `user_credentials`, `mfa_*`, `sessions`, `refresh_tokens`, `step_up_tokens`, `auth_challenges` |
| `directory` | Global lookup → `(tenant_id, id)` pointer; tiny rows; result ke baad TenantTx open hota hai | `membership_directory`, `license_key_directory`, `report_public_ids` |
| `platform` | Staff/catalogue/config; access PlatformTx | `tenants`, `products`, `platform_staff`, `staff_access_grants`, `data_keys`, `signing_keys`, `checkout_links`, `provider_products`, `product_releases`, `contact_leads`, `cleaner_redeem_codes`, `report_number_blocks`, `migration_id_map` |
| `infra` | Global append/churn; tenant_id nullable column + tenant-leading secondary index jahan tenant read hota hai | `audit_events`, `audit_chain_blocks`, `outbox_events`, `jobs`, `idempotency_keys`, `webhook_events`, `email_messages`, `email_provider_usage`, `download_events`, `download_daily`, `authz_epochs`, `orders` |

---

## 3. Encrypted value format (`VARBINARY`)
```
byte 0     : format version (0x01)
byte 1     : flags (must be 0x00; any other value is rejected. Flags are not in the AAD, so no flag may change meaning. Compression, if ever needed, gets a new format version)
byte 2     : kid length n (1..32)
bytes 3..  : kid (ASCII)
next 12    : nonce (random 96-bit)
rest       : ciphertext || 16-byte GCM tag
AAD        = "dsecure|v1|" || kid || "|" || table || "." || column || "|" || (tenant UUID, lowercase hyphenated | literal "platform") || "|" || row UUID (lowercase hyphenated)
             table/column must match [A-Za-z0-9_]+, kid [A-Za-z0-9_.-]{1,32}; source of truth = crates/crypto/src/envelope_format.rs
DEK wrap (data_keys.wrapped) = v2: AES-256-GCM under the KEK, AAD "dsecure|kek-wrap|v2|" || kek_ref || "|" || kid || "|" || purpose || "|" || (tenant UUID | "platform")  (binds each wrapped DEK to its kid/purpose/tenant, so rows cannot be swapped; review CR-1, 20 Oct)
```
- Row id app-side UUID, isliye AAD full row binding. Blind index: `HMAC-SHA256(K_bidx[purpose, scope], normalise(value))` → `BINARY(32)`. Scope `global` (login email, licence key, redeem code) ya `tenant` (serial, MAC, hwid, machine name).
- Large blobs object storage mein, chunked STREAM format (`SECURITY.md` §3).

---

## 4. Identity, tenancy, RBAC

### Migration set `0100_tenancy_identity` (one DDL per file, §11.1)
```sql
CREATE TABLE tenants (                               -- class: platform
  id                   BINARY(16)   NOT NULL,
  kind                 VARCHAR(16)  NOT NULL,        -- organization | individual
  display_name_enc     VARBINARY(512) NOT NULL,
  status               VARCHAR(16)  NOT NULL DEFAULT 'active',   -- active|suspended|closed|erased
  data_region          VARCHAR(16)  NOT NULL DEFAULT 'default',
  legacy_owner_user_id BIGINT       NULL,
  created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL,
  closed_at DATETIME(6) NULL, erased_at DATETIME(6) NULL,
  version INT UNSIGNED NOT NULL DEFAULT 1,
  PRIMARY KEY (id) /*T![clustered_index] CLUSTERED */,
  UNIQUE KEY ux_tenants_legacy (legacy_owner_user_id),
  KEY ix_tenants_status (status, id),
  CONSTRAINT ck_tenants_kind CHECK (kind IN ('organization','individual')),
  CONSTRAINT ck_tenants_status CHECK (status IN ('active','suspended','closed','erased'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- tenants row = per-tenant MUTEX row (SELECT ... FOR UPDATE) for last-owner, ownership transfer, tenant close.

CREATE TABLE tenant_settings (                       -- class: tenant (natural key)
  tenant_id BINARY(16) NOT NULL,
  timezone  VARCHAR(64) NOT NULL DEFAULT 'UTC',
  require_credit_allocation BOOLEAN NOT NULL DEFAULT FALSE,
  autopilot_auto_check BOOLEAN NOT NULL DEFAULT FALSE,     -- legacy Users.mdm_auto_check_enabled
  updated_at DATETIME(6) NOT NULL, version INT UNSIGNED NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE tenant_features (                       -- toggles; only platform staff writes
  tenant_id BINARY(16) NOT NULL,
  feature   VARCHAR(24) NOT NULL,                    -- subusers|groups|user_activity|private_cloud
  enabled   BOOLEAN NOT NULL DEFAULT FALSE,
  changed_by_staff BINARY(16) NOT NULL,
  changed_at DATETIME(6) NOT NULL,
  PRIMARY KEY (tenant_id, feature) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE tenant_feature_changes (                -- append-only history
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL,
  feature VARCHAR(24) NOT NULL, enabled BOOLEAN NOT NULL,
  changed_by_staff BINARY(16) NOT NULL, reason VARCHAR(500) NOT NULL, ticket_ref VARCHAR(64) NULL,
  changed_at DATETIME(6) NOT NULL,
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE tenant_quotas (                         -- NULL = unlimited; only platform staff writes; also quota MUTEX row
  tenant_id BINARY(16) NOT NULL,
  max_members INT NULL, max_groups INT NULL, max_departments INT NULL, max_licenses INT NULL,
  updated_by_staff BINARY(16) NULL, updated_at DATETIME(6) NOT NULL, version INT UNSIGNED NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE authz_epochs (                          -- class: infra; replaces LISTEN/NOTIFY (§4.4)
  tenant_id  BINARY(16) NOT NULL,                    -- 0x00.. row = platform/staff epoch
  epoch      BIGINT UNSIGNED NOT NULL DEFAULT 1,
  updated_at DATETIME(6) NOT NULL,
  PRIMARY KEY (tenant_id) /*T![clustered_index] CLUSTERED */,
  KEY ix_authz_epochs_updated (updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE users (                                 -- class: identity (global human identity)
  id                 BINARY(16) NOT NULL,
  email_bidx         BINARY(32) NOT NULL,            -- HMAC(global email key, normalised email); on erase overwritten with random
  email_enc          VARBINARY(512) NOT NULL,
  name_enc           VARBINARY(512) NULL,
  phone_enc          VARBINARY(256) NULL,
  status             VARCHAR(24) NOT NULL DEFAULT 'pending_verification', -- pending_verification|active|suspended|disabled|erased
  email_verified_at  DATETIME(6) NULL,
  verification_source VARCHAR(16) NULL,              -- email_link|legacy_import|payment_link|staff
  locale VARCHAR(16) NULL, timezone VARCHAR(64) NULL,
  authz_version      BIGINT UNSIGNED NOT NULL DEFAULT 1,
  tokens_valid_after DATETIME(6) NULL,
  last_tenant_id     BINARY(16) NULL,
  legacy_user_id     BIGINT NULL,
  created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL, erased_at DATETIME(6) NULL,
  version INT UNSIGNED NOT NULL DEFAULT 1,
  PRIMARY KEY (id) /*T![clustered_index] CLUSTERED */,
  UNIQUE KEY ux_users_email_bidx (email_bidx),       -- erase = bidx random (no partial index needed)
  UNIQUE KEY ux_users_legacy (legacy_user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE user_credentials (
  user_id BINARY(16) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,               -- PHC string
  hash_scheme   VARCHAR(16) NOT NULL,                -- argon2id|bcrypt_legacy
  password_changed_at DATETIME(6) NOT NULL,
  failed_attempts INT NOT NULL DEFAULT 0, last_failed_at DATETIME(6) NULL, locked_until DATETIME(6) NULL,
  version INT UNSIGNED NOT NULL DEFAULT 1,
  PRIMARY KEY (user_id) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE mfa_factors (
  user_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL,
  kind VARCHAR(16) NOT NULL,                         -- totp|webauthn
  secret_enc VARBINARY(256) NULL, credential_public_key VARBINARY(1024) NULL, label VARCHAR(64) NULL,
  created_at DATETIME(6) NOT NULL, last_used_at DATETIME(6) NULL, disabled_at DATETIME(6) NULL,
  PRIMARY KEY (user_id, id) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE mfa_recovery_codes (
  user_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL,
  code_hmac BINARY(32) NOT NULL, used_at DATETIME(6) NULL,
  PRIMARY KEY (user_id, id) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE platform_staff (                        -- class: platform
  user_id BINARY(16) NOT NULL,
  role VARCHAR(32) NOT NULL,                         -- platform_superadmin|platform_support|platform_billing|platform_auditor
  granted_by BINARY(16) NULL, granted_at DATETIME(6) NOT NULL, revoked_at DATETIME(6) NULL,
  PRIMARY KEY (user_id) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE staff_access_grants (                   -- class: platform; staff → tenant data, time boxed
  id BINARY(16) NOT NULL, staff_user_id BINARY(16) NOT NULL, tenant_id BINARY(16) NOT NULL,
  reason VARCHAR(500) NOT NULL, ticket_ref VARCHAR(64) NULL, scope VARCHAR(16) NOT NULL,   -- read|support_write
  opened_at DATETIME(6) NOT NULL, expires_at DATETIME(6) NOT NULL, closed_at DATETIME(6) NULL,
  PRIMARY KEY (id) /*T![clustered_index] CLUSTERED */,
  KEY ix_sag_staff (staff_user_id, tenant_id, expires_at),
  KEY ix_sag_tenant (tenant_id, opened_at)           -- tenant owner sees staff access in own audit view
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE departments (
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL,
  name VARCHAR(128) NOT NULL, name_norm VARCHAR(128) NOT NULL,
  name_active VARCHAR(128) NULL,                     -- = name_norm while not archived (unique-when-active)
  created_at DATETIME(6) NOT NULL, archived_at DATETIME(6) NULL, version INT UNSIGNED NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */,
  UNIQUE KEY ux_departments_name (tenant_id, name_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE `groups` (                              -- `groups` is a reserved word in MySQL 8: always quote
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL,
  parent_group_id BINARY(16) NULL,
  name VARCHAR(128) NOT NULL, name_norm VARCHAR(128) NOT NULL, name_active VARCHAR(128) NULL,
  description VARCHAR(500) NULL,
  created_by_membership BINARY(16) NOT NULL,
  created_at DATETIME(6) NOT NULL, archived_at DATETIME(6) NULL, version INT UNSIGNED NOT NULL DEFAULT 1,
  legacy_group_id BIGINT NULL,
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */,
  UNIQUE KEY ux_groups_name (tenant_id, name_active),
  KEY ix_groups_name_search (tenant_id, name_norm)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE memberships (
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL,
  user_id   BINARY(16) NOT NULL,
  role      VARCHAR(16) NOT NULL,                    -- owner|admin|member|viewer
  role_rank TINYINT UNSIGNED NOT NULL,               -- 100/80/40/20 (denormalised for visibility filters)
  kind      VARCHAR(16) NOT NULL DEFAULT 'primary',  -- primary|subuser (reporting only)
  status    VARCHAR(16) NOT NULL DEFAULT 'active',   -- invited|active|disabled|deleted
  parent_membership_id BINARY(16) NULL,
  department_id BINARY(16) NULL,
  authz_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  display_name_enc VARBINARY(512) NULL,
  display_name_norm_hash BINARY(32) NULL,            -- tenant bidx for exact-name search (optional)
  created_by BINARY(16) NULL, created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL,
  disabled_at DATETIME(6) NULL, deleted_at DATETIME(6) NULL,
  last_login_at DATETIME(6) NULL,
  legacy_subuser_id BIGINT NULL,
  version INT UNSIGNED NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */,
  UNIQUE KEY ux_memberships_user (tenant_id, user_id),
  KEY ix_memberships_role (tenant_id, status, role_rank, id),
  KEY ix_memberships_dept (tenant_id, department_id, id),
  KEY ix_memberships_parent (tenant_id, parent_membership_id, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE membership_directory (                  -- class: directory; login: user → tenants (no tenant known yet)
  user_id BINARY(16) NOT NULL, tenant_id BINARY(16) NOT NULL, membership_id BINARY(16) NOT NULL,
  status VARCHAR(16) NOT NULL, role VARCHAR(16) NOT NULL, updated_at DATETIME(6) NOT NULL,
  PRIMARY KEY (user_id, tenant_id) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- maintained in the SAME tx as memberships writes (repo fn writes both); nightly diff check.

CREATE TABLE membership_capabilities (
  tenant_id BINARY(16) NOT NULL, membership_id BINARY(16) NOT NULL,
  can_view_reports BOOLEAN NOT NULL DEFAULT TRUE,
  can_manage_machines BOOLEAN NOT NULL DEFAULT FALSE,
  can_assign_licenses BOOLEAN NOT NULL DEFAULT FALSE,
  max_machines INT NULL,
  updated_by BINARY(16) NULL, updated_at DATETIME(6) NOT NULL, version INT UNSIGNED NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, membership_id) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE group_memberships (
  tenant_id BINARY(16) NOT NULL, group_id BINARY(16) NOT NULL, membership_id BINARY(16) NOT NULL,
  added_by BINARY(16) NOT NULL, added_at DATETIME(6) NOT NULL,
  PRIMARY KEY (tenant_id, group_id, membership_id) /*T![clustered_index] CLUSTERED */,
  KEY ix_gm_member (tenant_id, membership_id, group_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE group_admin_grants (
  tenant_id BINARY(16) NOT NULL, group_id BINARY(16) NOT NULL, membership_id BINARY(16) NOT NULL,
  can_remote_wipe BOOLEAN NOT NULL DEFAULT FALSE,    -- explicit owner grant (D-31)
  granted_by BINARY(16) NOT NULL, granted_at DATETIME(6) NOT NULL,
  PRIMARY KEY (tenant_id, group_id, membership_id) /*T![clustered_index] CLUSTERED */,
  KEY ix_gag_member (tenant_id, membership_id, group_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE member_preferences (                    -- UI prefs (legacy pdf_export_settings.column_view_config etc.)
  tenant_id BINARY(16) NOT NULL, membership_id BINARY(16) NOT NULL, pref_key VARCHAR(48) NOT NULL,
  value_json JSON NOT NULL,                          -- app cap 8 KB; e.g. 'autopilot.device_table.columns'
  updated_at DATETIME(6) NOT NULL, version INT UNSIGNED NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, membership_id, pref_key) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
```

### 4.3 Invariants in app transactions (triggers ki jagah)
| Invariant | Transaction recipe |
|---|---|
| **Last owner**: active tenant ke paas ≥ 1 active owner | `SELECT status FROM tenants WHERE id=? FOR UPDATE` (tenant mutex) → `SELECT id FROM memberships WHERE tenant_id=? AND status='active' AND role_rank=100 LIMIT 2 FOR UPDATE` → agar target owner hai aur count = 1 → `409 members.last_owner`; else update. Do concurrent demotions tenant row par serialize hote hain (test T-DB3, dono engines) |
| `authz_version` bump on role/status change | Repo fn `memberships::set_role/set_status` hi role/status badal sakta hai; same statement `authz_version = authz_version + 1`, same tx `authz_epochs` bump (§4.4) |
| Quota (members/groups/departments/licenses/machines) | `SELECT ... FROM tenant_quotas WHERE tenant_id=? FOR UPDATE` (mutex) → count via counters table (`tenant_counters`, same tx locked) → insert → counter +1. Gap locks par kabhi depend nahi |
| `membership_directory` sync | Same repo fn, same tx; nightly diff |

### 4.4 Authz epochs (LISTEN/NOTIFY replacement)
- Har authz-affecting write (role, status, capability, group admin grant, toggle, quota, session revoke, tenant suspend) same tx mein: `UPDATE authz_epochs SET epoch=epoch+1, updated_at=? WHERE tenant_id=?` (row tenant create par insert).
- Har API instance: poller (`AUTHZ_EPOCH_POLL_MS`, default 2000) `SELECT tenant_id, epoch FROM authz_epochs WHERE updated_at > ? ORDER BY updated_at LIMIT 500` (index `ix_authz_epochs_updated`, point range) → in-memory map update → us tenant ki cache entries invalid. Cost ≈ 1 small range read / 2 s / instance.
- Cache entry `(session_id) → PrincipalState { epoch_seen, ... }`; request par entry valid sirf jab `epoch_seen == current_epoch[tenant]`. Same instance par write karne wala instance turant apni cache entry drop karta hai (zero staleness locally); doosre instances max ~2 s stale.
- Poller fail > 10 s → **cache bypass** (har request live load; deny nahi), metric + alert.
- High-risk actions (remote wipe, member delete, role grant, ownership transfer, credit consume, staff access) hamesha **live read** (cache bypass) — zero staleness.

---

## 5. Sessions, tokens, auth flows

### Migration set `0200_sessions`
```sql
CREATE TABLE sessions (                              -- class: identity (sid from token = PK point get)
  id BINARY(16) NOT NULL,
  user_id BINARY(16) NOT NULL,
  tenant_id BINARY(16) NULL,                         -- NULL for staff sessions
  membership_id BINARY(16) NULL,
  principal_kind VARCHAR(16) NOT NULL,               -- member|staff|cleaner
  client_kind VARCHAR(24) NOT NULL,                  -- web|desktop_app|platform_console
  product_code VARCHAR(16) NULL,
  ip_enc VARBINARY(128) NULL, ua_family VARCHAR(64) NULL, ua_hash BINARY(32) NULL,
  device_label VARCHAR(128) NULL,                    -- "Windows 11 / Chrome" (non-PII summary)
  mfa_at DATETIME(6) NULL,
  created_at DATETIME(6) NOT NULL, last_seen_at DATETIME(6) NOT NULL, expires_at DATETIME(6) NOT NULL,
  revoked_at DATETIME(6) NULL, revoke_reason VARCHAR(24) NULL,
  PRIMARY KEY (id) /*T![clustered_index] CLUSTERED */,
  KEY ix_sessions_user (user_id, expires_at),
  KEY ix_sessions_tenant_member (tenant_id, membership_id, id),   -- activity list / timeline (keyset by id = time)
  KEY ix_sessions_tenant (tenant_id, id)                          -- tenant-wide login activity (user_activity ON)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- last_seen_at updated at most once per 5 min per session (write RU control).

CREATE TABLE refresh_tokens (
  id BINARY(16) NOT NULL, session_id BINARY(16) NOT NULL,
  family_id BINARY(16) NOT NULL, token_hash BINARY(32) NOT NULL,
  issued_at DATETIME(6) NOT NULL, expires_at DATETIME(6) NOT NULL,
  used_at DATETIME(6) NULL, replaced_by BINARY(16) NULL, revoked_at DATETIME(6) NULL,
  PRIMARY KEY (id) /*T![clustered_index] CLUSTERED */,
  UNIQUE KEY ux_rt_hash (token_hash),
  KEY ix_rt_family (family_id),
  KEY ix_rt_session (session_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE step_up_tokens (
  id BINARY(16) NOT NULL, session_id BINARY(16) NOT NULL,
  action VARCHAR(48) NOT NULL, target_id BINARY(16) NULL, token_hash BINARY(32) NOT NULL,
  expires_at DATETIME(6) NOT NULL, used_at DATETIME(6) NULL,
  PRIMARY KEY (id) /*T![clustered_index] CLUSTERED */,
  UNIQUE KEY ux_sut_hash (token_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE auth_challenges (                       -- password reset (link and/or OTP), email verify, invites
  id BINARY(16) NOT NULL, user_id BINARY(16) NOT NULL,
  kind VARCHAR(24) NOT NULL,                         -- password_reset|email_verify|invite
  code_hmac BINARY(32) NULL,                         -- OTP (apps / dashboard OTP flow, D-46)
  token_hmac BINARY(32) NOT NULL,                    -- link token
  attempts INT NOT NULL DEFAULT 0, max_attempts INT NOT NULL DEFAULT 5,
  created_at DATETIME(6) NOT NULL, expires_at DATETIME(6) NOT NULL, used_at DATETIME(6) NULL,
  PRIMARY KEY (id) /*T![clustered_index] CLUSTERED */,
  UNIQUE KEY ux_ac_token (token_hmac),
  KEY ix_ac_user_kind (user_id, kind, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE device_credentials (                    -- enrolled app installations (Device principal)
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL, device_id BINARY(16) NOT NULL,
  operator_membership_id BINARY(16) NOT NULL,
  product_code VARCHAR(16) NOT NULL,
  scopes VARCHAR(255) NOT NULL,                      -- space-separated scope codes (no array type)
  secret_hash BINARY(32) NULL, public_key VARBINARY(128) NULL,  -- secret or Ed25519 device key (D-24 signed offline uploads)
  created_at DATETIME(6) NOT NULL, last_used_at DATETIME(6) NULL, revoked_at DATETIME(6) NULL,
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */,
  KEY ix_dc_device (tenant_id, device_id, revoked_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- device token claims carry tid + credential id → tenant known → TenantTx point get.
```

---

## 6. Devices, licences, credits, reports

### Migration set `0300_devices_licensing`
```sql
CREATE TABLE products (                              -- class: platform (catalogue, < 20 rows)
  code VARCHAR(16) NOT NULL,                         -- DSFE|DSFZ|DSDE|DSDG|DSCO|DSAM|DSAM_USB|DSAM_COMBO|DSSC
  name VARCHAR(64) NOT NULL,
  licensing_model VARCHAR(16) NOT NULL,              -- per_device_key|credit_pool|bundle
  PRIMARY KEY (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE product_bundle_components (             -- DSCO → DSDE + DSDG (full qty each); DSAM_COMBO → DSAM 80% / DSAM_USB 20% (legacy rule, payments contract §2.1)
  bundle_code VARCHAR(16) NOT NULL, component_code VARCHAR(16) NOT NULL,
  ratio_num INT NOT NULL, ratio_den INT NOT NULL,
  PRIMARY KEY (bundle_code, component_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE provider_products (                     -- Dodo product id → product + bundle size (replaces env maps + hardcoded USB id)
  provider VARCHAR(16) NOT NULL, provider_product_id VARCHAR(64) NOT NULL,
  product_code VARCHAR(16) NOT NULL, credits_per_unit INT NOT NULL, term_years INT NULL,
  display_name VARCHAR(128) NOT NULL, active BOOLEAN NOT NULL DEFAULT TRUE,
  updated_by_staff BINARY(16) NOT NULL, updated_at DATETIME(6) NOT NULL,
  PRIMARY KEY (provider, provider_product_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE devices (
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL,
  owner_membership_id BINARY(16) NOT NULL,           -- transferable (legacy transfer-to-subuser)
  fingerprint_bidx BINARY(32) NOT NULL,              -- tenant HMAC of app fingerprint (legacy fingerprint_hash)
  hostname_enc VARBINARY(512) NULL,
  mac_bidx BINARY(32) NULL, mac_enc VARBINARY(128) NULL,
  serial_bidx BINARY(32) NULL, serial_enc VARBINARY(256) NULL,
  hw_ids_enc VARBINARY(1024) NULL,                   -- cpu_id, physical_drive_id, bios_serial (legacy NOT NULL cols)
  manufacturer VARCHAR(128) NULL, model VARCHAR(128) NULL, os_name VARCHAR(64) NULL, os_version VARCHAR(64) NULL,
  vm_status VARCHAR(16) NULL,                        -- physical|virtual
  product_code VARCHAR(16) NULL,
  status VARCHAR(16) NOT NULL DEFAULT 'active',      -- active|decommissioned|wiped
  last_seen_at DATETIME(6) NULL, created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL,
  version INT UNSIGNED NOT NULL DEFAULT 1, legacy_fingerprint_hash VARCHAR(128) NULL,
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */,
  UNIQUE KEY ux_devices_fp (tenant_id, fingerprint_bidx),
  KEY ix_devices_owner (tenant_id, owner_membership_id, status, id),
  KEY ix_devices_mac (tenant_id, mac_bidx),
  KEY ix_devices_serial (tenant_id, serial_bidx)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE device_commands (
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL, device_id BINARY(16) NOT NULL,
  kind VARCHAR(16) NOT NULL,                         -- remote_wipe|lock|sync|custom
  payload_enc VARBINARY(4096) NULL, requested_by BINARY(16) NOT NULL, step_up_id BINARY(16) NULL,
  status VARCHAR(16) NOT NULL,                       -- queued|dispatched|acknowledged|completed|failed|cancelled
  created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL,
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */,
  KEY ix_dcmd_device (tenant_id, device_id, status, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE licenses (                              -- per-device key products (DSFE, DSFZ)
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL,
  product_code VARCHAR(16) NOT NULL, edition VARCHAR(64) NULL,     -- legacy edition label kept verbatim
  key_bidx BINARY(32) NOT NULL, key_enc VARBINARY(256) NOT NULL,
  status VARCHAR(16) NOT NULL,                       -- issued|active|suspended|revoked|expired
  max_devices INT NOT NULL DEFAULT 1,
  term_days INT NULL,                                -- legacy expiry_days; >= 36500 = perpetual
  starts_at DATETIME(6) NULL, expires_at DATETIME(6) NULL,          -- set at FIRST activation (legacy rule)
  server_revision INT UNSIGNED NOT NULL DEFAULT 1,   -- apps compare in sync
  assigned_membership_id BINARY(16) NULL,
  order_id BINARY(16) NULL, issued_by VARCHAR(16) NOT NULL,         -- payment|platform|migration
  reminder_sent_at DATETIME(6) NULL,
  created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL, version INT UNSIGNED NOT NULL DEFAULT 1,
  legacy_license_id BIGINT NULL,
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */,
  UNIQUE KEY ux_licenses_key (tenant_id, key_bidx),
  KEY ix_licenses_list (tenant_id, product_code, status, id),
  KEY ix_licenses_assignee (tenant_id, assigned_membership_id, id),
  KEY ix_licenses_expiry (tenant_id, expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE license_key_directory (                 -- class: directory; activation by key (tenant unknown until lookup)
  key_bidx BINARY(32) NOT NULL, tenant_id BINARY(16) NOT NULL, license_id BINARY(16) NOT NULL,
  PRIMARY KEY (key_bidx) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;    -- global uniqueness of keys enforced here

CREATE TABLE license_activations (
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL,
  license_id BINARY(16) NOT NULL, device_id BINARY(16) NOT NULL,
  hwid_bidx BINARY(32) NOT NULL,
  hwid_active BINARY(32) NULL,                       -- = hwid_bidx while active (unique-when-active)
  hardware_snapshot_enc VARBINARY(4096) NULL,        -- machine name, mac, serial, cpu, ram, storage, os (offline activation snapshot)
  activated_by BINARY(16) NOT NULL, activated_at DATETIME(6) NOT NULL,
  last_seen_at DATETIME(6) NULL, deactivated_at DATETIME(6) NULL, deactivated_by BINARY(16) NULL,
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */,
  UNIQUE KEY ux_la_active (tenant_id, license_id, hwid_active),
  KEY ix_la_device (tenant_id, device_id, deactivated_at),
  KEY ix_la_hwid (tenant_id, hwid_bidx)              -- validate-hardware poll
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE license_events (                        -- legacy license_usage_logs + license_transfer_logs
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL, license_id BINARY(16) NOT NULL,
  kind VARCHAR(16) NOT NULL,                         -- activate|renew|sync|revoke|transfer|deactivate|expire
  actor_membership_id BINARY(16) NULL, actor_staff_id BINARY(16) NULL, device_id BINARY(16) NULL,
  from_membership_id BINARY(16) NULL, to_membership_id BINARY(16) NULL,
  old_expires_at DATETIME(6) NULL, new_expires_at DATETIME(6) NULL, reason_code VARCHAR(32) NULL,
  occurred_at DATETIME(6) NOT NULL,
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */,
  KEY ix_le_license (tenant_id, license_id, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE offline_activation_requests (
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL, license_id BINARY(16) NOT NULL,
  request_hash BINARY(32) NOT NULL, response_signature VARBINARY(128) NULL, signing_key_id VARCHAR(48) NULL,
  created_by BINARY(16) NOT NULL, created_at DATETIME(6) NOT NULL, fulfilled_at DATETIME(6) NULL,
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */,
  UNIQUE KEY ux_oar_hash (tenant_id, request_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
```

### Migration set `0400_credit_ledger` (DB-1 fixed: every ledger table has `tenant_id`, tenant-leading keys)
```sql
CREATE TABLE credit_accounts (                       -- per tenant + product; no NULL tenant (platform totals = aggregation)
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL,
  product_code VARCHAR(16) NOT NULL,
  kind VARCHAR(16) NOT NULL,                         -- issued (source, goes negative)|available|consumed|expired|refunded
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */,
  UNIQUE KEY ux_ca_kind (tenant_id, product_code, kind)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE credit_transactions (
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL,
  product_code VARCHAR(16) NOT NULL,
  kind VARCHAR(24) NOT NULL,         -- purchase|platform_grant|redeem|consume|refund|expire|adjust|migration_opening|allocation_return|offline_grant
  idempotency_key VARCHAR(128) NOT NULL,
  reference_type VARCHAR(24) NULL,   -- order|report|autopilot_device|cleaner_run|redeem_code|staff_adjustment|migration|offline_grant
  reference_id BINARY(16) NULL,
  actor_membership_id BINARY(16) NULL, actor_staff_id BINARY(16) NULL,
  reason_code VARCHAR(48) NOT NULL,
  created_at DATETIME(6) NOT NULL,
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */,
  UNIQUE KEY ux_ct_idem (tenant_id, idempotency_key),
  KEY ix_ct_product (tenant_id, product_code, id),
  KEY ix_ct_reference (tenant_id, reference_type, reference_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE credit_postings (                       -- DB-1: tenant_id added; same tenant as its transaction
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL,
  transaction_id BINARY(16) NOT NULL, account_id BINARY(16) NOT NULL, lot_id BINARY(16) NULL,
  amount BIGINT NOT NULL,                            -- <> 0 (app-checked; CHECK for MySQL CI)
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */,
  KEY ix_cp_tx (tenant_id, transaction_id),
  KEY ix_cp_account (tenant_id, account_id, id),
  CONSTRAINT ck_cp_amount CHECK (amount <> 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE credit_lots (                           -- grants with expiry; FIFO by expiry
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL,
  product_code VARCHAR(16) NOT NULL, grant_transaction_id BINARY(16) NOT NULL,
  quantity BIGINT NOT NULL, remaining BIGINT NOT NULL,
  expires_at DATETIME(6) NULL,
  expires_sort DATETIME(6) NOT NULL,                 -- COALESCE(expires_at,'9999-12-31 23:59:59') (no NULLS LAST)
  status VARCHAR(16) NOT NULL DEFAULT 'active',      -- active|exhausted|expired|revoked
  created_at DATETIME(6) NOT NULL,
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */,
  KEY ix_lots_consume (tenant_id, product_code, status, expires_sort, id),
  CONSTRAINT ck_lots_qty CHECK (quantity > 0 AND remaining >= 0 AND remaining <= quantity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE credit_unlimited_windows (              -- Autopilot "unlimited until" (legacy notes='-1' + expires_at)
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL,
  product_code VARCHAR(16) NOT NULL, starts_at DATETIME(6) NOT NULL, ends_at DATETIME(6) NOT NULL,
  grant_transaction_id BINARY(16) NOT NULL, revoked_at DATETIME(6) NULL,
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */,
  KEY ix_cuw_active (tenant_id, product_code, ends_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE credit_balances (                       -- O(1) reads; ALSO the consume MUTEX row per (tenant, product)
  tenant_id BINARY(16) NOT NULL, product_code VARCHAR(16) NOT NULL,
  available BIGINT NOT NULL, consumed BIGINT NOT NULL DEFAULT 0,
  updated_at DATETIME(6) NOT NULL, version INT UNSIGNED NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, product_code) /*T![clustered_index] CLUSTERED */,
  CONSTRAINT ck_cb_avail CHECK (available >= 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE credit_allocations (                    -- optional per-member caps (D-33)
  tenant_id BINARY(16) NOT NULL, membership_id BINARY(16) NOT NULL, product_code VARCHAR(16) NOT NULL,
  allocated BIGINT NOT NULL, used BIGINT NOT NULL DEFAULT 0,
  group_id BINARY(16) NULL,
  updated_by BINARY(16) NOT NULL, updated_at DATETIME(6) NOT NULL, version INT UNSIGNED NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, membership_id, product_code) /*T![clustered_index] CLUSTERED */,
  CONSTRAINT ck_alloc CHECK (allocated >= 0 AND used >= 0 AND used <= allocated)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE credit_consumptions (                   -- grace-window dedupe (same disk/machine within 15 days)
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL,
  product_code VARCHAR(16) NOT NULL,
  subject_kind VARCHAR(24) NOT NULL,                 -- disk|machine|autopilot_device|cleaner_machine
  subject_bidx BINARY(32) NOT NULL,                  -- tenant HMAC of normalised serial / machine id
  transaction_id BINARY(16) NOT NULL, consumed_by BINARY(16) NOT NULL,
  consumed_at DATETIME(6) NOT NULL, grace_until DATETIME(6) NOT NULL,
  subject_details_enc VARBINARY(8192) NULL,          -- legacy disk_drives.drives_information (enc)
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */,
  KEY ix_cc_grace (tenant_id, product_code, subject_bidx, grace_until)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE offline_credit_grants (                 -- legacy offline quota transfer (wipe_count to an offline device)
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL,
  device_id BINARY(16) NOT NULL, product_code VARCHAR(16) NOT NULL,
  granted BIGINT NOT NULL, used BIGINT NOT NULL DEFAULT 0,
  grant_transaction_id BINARY(16) NOT NULL, response_signature VARBINARY(128) NOT NULL, signing_key_id VARCHAR(48) NOT NULL,
  created_by BINARY(16) NOT NULL, created_at DATETIME(6) NOT NULL, expires_at DATETIME(6) NOT NULL,
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */,
  KEY ix_ocg_device (tenant_id, device_id, product_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
```

### 6.4 Credit consume flow (one tx, TiDB-safe)
1. `INSERT` into `idempotency_keys` / check `credit_transactions(tenant_id, idempotency_key)` (unique → duplicate = return stored result).
2. Grace: `SELECT id FROM credit_consumptions WHERE tenant_id=? AND product_code=? AND subject_bidx=? AND grace_until >= ? LIMIT 1` → hit = free (no ledger write), `licenseDeducted=false`.
3. **Mutex**: `SELECT available FROM credit_balances WHERE tenant_id=? AND product_code=? FOR UPDATE`. Unlimited window active? (`credit_unlimited_windows` point range) → consume without lot decrement (transaction with `consume` postings against `issued` account only for audit, amount 1, reason `unlimited`).
4. Allocation (agar hai): `UPDATE credit_allocations SET used=used+1, version=version+1 WHERE tenant_id=? AND membership_id=? AND product_code=? AND used < allocated` → rows_affected=1 else `409 credits.allocation_exhausted`.
5. Lot: `SELECT id, remaining FROM credit_lots WHERE tenant_id=? AND product_code=? AND status='active' AND remaining > 0 AND expires_sort > ? ORDER BY expires_sort, id LIMIT 1 FOR UPDATE` (balance mutex ke andar consistent) → `UPDATE credit_lots SET remaining=remaining-1, status=IF(remaining-1=0,'exhausted',status) WHERE tenant_id=? AND id=? AND remaining >= 1` (expect_one).
6. `UPDATE credit_balances SET available=available-1, consumed=consumed+1, version=version+1 WHERE tenant_id=? AND product_code=? AND available >= 1` (expect_one).
7. Domain builds transaction + postings (`available −1`, `consumed +1`), `assert_balanced()` (sum 0) → inserts; consumption row (grace_until = now + 15 days); report state update; audit + outbox.
Revoked/expired lots kabhi consume nahi (status + `expires_sort > now` filter). Concurrent requests balance row par serialize (test: 100 parallel on balance 10 → exactly 10).
Nightly invariant job (keyset over `credit_transactions` of last 2 days, plus weekly full sweep RU-throttled): `SELECT transaction_id, SUM(amount) FROM credit_postings WHERE tenant_id=? AND transaction_id IN (...) GROUP BY transaction_id HAVING SUM(amount) <> 0` → alert; `credit_balances.available` vs Σ active lots remaining per tenant/product.

### Migration set `0500_reports`
```sql
CREATE TABLE report_number_blocks (                  -- class: platform; portable sequence replacement
  product VARCHAR(16) NOT NULL,                      -- drive|diagnostic|file|cleaner|freeze|autopilot
  next_value BIGINT NOT NULL,                        -- seeded with legacy max + 1 at migration
  PRIMARY KEY (product)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- allocate: short tx { SELECT next_value ... FOR UPDATE; UPDATE ... SET next_value = next_value + 20 }; instance caches the 20 numbers.

CREATE TABLE reports (
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL,
  product VARCHAR(16) NOT NULL,                      -- drive|diagnostic|file|cleaner|freeze|autopilot
  subtype VARCHAR(16) NULL,                          -- cleaner: standard|cvra ; freeze: basic|advanced|smart|full
  public_id VARCHAR(64) NOT NULL,                    -- DS-ERASE-000123 / DS-DIAG-... / DS-FILE-... / DS-CLEAN-... 
  seq BIGINT NOT NULL,
  state VARCHAR(16) NOT NULL,                        -- reserved|credit_checked|uploading|completed|failed|cancelled|unverified|archived
  result_status VARCHAR(32) NULL,                    -- app-reported outcome (Completed/Failed/Pass/...) normalised
  owner_membership_id BINARY(16) NOT NULL,           -- current owner (transferable)
  performed_by_membership_id BINARY(16) NOT NULL,    -- immutable operator
  device_id BINARY(16) NULL,
  subject_kind VARCHAR(16) NULL,                     -- disk|machine|files|endpoint
  subject_serial_bidx BINARY(32) NULL,
  subject_model VARCHAR(128) NULL,                   -- drive model / computer model (non-PII; list column)
  title VARCHAR(255) NULL,                           -- file eraser report_name, freeze title
  method_label VARCHAR(128) NULL,                    -- erasure method as reported (list/filter)
  method_norm VARCHAR(128) NULL,
  erasure_type VARCHAR(32) NULL,                     -- file_folder|deleted_data|drive|... (file eraser log table choice)
  totals_total INT NULL, totals_ok INT NULL, totals_failed INT NULL,   -- files or disks
  credit_transaction_id BINARY(16) NULL,
  source VARCHAR(16) NOT NULL,                       -- online|offline_upload|migration
  -- NIST SP 800-88 summary (full set inside signed payload; Rev 2 exact list not verified)
  media_type VARCHAR(32) NULL, media_interface VARCHAR(32) NULL, media_capacity_bytes BIGINT NULL,
  media_manufacturer VARCHAR(128) NULL, media_model VARCHAR(128) NULL, media_serial_enc VARBINARY(256) NULL,
  sanitization_method VARCHAR(16) NULL,              -- clear|purge|destroy
  sanitization_technique VARCHAR(128) NULL, tool_name VARCHAR(64) NULL, tool_version VARCHAR(32) NULL,
  verification_method VARCHAR(64) NULL, verification_result VARCHAR(16) NULL,   -- passed|failed|not_performed
  started_at DATETIME(6) NULL, completed_at DATETIME(6) NULL,
  -- integrity (ARCHITECTURE.md §10)
  canonical_version VARCHAR(24) NULL,                -- 'dsecure.cert/1'
  content_sha256 BINARY(32) NULL, render_sha256 BINARY(32) NULL, raw_sha256 BINARY(32) NULL,
  signature VARBINARY(64) NULL, signing_key_id VARCHAR(48) NULL, signed_at DATETIME(6) NULL,
  template_id VARCHAR(48) NULL,                      -- e.g. 'drive.v1' (PDF_TEMPLATES.md)
  branding_version_id BINARY(16) NULL,               -- D-62 snapshot
  app_signature VARBINARY(512) NULL, app_signature_status VARCHAR(16) NULL,   -- valid|invalid|absent|unverifiable
  -- blobs (object storage); never in this row
  raw_blob_key VARCHAR(255) NULL, render_blob_key VARCHAR(255) NULL, blob_size_bytes INT NULL,
  supersedes_report_id BINARY(16) NULL,              -- D-61 cleaner revisions
  revoked_at DATETIME(6) NULL, revoke_reason_code VARCHAR(32) NULL,
  reserved_at DATETIME(6) NOT NULL, created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL,
  version INT UNSIGNED NOT NULL DEFAULT 1, legacy_ref VARCHAR(64) NULL,
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */,
  UNIQUE KEY ux_reports_public (tenant_id, public_id),
  KEY ix_reports_list (tenant_id, product, state, id),
  KEY ix_reports_owner (tenant_id, owner_membership_id, product, state, id),
  KEY ix_reports_device (tenant_id, device_id, id),
  KEY ix_reports_serial (tenant_id, product, subject_serial_bidx, id),
  KEY ix_reports_method (tenant_id, product, method_norm, id),
  KEY ix_reports_reserved_gc (tenant_id, state, reserved_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- RESERVED rows: state='reserved' and excluded by every list query (state IN (...) predicate on the index).

CREATE TABLE report_public_ids (                     -- class: directory; public verify + legacy aliases (D-48, D-60)
  public_id_norm VARCHAR(80) NOT NULL,               -- upper-cased DS-* ids, lower-case uuid, legacy numeric 'FE#123', obfuscated 8-hex 'FEX#5A5A5BD7'
  tenant_id BINARY(16) NOT NULL, report_id BINARY(16) NOT NULL,
  product VARCHAR(16) NOT NULL, kind VARCHAR(16) NOT NULL,     -- primary|legacy_numeric|legacy_obfuscated|legacy_uuid
  PRIMARY KEY (public_id_norm) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;  -- global uniqueness of public ids enforced here

CREATE TABLE report_subjects (                       -- "drives view": per serial last report, times erased (no GROUP BY scans)
  tenant_id BINARY(16) NOT NULL, product VARCHAR(16) NOT NULL, subject_bidx BINARY(32) NOT NULL,
  last_report_id BINARY(16) NOT NULL, last_at DATETIME(6) NOT NULL, last_status VARCHAR(32) NULL,
  last_owner_membership_id BINARY(16) NOT NULL, last_performed_by BINARY(16) NOT NULL,
  times BIGINT NOT NULL DEFAULT 1, subject_model VARCHAR(128) NULL,
  PRIMARY KEY (tenant_id, product, subject_bidx) /*T![clustered_index] CLUSTERED */,
  KEY ix_rs_recent (tenant_id, product, last_at),
  KEY ix_rs_owner (tenant_id, last_owner_membership_id, product, last_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE report_uploads (                        -- staged/chunked uploads (File Eraser append flow → object storage multipart)
  tenant_id BINARY(16) NOT NULL, report_id BINARY(16) NOT NULL,
  staged_blob_key VARCHAR(255) NOT NULL, parts INT NOT NULL DEFAULT 0, bytes BIGINT NOT NULL DEFAULT 0,
  started_at DATETIME(6) NOT NULL, expires_at DATETIME(6) NOT NULL, finalized_at DATETIME(6) NULL,
  PRIMARY KEY (tenant_id, report_id) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE report_blobs (                          -- fallback only if object storage not chosen (D-41) — RU expensive
  tenant_id BINARY(16) NOT NULL, report_id BINARY(16) NOT NULL, part VARCHAR(16) NOT NULL,  -- raw|render
  content_enc MEDIUMBLOB NOT NULL,                   -- gzip + GCM; app cap 4 MB
  PRIMARY KEY (tenant_id, report_id, part) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE report_branding (                       -- legacy pdf_export_settings (current row per tenant + product)
  tenant_id BINARY(16) NOT NULL, product VARCHAR(16) NOT NULL,   -- global|drive|diagnostic|file|cleaner|autopilot
  current_version_id BINARY(16) NOT NULL,
  updated_by BINARY(16) NOT NULL, updated_at DATETIME(6) NOT NULL, version INT UNSIGNED NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, product) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE report_branding_versions (              -- append-only; slots per PDF_TEMPLATES.md §2
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL, product VARCHAR(16) NOT NULL,
  report_title VARCHAR(255) NULL, header_text VARCHAR(255) NULL,
  technician_name_enc VARBINARY(512) NULL, technician_dept VARCHAR(128) NULL, technician_company VARCHAR(128) NULL,
  validator_name_enc VARBINARY(512) NULL, validator_dept VARCHAR(128) NULL, validator_company VARCHAR(128) NULL,
  left_logo_key VARCHAR(255) NULL, left_logo_sha256 BINARY(32) NULL,
  right_logo_key VARCHAR(255) NULL, right_logo_sha256 BINARY(32) NULL,
  watermark_key VARCHAR(255) NULL, watermark_sha256 BINARY(32) NULL,
  technician_signature_key VARCHAR(255) NULL, technician_signature_sha256 BINARY(32) NULL,
  validator_signature_key VARCHAR(255) NULL, validator_signature_sha256 BINARY(32) NULL,
  created_by BINARY(16) NOT NULL, created_at DATETIME(6) NOT NULL,
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */,
  KEY ix_rbv_product (tenant_id, product, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE report_counters (                       -- dashboard counts without scans
  tenant_id BINARY(16) NOT NULL, product VARCHAR(16) NOT NULL, owner_membership_id BINARY(16) NOT NULL,
  completed BIGINT NOT NULL DEFAULT 0, failed BIGINT NOT NULL DEFAULT 0, pending BIGINT NOT NULL DEFAULT 0,
  last_report_at DATETIME(6) NULL,
  PRIMARY KEY (tenant_id, product, owner_membership_id) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE report_facet_counters (                 -- V2-style facets (status/method/performer) per tenant+product
  tenant_id BINARY(16) NOT NULL, product VARCHAR(16) NOT NULL, dimension VARCHAR(16) NOT NULL,  -- status|method|performer|month
  value_key VARCHAR(128) NOT NULL, count BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, product, dimension, value_key) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- member/GA scoped facets: bounded aggregate over ix_reports_owner (max 10k rows, else "facets_unavailable").
```

---

## 7. Autopilot, Freeze, System Cleaner

### Migration set `0600_products_extra`
```sql
CREATE TABLE mdm_connections (                       -- customer's Microsoft tenant (legacy uem_tenant_connections)
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL,
  provider VARCHAR(24) NOT NULL,                     -- microsoft_graph
  directory_tenant_id VARCHAR(64) NOT NULL,
  token_cache_enc MEDIUMBLOB NOT NULL,
  status VARCHAR(16) NOT NULL,                       -- active|expired|revoked|error
  connected_by BINARY(16) NOT NULL, connected_at DATETIME(6) NOT NULL, last_used_at DATETIME(6) NULL,
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE autopilot_devices (
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL,
  owner_membership_id BINARY(16) NOT NULL, performed_by_membership_id BINARY(16) NULL,   -- legacy subuser_email (donor)
  connection_id BINARY(16) NULL,
  serial_bidx BINARY(32) NOT NULL, serial_enc VARBINARY(256) NOT NULL,
  serial_active BINARY(32) NULL,                     -- unique-when-not-deleted
  uuid_enc VARBINARY(256) NULL,
  manufacturer VARCHAR(128) NULL, model VARCHAR(128) NULL, chassis_type VARCHAR(64) NULL, sku_number VARCHAR(128) NULL,
  bios_version VARCHAR(255) NULL, bios_details VARCHAR(500) NULL, bios_lock_status VARCHAR(64) NULL, tpm_status VARCHAR(64) NULL,
  hardware_hash_blob_key VARCHAR(255) NULL,          -- hash ~4 KB base64 → object storage (or _enc if small; D-41)
  execution_source VARCHAR(16) NOT NULL,             -- exe|bootable (bucket DSAM vs DSAM_USB)
  source VARCHAR(16) NOT NULL,                       -- csv_upload|dashboard|tool|dvinf
  status VARCHAR(32) NOT NULL,                       -- Pending|Processing|saved|locked|unlocked|error_* (legacy vocabulary kept)
  ztd_import_status VARCHAR(32) NULL, ztd_error_code BIGINT NULL, ztd_error_detail VARCHAR(500) NULL,
  unlock_credentials_enc VARBINARY(2048) NULL,       -- D-3 (autopilot contract) keep/drop
  credit_transaction_id BINARY(16) NULL,             -- replaces credit_charged
  custom_fields JSON NULL,                           -- app cap 8 KB, object of strings
  digital_identifier_legacy VARCHAR(512) NULL,       -- imported RSA identifier (verify-only)
  processing_started_at DATETIME(6) NULL, lease_until DATETIME(6) NULL, claimed_by VARCHAR(64) NULL,
  report_id BINARY(16) NULL,                         -- certificate in reports (product='autopilot')
  created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL, version INT UNSIGNED NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */,
  UNIQUE KEY ux_apd_serial (tenant_id, serial_active),
  KEY ix_apd_list (tenant_id, status, id),
  KEY ix_apd_owner (tenant_id, owner_membership_id, id),
  KEY ix_apd_changed (tenant_id, updated_at, id)     -- D-57 polling changes feed
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- worker pending queue: jobs table (kind='autopilot_check', one job per device), NOT a global scan of this table.

CREATE TABLE autopilot_schedules (                   -- legacy scheduled_tasks
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL,
  name VARCHAR(128) NOT NULL, frequency VARCHAR(48) NOT NULL,   -- once|daily|weekly|monthly|weekdays|custom:<days>
  next_run_at DATETIME(6) NULL, last_run_at DATETIME(6) NULL, last_run_status VARCHAR(255) NULL,
  status VARCHAR(24) NOT NULL,                       -- scheduled|running|completed|paused_no_credit|error
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_by BINARY(16) NOT NULL, created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL,
  version INT UNSIGNED NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- due schedules: one 'schedule_tick' job per schedule in jobs (run_after = next_run_at); no global scan.

CREATE TABLE autopilot_schedule_items (
  tenant_id BINARY(16) NOT NULL, schedule_id BINARY(16) NOT NULL, autopilot_device_id BINARY(16) NOT NULL,
  PRIMARY KEY (tenant_id, schedule_id, autopilot_device_id) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE device_check_jobs (                     -- UEM recheck jobs (legacy uem_recheck_jobs) + bulk imports
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL,
  kind VARCHAR(16) NOT NULL,                         -- uem_recheck|bulk_import
  connection_id BINARY(16) NULL, input_blob_key VARCHAR(255) NULL,
  status VARCHAR(16) NOT NULL,                       -- pending|running|completed|failed|cancelled
  total INT NOT NULL DEFAULT 0, processed INT NOT NULL DEFAULT 0, clear_count INT NOT NULL DEFAULT 0,
  enrolled_count INT NOT NULL DEFAULT 0, error_count INT NOT NULL DEFAULT 0, error_message VARCHAR(255) NULL,
  created_by BINARY(16) NOT NULL, created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL, completed_at DATETIME(6) NULL,
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE device_check_job_items (
  tenant_id BINARY(16) NOT NULL, job_id BINARY(16) NOT NULL, item_no INT NOT NULL,
  serial_bidx BINARY(32) NOT NULL, serial_enc VARBINARY(256) NOT NULL,
  status VARCHAR(16) NOT NULL,                       -- pending|clear|still_enrolled|error
  intune_found BOOLEAN NULL, entra_found BOOLEAN NULL, autopilot_found BOOLEAN NULL,
  error_detail VARCHAR(255) NULL, checked_at DATETIME(6) NULL,
  PRIMARY KEY (tenant_id, job_id, item_no) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE freeze_endpoints (
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL,
  device_id BINARY(16) NULL, owner_membership_id BINARY(16) NOT NULL, group_id BINARY(16) NULL,
  machine_key_bidx BINARY(32) NOT NULL,              -- tenant HMAC of agent machine_id (upsert key)
  machine_name_enc VARBINARY(512) NULL, os_info VARCHAR(128) NULL,
  group_label VARCHAR(128) NULL, sub_group VARCHAR(128) NULL,      -- free-text labels from agent
  status VARCHAR(16) NOT NULL, is_frozen BOOLEAN NOT NULL DEFAULT FALSE,
  activated_at DATETIME(6) NULL, expires_at DATETIME(6) NULL, last_seen_at DATETIME(6) NULL,
  created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL, archived_at DATETIME(6) NULL,
  version INT UNSIGNED NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */,
  UNIQUE KEY ux_fe_machine (tenant_id, machine_key_bidx),
  KEY ix_fe_updated (tenant_id, updated_at, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE freeze_events (                         -- legacy timeline_history JSON → rows (capped per endpoint)
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL, endpoint_id BINARY(16) NOT NULL,
  kind VARCHAR(24) NOT NULL, occurred_at DATETIME(6) NOT NULL,
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */,
  KEY ix_fev (tenant_id, endpoint_id, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE freeze_messages (
  tenant_id BINARY(16) NOT NULL, id BINARY(16) NOT NULL, endpoint_id BINARY(16) NOT NULL,
  sender_kind VARCHAR(16) NOT NULL,                  -- member|endpoint (token-derived, never body)
  sender_membership_id BINARY(16) NULL,
  message_type VARCHAR(16) NOT NULL DEFAULT 'text',  -- text|command|status|alert (command = device_commands path, not chat)
  body_enc VARBINARY(8192) NOT NULL,
  created_at DATETIME(6) NOT NULL, read_at DATETIME(6) NULL,
  PRIMARY KEY (tenant_id, id) /*T![clustered_index] CLUSTERED */,
  KEY ix_fm_thread (tenant_id, endpoint_id, id),
  KEY ix_fm_unread (tenant_id, endpoint_id, read_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- unread count: freeze_unread_counters (tenant_id, endpoint_id, sender_kind) maintained same tx → no COUNT scans.

CREATE TABLE freeze_unread_counters (
  tenant_id BINARY(16) NOT NULL, endpoint_id BINARY(16) NOT NULL, sender_kind VARCHAR(16) NOT NULL,
  unread BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, endpoint_id, sender_kind) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE cleaner_redeem_codes (                  -- class: platform; legacy dssc_license_keys; minted only by platform
  id BINARY(16) NOT NULL, code_bidx BINARY(32) NOT NULL, code_enc VARBINARY(256) NOT NULL,
  product_code VARCHAR(16) NOT NULL DEFAULT 'DSSC', credits INT NOT NULL,
  status VARCHAR(16) NOT NULL,                       -- unused|redeemed|revoked
  expires_at DATETIME(6) NULL,
  created_by_staff BINARY(16) NOT NULL, created_at DATETIME(6) NOT NULL,
  redeemed_tenant_id BINARY(16) NULL, redeemed_at DATETIME(6) NULL, credit_transaction_id BINARY(16) NULL,
  PRIMARY KEY (id) /*T![clustered_index] CLUSTERED */,
  UNIQUE KEY ux_crc_code (code_bidx)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- redeem: UPDATE ... SET status='redeemed', redeemed_tenant_id=? ... WHERE code_bidx=? AND status='unused' AND (expires_at IS NULL OR expires_at >= ?) → expect_one, then ledger 'redeem' tx (same DB tx).
-- cleaner runs/reports → reports(product='cleaner', subtype standard|cvra); credits → ledger (DSSC).
```

---

## 8. Keys, commerce, catalogue, leads, email, audit, infra

### Migration set `0150_keys` (runs before reports)
```sql
CREATE TABLE data_keys (                             -- class: platform; wrapped DEKs
  kid VARCHAR(48) NOT NULL,
  purpose VARCHAR(16) NOT NULL,                      -- identity|pii|reports|secrets|bidx_email|bidx_license|bidx_tenant|audit
  tenant_id BINARY(16) NULL,                         -- NULL = platform-wide
  scope_key BINARY(16) NOT NULL,                     -- tenant_id or 0x00..00 (no COALESCE index)
  kek_ref VARCHAR(255) NOT NULL, wrapped_dek VARBINARY(512) NOT NULL,
  status VARCHAR(16) NOT NULL,                       -- active|decrypt_only|retired|destroyed
  active_marker VARCHAR(1) NULL,                     -- 'Y' while active, else NULL (unique-when-active)
  created_at DATETIME(6) NOT NULL, rotated_at DATETIME(6) NULL, destroyed_at DATETIME(6) NULL, destroyed_by_approval BINARY(16) NULL,
  PRIMARY KEY (kid),
  UNIQUE KEY ux_dk_active (purpose, scope_key, active_marker)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE signing_keys (
  kid VARCHAR(48) NOT NULL,
  purpose VARCHAR(24) NOT NULL,                      -- report_certificate|jwt_member|jwt_device|jwt_staff|jwt_cleaner|offline_license|legacy_rsa_verify
  alg VARCHAR(16) NOT NULL,                          -- Ed25519|ES256|RS256 (legacy verify only)
  public_key VARBINARY(1024) NOT NULL,
  private_key_ref VARCHAR(255) NULL, wrapped_private_key VARBINARY(1024) NULL,
  status VARCHAR(16) NOT NULL,                       -- active|verify_only|retired
  not_before DATETIME(6) NOT NULL, not_after DATETIME(6) NULL, created_at DATETIME(6) NOT NULL,
  PRIMARY KEY (kid),
  KEY ix_sk_purpose (purpose, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
```

### Migration set `0700_commerce_misc`
```sql
CREATE TABLE orders (                                -- class: infra/commerce (tenant NULL until fulfilment)
  id BINARY(16) NOT NULL, tenant_id BINARY(16) NULL,
  provider VARCHAR(16) NOT NULL,                     -- dodo
  provider_payment_id VARCHAR(64) NULL, checkout_session_id VARCHAR(64) NULL,
  provider_customer_id VARCHAR(64) NULL, provider_invoice_id VARCHAR(64) NULL, provider_product_id VARCHAR(64) NULL,
  buyer_email_bidx BINARY(32) NOT NULL, buyer_email_enc VARBINARY(512) NOT NULL,
  billing_details_enc VARBINARY(4096) NULL,          -- names, phone, company, address
  billing_country VARCHAR(2) NULL, card_brand VARCHAR(16) NULL, card_last4_enc VARBINARY(128) NULL,
  product_code VARCHAR(16) NOT NULL, quantity INT NOT NULL, credits_total BIGINT NULL, term_years INT NULL,
  amount_minor BIGINT NOT NULL, tax_minor BIGINT NULL, currency VARCHAR(3) NOT NULL,
  status VARCHAR(16) NOT NULL,                       -- checkout_created|pending|paid|fulfilled|failed|refunded|cancelled
  paid_at DATETIME(6) NULL, fulfilled_at DATETIME(6) NULL, fulfilment_transaction_id BINARY(16) NULL,
  confirmation_email_sent_at DATETIME(6) NULL,
  created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL, version INT UNSIGNED NOT NULL DEFAULT 1,
  legacy_order_id BIGINT NULL,
  PRIMARY KEY (id) /*T![clustered_index] CLUSTERED */,
  UNIQUE KEY ux_orders_payment (provider, provider_payment_id),
  UNIQUE KEY ux_orders_checkout (provider, checkout_session_id),   -- fixes orphaned checkout orders
  KEY ix_orders_tenant (tenant_id, id),
  KEY ix_orders_buyer (buyer_email_bidx, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE webhook_events (
  id BINARY(16) NOT NULL, provider VARCHAR(16) NOT NULL, provider_event_id VARCHAR(128) NOT NULL,
  event_type VARCHAR(64) NOT NULL, signed_at DATETIME(6) NOT NULL, received_at DATETIME(6) NOT NULL,
  payload_blob_key VARCHAR(255) NULL, payload_sha256 BINARY(32) NOT NULL,   -- payload encrypted in object storage (90 days)
  status VARCHAR(16) NOT NULL,                       -- received|processed|ignored|failed
  attempts INT NOT NULL DEFAULT 0, processed_at DATETIME(6) NULL, error_code VARCHAR(48) NULL,
  PRIMARY KEY (id) /*T![clustered_index] NONCLUSTERED */,
  UNIQUE KEY ux_we_event (provider, provider_event_id),
  KEY ix_we_retry (status, received_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin /*T! SHARD_ROW_ID_BITS=4 */;

CREATE TABLE checkout_links (
  id BINARY(16) NOT NULL, product_code VARCHAR(16) NOT NULL, plan_code VARCHAR(48) NOT NULL,
  provider_product_id VARCHAR(64) NOT NULL, active BOOLEAN NOT NULL DEFAULT TRUE,
  created_by_staff BINARY(16) NOT NULL, created_at DATETIME(6) NOT NULL,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE product_releases (                      -- legacy Updates (both version schemes)
  id BINARY(16) NOT NULL, product_code VARCHAR(16) NOT NULL, app_product_id VARCHAR(32) NOT NULL,   -- DSErase|DSDrive|...
  version VARCHAR(32) NOT NULL, version_code INT NULL,                 -- semver + integer build code (Python client)
  platform VARCHAR(16) NULL, architecture VARCHAR(16) NULL, channel VARCHAR(16) NOT NULL DEFAULT 'stable',
  artifact_url VARCHAR(500) NOT NULL, artifact_sha256 BINARY(32) NOT NULL, file_size_bytes BIGINT NULL,
  notes TEXT NULL, update_type VARCHAR(16) NULL, min_os_version VARCHAR(32) NULL,
  min_supported_version VARCHAR(32) NULL, mandatory BOOLEAN NOT NULL DEFAULT FALSE,
  published_at DATETIME(6) NULL, created_by_staff BINARY(16) NOT NULL, created_at DATETIME(6) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY ux_pr_version (app_product_id, platform, channel, version),
  KEY ix_pr_latest (app_product_id, channel, published_at),
  KEY ix_pr_code (app_product_id, platform, version_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE download_events (                       -- privacy-minimal raw (90 days) → rollup
  id BINARY(16) NOT NULL, product_label VARCHAR(100) NOT NULL, release_id BINARY(16) NULL,
  version VARCHAR(50) NULL, platform VARCHAR(16) NOT NULL, architecture VARCHAR(16) NULL,
  file_size BIGINT NULL, source VARCHAR(32) NULL, tenant_id BINARY(16) NULL, membership_id BINARY(16) NULL,
  country VARCHAR(2) NULL, ua_family VARCHAR(64) NULL,
  started_at DATETIME(6) NOT NULL, completed_at DATETIME(6) NULL,
  PRIMARY KEY (id) /*T![clustered_index] NONCLUSTERED */,
  KEY ix_de_time (started_at),
  KEY ix_de_tenant (tenant_id, membership_id, id)    -- download history (own)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin /*T! SHARD_ROW_ID_BITS=4 */;

CREATE TABLE download_daily (                        -- stats endpoints read only this
  day DATE NOT NULL, product_label VARCHAR(100) NOT NULL, platform VARCHAR(16) NOT NULL, architecture VARCHAR(16) NOT NULL,
  started BIGINT NOT NULL, completed BIGINT NOT NULL,
  PRIMARY KEY (day, product_label, platform, architecture)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE contact_leads (                         -- class: platform (staff-only reads)
  id BINARY(16) NOT NULL, source VARCHAR(64) NOT NULL,
  name_enc VARBINARY(512) NULL, email_bidx BINARY(32) NULL, email_enc VARBINARY(512) NULL,
  phone_enc VARBINARY(256) NULL, company_enc VARBINARY(512) NULL, message_enc VARBINARY(16384) NULL,
  form_fields_enc VARBINARY(4096) NULL,              -- country, business_type, solution_type, compliance, usage_type
  message_hash BINARY(32) NULL,                      -- 5-minute duplicate rule (email_bidx + message_hash)
  ip_hmac BINARY(32) NULL,
  status VARCHAR(16) NOT NULL,                       -- new|in_progress|closed|spam
  read_at DATETIME(6) NULL, read_by_staff BINARY(16) NULL, assigned_staff BINARY(16) NULL, notes_enc VARBINARY(4096) NULL,
  created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL, retain_until DATETIME(6) NOT NULL,
  PRIMARY KEY (id),
  KEY ix_cl_list (status, id),
  KEY ix_cl_dupe (email_bidx, message_hash, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE email_messages (
  id BINARY(16) NOT NULL, tenant_id BINARY(16) NULL, template VARCHAR(48) NOT NULL,
  recipient_bidx BINARY(32) NOT NULL, recipient_enc VARBINARY(512) NOT NULL,
  provider VARCHAR(24) NOT NULL, provider_message_id VARCHAR(128) NULL, order_id BINARY(16) NULL,
  status VARCHAR(16) NOT NULL,                       -- queued|sent|failed|bounced
  created_at DATETIME(6) NOT NULL, sent_at DATETIME(6) NULL, send_ms INT NULL, error_code VARCHAR(48) NULL,
  PRIMARY KEY (id) /*T![clustered_index] NONCLUSTERED */,
  KEY ix_em_tenant (tenant_id, id),
  KEY ix_em_time (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin /*T! SHARD_ROW_ID_BITS=4 */;

CREATE TABLE email_provider_usage (
  provider VARCHAR(24) NOT NULL, day DATE NOT NULL, sent INT NOT NULL,
  PRIMARY KEY (provider, day)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
```

### Migration set `0800_audit_infra`
```sql
CREATE TABLE audit_events (                          -- append-only (no UPDATE/DELETE grants for app/worker)
  id BINARY(16) NOT NULL, occurred_at DATETIME(6) NOT NULL,
  tenant_id BINARY(16) NULL,
  actor_kind VARCHAR(16) NOT NULL,                   -- member|device|staff|cleaner|system|anonymous
  actor_id BINARY(16) NULL, staff_grant_id BINARY(16) NULL,
  action VARCHAR(64) NOT NULL, outcome VARCHAR(16) NOT NULL,       -- success|denied|failed
  target_type VARCHAR(32) NULL, target_id BINARY(16) NULL,
  request_id BINARY(16) NULL, ip_hmac BINARY(32) NULL,
  metadata JSON NULL,                                -- typed, no PII, app cap 2 KB
  row_hash BINARY(32) NOT NULL,                      -- SHA-256(canonical row); chained in audit_chain_blocks
  PRIMARY KEY (id) /*T![clustered_index] NONCLUSTERED */,
  KEY ix_ae_tenant (tenant_id, id),
  KEY ix_ae_target (tenant_id, target_type, target_id, id),
  KEY ix_ae_time (occurred_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin /*T! SHARD_ROW_ID_BITS=4 */;

CREATE TABLE audit_chain_blocks (                    -- hash chain without a hot row: worker seals hourly blocks
  block_start DATETIME(6) NOT NULL, block_end DATETIME(6) NOT NULL,
  first_id BINARY(16) NULL, last_id BINARY(16) NULL, event_count BIGINT NOT NULL,
  merkle_root BINARY(32) NOT NULL, prev_block_hash BINARY(32) NOT NULL, block_hash BINARY(32) NOT NULL,
  anchored_blob_key VARCHAR(255) NULL, sealed_at DATETIME(6) NOT NULL,
  PRIMARY KEY (block_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- seal job: after block_end + 5 min settle, reads ix_ae_time range in id order, computes merkle root, chains, anchors daily to object storage.

CREATE TABLE outbox_events (
  id BINARY(16) NOT NULL, tenant_id BINARY(16) NULL, event_type VARCHAR(64) NOT NULL,
  aggregate_type VARCHAR(32) NOT NULL, aggregate_id BINARY(16) NOT NULL,
  payload JSON NOT NULL,                             -- ids only, no PII, app cap 4 KB
  created_at DATETIME(6) NOT NULL, published_at DATETIME(6) NULL, attempts INT NOT NULL DEFAULT 0,
  claimed_by VARCHAR(64) NULL, lease_until DATETIME(6) NULL,
  PRIMARY KEY (id) /*T![clustered_index] NONCLUSTERED */,
  KEY ix_outbox_pending (published_at, created_at)   -- published_at IS NULL range first
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin /*T! SHARD_ROW_ID_BITS=4 */;

CREATE TABLE jobs (
  id BINARY(16) NOT NULL, kind VARCHAR(48) NOT NULL, job_key VARCHAR(160) NOT NULL,
  tenant_id BINARY(16) NULL, payload JSON NOT NULL,  -- app cap 4 KB
  status VARCHAR(16) NOT NULL,                       -- queued|running|succeeded|failed|dead
  run_after DATETIME(6) NOT NULL,
  claimed_by VARCHAR(64) NULL, claim_token BINARY(16) NULL, lease_until DATETIME(6) NULL,
  attempts INT NOT NULL DEFAULT 0, max_attempts INT NOT NULL DEFAULT 8,
  last_error_code VARCHAR(48) NULL, created_at DATETIME(6) NOT NULL, finished_at DATETIME(6) NULL,
  PRIMARY KEY (id) /*T![clustered_index] NONCLUSTERED */,
  UNIQUE KEY ux_jobs_key (job_key),
  KEY ix_jobs_due (status, kind, run_after),
  KEY ix_jobs_lease (status, lease_until),
  KEY ix_jobs_tenant (tenant_id, kind, status)       -- per-tenant max_pending checks
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin /*T! SHARD_ROW_ID_BITS=4 */;

CREATE TABLE idempotency_keys (
  scope_key BINARY(16) NOT NULL,                     -- tenant_id, or user_id for tenant-less principals
  principal_id BINARY(16) NOT NULL, idem_key VARCHAR(128) NOT NULL,
  request_hash BINARY(32) NOT NULL, status_code SMALLINT NULL, response_body VARBINARY(16384) NULL,
  resource_id BINARY(16) NULL, created_at DATETIME(6) NOT NULL, expires_at DATETIME(6) NOT NULL,
  PRIMARY KEY (scope_key, principal_id, idem_key) /*T![clustered_index] CLUSTERED */,
  KEY ix_idem_expiry (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE tenant_counters (                       -- O(1) dashboard summary; also used inside quota tx
  tenant_id BINARY(16) NOT NULL,
  members_active INT NOT NULL DEFAULT 0, groups_active INT NOT NULL DEFAULT 0, departments_active INT NOT NULL DEFAULT 0,
  devices_active INT NOT NULL DEFAULT 0, licenses_active INT NOT NULL DEFAULT 0, licenses_in_use INT NOT NULL DEFAULT 0,
  autopilot_devices INT NOT NULL DEFAULT 0, freeze_endpoints INT NOT NULL DEFAULT 0,
  updated_at DATETIME(6) NOT NULL,
  PRIMARY KEY (tenant_id) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE member_counters (                       -- per-member devices/reports (Group with-users counts, max_machines)
  tenant_id BINARY(16) NOT NULL, membership_id BINARY(16) NOT NULL,
  devices_active INT NOT NULL DEFAULT 0, reports_total BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, membership_id) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE private_cloud_connections (             -- D-13; feature 'private_cloud' (not in first release)
  tenant_id BINARY(16) NOT NULL,
  engine VARCHAR(16) NOT NULL, host_allowlisted BOOLEAN NOT NULL DEFAULT FALSE,
  connection_enc VARBINARY(2048) NOT NULL, status VARCHAR(16) NOT NULL, validated_at DATETIME(6) NULL,
  selected_tables JSON NULL,
  configured_by BINARY(16) NOT NULL, approved_by_staff BINARY(16) NULL, updated_at DATETIME(6) NOT NULL,
  PRIMARY KEY (tenant_id) /*T![clustered_index] CLUSTERED */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE migration_id_map (                      -- class: platform; importer traceability
  legacy_table VARCHAR(64) NOT NULL, legacy_key VARCHAR(255) NOT NULL,
  new_tenant_id BINARY(16) NULL, new_id BINARY(16) NOT NULL, imported_at DATETIME(6) NOT NULL,
  PRIMARY KEY (legacy_table, legacy_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
```

### 8.4 Job claiming without SKIP LOCKED (lease)
```text
loop (per worker, poll 1-30 s with jitter, bounded by WORKER_CONCURRENCY + per-kind semaphores):
  candidates = SELECT id FROM jobs WHERE status='queued' AND kind=? AND run_after <= ? ORDER BY run_after LIMIT 10   -- snapshot read, no lock
  for id in shuffle(candidates):
     UPDATE jobs SET status='running', claimed_by=?, claim_token=?, lease_until=?+30s, attempts=attempts+1
       WHERE id=? AND status='queued'                -- rows_affected = 1 → owned
  run handler; heartbeat: UPDATE ... SET lease_until=? WHERE id=? AND claim_token=?
  finish:  UPDATE ... SET status='succeeded', finished_at=? WHERE id=? AND claim_token=?   (expect_one; 0 = lost lease → handler must be idempotent)
reaper (every 60 s): UPDATE jobs SET status='queued', claimed_by=NULL, claim_token=NULL, run_after=? WHERE status='running' AND lease_until < ? LIMIT 100
```
Same pattern for `outbox_events` relay and `autopilot_devices` (via `autopilot_check` jobs). Works identically on MySQL and TiDB (row lock on the single-row UPDATE; no gap locks needed). Test T-DB5.

---

## 9. Index plan (query → index) and RU checks

### 9.1 Hot queries
| Table | Query (API) | Index / access |
|---|---|---|
| users | login by email | `ux_users_email_bidx` point get |
| membership_directory | user's tenants at login/switch | PK range `(user_id)` |
| memberships | principal state per request | PK point get `(tenant_id, id)` (cached by epoch) |
| memberships | members list (owner/admin; rank filter) | `ix_memberships_role (tenant_id, status, role_rank, id)` |
| group_memberships / group_admin_grants | GA visibility, my groups | PK + `ix_gm_member`, `ix_gag_member` |
| sessions | per-request session check | PK point get |
| sessions | `/me/sessions`; activity per member; tenant login activity | `ix_sessions_user`, `ix_sessions_tenant_member`, `ix_sessions_tenant` |
| refresh_tokens | refresh by hash; family revoke | `ux_rt_hash`, `ix_rt_family` |
| devices | list tenant (PK range), list owner, fingerprint lookup, MAC/serial exact | PK, `ix_devices_owner`, `ux_devices_fp`, `ix_devices_mac`, `ix_devices_serial` |
| device_commands | pending commands poll | `ix_dcmd_device (tenant_id, device_id, status, id)` |
| license_key_directory → licenses | activation by key | directory PK → licenses PK |
| license_activations | validate-hardware poll by hwid | `ix_la_hwid` |
| credit_balances | balance read / consume mutex | PK |
| credit_lots | pick lot | `ix_lots_consume` |
| credit_consumptions | grace check | `ix_cc_grace` |
| credit_transactions | history list; idempotency | PK range / `ix_ct_product`; `ux_ct_idem` |
| reports | list by product (tenant / owner), filter state | `ix_reports_list`, `ix_reports_owner` |
| reports | by public id (tenant known) | `ux_reports_public` |
| report_public_ids | public verify / legacy QR | PK point get → reports PK |
| reports | serial exact search, device history, method filter | `ix_reports_serial`, `ix_reports_device`, `ix_reports_method` |
| report_subjects | drives view | PK range `(tenant_id, product)` order by `ix_rs_recent` |
| report_counters / facets / tenant_counters / member_counters | dashboard summary, facets, Group with-users counts | PK range (no scans) |
| autopilot_devices | list, changes feed, serial uniqueness | `ix_apd_list`, `ix_apd_changed`, `ux_apd_serial` |
| freeze_* | endpoints list, thread, unread | `ix_fe_updated`, `ix_fm_thread`, `freeze_unread_counters` PK |
| orders | tenant list, webhook match | `ix_orders_tenant`, `ux_orders_payment`, `ux_orders_checkout` |
| webhook_events | dedupe, retry | `ux_we_event`, `ix_we_retry` |
| product_releases | latest per product / update check | `ix_pr_latest`, `ix_pr_code` |
| audit_events | tenant audit list, target history | `ix_ae_tenant`, `ix_ae_target` |
| jobs / outbox | due work, lease reaper | `ix_jobs_due`, `ix_jobs_lease`, `ix_outbox_pending` |
| authz_epochs | poller | `ix_authz_epochs_updated` |

Rule: list ordering = `id DESC` (UUIDv7). Allowed filter/sort combos sirf wo jinka index upar hai; baaki API reject karta hai (400 `filter.unsupported`).

### 9.2 Plan gates (TiDB)
- CI (TiDB container + nightly Serverless): har query file seeded data par `EXPLAIN FORMAT='brief'` → operator tree mein `TableFullScan` ya `IndexFullScan` on tables > 1k seeded rows = fail; `estRows` > 10× LIMIT = warn.
- Nightly Serverless: `INFORMATION_SCHEMA.CLUSTER_STATEMENTS_SUMMARY` (ya Serverless equivalent; availability nv) se per-digest RU/rows-scanned report artifact; regression > 30% = fail.

---

## 10. Sizes, RU estimates, retention

### 10.1 RU estimates for hot paths (rough; NOT verified)
Assumption (my understanding of TiDB Cloud Serverless RU; exact formula and prices **not verified**, Phase 0 P0-22 calibrate karega): reads ≈ proportional to storage read requests/bytes (order: ~1 RU per few point gets / per ~64 KiB scanned), writes ≈ ~1 RU per write request + ~1 RU per KiB written (indexes included), plus SQL CPU time.
| Hot path | DB work (design) | Rough RU / request |
|---|---|---|
| Login | email bidx point get, credentials PK, membership_directory range (1-3 rows), tenant/membership PK; writes: session row + refresh token + credentials counter reset + audit event (+indexes) | ~10-25 |
| Request auth (cached) | 0 (epoch cache hit); miss = 3-4 point gets | 0 / ~2-4 |
| Reserve report id | block allocator amortised (1 locked update per 20 ids) + report insert (+6 index entries) + public id directory insert + audit | ~10-20 |
| Pre-check (credit consume) | idempotency insert, grace point range, balance FOR UPDATE, lot select + update, balance update, tx + 2 postings + consumption insert, report update, counters, audit, outbox | ~35-60 |
| Report upload (metadata only; 2 MB JSON to object storage) | report update (signature, NIST cols), report_subjects upsert, counters/facets 3-5 updates, audit, outbox | ~20-40 |
| Same upload if JSON stored in TiDB (`report_blobs`) | + ~2 MB write | **~2,000+** (why D-41 says object storage) |
| Dashboard list (50 rows) | one PK/secondary range scan, ~50 × ~1 KB | ~5-15 |
| Dashboard summary | 3-6 counter point gets/ranges | ~2-5 |
| Legacy-style unindexed scan (for comparison) | 100k rows × ~1 KB | ~1,500+ |
Budget alarm: Serverless spending limit + metric `db_ru_per_request` (from `statements_summary`) per route class.

### 10.2 Size estimates (assumed volumes, **not verified**: 2,000 tenants, 20,000 members, 200,000 devices, 1,000,000 reports/year)
| Table | Avg row (+idx) | Rows yr 1 | Size (logical) | Retention / archival |
|---|---|---|---|---|
| reports (metadata) | ~0.9 KB + ~0.6 KB idx | 1M | ~1.5 GB | Indefinite (certificates); `archived` state |
| report blobs (object storage) | ~20-80 KB gz+enc (raw + render) | 1M | ~20-80 GB (not TiDB) | Per contract (D-17); crypto-shred with tenant DEK |
| credit ledger (tx + postings + consumptions) | ~200 B × 4 | 1M consumes | ~0.8 GB | 7 yrs min (lawyer) |
| audit_events | ~350 B | ~20-50M | 7-18 GB | Hot 13 months; then archive to object storage + owner-approved purge (D-56) |
| sessions + refresh_tokens | ~300 B | ~2M | ~0.6 GB | 90 days after expiry (approved purge) |
| auth_challenges, step_up_tokens, idempotency_keys | small | churn | < 100 MB | TTL sweeps (approved purge) |
| webhook_events | ~300 B (payload in object storage) | ~50k | ~15 MB | 2 yrs; payload blob 90 days |
| outbox_events, jobs | small | churn | < 300 MB | finished > 7 days purge (approved) |
| contact_leads, email_messages, download_events | — | — | < 300 MB | 2 yrs / 1 yr / 90 days raw |
| devices, licenses, memberships, users | 0.5-1 KB | < 300k | < 0.5 GB | Life of tenant |
TiDB storage = logical × replication (billing basis for Serverless not verified). Hot DB year 1 ≈ 12-25 GB logical (mostly audit). Purges = deletion → har class ka policy owner approve kare; tab tak jobs sirf archive/mark.

---

## 11. Migrations, DDL rules, legacy mapping

### 11.1 Migration rules (TiDB DDL limits)
- Tool: `sqlx migrate` (MySQL driver) — **one DDL statement per migration file** (MySQL/TiDB DDL implicitly commit hai; multi-statement file beech mein fail = half-applied). Files numbered `0100_0001_tenants.sql` style; `xtask migrate-lint` single-statement rule enforce karta hai. sqlx ka MySQL migrator partial-failure handling P0 mein test (nv).
- Forward-only, expand/contract: naya column NULL/default ke saath add → code dual-write → backfill job (batched, RU-throttled) → constraint/use → old column later.
- TiDB limits: clustered PK create-time par fix (baad mein change = table rebuild/copy); STORED generated column ALTER se add nahi; ek table par ek DDL at a time; ADD INDEX backfill bade table par RU kharch karta hai (off-peak, owner ko RU estimate ke saath); column type lossy change avoid; `RENAME COLUMN` support hai par wire rule (additive) ki wajah se use nahi.
- Migrations kabhi app startup par nahi: release step `dsecure-api migrate` (migrator user) **pehle**, phir deploy.
- FK shadow: `migrations_shadow/` (MySQL CI only).

### 11.2 Old 62 tables → new home
| # | Legacy table | New home | Note |
|---|---|---|---|
| 1 | `Users` | `tenants` + `users` + `user_credentials` + `memberships(owner)` + `membership_directory` + `tenant_features` + `tenant_quotas` + `tenant_settings` | Plaintext `user_password` never migrated (D-10); `mdm_auto_check_enabled` → `tenant_settings.autopilot_auto_check`; `payment_details_json` → orders |
| 2 | `subuser` | `users` + `memberships(kind=subuser)` + `membership_capabilities` + `credit_allocations` | `RBAC.md` §9 |
| 3-10 | `UserRoles`, `SubuserRoles`, `Roles`, `Permissions`, `RolePermissions`, `Routes`, `PermissionRoutes`, `User_role_profile` | role mapping only / code catalogue | Dropped after import |
| 11 | `Groups` | `groups` | `license_allocation` dropped unless owner wants group budgets (users contract GD16) |
| 12 | `GroupMembers` | `group_memberships` + `group_admin_grants` | Email → membership id |
| 13 | `GroupDetails` | — | Dropped (count check) |
| 14 | `Departments` | `departments` | — |
| 15 | `sessions` | `sessions` (last 90 days, optional) | IP encrypted |
| 16 | `token_revocations` | `users.tokens_valid_after` | — |
| 17 | `forgot_password_requests` | `auth_challenges` | Not imported |
| 18 | `activity_sessions` | `audit_events` (optional) | — |
| 19 | `logs` | `audit_events` (filtered, optional) | No PII import |
| 20 | `audit_logs` | — | Dropped |
| 21 | `Machines` | `devices` (+ `member_counters`) | `license_details_json`/`machine_details_json` → `hw_ids_enc` / dropped (count report) |
| 22 | `Commands` | `device_commands` (open only) | — |
| 23 | `CommandHistory` | — | Dropped |
| 24 | `licenses` | `licenses` + `license_key_directory` (DSFE/DSFZ) + `credit_lots`/`credit_balances`/`credit_unlimited_windows` opening balances (pool products) | `Notes` counters → reconciliation, owner sign-off |
| 25 | `license_devices` | `license_activations` | — |
| 26 | `disk_drives` | `credit_consumptions` (subject=disk, last 15 days; `drives_information` → `subject_details_enc`) | — |
| 27 | `diagnostic_machines` | `credit_consumptions` (subject=machine) | — |
| 28 | `offline_requests` | — | Dropped |
| 29 | `drive_eraser_reports` | `reports(drive)` + `report_public_ids` + `report_subjects` + blobs | Legacy CBC JSON decrypt at import |
| 30 | `diagnostic_reports` | `reports(diagnostic)` + … | — |
| 31 | `AuditReports` | `reports(file)` + `report_public_ids` (DS-FILE + legacy numeric + obfuscated + uuid aliases) | Private-cloud rows not here (D-13) |
| 32 | `pdf_export_settings` | `report_branding` + `report_branding_versions` + images in object storage; `column_view_config` → `member_preferences` | `GZIP:`/base64 decode (D-59) |
| 33 | `ProductRsaKeys` | `signing_keys(legacy_rsa_verify, public key only)` | Private keys not migrated |
| 34-38 | `dssc_accounts`, `dssc_license_keys`, `dssc_credit_transactions`, `dssc_cleaner_reports`, `cvra_reports` | `users`+`tenants(individual)` (D-11), `cleaner_redeem_codes`, ledger opening balance, `reports(cleaner, standard|cvra)` | — |
| 39 | `autopilot_devices` | `autopilot_devices` | `credit_charged` → transaction ref; `digital_identifier` → `digital_identifier_legacy` |
| 40-41 | `scheduled_tasks`, `scheduled_task_devices` | `autopilot_schedules`, `autopilot_schedule_items` | — |
| 42 | `uem_tenant_connections` | `mdm_connections` | Re-encrypt or reconnect (D-12) |
| 43-44 | `uem_recheck_jobs`, `uem_recheck_results` | `device_check_jobs`, `device_check_job_items` (recent/open) | — |
| 45-47 | `FreezeDevices`, `FreezeReports`, `FreezeChatMessages` | `freeze_endpoints`+`freeze_events`, `reports(freeze)`, `freeze_messages`+`freeze_unread_counters` | `tenant_id` from owner, not client value |
| 48-49 | `orders`, `checkout_links` | `orders`, `checkout_links` (+ `provider_products` from env maps) | `webhook_payload` not migrated |
| 50-52 | `purchase_orders`, `purchased_licenses`, `payment_records` | — | Dropped (dead) |
| 53 | `downloads` | `download_daily` rollup | — |
| 54 | `Updates` | `product_releases` | Both version schemes |
| 55 | `contact_form_submissions` | `contact_leads` | Encrypted |
| 56-58 | `EmailLogs`, `email_sent_logs`, `EmailQuotas` | `email_messages`, `email_provider_usage` | Open-tracking not migrated (D-20) |
| 59 | `private_cloud_databases` | `private_cloud_connections` (D-13) | Re-encrypt |
| 60-62 | `global_user_directory`, `AccessRequests`, `ScheduledReports` | — | Dropped |
EF-only tables ignore. `license_usage_logs` / `license_transfer_logs` → `license_events` (agar live DB mein hain; importer `SHOW TABLES` se confirm; not verified).

---

## 12. Open items / not verified
- TiDB Serverless engine version + flags: FK maturity, `tidb_enable_check_constraint`, `SKIP LOCKED`, `max_execution_time` semantics, txn size limits, `statements_summary` availability, default txn mode — P0-21 job record karega.
- RU formula/prices; real row counts, report JSON sizes, legacy column types; NIST Rev 2 exact fields; `Groups` creator column.
- sqlx MySQL migrator partial-failure behaviour; sqlx `query_file!` offline mode with TiDB.
- DB-1: **closed** in v3 (§6 `0400_credit_ledger`).

---

## 13. Contract → schema coverage (reconciliation, 20 Oct 2026)
"Do NOT port" items excluded. Permission side: `RBAC.md` §4 and §4.12.
| Contract feature (docs/contracts) | Tables |
|---|---|
| auth: login (multi-tenant, product context), refresh, logout, validate, change password, edit profile, timezone, forgot (OTP + link), roles/permissions read, login activity, sessions timeline, user action log (ActivitySessions), profile | `users`, `user_credentials`, `membership_directory`, `memberships`, `sessions`, `refresh_tokens`, `auth_challenges`, `audit_events`, `tenant_settings`/`users.timezone` |
| users-subusers-groups: register (self-signup), profile update, subuser CRUD + capabilities + license allocation, departments, groups CRUD, members by email add/remove, group with-users (machine/report counts), group admin transfer/revoke | `memberships`, `membership_capabilities`, `credit_allocations`, `departments`, `groups`, `group_memberships`, `group_admin_grants`, `member_counters`, `tenant_counters` |
| machines: list/filter, by-mac/fingerprint, register, update, transfer to member, statistics, licence status / remaining days, server time | `devices`, `license_activations`, `member_counters`, `device_commands` |
| licences: activate, validate-hardware (polled), licence quota, sync (server_revision, last_seen), renew, admin revoke/export/list, offline request/response, offline quota transfer, RSA public key/verify (legacy), usage/transfer logs | `licenses`, `license_key_directory`, `license_activations`, `license_events`, `offline_activation_requests`, `offline_credit_grants`, `credit_*`, `signing_keys` |
| drive-eraser: reserve-id, pre-wipe-check (grace 15 days per disk), upload, offline upload (file), quota stats, user reports + filters, drives view, PDF | `reports`, `report_public_ids`, `report_number_blocks`, `credit_consumptions`, `credit_*`, `report_subjects`, `report_counters`, `report_facet_counters`, `report_branding*` |
| diagnostic: same pipeline, grace per machine, list/get, PDF | same |
| file-eraser: reserve, upload + append + finalize, list/filters (search, method, type, sync status, group), by MAC (scoped), statistics, CSV export, PDF single/batch, branding settings (multipart + JSON), public resolve/verify, V2 lists | `reports`, `report_uploads`, `report_public_ids` (aliases), `report_facet_counters`, `report_counters`, `devices` (MAC), `report_branding*`, `jobs` (exports) |
| dssc: register/login (merged identity D-11), balance, redeem, erase (1 credit), reports, upload (+CVRA subtype), export PDF, transactions | `users`/`tenants`, `cleaner_redeem_codes`, `credit_*` (DSSC), `reports(cleaner)` |
| freeze: endpoint register/list/get/delete, reports upload/list/by machine/delete, chat send/list/thread/read/unread count | `freeze_endpoints`, `freeze_events`, `reports(freeze)`, `freeze_messages`, `freeze_unread_counters` |
| private cloud (D-13 later) | `private_cloud_connections` |
| autopilot: check-status-direct, CSV/DVINF upload, list/lookup/delete, custom fields, quota (DSAM + DSAM_USB, unlimited), auto-check preference, recheck (single/bulk), delete from Intune (own tenant only), unlock credentials, allocate/grant (platform), digital identifier, PDFs (single, consolidation), branding + column view, scheduled tasks, UEM tenant + recheck jobs, realtime status | `autopilot_devices`, `credit_*` + `credit_unlimited_windows`, `tenant_settings.autopilot_auto_check`, `autopilot_schedules`, `autopilot_schedule_items`, `mdm_connections`, `device_check_jobs`, `device_check_job_items`, `jobs`, `reports(autopilot)`, `report_branding*`, `member_preferences` |
| payments-and-misc: Dodo webhook (idempotent, product map, bundles, DSCO/DSAM_COMBO split), checkout sessions, orders/invoices, checkout links, contact leads (+ FormSubmit webhook, duplicate rule), email logs/stats (platform), downloads record/stats/history, app update check + latest + admin, performance metrics (erasure metrics, managed stats), health, logs (own), audit | `orders`, `webhook_events`, `provider_products`, `product_bundle_components`, `checkout_links`, `contact_leads`, `email_messages`, `email_provider_usage`, `download_events`, `download_daily`, `product_releases`, `report_counters`/`report_facet_counters` (metrics), `audit_events` |
Gaps intentionally left: group licence budgets (`Groups.license_allocation`, owner decision), email open-tracking (D-20), private cloud routing (D-13), performance "fake" endpoints (dropped).
