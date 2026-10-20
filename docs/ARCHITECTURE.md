# DSecure Rust backend: Architecture (draft v3, 20 Oct 2026)

Owner: Mr. W. Author: architect. Status: **DRAFT**. Owner ne 20 Oct 2026 ko Rust rewrite approve kiya.
Is doc mein koi secret, key ya connection string nahi hai: sirf config names.

**v2 mein kya badla (owner ke 20 Oct ke updates):**
1. **Wire compatibility ab zaruri nahi.** Rust backend naya project hai: saaf, versioned API `/api/v1/...`. .NET routes, JSON shapes, legacy response-encryption envelope aur legacy token acceptance core mein **nahi** banenge. .NET ka behaviour ab **feature inventory** hai (kya hona chahiye), contract nahi. Feature checklists `docs/contracts/*.md` mein (doosre agents likh rahe hain; aaj folder khaali tha, not verified). Unke "BUGS — do NOT port" sections lagu hain.
2. **Resource budget: Render par 512 MB RAM** (owner confirm karenge). §12 "Performance & resource budget" dekho.
3. RBAC poora: `RBAC.md`.

**v3 (owner, 20 Oct 2026):** (a) **DB = TiDB Cloud** (D-01 *"Tidb"*): RLS/triggers/NOTIFY/RETURNING/SKIP LOCKED nahi, isliye tenant isolation aur invariants data layer + app transactions mein (`DATABASE.md` §1-§2); (b) **512 MB confirmed** (D-50); (c) **PDF = .NET jaisa layout**, PAdES nahi, hybrid (server signs render data, client renders) — `PDF_TEMPLATES.md` (D-19).

Saath ke docs: `DATABASE.md`, `SECURITY.md`, `RBAC.md`, `MIGRATION_PLAN.md`, `DECISIONS.md`, `PHASE0_SPEC.md`.

**Evidence base (.NET reference, read-only):** `CLAUDE.md` codebase map, `BACKEND_FULL_REPORT_20-Oct-2026.md`, `docs/ENCRYPTION_DESIGN.md`, `docs/COMPLIANCE_GAP.md`, `noop-writes-list.md`, `A-to-Z-18-Oct-2026.md` §4/§9, `rbac-audit-report.md`, `rbac-deep-audit.md`; kuch controllers/middleware feature details ke liye; frontend repo sirf padha.

---

## 1. Principles

| # | Principle | Matlab |
|---|---|---|
| P1 | **Deny by default** | Har route ko startup par ek policy chahiye; policy nahi = server start nahi. Public route sirf explicit `Public { reason }` |
| P2 | **Identity sirf token se** | Body/URL mein `tenant_id`, `user_email`, `client_email` jaisi cheez authority kabhi nahi. v1 API mein aise fields hote hi nahi |
| P3 | **Teen checks backend mein** | Tenant + feature toggle/entitlement + role/permission (`RBAC.md`) |
| P4 | **Tenant scope data layer mein** | `TenantTx` ke bina repository compile nahi; SQL sirf `db` crate ki query files mein, `tenant_id = ?` lint-enforced; tenant-leading keys schema-check se; row-tenant assert (TiDB par RLS nahi) |
| P5 | **Har write ka asli result** | rows-affected check (`expect_one`); ids app-generated (TiDB/MySQL mein RETURNING nahi); 0 rows = error (.NET NoTracking no-op problem possible nahi) |
| P6 | **Fail closed** | Secret missing, key unwrap fail, policy error, tenant mismatch in row, schema-check fail → deny / 500 / startup or release fail |
| P7 | **Bounded resources** | Har queue, cache, body, pool, concurrency ki upper limit; 512 MB mein kabhi OOM nahi (§12) |
| P8 | **Clean versioned API** | `/api/v1`, REST resources, ek error format, cursor pagination, idempotency keys. Breaking change = `/api/v2` |
| P9 | **No PII in logs** | `Redacted<T>` type-level; logs/traces/metrics mein email/naam/IP plain nahi |
| P10 | **No hard DELETE of customer data** | Erasure = crypto-shredding + tombstone; disable/archive alag |
| P11 | **Ek waqt mein ek badi cheez** | Language + DB badal rahe hain; hosting (Render) same rakho jab tak zarurat na ho (D-02) |

---

## 2. Stack choice

Versions sirf major line jahan bharosa hai; **exact versions Phase 0 start par pin karo (aaj crates.io check nahi kiya: not verified).**

| Kaam | Choice | Kyun | Alternative (kyun nahi) |
|---|---|---|---|
| Toolchain | Rust stable, edition 2024 (1.85+), `rust-toolchain.toml` | Memory safety, type-level tenant/permission enforcement | — |
| Runtime | `tokio` 1.x, **worker_threads = 2** (configurable) | Render 512 MB plan par CPU kam (exact CPU share not verified); kam threads = kam memory | — |
| HTTP | `axum` 0.8 + `tower` 0.5 + `tower-http` 0.6 + `hyper` 1 | Extractors se `Principal`/`TenantScope`; tower se limits/timeouts/load-shed | actix-web (theek, par tower layers ka ecosystem kam) |
| DB | **TiDB Cloud** via `sqlx` 0.8 **`mysql` feature**, `query_file_as!` (compile-time checked against MySQL 8 dev DB / offline `.sqlx/`) | SQL files lintable (tenant predicate), keyset + `FOR UPDATE` visible, no ORM hidden state, prepared statements (TiDB supports) | SeaORM/Diesel (ORM hides tenant predicate; harder to lint) |
| Migrations | `sqlx migrate`, forward-only, expand/contract, **one DDL per file** (MySQL/TiDB DDL implicit commit) | — | — |
| JSON | `serde` + `serde_json` | — | `simd-json` (zarurat nahi) |
| Allocator | **jemalloc (`tikv-jemallocator`)** | §12.2 | mimalloc (benchmark mein compare), glibc (fragmentation) |
| Logs/traces/metrics | `tracing` + `tracing-subscriber` (JSON) + OpenTelemetry OTLP | Ek API; bounded batch exporter | — |
| Password hash | `argon2` 0.5 (Argon2id) + `bcrypt` (sirf data-migration ke legacy hashes verify) | OWASP; legacy users bina reset login kar sakein | scrypt |
| Crypto | **`aws-lc-rs`** (AES-256-GCM, HMAC-SHA256, HKDF, Ed25519, ECDSA P-256) | FIPS-capable, rustls default provider | RustCrypto (theek; RSA crate par timing advisory RUSTSEC-2023-0071) |
| TLS | `rustls` (aws-lc-rs provider) | — | openssl (C dep) |
| JWT | `jsonwebtoken` (ES256 only; alg allowlist) | Dashboard `jwt-decode` use karta hai; JWT standard hai | PASETO (D-04) |
| OpenAPI | `utoipa` 5 + `utoipa-axum` | Spec code se; apps/dashboard client generation | — |
| Config | `figment` + `secrecy` + `zeroize` | Typed, secrets redacted | — |
| Errors | `thiserror` 2 (libs), `anyhow` (bins/tests) | — | — |
| IDs/time | `uuid` 1 (v7), `time` 0.3 | App-side id (AAD binding), index-friendly | — |
| HTTP client | `reqwest` 0.12 (rustls), shared client, pool limits | Dodo, Microsoft Graph, email | — |
| Cache | `moka` (bounded, weighted) ya none | §12.7 | unbounded HashMap (kabhi nahi) |
| Shared limiter store | Redis-compatible (Render Key Value) ya local-only (D-14); TiDB table nahi (har request RU) | Multi-instance rate limits | — |
| Object storage | S3-compatible (Cloudflare R2 / S3) via `aws-sdk-s3` ya `object_store` crate (D-41) | Report blobs + PDFs DB ke bahar (§12.4) | DB bytea (DB bada + mehnga) |
| PDF | **Server request paths par PDF render nahi.** Dashboard/apps/verify page shared template (`PDF_TEMPLATES.md`, .NET layout parity) se client-side render karte hain server-signed render data se (§10, D-19). PAdES nahi. Optional `pdf-worker` sirf email attachments (D-58) | .NET server-side PDF ne 512 MB box crash kiya tha | Server-side Typst/Chrome on request (RAM spike) |
| Tests | `nextest`, `testcontainers` (MySQL 8 + `pingcap/tidb` standalone), `insta`, `proptest`, `wiremock`, `sqlparser` (sql-lint) | — | — |
| Supply chain | `cargo-deny`, `cargo-audit`, `cargo-cyclonedx` | SOC 2 CC7.1 | — |

---

## 3. Cargo workspace layout

```
dsecure-rs/
  Cargo.toml  rust-toolchain.toml  deny.toml  rustfmt.toml  clippy.toml  .cargo/config.toml
  crates/
    common/    # ids, time, Redacted<T>, AppError kinds, pagination cursor, config primitives
    crypto/    # KeyProvider, KeyRing, FieldEncryptor, BlindIndexer, PasswordHasher, Signer
    domain/    # pure rules: RBAC catalogue + rank rules, quotas, credit postings, report canonicalisation, NIST validation
    auth/      # Principal, token issue/verify, sessions, step-up, policy engine (3 checks)
    db/        # sqlx MySqlPool (TiDB), TenantTx, queries/**.sql, repositories, migrations/ (+ migrations_shadow/ MySQL FKs), write guards, retry, outbox, job lease
    audit/     # AuditEvent, AuditSink (same-tx), hash chain
    storage/   # BlobStore trait (S3-compatible impl + local fs dev impl), streaming encrypt/decrypt
    api/       # axum router (PolicyRouter), middleware, v1 handlers, OpenAPI  (bin: dsecure-api)
    workers/   # bounded job runner, outbox relay, Graph/Autopilot, email, retention (bin: dsecure-workers)
    pdf-worker/ # OPTIONAL (D-58): bounded server PDF for email attachments only, same PDF_TEMPLATES.md spec (bin: dsecure-pdf-worker, alag process)
    importer/  # one-time data migration from legacy TiDB (bin: dsecure-import; owner/main session chalata hai)
    testkit/   # fixtures, MySQL + TiDB containers, principal builders, authz matrix + cross-tenant harness
  xtask/       # dev-keys, sqlx prepare, route-policy report, sql-lint, schema-check, migrate-lint, no-raw-sql, explain-check, load-test helpers
  docs/
```

Optional future (core mein nahi): `compat-adapter` — agar kabhi kisi purani app version ko chalana pade to ek alag thin service jo purane routes ko v1 par map kare. **Aaj design ka hissa nahi** (D-07).

**Dependency direction** (neeche walon par depend; ulta nahi):
```
api, workers, importer ──► auth ──► domain ──► common
        │                   │
        ├──► audit ──► db ──┴──► crypto ──► common
        └──► storage ──► crypto
testkit ──► (sab, dev-dependency only)
```

| Crate | Zimmedari | Kya nahi karta |
|---|---|---|
| `common` | Newtype IDs, `Redacted<T>`, `AppErrorKind`, `Cursor`, clock | IO |
| `crypto` | KEK→DEK, AES-256-GCM + AAD, blind index, Argon2id (bounded), signing | SQL |
| `domain` | Permission enum, roles, `can_grant`, quota/credit/report rules | HTTP, SQL |
| `auth` | Tokens, `Principal`, live account-state check, step-up, policy evaluation | Route registration |
| `db` | `TenantTx`, scoped repositories (query files), `expect_one()`, `with_retry`, outbox insert, job lease, keyset queries, authz epoch poller | Business decisions |
| `audit` | Typed events, same-tx write, hash chain | Free-text PII |
| `storage` | Blob put/get streaming, per-tenant DEK encryption, content hash | Policy |
| `api` | Middleware order, routes + policies, handlers, OpenAPI | Direct SQL |
| `workers` | Jobs, schedules, exports, external calls (Graph, email) | HTTP serving (sirf health), PDF rendering |
| `importer` | Legacy read (read-only DB user), legacy CBC/BCrypt handling, new DB write, reconciliation report | Production mein khud se chalna |

Lints: `unsafe_code = "forbid"` (allocator crate ke alawa), clippy `unwrap_used`, `expect_used`, `panic`, `print_stdout`, `dbg_macro`, `disallowed_methods` (e.g. `axum::Router::route` outside PolicyRouter, any `sqlx::query*`/`raw_sql`/`Executor` use outside `db` crate) = deny; `-D warnings` CI mein.

**Process modes:** ek hi codebase se `dsecure-api` (HTTP) aur `dsecure-workers` (jobs). Budget bachane ke liye Phase 0-2 mein `dsecure-api --mode=all` (HTTP + bounded in-process worker pool, PDF kabhi nahi) chal sakta hai; Graph/email load badhne par worker alag Render background service (D-02). Optional `dsecure-pdf-worker` hamesha **alag process/service** (kabhi API process mein nahi).

---

## 4. API design (`/api/v1`)

### 4.1 Conventions
| Cheez | Rule |
|---|---|
| Base | `/api/v1/...`; platform staff `/api/v1/platform/...`; public `/api/v1/public/...`; device `/api/v1/device/...` |
| Naming | Plural resources, kebab-case paths, **snake_case JSON** (apps pehle se snake_case use karti hain) |
| IDs | UUIDv7 strings; reports ka public id (`DS-ERASE-000123` style) alag field `public_id`, verify/QR ke liye |
| Time | RFC 3339 UTC (`2026-10-20T10:11:12.123Z`) |
| Methods | GET read, POST create/action, PATCH partial update (JSON merge), PUT replace (role/capabilities), DELETE = soft (archive/disable) jahan allowed |
| Status | 200/201 (+`Location`)/202 (async job)/204; 400 validation; 401; 403; 404 (cross-tenant bhi); 409 conflict/quota/idempotency mismatch; 412 ETag mismatch; 413; 415; 422 semantic; 429 + `Retry-After`; 503 + `Retry-After` |
| Errors | RFC 9457 `application/problem+json`: `type`, `title`, `status`, `code` (stable, e.g. `credits.insufficient`), `detail` (safe), `request_id`, `errors[{field,code,message}]` |
| Pagination | **Cursor/keyset only**: `?limit=` (default 50, max 200) + `?cursor=` (opaque, signed/encoded `(sort_key,id)`); response `{ "data": [...], "next_cursor": "..."\|null }`. Offset pagination nahi. Total counts sirf summary endpoints se (counters) |
| Filtering/sort | Allowlisted fields per resource, har allowed sort ke liye index (DATABASE.md §9) |
| Idempotency | `Idempotency-Key` header **required** on POST that creates or consumes (reservations, credit-checks, uploads, members, devices, orders, remote-wipe); 24h retention; same key + different body = 409 |
| Concurrency | Mutable resources par `ETag` (row `version`), PATCH/PUT/DELETE par `If-Match` required (dashboard double-submit/lost update band) |
| Large bodies | Report upload `PUT .../content` streaming (`application/json` ya `application/gzip`), size limit header; downloads streamed with `Content-Length`/range jahan possible |
| Versioning | Additive changes v1 mein; breaking = v2 (parallel). OpenAPI spec CI artifact |
| Rate limits | `RateLimit-*` headers (draft standard) + 429 |
| Security | HTTPS only, no response/request "encryption envelope" (TLS hi transport security; D-07) |

### 4.2 Resource catalogue (feature inventory se; detail phases `MIGRATION_PLAN.md`)
| Area | Resources |
|---|---|
| Auth | `POST /auth/login`, `/auth/refresh`, `/auth/logout`, `/auth/step-up`, `/auth/switch-tenant`, `/auth/password/forgot`, `/auth/password/reset`, `/auth/email/verify`, `/auth/mfa/totp` (enroll/verify/disable) |
| Self | `GET/PATCH /me`, `POST /me/password`, `GET /me/sessions`, `DELETE /me/sessions/{id}`, `GET /me/activity` (own login timeline), `GET/PUT /me/preferences/{key}` (e.g. Autopilot column view) |
| Tenant | `GET /tenant`, `PATCH /tenant/settings`, `GET /tenant/features`, `GET /tenant/quotas`, `GET /tenant/summary` (counters), `GET /tenant/audit-events`, `POST /tenant/ownership-transfer`, `POST /tenant/data-exports` |
| Members | `GET/POST /members`, `GET/PATCH /members/{id}`, `PUT /members/{id}/role`, `PUT /members/{id}/capabilities`, `POST /members/{id}/disable|enable`, `POST /members/{id}/password-reset`, `DELETE /members/{id}` (body `transfer_to`), `POST /members/{id}/resource-transfers` |
| Groups | `GET/POST /groups`, `GET/PATCH/DELETE /groups/{id}`, `PUT/DELETE /groups/{id}/members/{member_id}`, `PUT/DELETE /groups/{id}/admins/{member_id}`, `GET/POST/PATCH /departments` |
| Activity | `GET /activity/sessions?member_id=`, `GET /activity/logins`, `DELETE /activity/sessions/{id}` |
| Devices | `GET/POST /devices`, `GET/PATCH /devices/{id}`, `POST /devices/{id}/assignment`, `POST /devices/{id}/commands`, `POST /devices/{id}/remote-wipe`, `POST /devices/{id}/decommission` |
| Device auth | `POST /device-enrollments` (member token se), `POST /device/token` (device credential → short token) |
| Licences/credits | `GET /licenses`, `GET /licenses/{id}`, `POST /licenses/{id}/activations`, `DELETE /licenses/{id}/activations/{aid}`, `POST /licenses/{id}/transfer`, `POST /licenses/offline-requests` + `POST /licenses/offline-requests/{id}/response`, `GET /credits`, `GET /credits/transactions`, `PUT /members/{id}/credit-allocations/{product}`, `POST /licenses/{id}/sync` (server_revision, last seen), `POST /licenses/{id}/renewals`, `POST /licenses/{id}/revoke`, `GET /devices/{id}/license-status`, `POST /credits/offline-grants` (offline quota transfer, signed response), `POST /licenses/exports` (202) |
| Reports (`{product}` = `drive`, `diagnostic`, `file`, `cleaner`, `freeze`) | `POST /reports/{product}/reservations`, `POST /reports/{product}/credit-checks`, `PUT /reports/{product}/{public_id}/content`, `POST /reports/{product}/offline-uploads`, `GET /reports/{product}`, `GET /reports/{product}/{public_id}`, `GET /reports/{product}/{public_id}/certificate` (signed data for client-side PDF), `POST /reports/{product}/{public_id}/transfer`, `GET/PUT /report-branding/{product}`, `POST /report-exports` (CSV, async 202) |
| Public | `GET /public/certificates/{public_id}` (server-verified, masked), `GET /public/signing-keys`, `POST /public/contact-leads`, `GET /public/releases/{product}/latest`, `POST /public/releases/check` (app update check, both version schemes), `POST /public/downloads`, `POST /public/formsubmit-webhook?k=` (secret), `GET /public/time` |
| Autopilot | `/autopilot/devices`, `/autopilot/imports` (CSV/DVINF upload, async), `/autopilot/rechecks`, `/autopilot/schedules`, `/autopilot/connections` (Microsoft tenant), `/autopilot/devices/{id}/unlock-credentials`, `/autopilot/devices/{id}/certificate`, `/autopilot/devices?changed_after=` (polling feed, D-57), `/autopilot/check-status` (tool, quota + charge), `/autopilot/settings` (auto-check), `/autopilot/devices/{id}/custom-fields`, `/autopilot/quota`, `/autopilot/consolidation-certificates` (signed batch data) |
| Freeze | `/freeze/endpoints`, `/freeze/reports`, `/freeze/messages`, `/freeze/messages/{id}/read`, `/freeze/endpoints/{id}/unread-count` |
| System Cleaner | `/cleaner/balance`, `/cleaner/redemptions`, `/cleaner/runs` (erase = 1 credit), `/cleaner/reports` (standard + cvra subtype; revisions D-61), `/cleaner/transactions` |
| Commerce | `POST /checkout/sessions`, `GET /orders`, `GET /orders/{id}`, `GET /orders/{id}/invoice`, `POST /webhooks/dodo` (signed, public) |
| Private cloud | `/private-cloud/connection` (feature gated, D-13) |
| Platform | `/platform/tenants`, `/platform/tenants/{id}/features|quotas|suspension`, `/platform/staff-access-grants`, `/platform/licenses` (issue), `/platform/credit-adjustments`, `/platform/checkout-links`, `/platform/leads`, `/platform/releases`, `/platform/audit-events`, `/platform/staff` |
| Health | `GET /health/live`, `GET /health/ready` (no auth, no details beyond status) |

Jo .NET mein tha par v1 mein nahi: debug/test endpoints, anonymous licence minting, global role-permission editing, `fix-report-uuids` jaise maintenance endpoints, Swagger "try it out" prod mein, response-encryption bypass flags (`MIGRATION_PLAN.md` §8).

---

## 5. Request lifecycle (middleware order, outer → inner)

| # | Layer | Kaam | Fail |
|---|---|---|---|
| 1 | Catch panic | → 500 problem + metric | 500 |
| 2 | Request ID | `X-Request-Id` validate (UUID/≤64 chars) ya naya | — |
| 3 | Client IP | Sirf `TRUSTED_PROXY_HOPS`/`TRUSTED_PROXY_CIDRS` se `X-Forwarded-For` | — |
| 4 | Trace span | route template (values nahi), request id, status, latency; tenant id baad mein record | — |
| 5 | **Global concurrency limit + load shed** | `MAX_INFLIGHT_REQUESTS` (default 128); full → 503 `Retry-After: 1` (queue nahi) | 503 |
| 6 | Timeout | Route class: default 15s, upload 120s, export 30s | 503/504 |
| 7 | Body limit | Default 64 KB JSON; upload class `MAX_REPORT_UPLOAD_BYTES` (streamed); CSV import `MAX_IMPORT_BYTES` | 413 |
| 8 | CORS | `CORS_ALLOWED_ORIGINS` allowlist | — |
| 9 | Security headers | HSTS, nosniff, frame deny, `Cache-Control: no-store` on authenticated responses | — |
| 10 | Pre-auth rate limit | IP + route class (login, forgot, public verify, contact, webhooks) | 429 |
| 11 | Authentication | Bearer → `Principal` (member/device/staff/cleaner/service) ya `Anonymous`; token `aud`/`typ`/`kid` match; session + account + tenant state **live** (bounded cache keyed by `authz_version`) | 401 |
| 12 | Authorization | Route policy: 3 checks + capabilities + step-up (`RBAC.md` §6) | 403/404 |
| 13 | Post-auth rate limit + class semaphores | Per principal/tenant; heavy classes (upload, export, remote-wipe, login hashing) ke alag semaphores | 429/503 |
| 14 | Idempotency | `Idempotency-Key` lookup/store (stored response ≤ 16 KB; bada hai to sirf status + resource id) | 409 |
| 15 | Handler | Domain service + `TenantTx`; audit event same tx | `AppError` |
| 16 | Error mapping | `AppError` → problem+json | — |

---

## 6. AuthN / AuthZ (short; detail `SECURITY.md` §4-5, `RBAC.md`)

| Principal | Token | Audience | TTL |
|---|---|---|---|
| `TenantMember` (dashboard/app user) | ES256 access + opaque rotating refresh | `dsecure-web`, `dsecure-app` | access 15 min; refresh 30 din sliding (web), 90 din (app; D-40) |
| `Device` (enrolled app installation) | ES256 access from device credential | `dsecure-device` | 15 min |
| `PlatformStaff` | ES256, alag key, MFA mandatory | `dsecure-platform` | 15 min, session 8h max |
| `CleanerAccount` (agar D-11 merge na ho) | ES256 alag key | `dsecure-cleaner` | 15 min |
| `Service` (internal) | Workers → API nahi bulate; zarurat ho to mTLS | `dsecure-internal` | — |

Access claims: `iss`, `aud`, `sub` (user id), `tid`, `mid`, `sid`, `typ`, `av` (authz version), `amr`, `auth_time`, `exp`, `iat`, `jti`. Display ke liye `role` aur `email` claims optional (dashboard decode karta hai; authority hamesha server ka live state).

Tenant scoping: `Principal` → `TenantScope { tenant, membership, visibility, staff_grant }` → `TenantTx` (tenant id bound into every query file; L1-L8 `DATABASE.md` §2.2); cross-tenant = 404.

---

## 7. Error model

```rust
pub struct AppError {
    pub kind: AppErrorKind,   // BadRequest, Unauthenticated, Forbidden, NotFound, Conflict, PreconditionFailed,
                              // FeatureDisabled, StepUpRequired, QuotaExceeded, RateLimited{retry_after},
                              // PayloadTooLarge, Unavailable{retry_after}, NotPersisted, Internal
    pub code: &'static str,   // "credits.insufficient", "members.last_owner", "feature.disabled"
    pub detail: Cow<'static, str>,     // safe text, no PII
    pub fields: Vec<FieldError>,
    pub source: Option<anyhow::Error>, // sirf log
}
```
- `NotPersisted` (expected 1 row, got 0) → 500 + alert: kabhi silent success nahi.
- Cross-tenant / out-of-visibility object → 404.
- Error codes ka catalogue OpenAPI mein; clients `code` par branch karein, `detail` par nahi.

---

## 8. Config and secrets
- Env vars (Render secret env) ya KMS; repo mein kuch nahi; `.dev/` gitignored; gitleaks CI mein.
- Typed config; secrets `SecretBox`; `Debug` redacted.
- **Startup fail-closed (production):** KEK provider reachable; active DEKs unwrap; JWT signing keys present; `DATABASE_URL` TLS verify-full; trusted proxy config; object storage creds; dev keys refuse (`DSECURE_ENV=production`); OpenAPI UI off; key values kabhi log nahi (kid + fingerprint prefix only).
- Migrations app startup par **nahi** chalti: alag release step `dsecure-api migrate` (Render pre-deploy command; availability not verified) taaki startup fast + low memory rahe aur DB change pehle ho.
- Full list: `PHASE0_SPEC.md` §5.

---

## 9. Background jobs
- TiDB `jobs` table + **lease claim** (candidate snapshot read → conditional `UPDATE ... WHERE id=? AND status='queued'`, rows_affected=1 = owned; lease heartbeat; reaper) — `SKIP LOCKED` par depend nahi (`DATABASE.md` §8.4); retries with backoff; dead-letter; idempotent handlers (unique job key).
- **Bounded:** `WORKER_CONCURRENCY` (default 2), per-kind semaphores (Graph 1, email 2, export 1); poll interval with jitter; queue depth metric + alert; producers check `max_pending` per kind (e.g. export 200) → 503 to caller instead of unbounded growth.
- Outbox (same tx) → relay (emails, counters fan-out, optional PDF-for-email jobs jo sirf `dsecure-pdf-worker` uthata hai).
- Scheduled (each a `jobs` row with `run_after`, no global table scans): retention purges (owner-approved, D-56), audit chain sealing, credit lot expiry, ledger/orphan invariant checks, Autopilot device checks (one job per device), schedule ticks, UEM recheck, key rotation re-encrypt, reconciliation during migration.

---

## 10. Reports, certificates and PDF (hybrid: server signs, client renders .NET-identical layout)

Owner inputs (20 Oct 2026): .NET server-side PDF ne 512 MB box crash kiya; **PAdES/Adobe signature nahi chahiye**; PDF **waisa hi dikhe jaisa aaj ki .NET report** (D-19 CLOSED). Isliye:

**10.1 Server (Rust): data + signature, PDF nahi**
1. Upload: stream → size cap (`MAX_REPORT_JSON_BYTES`, default 2 MB; real sizes not verified) → JSON parse → schema validate (product + NIST fields) → **render model**: .NET mappers ka Rust port (`domain::report_render::{drive, diagnostic, file, cleaner, autopilot, freeze}`, rules `PDF_TEMPLATES.md` §4-§9) → `render_data` (exact strings the template prints, defaults applied) → `certificate_payload` (NIST summary + `render_sha256` + `raw_sha256` + `branding_version_id` + personnel text snapshot) → **RFC 8785 JCS** → `content_sha256` → **Ed25519** over `"dsecure-cert-v1\n" || content_sha256`.
2. Raw report JSON aur `render_data` → gzip → AES-256-GCM (tenant DEK) → **object storage** (DB mein sirf metadata, hashes, signature, blob keys; `DATABASE.md` §6).
3. Endpoints: `GET /api/v1/reports/{product}/{public_id}/certificate` → `{ template_id, render_data, certificate_payload, content_sha256, signature, signing_key_id, alg, verify_url, fingerprint, branding: {version_id, text slots, image URLs (signed, 15 min)} }` (authz `reports.<p>.read` + cap); `GET /api/v1/public/certificates/{public_id}` (server verifies, masked public view, `valid|invalid|revoked|not_found`; legacy ids via `report_public_ids` aliases); `GET /api/v1/public/signing-keys`.
4. Server kabhi request path par PDF render nahi karta; v1 mein `GET .../pdf` nahi. Batch export = signed data batch (≤ 100); zip client banata hai.

**10.2 Ed25519** — v2 jaisa hi (deterministic, fast, small; KEK-wrapped key; 12-month rotation; public keys forever; KMS Ed25519 support not verified → D-42).

**10.3 Certificate data model** — `certificate_payload` = `{ schema: "dsecure.cert/1", public_id, product, template_id, tenant_display_name, issued_at, operator, validator?, personnel_text (names/dept/company as printed), device, media, sanitization{method, technique, standard_reference, passes?, tool_name, tool_version, started_at, completed_at, result}, verification{method, result, verified_at}, app_signature{value, status}, raw_sha256, render_sha256, branding_version_id }`. Printed fields covered hain kyunki `render_sha256` signed payload ke andar hai. NIST Rev 2 exact field list not verified.

**10.4 Client-side PDF = .NET layout parity**
- Spec: **`PDF_TEMPLATES.md`** (per product: page, header, sections in .NET order with exact labels, field → `render_data` mapping, defaults, colours, annexure tables, branding slots, footer). Footer = .NET footer + **verification code (fingerprint + kid) + QR `https://<verify-host>/v/{public_id}#{fingerprint}`** (D-60); legacy QR hosts redirect.
- Renderers: dashboard (browser PDF lib), desktop apps (native), verify page. **Golden fixtures** (`fixtures/pdf/<template_id>/*.json` + expected text extraction + reference PNGs rendered from the .NET QuestPDF output) taaki teeno .NET jaisa dikhein.
- Branding: issue-time snapshot (`branding_version_id`, D-62); images signed URLs se; fonts Liberation Sans/Mono (OFL) bundled.
- Tamper detection: PDF khud "truth" nahi; QR/ID → server verify → server ka data + fingerprint.

**10.5 Optional server PDF worker (D-58, OPEN)** — sirf email attachments (aaj DSSC upload PDF email karta hai). Recommended: email mein signed expiring link. Agar worker bane: alag service, concurrency 1, container memory cap, wahi template spec, golden-fixture parity tests; API process mein kabhi nahi.

**10.6 Other files** — CSV exports: worker keyset batches → gzip → blob → API 202 + signed link (15 min). Autopilot CSV/DVINF imports: blob + worker parse (bounded rows per job).

## 11. Testing strategy

| Level | Kya | Gate |
|---|---|---|
| Unit | domain rules, crypto (round-trip, tamper, AAD swap, nonce uniqueness), tokens (alg/aud/kid confusion), cursor encode/decode | CI |
| Integration | **MySQL 8 + TiDB standalone containers** (both, every PR): migrations, repositories, cross-tenant negative tests, write guards, last-owner/quota races (no gap locks), retry on conflict, idempotency, job lease, keyset pagination | CI |
| Data-layer gates | `xtask sql-lint`, `schema-check`, `migrate-lint`, `no-raw-sql` | CI (blocking) |
| Real TiDB | Nightly + RC on TiDB Cloud Serverless non-prod scratch DB (D-54): migrations, integration subset, RU report per query digest | Nightly / release gate |
| Authz matrix | Har route × principal fixtures → expected (`RBAC.md` §8), cross-tenant substitution har by-id route | CI, 100% routes |
| API contract | OpenAPI spec snapshot (`insta`); breaking diff = CI fail (v1 frozen after first client) | CI |
| Feature parity | `docs/contracts/*.md` checklists: har feature ka ek acceptance test (behaviour, not .NET shape); "BUGS — do NOT port" items ke negative tests | Phase exit |
| Query plans | Har query file ka `EXPLAIN FORMAT='brief'` on TiDB seeded data: `TableFullScan`/`IndexFullScan` on > 1k-row tables = fail | CI (TiDB container) + nightly |
| Load + memory | §12.9 | Phase exit |
| Security | `cargo deny/audit`, gitleaks, ZAP baseline staging, yearly pentest | CI + manual |

---

## 12. Performance & resource budget (512 MB Render instance)

Assumption: Render instance **512 MB RAM**, CPU share chhota (exact vCPU not verified). Target: **idle RSS 30-80 MB, hard ceiling 350 MB under load** (150 MB headroom for spikes/fragmentation), kabhi OOM nahi.

### 12.1 Memory budget (`--mode=api`)
| Component | Budget | Kaise bound |
|---|---|---|
| Binary + runtime + TLS + config | 15-25 MB | Static binary, 2 tokio workers, `max_blocking_threads = 4` |
| DB pool | ~5-10 MB | `DB_MAX_CONNECTIONS=8`, statement cache 100 per connection |
| In-flight requests (JSON) | ≤ 128 × ~64 KB ≈ 8 MB (+ parse overhead ~3x ≈ 25 MB) | Global inflight 128, JSON body 64 KB |
| Report uploads | ≤ 4 concurrent × 2 MB JSON × ~4x parse/canonical/gzip ≈ 32 MB | `UPLOAD_CONCURRENCY=4` semaphore; beyond = 503 Retry-After |
| S3 blob uploads (storage crate) | ≤ 2 concurrent multipart uploads × ~15 MB part buffers ≈ 30 MB (single PUT below 5 MiB) | `S3Limits.max_concurrent_uploads=2` semaphore in `storage`; bucket lifecycle rule `AbortIncompleteMultipartUpload` required |
| Argon2id logins | 3 × 19 MiB ≈ 57 MB | `LOGIN_HASH_CONCURRENCY=3` semaphore (blocking pool); queue wait max 2s else 503 |
| Streaming downloads | 8 × 64 KB chunk buffers | No full-file buffering |
| Caches | ≤ 8 MB | `moka` weighted caps (§12.7) |
| Telemetry buffers | ≤ 5 MB | OTLP batch exporter bounded queue (drop on full, metric) |
| Allocator fragmentation headroom | ~50 MB | jemalloc decay |
| **Worst-case total** | **~230-260 MB** | < 350 MB ceiling |

**PDF ka RAM cost API budget mein zero hai**: request path par PDF render nahi hota (§10). Ed25519 signing per report µs-level; JCS canonicalisation report size ke linear (2 MB cap, upload semaphore ke andar). Optional `dsecure-pdf-worker` alag container mein apne cap ke saath; woh OOM ho to bhi API safe.

### 12.2 Allocator: jemalloc
- glibc malloc multi-threaded async workloads mein per-thread arenas se RSS badhata hai aur wapas OS ko kam deta hai; long-running service mein "slow leak" jaisa dikhta hai.
- **jemalloc** (`tikv-jemallocator`): `background_thread:true`, `dirty_decay_ms:1000`, `muzzy_decay_ms:1000`, `narenas:2` (config via `_RJEM_MALLOC_CONF`/build-time) → freed memory jaldi OS ko; `tikv-jemalloc-ctl` se `allocated`/`resident` metrics export (alert at 300 MB).
- mimalloc bhi achha option hai; Phase 0 load test mein dono compare karke final (P0-17). glibc default nahi.

### 12.3 Concurrency, limits, backpressure
- Global `ConcurrencyLimitLayer`/load-shed: limit par turant 503 + `Retry-After` (unbounded queue nahi).
- Per-class semaphores: login hashing 3, uploads 4, exports 2, remote-wipe 1/tenant, certificate fetch 16.
- Timeouts har layer par (request, DB statement `statement_timeout=5s` default, external HTTP 10s connect/30s total).
- Body limits per route class; multipart/CSV uploads streamed to object storage, parsing worker mein.
- Rate limits per IP/principal/tenant (shared store; store down → local `governor` with stricter limits, login fail-closed).
- Client retries: idempotency keys ke saath safe.

### 12.4 Streaming + blob storage
- Report JSON, CSV imports/exports (aur optional worker ke PDFs) **object storage** mein (encrypted, compressed); hot DB rows mein sirf metadata (~0.5-1 KB/row).
- Uploads: request body → bounded buffer (JSON parse ke liye max 2 MB) → gzip+encrypt streaming → multipart upload. Raw binary attachments (agar aaye) parse nahi, seedha stream.
- Downloads: blob → decrypt chunked (GCM per 64 KB chunk, STREAM construction, chunk index in AAD) → response stream.
- CSV exports: worker keyset batches (1000 rows) → gzip stream → blob; API 202 + poll/download link.

### 12.5 Database pool + queries
- Pool (`MySqlPool` → TiDB Serverless, TLS): api 8, workers 4 (`DB_MAX_CONNECTIONS`), `acquire_timeout=2s` (fail fast → 503), idle timeout 5 min, `max_lifetime` 30 min (Serverless idle/proxy disconnects; exact limits not verified). Connection init: `time_zone='+00:00'`, `max_execution_time=5000`, `innodb_lock_wait_timeout=5`, `tidb_txn_mode='pessimistic'` (TiDB only).
- **Har list keyset/cursor paginated**, max 200 rows; koi unbounded query nahi (CI lint: repository functions jo `Vec<T>` lautate hain unhe `Page` param chahiye).
- **No N+1:** list endpoints ek query (JOIN ya `IN (?, ...)` batch ≤ 200); per-row lookups ban (review checklist + query-count test: har list endpoint ≤ 3 queries).
- Prepared statements (sqlx default) + per-query composite indexes (`DATABASE.md` §9: har query ka index naam ke saath).
- `LOWER()`/function on column kabhi nahi: emails ke liye blind index (normalised HMAC), names ke liye normalised columns jahan search zaroori.
- Counts: `tenant_counters` / `report_counters` summary tables same tx mein maintain; dashboard `COUNT(*)` scans nahi. Nightly reconciliation counters vs truth (sampled).
- Timeouts: session vars upar + app `tokio::time::timeout` per tx (default 5 s); retry wrapper for TiDB conflict/deadlock codes (`DATABASE.md` §1.2). RU: lists keyset over clustered `(tenant_id, id)`, counters instead of COUNT, blobs in object storage (`DATABASE.md` §10.1 estimates).

### 12.6 Background jobs
- `WORKER_CONCURRENCY=2`, per-kind semaphores, `max_pending` per kind, poll with backoff (idle par 5-30s), batch sizes 100-1000.

### 12.7 Caching
- Sirf bounded `moka` caches:
  - authz state keyed by session → 10k entries (~3 MB); valid only while `tenant epoch` unchanged; `authz_epochs` poller (2 s, one indexed query per instance) invalidates (TiDB mein LISTEN/NOTIFY nahi); same-instance writes invalidate immediately; high-risk actions bypass cache; TTL 60 s safety.
  - JWKS/public keys, feature catalogue: tiny.
  - DEK cache: KeyRing in memory (zeroized), max `MAX_TENANT_DEKS_CACHED=5000` LRU (per-tenant DEKs unwrap on demand).
- Response caching nahi (tenant data); `ETag` + 304 for GET details.

### 12.8 Crypto cost
- Argon2id **m = 19 MiB, t = 2, p = 1** (OWASP minimum recommendation) + semaphore 3 → max ~57 MB; target 150-300 ms/hash on Render CPU (benchmark P0-17; agar slow ho to t=2 rakho, m kam nahi karna). Parameters PHC string mein, upgrade on login.
- AES-GCM per field µs-level; blind index HMAC cheap.
- Startup: KMS unwrap sirf platform DEKs (≤10); tenant DEKs lazy.

### 12.9 Startup
- Target: process start → `/health/live` < 300 ms; `/health/ready` (DB + keys) < 2 s.
- No migrations at startup, no cache warmup, lazy tenant DEKs, fonts/templates sirf worker mein.

### 12.10 Load test plan
| Item | Value (proposal; aaj ka real traffic not verified) |
|---|---|
| Environment | Docker `--memory=512m --memory-swap=512m --cpus=0.5` (Render plan ke closest), TiDB standalone container (functional) **plus** one run against TiDB Serverless non-prod (real latency + RU), seeded: 200 tenants, 5k members, 50k devices, 500k reports metadata |
| Tool | k6 (scenarios) ya `oha` |
| Mix (steady) | 50 RPS: 40% list/detail reads, 15% `GET /tenant/summary`, 10% credit-checks, 10% reservations, 10% report uploads (200 KB-2 MB), 5% login, 5% certificate fetch + public verify, 5% writes (members/devices) |
| Targets | p95: reads < 150 ms, writes < 250 ms, credit-check < 200 ms, upload 1 MB < 1.5 s, login < 600 ms; error rate < 0.1% |
| Spike | 5x (250 RPS) for 2 min: 503/429 allowed, **no OOM, no restart**, recovery < 30 s |
| Soak | 2 hours steady: RSS growth < 10% after warmup, no pool exhaustion |
| Login storm | 50 parallel logins: RSS < 350 MB, extra requests 503 with Retry-After |
| Pass criteria | All above + DB: no full scans on tables > 10k rows (`statements_summary`), avg rows scanned per request < 100, RU per route class within `DATABASE.md` §10.1 estimates ±50% |

---

## 13. Risks
| ID | Risk | Mitigation |
|---|---|---|
| A1 | 512 MB mein uploads + logins + spikes ek saath | Semaphores, load-shed, server PDF nahi, load test gate |
| A2 | Clients (apps/dashboard) ko naya API integrate karna: effort + timeline apps team par | OpenAPI + generated clients, staging, product-by-product switch (`MIGRATION_PLAN.md`) |
| A3 | Do systems ek saath production mein (switch period) | Single-writer rules + down-sync projection (`MIGRATION_PLAN.md` §4) |
| A4 | Client-side PDFs dashboard vs apps alag dikhein | Shared template spec + golden fixtures + verify page as reference |
| A5 | Team ka Rust experience | Phase 0 patterns lock; review checklist |
| A6 | Object storage naya vendor/cost | D-41; dev mein local fs impl |
| A7 | TiDB par RLS nahi: ek missed `tenant_id` predicate = cross-tenant leak | L1-L8 layers, sql-lint + schema-check release-blocking, generated negative tests, be-reviewer checklist |
| A8 | RU bill spike (bad query / retry storm) | Plan tests, RU metric per route, spending limit, bounded retries with jitter, counters |
| A9 | TiDB vs MySQL test drift (gap locks, CHECK, FK) | Tests on both engines + nightly real Serverless |
| A10 | Client PDF .NET jaisa na dikhe | `PDF_TEMPLATES.md` + golden fixtures from .NET output + visual diff in client CI |

## 14. Not verified
- Crate versions; WebCrypto Ed25519 browser coverage; KMS Ed25519 support; Render plan CPU share, private networking, pre-deploy command, Key Value availability.
- TiDB Serverless: engine version, connection limits/idle timeouts, RU formula and prices, `statements_summary` availability, SKIP LOCKED / CHECK / FK behaviour, region next to Render.
- Real report JSON sizes, traffic (RPS), row counts → budgets aur load mix proposals hain.
- `docs/contracts/*.md` ab maujood hain (10 files) aur `DATABASE.md` §13 / `RBAC.md` §4.12 mein reconcile kiye; unke andar ke "not verified" items (app callers, encryption mode) abhi bhi open.
