# DSecure Rust backend: Owner decisions (draft v3, 20 Oct 2026)

Owner: Mr. W. Author: architect. Har decision mein options aur **bold recommended option**. Jab tak owner ka jawab nahi, design recommended option maan ke chalta hai, par production/irreversible step se pehle owner ka exact word chahiye.

Status legend: **OPEN** (owner chahiye), **CLOSED** (owner ne direction de di ya design mein band), **N/A** (zarurat nahi).

**v3 (20 Oct 2026) mein kya badla:** D-01 CLOSED = TiDB; D-50 CLOSED = 512 MB; D-19 CLOSED = hybrid, no PAdES, .NET layout parity; naye TiDB decisions D-51..D-57; PDF sub-decisions D-58..D-62; D-14 options TiDB ke hisaab se.

## A. Platform / infra

| # | Decision | Options | Recommended | Status |
|---|---|---|---|---|
| D-01 | Database engine | (a) PostgreSQL managed; (b) TiDB Cloud (MySQL-compatible) | **(b) TiDB.** Owner (20 Oct 2026): *"Tidb"*. Design: tenant isolation data layer mein (`DATABASE.md` §1-§2, `RBAC.md` §6.7), no RLS/triggers/NOTIFY/RETURNING; RU-aware queries (`DATABASE.md` §9-§10) | **CLOSED** |
| D-02 | Hosting + process layout | (a) Render: `dsecure-api` (512 MB) + later separate `dsecure-workers`; (b) AWS/Azure India region | **(a) Render**, TiDB cluster ke same/nearest region mein (region not verified); Phase 0-2 `--mode=all` | OPEN |
| D-03 | KMS | (a) env KEK only; (b) Azure Key Vault; (c) AWS KMS | **(b) Azure Key Vault**; env KEK only dev/staging; production go-live requires KMS | OPEN |
| D-04 | Token format | (a) JWT; (b) PASETO | **(a) JWT ES256**, alg allowlist | CLOSED |
| D-05 | Strangler reverse proxy | — | Not needed (no wire compat) | N/A |
| D-14 | Shared rate-limit/session-cache store | (a) Redis-compatible (Render Key Value); (b) TiDB table (har request par RU kharch: **not recommended**); (c) in-memory only | **(a)** with local fallback (stricter); single instance par (c) bhi chalega | OPEN |
| D-18 | Observability + log residency | (a) Grafana Cloud OTLP + India-region object storage archive; (b) self-host; (c) Render logs only | **(a)** | OPEN |
| D-41 | Object storage for report blobs/exports/branding images | (a) Cloudflare R2; (b) S3 (Mumbai); (c) DB table | **(a) or (b)**. (c) TiDB par mehnga (write RU ≈ bytes; `DATABASE.md` §10) — sirf emergency fallback | OPEN |
| D-50 | Render plan for API | (a) 512 MB; (b) larger | **(a) 512 MB.** Owner (20 Oct 2026): *"512 MB"*. vCPU share abhi bhi not verified | **CLOSED** |
| D-51 | **Naya TiDB cluster/database for Rust** (legacy `Cloud_Erase__App` kabhi nahi) | (a) Do naye TiDB Cloud Serverless clusters: `dsecure-rs-nonprod` (dev CI + staging alag databases) aur `dsecure-rs-prod`; (b) ek naya cluster, alag databases (staging/prod); (c) legacy cluster mein naya database | **(a)**: prod ka blast radius aur RU spending limit alag; staging data kabhi prod cluster par nahi. (c) reject: legacy RU/throttling aur galti se legacy tables chhoone ka risk. **Cluster banana = owner approval** (billing + production resource); main session SQL/steps likhega, owner create karega. Region: Render region ke paas (not verified) | CLOSED (20 Oct, owner: "Main bana dunga"): owner TiDB console mein non-prod cluster banayega; connection string sirf local `.dev/dev.env` / CI secret. Prod cluster baad mein |
| D-52 | **ID strategy** | (a) App-generated UUIDv7 `BINARY(16)`; tenant tables clustered PK `(tenant_id, id)`; append-heavy global tables NONCLUSTERED PK + `SHARD_ROW_ID_BITS`; report numbers block allocator; (b) `BIGINT AUTO_RANDOM` PKs; (c) `AUTO_INCREMENT` | **(a)**. RETURNING ke bina id pehle se pata (AAD binding, outbox, audit); UUIDv7 time-ordered = keyset `ORDER BY id`; tenant-leading clustered key writes ko tenants mein phailata hai; AUTO_RANDOM TiDB-only hai (MySQL 8 test DB par nahi chalta) aur keyset order tod deta hai. Detail `DATABASE.md` §2.3 | CLOSED (20 Oct, owner: "Haan, recommendation lock karo"): option (a) |
| D-53 | **Local dev / CI test database** | (a) MySQL 8.0 container (fast, FK/CHECK shadow mode) **aur** TiDB standalone container (`pingcap/tidb`, unistore) dono par integration tests; (b) sirf `tiup playground`; (c) sirf MySQL | **(a)**. Local PostgreSQL 17 ab irrelevant. `tiup playground` optional (heavier). Gaps list `DATABASE.md` §1.4 | CLOSED (20 Oct, owner: "MySQL 8 install karo"): local = portable MySQL 8.4 LTS (no Docker; port 3307, localhost only) + owner ka TiDB non-prod cluster for TiDB-specific tests; TiDB container sirf CI mein (optional) |
| D-54 | **CI against real TiDB Serverless** | (a) Nightly + har release-candidate par `dsecure-rs-nonprod` cluster ke `ci_<run>` database par migrations + integration + RU report; (b) none | **(a)**; CI secret sirf CI env mein; database har run ke baad drop (sirf non-prod cluster ka scratch database; prod/staging par kabhi nahi) — is scratch drop ke liye bhi owner ka ek baar approval | OPEN (depends D-51) |
| D-55 | **Foreign keys** | (a) TiDB par DB FKs nahi; app-enforced references (tenant-filtered parent check same tx) + MySQL CI mein FK "shadow" migration + nightly orphan check; (b) TiDB FKs rely karo | **(a)**: TiDB FK support version-dependent (Serverless version not verified), har write par extra reads (RU), import/online DDL complicate. Detail `DATABASE.md` §2.4 | CLOSED (20 Oct, owner: "Haan, recommendation lock karo"): option (a) |
| D-56 | **Retention mechanism on TiDB** | (a) No partitions v1; owner-approved batch purge jobs (separate `dsecure_retention` DB user); (b) TiDB `TTL` tables; (c) range partitions + DROP PARTITION | **(a)**: portable (MySQL+TiDB), har purge explicit + approved. (b) automatic delete = owner rule ke khilaf (approval ke bina deletion); MySQL mein nahi. (c) later agar audit volume bade | OPEN |
| D-57 | **Realtime updates (Autopilot device status; .NET SignalR)** | (a) Polling changes feed `GET /autopilot/devices?changed_after=<cursor>` (indexed, cheap); (b) SSE stream (bounded connections) + poll fallback; (c) WebSocket | **(a) v1**, (b) baad mein agar dashboard ko chahiye. NOTIFY nahi hai, SSE multi-instance fan-out ke liye bhi poll chahiye | OPEN |
| D-21 | Team + timeline | Rust engineers count, app/frontend team availability | Confirm; estimate 48-66 engineer-weeks backend (`MIGRATION_PLAN.md` §2) | OPEN |

## B. API / clients / cutover

| # | Decision | Options | Recommended | Status |
|---|---|---|---|---|
| D-06 | First product after core | Drive Eraser / File Eraser / Diagnostic | **Drive Eraser** | OPEN (confirm) |
| D-07 | Legacy response-encryption envelope / old routes | (a) Not in core; (b) build compat into core | **(a)**. TLS only | CLOSED |
| D-45 | Rollback path for new app versions | (a) Apps dual-stack one release, server-driven `api_mode`; (b) fix-forward only | **(a)** | OPEN (app team) |
| D-49 | Production cutover style | (a) Product-by-product with core first + down-sync; (b) tenant cohorts | **(a)** | OPEN |
| D-15 | Rust prod access to legacy TiDB during transition | (a) Restricted DB user (SELECT; INSERT/UPDATE on listed tables; **no DELETE**); (b) none | **(a)**; owner creates user (production change), main session writes SQL | OPEN |
| D-46 | Password reset style | (a) Signed link; (b) OTP code; (c) both | **(c)**: link web ke liye, OTP apps ke liye (dashboard aaj OTP flow use karta hai) | OPEN |
| D-47 | Existing offline-activation app versions (Fernet shared key) | (a) Keep supported only on .NET until sunset; (b) port Fernet flow | **(a)**; Rust offline flow = per-request Ed25519-signed responses | OPEN (app team) |
| D-48 | File Eraser report id | (a) `DS-FILE-000123` public id + legacy numeric / 8-hex obfuscated / uuid as aliases; (b) numeric only | **(a)**; aliases `report_public_ids` mein hamesha resolve (purane QR/PDF) | OPEN |
| D-24 | Offline uploads (Drive/Diag) | (a) device-signed uploads accepted + credit consumed (pool, offline grant, or grace); unsigned → `unverified` quarantine; (b) accept all, no credit | **(a)** | OPEN |

## C. Data model / migration

| # | Decision | Options | Recommended | Status |
|---|---|---|---|---|
| D-08 | Legacy Users → tenants | (a) one tenant per legacy top-level Users row; merges only from owner list; (b) auto-merge | **(a)** | OPEN (merge list) |
| D-09 | Platform staff accounts | Explicit list from owner | **Explicit list**; MFA mandatory | OPEN |
| D-10 | Plaintext-only legacy passwords | (a) Argon2id at import; (b) force reset | **(a)** | OPEN |
| D-11 | System Cleaner (DSSC) identities | (a) Merge into main identity; (b) separate realm | **(a)** | OPEN |
| D-12 | Autopilot master-tenant fallback | (a) Disable for customers; (b) keep | **(a)** | OPEN (business impact) |
| D-13 | Private cloud (customer DB) | (a) Not in first Rust release; (b) port as-is | **(a)** | OPEN |
| D-16 | Device identifiers (serial, MAC) | (a) Encrypted + tenant blind index; (b) plain | **(a)** | OPEN |
| D-17 | Retention periods | As listed in v2 | **As listed**, lawyer confirm; every purge job owner-approved once per data class (mechanism D-56) | OPEN |
| D-20 | Email open-tracking pixel | (a) Drop; (b) keep opt-in | **(a)** | OPEN |
| D-42 | Certificate signing algorithm/custody | (a) Ed25519, KEK-wrapped; (b) ECDSA P-256 in KMS | **(a)** | OPEN |

## D. RBAC

| # | Decision | Options | Recommended | Status |
|---|---|---|---|---|
| R-1 | Customer role | Owner vs SuperAdmin | **Owner (tenant-scoped)** | CLOSED |
| R-2 | Tenant isolation | Redesign vs endpoint ownership | **Full redesign**: `tenant_id` har tenant table par, tenant-leading keys, data-layer enforcement (TenantTx + SQL lint + schema check + negative tests), no-DELETE DB grants (v3: RLS ki jagah, D-01) | CLOSED |
| R-3 | Two role models | Merge? | **One model** | CLOSED |
| R-4 | Status/lockout | Enforce? | **Enforced** | CLOSED |
| R-5 | Capability flags | Enforce or drop | **Enforce** as narrowing masks | CLOSED |
| D-23 | MFA for tenant owners | (a) Optional + nudges; (b) mandatory | **(a)** now | OPEN |
| D-30 | Custom per-tenant roles | (a) Not in v1; (b) v1 | **(a)** | OPEN |
| D-31 | Group admin remote wipe | (a) Explicit per-GA owner grant; (b) never | **(a)** | OPEN |
| D-32 | `can_view_reports=false` / `can_manage_machines=false` meaning | (a) own only; (b) none | **(a)** | OPEN |
| D-33 | Credit model per member | (a) Tenant pool + optional caps; (b) mandatory quotas | **(a)** | OPEN |
| D-34 | Members when `subusers` toggle OFF | (a) Non-owner logins blocked; (b) keep | **(a)** | OPEN |
| D-35 | Member delete without transfer target | — | `transfer_to` required | CLOSED |
| D-36 | Remote wipe from legacy clients without step-up | — | Only v1 step-up flow | CLOSED |
| D-37 | Legacy Manager/Support mapping | (a) member + list; (b) admin | **(a)** | OPEN |
| D-38 | Email verification for imported users | (a) Mark verified; (b) force verify | **(a)** | OPEN |
| D-39 | `user_activity` toggle for migrated tenants | (a) ON if ≥1 subuser; (b) OFF | **(a)** | OPEN |
| D-40 | App sessions | Refresh 90 days apps, 30 days web | **As stated** | OPEN |
| D-43 | Breached-password check | (a) k-anonymity; (b) none | **(a)** | OPEN |
| D-44 | Captcha for public forms | Provider | **Cloudflare Turnstile** (not verified on stack) | OPEN |

## E. Reports / PDF

| # | Decision | Options | Recommended | Status |
|---|---|---|---|---|
| D-19 | Certificate PDF generation | (a) Hybrid: server signs canonical data, clients render PDF; (b) server-side PDF on request; (c) client-only | **(a) Hybrid, no PAdES / Adobe signature, PDF layout = today's .NET reports** (same sections, labels, order, branding from `pdf_export_settings` → `report_branding`), plus QR/verify footer. Owner (20 Oct 2026): *"Reports Pdf h ushmein nahi chaiye waise banenga jaise dotnet report hoti h"*. Template spec `PDF_TEMPLATES.md`. Server worker sirf email attachments ke liye optional (D-58) | **CLOSED** |
| D-58 | Server PDF worker for email attachments (DSSC upload email, order emails) | (a) No worker: email mein signed expiring link (15 min - 7 din) to verify/download page; (b) isolated `dsecure-pdf-worker` (concurrency 1, memory cap, alag service) jo wahi template render kare | **(a)**; (b) sirf agar customers attachment hi maangein. (b) ke liye Rust PDF engine choice + template parity tests | OPEN |
| D-59 | Branding images storage | (a) Object storage (encrypted, max 2 MB, magic-byte check), DB mein sirf key + sha256; (b) DB column | **(a)**; legacy `GZIP:`/base64 values importer decode karega | OPEN (follows D-41) |
| D-60 | QR / verify URL host | (a) Naya `https://<verify-host>/v/{public_id}#{fingerprint}`; legacy `qrcloud.dsecuretech.com/{id}` aur `autopilotdetection.dsecuretech.com/report/{id}` purane printed PDFs ke liye redirect karte rahein; (b) purana host hi | **(a)** + legacy redirects hamesha (purane certificates zinda rehte hain). Host naam owner decide kare | OPEN |
| D-61 | DSSC/Cleaner upload "same machine = overwrite" (.NET upsert) | (a) Har upload naya immutable report revision, `supersedes` link, list sirf latest dikhaye; (b) overwrite | **(a)**: signed certificate kabhi overwrite nahi hota | OPEN |
| D-62 | PDF branding at render time vs issue time | (a) Issue time par branding version snapshot (text fields signed, images by immutable `branding_version_id`), PDF hamesha same dikhe; optional `branding=current` re-render; (b) hamesha current branding (.NET behaviour) | **(a)**; .NET parity ke liye (b) option download par available | OPEN |

## Needs owner before Phase 0 starts
1. **D-51**: naye TiDB clusters banane ka approval (billing). Bina iske Phase 0 local MySQL/TiDB containers par chalega, par P0-21 (Serverless CI job) aur RU measurement nahi.
2. **D-52, D-53, D-55** confirm (Phase 0 inhi defaults par code likhega; baad mein badalna mehnga: PK layout create-time par fix hota hai TiDB mein).
3. **D-03** (KMS) production se pehle; Phase 0 env KEK par.

## Not verified
Pricing, region availability (Render, TiDB Cloud region, Azure Key Vault, R2), TiDB Serverless engine version and its feature flags (FK, CHECK enforcement, SKIP LOCKED), app team capacity.

## Owner decisions on RBAC interpretations (20 Oct 2026, owner: "haan")
| # | Decision | Result |
|---|---|---|
| D-63 | `devices.register` for a Member without `can_manage_machines` | CLOSED: a Member may register **their own** device (scope self; the device is owned by that member). Registering/assigning/managing devices for others needs `can_manage_machines` (and the role grant). Also closes the device part of D-32. |
| D-64 | `members.read` for Owner | CLOSED: Owner sees every member including co-owners; Admin sees strictly lower ranks plus self; Member/Viewer see only self. |
| D-65 | `performance.read` when `user_activity` toggle is OFF | CLOSED: Owner (and Admin per matrix) always see org-level performance. The `user_activity` toggle only gates per-member activity tracking/timelines; with it OFF, member-level activity data is not collected or shown. |
| D-66 | Who may add members to a group | DEFAULT (orchestrator ruling 20 Oct, fail-closed; owner may override): only Owner/Admin add members to a group. A GroupAdmin may view/manage members already in its own groups within its matrix grants and may remove a member from its own group, but can never add members (prevents a GA pulling another group's member under its control). |
