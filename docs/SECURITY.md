# DSecure Rust backend: Security design (draft v2, 20 Oct 2026)

Owner: Mr. W. Author: architect. Status: **DRAFT v3** (20 Oct 2026: DB = TiDB, D-01; RLS/trigger-based controls replaced by data-layer enforcement + DB grants; PDF = hybrid with .NET layout, no PAdES, D-19). Koi secret/key value is doc mein nahi. Legal advice nahi (compliance mapping `COMPLIANCE_GAP.md` se; lawyer review baaki).

Saath: `RBAC.md` (roles/permissions/tests), `DATABASE.md` (schema), `ARCHITECTURE.md` §10 (certificates), §12 (budget).

---

## 1. Threat model

| ID | Attacker / scenario | Assets at risk | Primary controls |
|---|---|---|---|
| T1 | DB dump/backup leak | PII, report content, secrets | Field encryption (AES-256-GCM, keys outside DB), blind indexes, blobs encrypted, KEK in KMS |
| T2 | Stolen DB credentials / insider with DB console | Same + write tampering | T1 + least-privilege TiDB users (app: no DELETE/DDL; retention user disabled until approved), audit hash-chain blocks anchored to object storage, ledger invariant jobs, TLS-only Serverless endpoint, separate prod cluster (D-51). Note: TiDB par RLS nahi, isliye stolen **app** credentials sab tenants padh sakte hain → field encryption (T1) hi asli backstop |
| T3 | Cross-tenant API abuse (IDOR, body/URL identity injection) | Other tenants' data | Identity from token only, `TenantTx` repositories, SQL lint (`tenant_id = ?` mandatory), schema check (tenant-leading keys), row-tenant assert, generated cross-tenant tests (`DATABASE.md` §2.2) |
| T4 | Privilege escalation inside tenant (member → admin, admin → owner, GA outside group) | Tenant control | Rank rules, live authz state, last-owner guard, E1-E30 tests |
| T5 | Token theft/replay/confusion (DSSC-style token on main API, alg confusion) | Accounts | Per-audience keys, ES256 allowlist, short access TTL, session check per request, refresh rotation + reuse detection |
| T6 | Credential stuffing / brute force | Accounts | Shared rate limits, lockout, Argon2id, MFA (staff mandatory, owners recommended) |
| T7 | Webhook forgery/replay (free licences) | Credits/licences | Signature mandatory (fail closed), timestamp window, event-id idempotency, order state machine |
| T8 | Certificate forgery/tampering (fake erasure proof) | Product trust (NIST claims) | Ed25519 over canonical full content, public verify, key rotation, QR fingerprint |
| T9 | App server compromise (env leak, RCE) | Keys + DB | KMS (KEK never leaves), least-privilege DB roles, egress allowlist, audit, fast key rotation runbook |
| T10 | Resource exhaustion (512 MB OOM) | Availability | Bounded everything (`ARCHITECTURE.md` §12), load-shed, no server PDF on request path |
| T11 | Malicious staff / over-broad support | All tenants | Staff realm separate, MFA, time-boxed access grants with reason, every access audited, 4-eyes for destructive ops |
| T12 | Supply chain (crates) | Code integrity | `cargo-deny`, `cargo-audit`, lockfile, SBOM, pinned toolchain |
| T13 | SSRF via private-cloud host / Graph callbacks | Internal network | Host allowlist + DNS pinning, egress policy, no user-controlled URLs elsewhere |
| T14 | Client reverse engineering (keys in apps/bundle) | — | No shared secrets in clients (legacy `VITE_RES_KEY`/Fernet pattern band); device credentials per installation |

Out of scope (accepted): T9 with simultaneous KMS credential theft is reduced (audit/revoke) not prevented; client-side PDF printouts are not trusted documents (verify page is the truth).

---

## 2. Key hierarchy

```
KMS (Azure Key Vault or AWS KMS, D-03)
 └─ KEK (per environment; never leaves KMS; wrap/unwrap only)
     ├─ Platform DEKs (purpose: identity, secrets, audit, bidx_email, bidx_license, signing-key wrapping)
     └─ Tenant DEKs (purpose: pii, reports, bidx_tenant) — one set per tenant  → crypto-shredding unit
Separate signing keys (purpose-bound, kid-versioned):
 ├─ JWT member/device (ES256)   ├─ JWT staff (ES256)   ├─ JWT cleaner (ES256)
 ├─ Report certificate (Ed25519) └─ Offline licence responses (Ed25519)
Separate HMAC keys: refresh-token/challenge hashing (platform DEK-derived via HKDF with purpose label), IP hashing for audit
```
- **Har purpose ki alag key** (JWT ≠ report signing ≠ field encryption ≠ blind index ≠ OTP HMAC). HKDF-SHA256 derivation sirf jahan same root + distinct `info` label safe hai; KEK se seedha data kabhi encrypt nahi.
- Dev/test: `cargo xtask dev-keys` local random keys `.dev/keys/` mein (gitignored), dev KEK ids `DEV_<FP16>_<random>` aur dev signing keys bhi same dev-marker fingerprint ke saath (FP16 = first 16 hex of SHA-256("dsecure-dev-key-marker-v1")); staging/production startup inhe refuse karta hai; production startup dev keys refuse karta hai.
- Key material memory mein `Zeroizing`/`SecretBox`; core dumps disabled (`RLIMIT_CORE=0`); never logged.

### 2.1 Rotation
| Key | Rotation | Procedure |
|---|---|---|
| KEK | Yearly / incident | KMS new version; worker rewraps `data_keys` (few rows); old version disabled after rewrap |
| DEK (platform/tenant) | Yearly / incident | New `kid` active for writes; old `decrypt_only`; background re-encrypt job (bounded batch) until `count(old kid)=0`; then `retired` (never deleted except crypto-shred) |
| Blind index keys | Rare (expensive) | New column `*_bidx2` dual-write + backfill + switch; keep long-lived in KMS |
| JWT signing | 6 months | New `kid` published; old verify-only until max token TTL passes (refresh tokens unaffected) |
| Report certificate key | 12 months | New `kid`; old public keys **forever** published in `/public/signing-keys` (old certificates must stay verifiable) |
| Ciphertext versioning | — | Format byte + kid in every value (`DATABASE.md` §3); readers dispatch by version/kid |

### 2.2 Legacy data (importer only)
Legacy .NET data mein AES-CBC values hain (response-key envelope `report_details_json`, fixed-IV private cloud strings, UEM token cache, unlock creds; `ENCRYPTION_DESIGN.md` F8, F13, F16, F18). **Rust API mein koi CBC code nahi.** Sirf `importer` crate legacy CBC/gzip decrypt karta hai (keys importer run ke env mein, run ke baad remove), turant GCM mein re-encrypt karta hai, plaintext disk/log par kabhi nahi. Legacy RSA public keys (`ProductRsaKeys`) `signing_keys(verify_only)` mein import taaki purane app `digital_identifier` verify ho sakein; legacy **private** keys import nahi hoti.

---

## 3. Field encryption

- AES-256-GCM, 96-bit random nonce, AAD binds kid + table.column + tenant + row id (`DATABASE.md` §3). Tag fail = error (fail closed), metric + audit (`crypto.decrypt_failed`, no value).
- Encrypted: emails (+bidx), names, phones, addresses/billing, IP (or keyed hash), MAC/serial (+tenant bidx), hostnames, licence keys (+global bidx), report content + signature images (blob), Graph token cache, unlock credentials, private-cloud connection, chat messages, lead messages, TOTP secrets.
- Plain: ids, statuses, timestamps, product codes, counters, manufacturer/model, NIST method/technique enums, public keys.
- Blind index: HMAC-SHA256, normalisation (email: trim + NFKC + lowercase; licence key: trim + uppercase; MAC: hex lowercase no separators; serial: trim + uppercase). Low-entropy values (phone) ki bidx nahi.
- **Large blob streaming (STREAM construction):** 64 KB chunks; per-chunk nonce = random 8-byte prefix ‖ 4-byte counter; AAD includes chunk index + "last" flag (truncation/reorder detect). Memory O(chunk).
- Search tradeoff: encrypted fields par partial search nahi; exact bidx search; partial search sirf non-PII normalised columns (group/department names) par (D-16).

---

## 4. Authorization matrix (summary; full catalogue `RBAC.md` §4)

| Capability area | Platform superadmin | Platform support | Platform billing | Platform auditor | Tenant owner | Tenant admin | Group admin | Member | Viewer | Device token | Cleaner token | Anonymous |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Tenant data read | Grant only | Grant only | Commerce only | Audit metadata | T | T | G | S | S | own device | own account | — |
| Members manage | Support actions w/ grant | Reset-link/unlock w/ grant | — | — | T (subusers ON) | T, rank < admin | Group membership only | — | — | — | — | — |
| Roles grant | — (owner via co-owner flow on ticket) | — | — | — | < owner | member/viewer | — | — | — | — | — | — |
| Feature toggles / quotas | ✓ (audited, reason) | toggles w/ ticket | quotas | — | read | read | — | — | — | — | — | — |
| Devices manage / remote wipe | — | — | — | — | T / T+step-up | T / T+step-up | G / explicit grant | own register | — | heartbeat | — | — |
| Credits consume | — | — | — | — | T | T | G | S (allocation) | — | `credits.consume` scope | own (DSSC) | — |
| Licence/credit issuance | ✓ | — | ✓ | — | — | — | — | — | — | — | — | Webhook (signed) |
| Reports read/create | Grant only | Grant only | — | — | T | T | G | S | S read | create/upload own | own | Public verify (masked) |
| Audit log | ✓ | — | — | ✓ | own tenant | own tenant | — | — | — | — | — | — |
| Crypto-shred / tenant erase | ✓ + owner approval record | — | — | — | request only | — | — | — | — | — | — | — |

T = tenant, G = own group(s), S = self. Har cell 3 checks + capabilities ke saath (`RBAC.md` §1, §5).

---

## 5. Sessions and tokens

| Item | Design |
|---|---|
| Access token | JWT ES256, 15 min, `kid` header, alg allowlist = ES256 only, `aud` per principal kind, `typ` claim, `sid`, `av` |
| Refresh token | Opaque 256-bit random, SHA-256 stored, **rotation on every use**, family id; reused (already-used) token → whole family + session revoked + audit `auth.refresh_reuse` |
| Session check | Every request: session not revoked/expired, user/membership/tenant status active, `tokens_valid_after < iat` — bounded cache keyed by session + tenant epoch; `authz_epochs` poll (2 s) invalidation (TiDB mein NOTIFY nahi); high-risk actions live read |
| Web storage | Dashboard: access token memory mein; refresh token `HttpOnly; Secure; SameSite=Strict` cookie scoped to `/api/v1/auth/refresh` + CSRF double-submit header. Apps: OS secure storage (DPAPI/Keychain) |
| Device credential | Enrollment by member with `devices.register`; per-installation secret (or keypair); exchange for 15-min device token; revoked when device decommissioned or operator disabled |
| Step-up | `/auth/step-up` (password or TOTP) → 5-min single-use token bound to session + action + target |
| MFA | TOTP (RFC 6238) day one; WebAuthn later. Staff mandatory; tenant owners strongly recommended (enforce toggle per tenant later, D-23) |
| Logout | Session revoke + refresh family revoke |
| Revocation events | Password change/reset, disable, delete, demote, MFA reset, admin revoke, reuse detection → sessions revoked; access tokens die on next request (session check) |
| Password policy | Min 12 chars, breached-password check (k-anonymity range API optional, D-43), no composition rules (NIST 800-63B) |
| Lockout | `RBAC.md` §6.3 |
| Clock | NTP-synced host (CERT-In); `exp`/`nbf` leeway 30s max |

---

## 6. Webhooks (Dodo, Standard Webhooks format)

1. Secret required at startup (`DODO_WEBHOOK_SECRET`); missing = startup fail (no "skip verification").
2. Verify `webhook-signature` = HMAC-SHA256 over `webhook-id.webhook-timestamp.raw_body` (constant-time compare, support multiple `v1,` signatures for secret rotation).
3. Timestamp window ±5 min; outside → 400 + audit.
4. `webhook_events (provider, provider_event_id)` UNIQUE → duplicate = 200 no-op (idempotent).
5. Processing in transaction with order state machine (`pending → paid → fulfilled`); fulfilment credit transaction idempotency key = `order:{id}:fulfil` → retries never double-grant.
6. Raw payload encrypted, 90-day retention; logs never contain payload/PII.
7. New customer onboarding: tenant + owner user created `pending_verification` with **no password**; set-password link email (no fixed temp password ever).

---

## 7. Certificate integrity (reports)

| Control | Design |
|---|---|
| What is signed | RFC 8785 JCS canonical `certificate_payload` (full certificate content incl. NIST SP 800-88 Rev 2 fields, report sha256 of the full uploaded report, product, tenant display name, operator, timestamps) — not just `id|serial|status` like legacy |
| Algorithm | **Ed25519** (`ARCHITECTURE.md` §10.2): deterministic, small, fast; signature over `"dsecure-cert-v1\n" ‖ SHA-256(JCS)` (domain separation) |
| Stored | `content_sha256`, `signature`, `signing_key_id`, `canonical_version`, `signed_at` (`DATABASE.md` §6) |
| Key custody | Ed25519 private key wrapped by KEK, unwrapped only in API memory; rotation 12 months; public keys published forever; HSM-only alternative ES256 in KMS (D-42) |
| Verify | `/public/certificates/{public_id}`: server recomputes hash from stored canonical payload, verifies signature, checks revocation, returns masked view + `fingerprint`; `/public/signing-keys` for offline verification |
| Client PDFs | Rendered by dashboard/apps/verify page from signed render data using the shared template (`PDF_TEMPLATES.md`, same layout as .NET reports). PDF has QR (`/v/{public_id}#{fingerprint}`) + printed fingerprint. A tampered PDF is detected because verify lookup returns server data/fingerprint that does not match the paper |
| App signature | App's own `digital_identifier` stored + status (`valid/invalid/absent/unverifiable`); server certificate signature is independent of it |
| Revocation | `revoked_at` + reason code (e.g. wrong device); verify shows `revoked` |
| PAdES | **Nahi** (owner D-19 closed: Adobe signature nahi chahiye). PDF ka integrity = printed verification code + QR → server verify |
| Upload integrity | Report hash computed server-side; idempotent upload (same content → same result; different content for completed report → 409, never overwrite) |

---

## 8. Destructive operations, approvals, erasure

| Operation | Controls |
|---|---|
| Remote wipe / member delete / ownership transfer / tenant export / tenant close | Dedicated permission + confirmation + step-up + audit + rate limit (`RBAC.md` §6.6) |
| Feature toggle / quota change | Staff only, reason + ticket, audit, history table |
| Staff access to tenant data | Time-boxed grant (max 8h), reason/ticket, every request audited with grant id, tenant owner can see staff access entries in their audit log |
| Tenant erasure (DPDP/GDPR) | **Crypto-shredding**: tenant DEKs status `destroyed` + wrapped key overwritten → tenant PII/report blobs unreadable incl. backups; identity rows tombstoned; credits/orders retained in pseudonymous form for legal retention. Requires platform superadmin + **owner (Mr. W) approval record** per tenant (production data deletion rule) |
| Retention purges (sessions, audit partitions older than policy, webhook payloads) | Policy document owner approves once per data class (D-17); job logs counts only; until approved: archive/mark only |
| Production migrations | Main session/owner applies; DB change before code; never by agents |

---

## 9. Rate limits (shared store; local fallback stricter)

| Class | Key | Limit (default, configurable) |
|---|---|---|
| Login | IP | 20/min; email bidx: 10/15 min (+ lockout) |
| Forgot/verify email | email bidx + IP | 3/15 min |
| Refresh | session | 30/min |
| Step-up | session | 5/15 min |
| Public verify | IP | 30/min + global 50/s |
| Contact lead | IP | 5/hour + captcha (provider D-44) |
| Webhook | provider IP range (if published) | 50/s |
| Credit checks / uploads | device or member | 60/min; tenant 600/min |
| Remote wipe | tenant 5/h, 20/day; actor 3/h | — |
| Exports | tenant | 5/hour |
| Platform | staff | 120/min |
Client IP only via trusted proxy config; spoofed `X-Forwarded-For` ignored. 429 with `Retry-After`.

---

## 10. Logging, redaction, observability, incident timelines

- Structured JSON logs; `Redacted<T>` for every PII type (email, name, IP, serial, MAC, licence key, tokens) → logs show `[redacted]` or keyed hash prefix. Request/response bodies never logged. Query strings stripped (route template only). SQL parameters not logged.
- Audit log (`audit_events`): append-only (app/worker DB users ke paas UPDATE/DELETE grant nahi; TiDB mein trigger nahi), har row `row_hash`; worker hourly **chain blocks** seal karta hai (`audit_chain_blocks`: merkle root of the hour + prev block hash; global hot row nahi) aur har hourly sealed block blob store (object storage, India region) mein anchor hota hai (hourly sealed blocks, anchored to blob store; tamper evidence). Retention ≥ 1 year (DPDP), hot 13 months; archived copies in India-region storage for CERT-In 180-day log requirement (D-18).
- Audited actions: login success/failure, lockout, MFA changes, password change/reset, session revoke, role/capability/status changes, member create/delete/transfer, group admin grants, toggles/quotas, staff access open/close + each staff request, licence/credit issuance/consume/refund/adjust, remote wipe lifecycle, exports, key rotations, webhook verification failures, crypto decrypt failures, authz denials (sampled aggregate + all for staff/cross-tenant attempts).
- Metrics (OTLP): RED per route, authz denials by reason, cross-tenant 404 rate, login failures, lockouts, webhook failures, credit consume rate, job queue depth/lag, DB pool wait, RSS/jemalloc resident, 503 load-shed count.
- **Alerts** (target: detect within minutes to meet CERT-In 6h / DPDP 72h reporting): 5xx > 2% 5 min; login failure spike; cross-tenant denial spike; staff access outside hours; webhook signature failures; decrypt failures; RSS > 300 MB; queue lag > 10 min; DB errors; certificate verify failures spike. Paging to incident owner (C5 in COMPLIANCE_GAP).
- Incident runbook (`docs/INCIDENT_RESPONSE.md`, owner + lawyer) with key-rotation and token-revocation procedures.

---

## 11. Scan findings → design control

_Legacy .NET scan findings and their design controls are kept in a private document (`docs/private/`, not in the public repo)._

## 12. Database security (TiDB)
| Control | Design |
|---|---|
| Separate clusters | Rust staging/prod alag TiDB clusters (D-51); legacy `Cloud_Erase__App` ke credentials Rust prod mein sirf restricted down-sync user (D-15) |
| Transport | TLS mandatory, `VERIFY_IDENTITY`, CA pinned in config (`DB_TLS_CA`) |
| Users / grants | `DATABASE.md` §2.5: app = SELECT/INSERT/UPDATE only; migrator alag (release step only); retention user disabled until owner approval; readonly for reconciliation |
| Isolation without RLS | `DATABASE.md` §2.2 L1-L8; CI gates (sql-lint, schema-check, negative tests) are **release-blocking** |
| RU as DoS surface | Spending limit per cluster; per-route RU metric; rate limits before DB; no unbounded queries (keyset, LIMIT ≤ 200); plan tests in CI |
| Secrets | `DATABASE_URL` only from secret env; never logged (URL redacted type); connection string never in errors |
| Backups | TiDB Cloud managed backups (Serverless PITR/retention not verified); restore drill per phase on non-prod; encrypted columns make backup leak low-value (T1) |

## 13. Not verified
- KMS Ed25519 support (Azure/AWS); WebCrypto Ed25519 coverage; Render secret features; region availability for India log archive.
- NIST SP 800-88 Rev 2 exact certificate field list; legal retention periods (lawyer).
- Dodo IP ranges; captcha provider.
