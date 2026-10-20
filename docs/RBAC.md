# DSecure Rust backend: RBAC design (draft, 20 Oct 2026)

Owner: Mr. W. Author: architect. Status: **DRAFT v3** (v2: legacy wire-compat hata; API `/api/v1`. v3, 20 Oct 2026: DB = TiDB (D-01), isliye tenant isolation RLS ki jagah **data layer** mein (§6.7); authz invalidation NOTIFY ki jagah **authz epochs** (§6.4); contracts se coverage additions §4.12). Owner ka model (A-to-Z 18 Oct §4) aur owner ki maani hui corrections is design ka base hain. .NET mein jo RBAC kabhi poora nahi hua (`rbac-deep-audit.md` §3 B/C/D, `rbac-audit-report.md`), wo sab yahan day one se built-in hai.

Schema: `DATABASE.md` §4 (identity + RBAC tables). Authz matrix ka security view: `SECURITY.md` §4.

---

## 1. Model ek nazar mein

```
Platform (D-Secure)                         Tenant (har khareedne wali org ya akela banda)
 ├─ platform_staff: superadmin, support,     ├─ tenant_features: subusers, groups, user_activity, private_cloud (default OFF)
 │   billing, auditor (MFA, access grants)    ├─ tenant_quotas: max_members, max_groups, max_departments, max_licenses
 │                                            ├─ memberships (user ↔ tenant): role = owner | admin | member | viewer
 │                                            │    ├─ capabilities (narrowing): can_view_reports, can_manage_machines,
 │                                            │    │    can_assign_licenses, max_machines, credit allocation
 │                                            │    └─ group_admin grants (scope = ek group)
 │                                            ├─ groups / departments
 │                                            └─ devices, licences, credits, reports, sessions ... (sab tenant_id ke saath)
```

**Teen checks, har request par, backend mein, teeno pass hone chahiye:**

| # | Check | Sawaal | Kahan enforce |
|---|---|---|---|
| 1 | **Tenant** | Ye data kis tenant ka hai, aur caller usi tenant ka hai? | `TenantScope` (token ke `tid` + live membership) → `TenantTx` → repository query files jinme `tenant_id = ?` mandatory (SQL lint), tenant-leading keys, row-tenant assert (§6.7) |
| 2 | **Feature toggle / entitlement** | Ye feature is tenant ke liye ON hai? (aur product ka valid licence hai?) | Route policy `.feature(Feature::X)` / `.product(P)`; live `tenant_features` |
| 3 | **Role / permission (+ capability + visibility)** | Ye insaan ye action kar sakta hai, aur kis data par? | Route policy `.permission(Perm::X)` + capability mask + visibility scope (`Tenant`/`Groups`/`SelfOnly`) |

Kisi bhi check ka error (DB down, unknown feature, unknown permission) = **deny**.

---

## 2. Owner ke rules → design (har rule kaise pura hota hai)

| Owner rule | Design |
|---|---|
| Har buying org/individual = tenant | Payment fulfilment `tenants` row + owner membership banata hai (individual = `kind='individual'`) |
| Owner apne tenant mein sab dekhe/manage kare (reports, machines, sessions, performance, subusers, licences, downloads, remote wipe, members create/delete, groups, members add, group admins) | Owner role = tenant ke saare tenant-permissions (§4); kuch features toggle par depend (subusers/groups/user_activity) |
| Upar wale neeche ko dekhein, neeche wale upar ko kabhi nahi | Visibility scope: owner/admin = `Tenant`; group_admin = `Groups(own)` (sirf members with lower rank); member/viewer = `SelfOnly`. Member list query rank filter: `role_rank < caller_rank` ya self |
| Ek org dusri org ka kuch nahi dekhe | Check 1 + data-layer enforcement L1-L8 (`DATABASE.md` §2.2) + cross-tenant tests (§8) |
| Plans tiers nahi; features per account toggle (subusers, user activity, private cloud, groups); single buyer ke liye default OFF; single buyer sirf apne sessions dekhe | `tenant_features` rows default OFF; `user_activity` OFF par `sessions.read_members` deny, sirf self sessions |
| Private cloud per-tenant add-on | Feature `private_cloud` + `private_cloud_connections` table (platform staff enable, tenant owner configure) |
| Customer kabhi SuperAdmin nahi; SuperAdmin/support = staff, alag | `platform_staff` alag table, alag login/audience/MFA; tenant role list mein "superadmin" exist hi nahi karta |
| Staff ka har tenant data access logged, reason/ticket ke saath | `staff_access_grants` (reason + ticket, expiry); bina active grant staff ki tenant query fail; har request audit event mein `grant_id` |
| Tenant roles: Owner, Admin, Member, Viewer + GroupAdmin (sirf apne group tak) | §3 |
| Subusers = tenant members with roles, alag silo nahi | Ek `users` identity + `memberships`; legacy "subuser" concept sirf data migration mein `membership.kind='subuser'` banta hai (reporting ke liye); permissions role se aati hain, kind se nahi |
| Toggles sirf D-Secure staff badle; har change audit; toggle off par data delete nahi | `platform.features.toggle` sirf staff; `tenant_feature_changes` history + audit; OFF = access gate, data untouched |
| Ek hi role model, free-text role column nahi | Role = `VARCHAR` + `CHECK` (MySQL CI) value from code catalogue (Rust enum; app validates, TiDB CHECK par bharosa nahi); koi `user_role` free text nahi; permissions code mein (versioned), DB mein global editable `RolePermissions` nahi |
| Role/permission change turant lagu | `authz_version` (membership/user/tenant) har change par +1; per-request live state; tokens/sessions re-evaluate; demotion/disable par sessions revoke (§6.4) |
| Status, lockout, email verification login + refresh + har request par | §6.3 |
| Per-member capabilities aur tenant quotas enforce | §5 |
| Hierarchy: equal/higher role grant nahi; last owner delete/demote nahi; disable ≠ delete; delete par resources explicit transfer | §3.3, §6.5 |
| Remote wipe + destructive: dedicated permission, confirmation + step-up, audit, rate limit | §6.6 |
| Desktop app/device tokens alag principal, minimal scopes; DSSC-style confusion impossible | §6.2 |
| Group admins sirf apne group ke members, machines, reports | Visibility `Groups(ids)`; group admin grant ka scope = group id |

---

## 3. Roles

### 3.1 Tenant roles (code catalogue, `domain::rbac`)

| Role | Rank | Visibility | Kaun | Note |
|---|---|---|---|---|
| `owner` | 100 | Tenant | Account khareedne wala; tenant ka final authority | Kam se kam 1 active owner hamesha |
| `admin` | 80 | Tenant (lekin owner/dusre admins ko manage nahi kar sakta) | Owner ka delegate | Admin ko sirf owner banata hai |
| `member` | 40 | Self (+ jo devices/reports use assign hain) | Operator: desktop apps chalata hai, apni reports dekhta hai | Legacy subuser ka default |
| `viewer` | 20 | Self (read-only) | Sirf dekhne wala (e.g. apni assigned machines ki reports) | Credits consume nahi kar sakta |

**GroupAdmin** role nahi, ek **scoped grant** hai: `group_admin_grants(membership_id, group_id)`. Grant wala member apne base role (member) ke upar, sirf us group ke andar extra permissions paata hai (§4 column "GA"). Effective rank group ke andar = 60. Ek member kai groups ka admin ho sakta hai. Owner/admin ko grant ki zarurat nahi (unke paas tenant visibility hai).

Custom roles (per-tenant) **v1 mein nahi**: owner ki zarurat built-in roles + capabilities se poori hoti hai; custom roles baad mein per-tenant (global kabhi nahi) — `DECISIONS.md` D-30.

### 3.2 Platform staff roles (alag realm)

| Role | Kya kar sakta hai | Tenant data |
|---|---|---|
| `platform_superadmin` | Staff manage, toggles, quotas, tenant suspend, key rotation, break-glass | Sirf active access grant ke saath |
| `platform_support` | Tenant read for support, password reset email trigger, session revoke | Grant ke saath, read-mostly; destructive nahi |
| `platform_billing` | Orders, licence/credit issuance, refunds, checkout links | Commerce data; reports nahi |
| `platform_auditor` | Audit logs, compliance exports | Audit metadata; customer content nahi |

Staff MFA mandatory, session 8h max, idle 30 min, optional IP allowlist (`PLATFORM_ALLOWED_CIDRS`). Crypto-shredding / tenant erasure = superadmin + **owner (Mr. W) approval record** (`SECURITY.md` §8).

### 3.3 Hierarchy rules (domain functions, unit + property tests)

```rust
fn can_grant(actor: &Actor, target_role: TenantRole) -> bool      // target_rank < actor_rank, actor has members.assign_role
fn can_manage(actor: &Actor, target: &MemberState) -> bool         // target_rank < actor_rank (owner > admin > member/viewer);
                                                                   // group_admin: target in own group AND target_rank < 60
fn can_grant_group_admin(actor: &Actor, group: GroupId) -> bool    // owner/admin only (group admins cannot create group admins)
```
- Koi bhi apne barabar ya upar ka role grant nahi kar sakta. Owner role sirf **ownership transfer** (owner step-up ke saath, atomically self-demote to admin) ya **co-owner via platform staff** (owner ki request/ticket par) se. Dono audited.
- Koi apna khud ka role/capability/status nahi badal sakta (self-escalation impossible; self-disable bhi nahi, "leave tenant" alag flow jo last-owner rule maanta hai).
- Admin dusre admin ya owner ko disable/delete/edit/password-reset nahi kar sakta.
- **Last owner guard:** owner demote/disable/delete se pehle `SELECT ... FOR UPDATE` on `tenants` row, phir active owners count; 1 hai to `409 members.last_owner`. TiDB mein trigger nahi: ye check **sirf** `memberships::set_role/set_status/delete` repo functions ke andar (inke alawa role/status badalne ka koi query file nahi; SQL lint enforce karta hai), tenant row mutex ke saath (`DATABASE.md` §4.3); nightly invariant job "active tenant without active owner" = alert.

---

## 4. Permission catalogue + role × permission matrix

Legend: **T** = poore tenant par, **G** = sirf apne group(s) ke andar (members with lower rank, unke devices/reports), **S** = sirf self (ya khud ko assigned resources), **—** = nahi. Feature column = kaunsa toggle ON chahiye (§5). "Cap" = capability mask lagta hai.

### 4.1 Account / self
| Permission | Owner | Admin | GA | Member | Viewer | Feature |
|---|---|---|---|---|---|---|
| `profile.read_self`, `profile.update_self` | S | S | S | S | S | — |
| `password.change_self` | S | S | S | S | S | — |
| `mfa.manage_self` | S | S | S | S | S | — |
| `sessions.read_self`, `sessions.revoke_self` | S | S | S | S | S | — |

### 4.2 Members (subusers)
| Permission | Owner | Admin | GA | Member | Viewer | Feature |
|---|---|---|---|---|---|---|
| `members.read` | T | T (rank < 80 + self) | G | S | S | subusers |
| `members.create` | T | T (role < admin) | — | — | — | subusers + quota `max_members` |
| `members.update` (name, phone, dept) | T | T (rank < 80) | G (name/dept nahi badle, sirf group membership) | — | — | subusers |
| `members.assign_role` | T (< owner) | T (member/viewer) | — | — | — | subusers |
| `members.set_capabilities` | T | T (rank < 80) | — | — | — | subusers |
| `members.disable` / `members.enable` | T | T (rank < 80) | — | — | — | subusers |
| `members.delete` (+ resource transfer) | T | T (rank < 80) | — | — | — | subusers |
| `members.reset_password` (sends reset link; password set karna nahi) | T | T (rank < 80) | — | — | — | subusers |
| `members.transfer_resources` | T | T | G (group ke andar) | — | — | subusers |
| `tenant.ownership.transfer` | T + step-up | — | — | — | — | — |

### 4.3 Groups / departments
| Permission | Owner | Admin | GA | Member | Viewer | Feature |
|---|---|---|---|---|---|---|
| `groups.read` | T | T | G | S (apna group) | S | groups |
| `groups.create`, `groups.update`, `groups.delete` (soft) | T | T | — | — | — | groups + quota `max_groups` |
| `groups.manage_members` | T | T | G (existing members ko apne group mein add/remove) | — | — | groups |
| `groups.assign_admin` | T | T | — | — | — | groups |
| `departments.read` / `departments.manage` | T / T | T / T | G / — | S / — | S / — | groups + quota `max_departments` |

### 4.4 Activity / sessions / performance
| Permission | Owner | Admin | GA | Member | Viewer | Feature |
|---|---|---|---|---|---|---|
| `activity.read_members` (others' sessions, login activity, timelines, performance) | T | T | G | — | — | user_activity |
| `sessions.revoke_members` | T | T (rank < 80) | — | — | — | user_activity |
| `performance.read` (tenant KPIs) | T | T | G | S | S | — (own data); others = user_activity |

### 4.5 Devices / machines
| Permission | Owner | Admin | GA | Member | Viewer | Feature / Cap |
|---|---|---|---|---|---|---|
| `devices.read` | T | T | G | S | S | — |
| `devices.register` (app) | T | T | G | S | — | Cap `can_manage_machines`, `max_machines` |
| `devices.update` / `devices.assign` | T | T | G | — | — | Cap `can_manage_machines` |
| `devices.remote_command` | T | T | G | — | — | Cap; step-up nahi |
| **`devices.remote_wipe`** | T + step-up + confirm | T + step-up + confirm | — (default; owner per-GA grant kar sakta hai: D-31) | — | — | Rate limit, audit |
| `devices.delete` (soft/decommission) | T | T | — | — | — | — |

### 4.6 Licences / credits / billing
| Permission | Owner | Admin | GA | Member | Viewer | Feature / Cap |
|---|---|---|---|---|---|---|
| `licenses.read` | T | T | G (group members ki allocations/activations) | S | S | — |
| `licenses.activate` (app, apne device par) | T | T | G | S | — | Cap `can_assign_licenses` nahi chahiye; product entitlement |
| `licenses.allocate` (member ko credit/licence allocation) | T | T | G (sirf group allocation pool ke andar, D-33) | — | — | Cap `can_assign_licenses` (admins ke liye bhi narrowing) + quota `max_licenses` |
| `licenses.deactivate_device` (binding hatao) | T | T | G | — | — | — |
| `licenses.transfer` (device/member ke beech) | T | T | G | — | — | — |
| `credits.read` | T | T | G | S | S | — |
| `credits.consume` (pre-wipe/pre-diagnostic) | T | T | G | S (allocation ke andar) | — | Product entitlement + allocation |
| `orders.read`, `invoices.read` | T | T | — | — | — | — |
| `billing.manage` (checkout start) | T | — | — | — | — | — |

Licence/credit **issuance** (naye credits banana) kisi tenant role ke paas nahi: sirf payment fulfilment (webhook) ya `platform.licenses.issue`.

### 4.7 Reports (per product: `drive`, `diag`, `file`, `cleaner`, `freeze`, `autopilot`)
| Permission | Owner | Admin | GA | Member | Viewer | Feature / Cap |
|---|---|---|---|---|---|---|
| `reports.<p>.read` | T | T | G | S | S | Product entitlement; Cap `can_view_reports` (false = sirf khud ki reports, dusron ki nahi; D-32) |
| `reports.<p>.create` (reserve-id, pre-check, upload) | T | T | G | S | — | Product entitlement |
| `reports.export` (PDF/CSV) | T | T | G | S | S | Cap `can_view_reports` |
| `reports.branding.manage` | T | T | — | — | — | — |
| `reports.transfer` (owner_membership change; performed_by kabhi nahi badalta) | T | T | G | — | — | — |
| `reports.archive` (soft hide; certificates immutable) | T | T | — | — | — | — |

### 4.8 Products ke specific
| Permission | Owner | Admin | GA | Member | Viewer | Feature |
|---|---|---|---|---|---|---|
| `autopilot.devices.read` / `.import` / `.delete` | T/T/T | T/T/T | G/G/— | S/S/— | S/—/— | DSAM entitlement |
| `autopilot.recheck` | T | T | G | S | — | DSAM |
| `autopilot.connection.manage` (Microsoft tenant connect) | T + step-up | T + step-up | — | — | — | DSAM |
| `autopilot.unlock_credentials.submit` | T | T | — | — | — | DSAM |
| `freeze.endpoints.read` / `.manage` | T/T | T/T | G/G | S/— | S/— | DSFZ |
| `freeze.chat.read` / `.send` | T/T | T/T | G/G | S/S | S/— | DSFZ |
| `cleaner.run`, `cleaner.redeem`, `cleaner.reports.read` | T | T | — | S | S (read) | DSSC |
| `downloads.read` | T | T | — | — | — | — |
| `private_cloud.read` / `.manage` | T / T + step-up | T / — | — | — | — | private_cloud |

### 4.9 Tenant administration
| Permission | Owner | Admin | Others | Feature |
|---|---|---|---|---|
| `tenant.settings.read` | T | T | — | — |
| `tenant.settings.update` (timezone, branding, notification prefs; **toggles/quotas nahi**) | T | — | — | — |
| `tenant.audit.read` (apne tenant ka audit log) | T | T | — | — |
| `tenant.export_data` (DPDP/GDPR export) | T + step-up | — | — | — |
| `tenant.close` (account close request → platform workflow) | T + step-up | — | — | — |

### 4.10 Platform permissions (staff only; tenant roles ke paas kabhi nahi)
| Permission | superadmin | support | billing | auditor |
|---|---|---|---|---|
| `platform.tenants.read` | ✓ | ✓ | ✓ (commerce fields) | ✓ (metadata) |
| `platform.tenants.suspend` | ✓ | — | — | — |
| `platform.features.toggle` | ✓ | ✓ (ticket mandatory) | — | — |
| `platform.quotas.update` | ✓ | — | ✓ | — |
| `platform.staff_access.open` (tenant data grant) | ✓ | ✓ | — | — |
| `platform.members.support` (reset link bhejna, sessions revoke, unlock) | ✓ | ✓ | — | — |
| `platform.licenses.issue`, `platform.credits.adjust`, `platform.refunds` | ✓ | — | ✓ | — |
| `platform.checkout_links.manage`, `platform.webhooks.manage` | ✓ | — | ✓ | — |
| `platform.leads.read` / `.manage` | ✓ | ✓ | ✓ | — |
| `platform.releases.manage` | ✓ | — | — | — |
| `platform.audit.read` | ✓ | — | — | ✓ |
| `platform.keys.rotate` | ✓ (+ owner approval) | — | — | — |
| `platform.tenant.erase` (crypto-shred) | ✓ (+ owner approval record) | — | — | — |
| `platform.staff.manage` | ✓ | — | — | — |

### 4.11 Device / app principal scopes (alag, minimal)
| Scope | Allowed |
|---|---|
| `device:reports.reserve` | reserve-id |
| `device:credits.consume` | pre-wipe-check / pre-diagnostic-check |
| `device:reports.upload` | upload, upload-offline (apne device ke liye) |
| `device:licenses.activate` | activate/validate on that device |
| `device:heartbeat` | last seen, updates check |
| `device:licenses.offline` | offline activation request/response for that device |
| `device:credits.offline_grant.read` | read own offline credit grant (wipe_count) |
| `device:freeze.agent` | Freeze agent: register/heartbeat endpoint, upload freeze reports, chat as `endpoint` (sender kind from token, never body) |
| `device:autopilot.check` | Autopilot tool: check-status / upload devices for its tenant (bucket by tool type) |
Device token kisi dashboard/admin/member/platform route par **kabhi** valid nahi (alag audience). Device ka operator member (agar app user login se enrol hua) audit mein record hota hai; device scopes operator ke permissions ka **subset** hote hain (operator disable = device token invalid).

### 4.12 Contract reconciliation additions (20 Oct 2026; `docs/contracts/*.md`, "do NOT port" excluded)
Ye permissions upar ki tables mein nahi the; contracts ke features cover karne ke liye add. Legend same.
| Permission | Owner | Admin | GA | Member | Viewer | Feature / note | Contract source |
|---|---|---|---|---|---|---|---|
| `profile.update_timezone` (part of `profile.update_self`) | S | S | S | S | S | — | auth 2 (update-timezone) |
| `members.read_roles_catalogue` (roles/permissions list, my-permissions) | T | T | G | S | S | — (read-only code catalogue) | auth 2 |
| `members.bulk_assign_department` | T | T | — | — | — | subusers + groups | auth 2 |
| `members.preferences.manage_self` (column view etc.) | S | S | S | S | S | — | autopilot branding `column_view_config` |
| `activity.read_self` (own login activity, timeline) | S | S | S | S | S | always | auth 7-9 |
| `audit.read_actions` (user action log = legacy ActivitySessions) | T | T | G | S | — | user_activity for others | auth 11 |
| `devices.read_license_status` (status, remaining days) | T | T | G | S | S | — | machines B5/B6 |
| `devices.transfer` (to another member) | T | T | G (group ke andar) | — | — | Cap `can_manage_machines` | machines A12 |
| `devices.statistics.read` | T | T | G | S | — | — | machines A14 |
| `licenses.sync` / `licenses.renew` | T | T | G | S | — | device scope bhi | licences sync/renew |
| `licenses.revoke` | T | T | — | — | — | step-up if bulk > 10 | licences admin/revoke |
| `licenses.export` (CSV, async) | T | T | G | — | — | — | licences admin/export |
| `credits.offline_grant` (offline quota transfer to a device) | T | T | G | S (own device, allocation ke andar) | — | product entitlement | licences activate-drive-diag |
| `reports.<p>.offline_upload` | T | T | G | S | — | device-signed (D-24) | drive 4-5, diagnostic |
| `reports.<p>.statistics.read`, `reports.<p>.facets.read` | T | T | G | S | S | Cap `can_view_reports` | file 2.8, V2 lists |
| `reports.drive.subjects.read` (drives view) | T | T | G | S | S | — | drive V2 view=drives |
| `reports.export_batch` (zip of PDFs is client-side; server = signed data batch ≤ 100) | T | T | G | S | S | Cap `can_view_reports` | file 4.7 |
| `reports.branding.read` | T | T | G | S | S | — (needed to render PDF) | file 5.1 |
| `autopilot.settings.manage` (auto-check preference) | T | T | — | — | — | DSAM | autopilot A9/auto-check |
| `autopilot.custom_fields.update` | T | T | G | S (own devices) | — | DSAM | autopilot A4 |
| `autopilot.schedules.read` / `.manage` | T/T | T/T | G/— | S/— | S/— | DSAM | autopilot §6 |
| `autopilot.uem_recheck.run` / `.read` | T/T | T/T | —/G | —/S | —/S | DSAM + `mdm_connections` | autopilot §5 |
| `autopilot.intune.delete_device` (own tenant connection only, never master tenant) | T + confirm | T + confirm | — | — | — | DSAM; D-12 | autopilot A14 |
| `autopilot.donors.create` (if autopilot D-9 = keep) = `members.create` with role member | T | T | — | — | — | subusers | autopilot A6 |
| `freeze.endpoints.delete` (soft) | T | T | — | — | — | DSFZ | freeze B.4 |
| `freeze.reports.read` / `.archive` | T/T | T/T | G/— | S/— | S/— | DSFZ | freeze B.6-B.9 |
| `cleaner.transactions.read` | T | T | — | S | S | DSSC | dssc A.9 |
| `downloads.history.read_self` | S | S | S | S | S | — | misc 8.8 |
| `orders.invoice.download` | T | T | — | — | — | — | payments 3.15 |
| `performance.erasure_metrics.read` | T | T | G | S | S | own scope; others = user_activity | misc 10.1-10.2 |

Platform additions (staff only):
| Permission | superadmin | support | billing | auditor | Contract source |
|---|---|---|---|---|---|
| `platform.cleaner_codes.mint` (DSSC redeem codes, count 1..100) | ✓ | — | ✓ | — | dssc A.10 (customer minting = do NOT port) |
| `platform.autopilot.credits` (allocate checks / grant unlimited window; = `platform.credits.adjust` scoped to DSAM) | ✓ | — | ✓ | — | autopilot A7/A8 |
| `platform.provider_products.manage` (Dodo product → product/bundle map) | ✓ | — | ✓ | — | payments 2.1 |
| `platform.email_logs.read` | ✓ | ✓ | — | ✓ | misc 7.2-7.4 |
| `platform.downloads.read` (global stats) | ✓ | ✓ | ✓ | — | misc 8.3-8.7 |
| `platform.leads.manage` (incl. FormSubmit webhook secret rotation) | ✓ | ✓ | ✓ | — | misc 6 |
| `platform.reports.revoke` (certificate revoke with reason) | ✓ | ✓ (ticket) | — | — | verify `revoked` status |
| `platform.health.detailed` | ✓ | ✓ | — | — | misc 11.3-11.4 |
Public (no principal, rate-limited): `public.contact_lead.create`, `public.formsubmit_webhook` (shared secret in URL, constant-time), `public.releases.check` (app update check), `public.downloads.record`, `public.certificates.verify`, `public.time`.

---

## 5. Feature toggles, quotas, capabilities

### 5.1 Toggles (per tenant, default OFF, sirf staff badle)

| Feature | OFF par | ON par | Gated v1 endpoints (+ .NET feature inventory jo inhe cover karta tha) |
|---|---|---|---|
| `subusers` | Sirf owner (single buyer). Member management APIs `403 feature.disabled`. Existing members (agar pehle ON tha): login blocked `403 feature.disabled`, data safe (D-34) | Owner/admin members bana sakte | `/api/v1/members/*` (sab), `/api/v1/members/{id}/resource-transfers`, `PUT /api/v1/devices/{id}/assignment` (member ko assign). Inventory: .NET `EnhancedSubuser*`, `Subuser/*`, `RoleBasedAuth/create-subuser|my-subusers|assign-role|...`, V2 subusers |
| `groups` | Groups/departments APIs 403; group_admin grants inactive (data safe) | Groups, departments, group admins | `/api/v1/groups/*`, `/api/v1/departments/*`, `?group_id=` filters on lists. Inventory: .NET `Group*`, `GroupDetails*`, `GroupMembers*`, `GroupManagement*`, `Department*`, V2 groups |
| `user_activity` | Har koi sirf apne sessions/activity dekhe (owner bhi sirf apne + tenant aggregates jisme kisi member ki identity nahi) | Owner/admin/GA members ki activity, sessions, performance dekh sakein | `/api/v1/activity/*` (dusron ka data), `GET /api/v1/tenant/summary` ke per-member breakdown fields. `/api/v1/me/sessions` hamesha allowed. Inventory: .NET `UserActivity*`, `LoginActivity*`, `EnhancedSessions*`, `Sessions*`, `ActivitySessions*`, `Performance*`, V2 sessions |
| `private_cloud` | Private cloud APIs 403; data shared DB mein (normal) | Tenant owner customer DB configure kar sake (platform-approved host policy) | `/api/v1/private-cloud/*` (D-13 ke baad). Inventory: .NET `PrivateCloud*` |

- Toggle change: `POST /api/v1/platform/tenants/{id}/features` (`platform.features.toggle`), body mein `reason` + `ticket_ref` required; `tenant_feature_changes` row + audit event; tenant `authz_version` +1 (turant lagu).
- Toggle OFF kabhi data delete/disable nahi karta (members ka status untouched; sirf access gate).
- **Product entitlements** (DSDE, DSDG, DSFE, DSFZ, DSAM, DSSC) toggles nahi: valid licence/credit pool se derive hote hain; check #2 ka hissa (`.product(P)`).

### 5.2 Quotas (per tenant, staff set; enforced in same transaction)
| Quota | Enforced kahan | Race safety |
|---|---|---|
| `max_members` (legacy `max_subusers`) | member create/enable | `SELECT ... FOR UPDATE` on `tenant_quotas` row + count in same tx |
| `max_groups` | group create/restore | same |
| `max_departments` | department create | same |
| `max_licenses` | per-device licence allocation/activation count | same |
NULL = unlimited (staff decision). Exceed = `409 quota.exceeded` with `quota` name. Migration mein agar current count > quota to quota = current (data delete nahi), report owner ko.

### 5.3 Per-member capabilities (narrowing masks; kabhi role se zyada power nahi dete)
| Capability | Default | Effect |
|---|---|---|
| `can_view_reports` | true | false = sirf apni khud ki reports (dusron ki nahi, chahe role allow kare) — D-32 |
| `can_manage_machines` | true for admin, false for member | false = `devices.update/assign/register` deny (register: member apne app device ke liye allowed rahe? D-32) |
| `can_assign_licenses` | true for owner/admin | false = `licenses.allocate/transfer` deny |
| `max_machines` | NULL (unlimited) | member ke active devices count limit (register/assign tx mein check) |
| credit allocation (`credit_allocations`) | none | Hai to `credits.consume` allocation ke andar; none = tenant setting `require_allocation` (default false: pool se) — D-33 |
Effective = role permissions ∩ capabilities. Owner ki capabilities hamesha full (owner ko koi narrow nahi kar sakta).

---

## 6. Enforcement in code (fail closed)

### 6.1 Route registration: policy ke bina route nahi
```rust
// api::router — sirf PolicyRouter se routes add hote hain; axum::Router::route direct use clippy disallowed_methods se band.
r.route(post("/api/v1/members"), members::create,
    Policy::member()
        .permission(Perm::MembersCreate)
        .feature(Feature::Subusers)
        .idempotent());

r.route(post("/api/v1/reports/drive/credit-checks"), reports::credit_check,
    Policy::member_or_device()
        .permission(Perm::CreditsConsume).device_scope(Scope::CreditsConsume)
        .product(Product::DriveEraser));

r.route(get("/api/public/reports/verify"), public::verify,
    Policy::public("public certificate verification; rate limited; masked fields"));
```
- `Policy` builder required; `cargo xtask route-policies --check` CI mein saare routes + policies ki report banata hai aur `docs/public-routes.txt` (reviewed list) se mismatch par fail.
- Startup par router build se pehle check: har route ki policy present; `Public` routes ka reason non-empty.

### 6.2 Principal and token separation
- Token verify `aud` + `typ` + `kid` → `Principal` variant. Route policy expected principal kinds batata hai (`member()`, `device()`, `staff()`, `cleaner()`); mismatch = 401.
- Keys alag per issuer: member/device ES256 key A, staff key B, cleaner key C. Ek key ka token dusre audience par verify hi nahi hota. Algorithm allowlist sirf ES256 (HS256/none kabhi accept nahi). .NET ke koi token Rust par valid nahi (legacy token acceptance core mein nahi).
- DSSC-style confusion impossible: cleaner tokens alag key + `aud=dsecure-cleaner` + `typ=cleaner`; member routes ka policy `member()` cleaner principal ko 401 deta hai.

### 6.3 Account state (login, refresh, har request)
| State | Login | Refresh | Har request |
|---|---|---|---|
| user `status` != active (suspended/disabled/erased) | 403 `account.inactive` | 401 | 401 (session revoked on change) |
| membership `status` != active | Us tenant mein login nahi; dusri membership ho to wahan | 401 | 401 |
| tenant `status` suspended/closed | 403 | 401 | 401 (staff exempt with grant) |
| `locked_until > now` | 423-like 403 `account.locked` (+ `Retry-After`) | 401 | — (lock sirf login par) |
| email not verified | 403 `account.email_unverified` (resend link) | 401 | 401 |
| `authz_version` mismatch (token old) | — | naya token new state se | **re-evaluate** from live state (role downgrade turant), token reject nahi zaroori; disable/delete par session revoke |
Lockout: per user 10 failed attempts / 15 min → `locked_until = now + 15 min` (exponential to 24h), plus per IP+email progressive delay (pre-auth limiter). Success par counter reset. Lock par user ko email (no PII in logs).

### 6.4 Immediate effect
- Har role/capability/status/group-admin/toggle/quota/suspension change: same tx mein `authz_version += 1` (membership/user) **aur** `authz_epochs` tenant epoch +1 (`DATABASE.md` §4.4). Likhne wala instance apni cache entry turant drop karta hai; baaki instances 2 s poller se changed epochs dekh ke us tenant ki entries drop karte hain (TiDB mein LISTEN/NOTIFY nahi). Poller down > 10 s = cache bypass (live load), deny nahi.
- High-risk policies (`devices.remote_wipe`, `members.delete`, `members.assign_role`, `tenant.ownership.transfer`, `credits.consume`, staff access) hamesha live state padhte hain (cache bypass): zero staleness.
- Disable/delete/demote-from-admin/password change: us user ke sessions `revoked_at` set + refresh token families revoke. Access token (15 min) bhi turant fail hota hai kyunki har request par `sid` session state live check hoti hai.

### 6.5 Disable vs delete
- **Disable:** status = disabled, sessions revoke, data untouched, reversible (`members.enable`).
- **Delete:** `DELETE /api/v1/members/{id}` body `{ transfer_to: <membership_id of parent/owner> }` **required** (explicit choice); same tx mein: devices `owner_membership_id`, licence allocations, credit allocations (balance return to pool), reports `owner_membership_id`, group memberships → transfer target; membership status `deleted` + `deleted_at` (soft); agar user ki koi aur membership nahi to identity PII tombstone (email_enc/name_enc overwrite, bidx random) — hard DELETE nahi. `performed_by` historical fields kabhi nahi badalte (certificate integrity).
- `transfer_to` missing = 400 (koi silent default nahi). Dashboard UI default suggestion = tenant owner, par user ko explicit choose karna padta hai.

### 6.6 Remote wipe aur destructive actions
| Control | Detail |
|---|---|
| Permission | `devices.remote_wipe` (dedicated; admin/owner; GA sirf explicit owner grant se) |
| Confirmation | Request body `confirm_device_id` == path device id **aur** `confirm_text` == device display name ka last 4 chars (UI dikhata hai) |
| Step-up | `X-Step-Up-Token` (5 min, single use, bound to `action=devices.remote_wipe` + `target=device_id` + session): password re-entry ya TOTP se `/api/v1/auth/step-up` |
| Audit | `device.remote_wipe.requested` (before), `.dispatched`, `.confirmed_by_device` events; reason optional field |
| Rate limit | Tenant: 5/hour, 20/day (config `RL_REMOTE_WIPE_*`); actor: 3/hour; exceed = 429 + alert to tenant owner email |
| Notification | Tenant owner ko email har wipe par |
| Same pattern | `members.delete`, `tenant.ownership.transfer`, `tenant.export_data`, `tenant.close`, `autopilot.connection.manage`, `private_cloud.manage`, bulk licence revoke (`licenses.transfer` bulk > 10) |

### 6.7 Tenant-scoped repositories (TiDB: no RLS, enforcement in the data layer)
```rust
pub struct TenantScope { tenant: TenantId, actor: MembershipId, visibility: Visibility, staff_grant: Option<GrantId> }
pub enum Visibility { Tenant, Groups(SmallVec<[GroupId; 4]>), SelfOnly }

impl DeviceRepo {
    pub async fn list(tx: &mut TenantTx<'_>, page: Page) -> Result<PageOut<Device>>;                 // visibility from tx.scope()
    pub async fn get(tx: &mut TenantTx<'_>, id: DeviceId) -> Result<Option<Device>>;                 // out of scope = None → 404
}
```
- `TenantTx` sirf `Db::tenant_tx(&Authorized)` (API) ya `Db::tenant_tx_for_job(&ClaimedJob)` (worker; tenant job row se) se banta hai; `TenantId` ka koi public constructor `db`/`auth` ke bahar nahi.
- Har query `crates/db/queries/**.sql` file mein; pehla bind `tenant_id` (tx se automatically, caller pass nahi karta). Visibility SQL: `Tenant` = `tenant_id=?`; `Groups` = `tenant_id=? AND owner_membership_id IN (SELECT membership_id FROM group_memberships WHERE tenant_id=? AND group_id IN (...)) AND <target rank> < 60`; `SelfOnly` = `tenant_id=? AND owner_membership_id=?`.
- Enforcement layers (detail `DATABASE.md` §2.2): L1 type-level TenantTx, L2 query files, L3 `xtask sql-lint` (har tenant table reference par `tenant_id = ?` conjunct, JOINs par bhi), L4 raw SQL `db` crate ke bahar `disallowed_methods` + grep, L5 `xtask schema-check` (tenant PK + har index `tenant_id`-leading), L6 row-tenant assert in mappers, L7 generated cross-tenant negative tests, L8 DB grants (no DELETE/DDL for app user).
- Directory tables (`membership_directory`, `license_key_directory`, `report_public_ids`) global lookups hain: unka result sirf `(tenant_id, id)` pointer hai; uske baad hamesha TenantTx khulta hai aur wahi visibility rules lagte hain. Public verify path `PublicVerifyTx` sirf masked columns ka named query chala sakta hai.
- Platform/staff queries: `PlatformTx` + `StaffScope { grant }`; tenant data padhne ke liye `Db::tenant_tx_for_staff(grant)` (grant active + tenant match check, har query audit with grant id).

---

## 7. Endpoint gating summary (v1)

| v1 resource | Check 1 (tenant/visibility) | Check 2 (toggle/entitlement) | Check 3 (permission) | Extra |
|---|---|---|---|---|
| `POST /auth/login`, `/auth/refresh`, `/auth/password/*`, `/auth/email/verify` | membership resolve (login) | — | Public (rate limited) | Account state §6.3 |
| `/me`, `/me/password`, `/me/sessions` | self | — | `profile.*`, `password.change_self`, `sessions.*_self` | password change = step-up (current password) |
| `/members/*` | tenant + rank visibility | subusers | `members.*` + `can_grant`/`can_manage` | quota `max_members`; delete needs `transfer_to` + step-up |
| `/groups/*`, `/departments/*` | tenant / GA own group | groups | `groups.*`, `departments.*` | quotas |
| `/activity/*` | visibility | user_activity | `activity.read_members`, `sessions.revoke_members` | — |
| `/devices/*` | visibility | product entitlement (agar product device) | `devices.*` | caps; `remote-wipe` = step-up + confirm + rate limit |
| `/device-enrollments`, `/device/token` | tenant | product | `devices.register` / device credential | device scopes §4.11 |
| `/licenses/*`, `/credits/*` | tenant/visibility | product | `licenses.*`, `credits.*` | allocation, quota `max_licenses` |
| `/reports/{p}/*` | tenant/visibility | product `p` | `reports.<p>.*`, `credits.consume` | idempotency keys |
| `/reports/{p}/{id}/certificate` | visibility | product | `reports.<p>.read` + cap `can_view_reports` | — |
| `/public/certificates/{id}` | — | — | Public (masked, rate limited) | — |
| `/autopilot/*` | tenant/visibility | DSAM | `autopilot.*` | connection manage = step-up |
| `/freeze/*` | tenant **token se** (koi tenant id body/path mein nahi) | DSFZ | `freeze.*` | — |
| `/cleaner/*` | cleaner account/tenant | DSSC | `cleaner.*` | key minting sirf platform |
| `/orders/*`, `/checkout/sessions` | tenant | — | `orders.read`, `billing.manage` | — |
| `/webhooks/dodo` | — | — | Public + signature + timestamp + idempotency | — |
| `/private-cloud/*` | tenant | private_cloud | `private_cloud.*` | manage = step-up |
| `/tenant/*` | tenant | — | `tenant.*` | export/ownership/close = step-up |
| `/platform/*` | staff grant (tenant data) | — | `platform.*` | MFA, audit with grant id |

_The list of legacy .NET endpoints that are intentionally not rebuilt is kept privately (`docs/private/`)._

## 8. Test plan (negative tests mandatory)

### 8.1 Fixtures (`testkit::world()`)
Do tenants A, B (har ek mein owner, admin, GA of group G1, member in G1, member in G2, viewer, disabled member, locked member, unverified member), single-buyer tenant C (sab toggles OFF), staff (superadmin with/without grant, support, billing, auditor), device token A (member-in-G1 operator), cleaner token, expired token, token signed with wrong key, HS256-forged token, `alg=none` token, staff token used on tenant routes, anonymous.

### 8.2 Generated matrix tests
- Route registry × principal fixtures → expected status `RBAC.md` §4 matrix se (table-driven `expected.rs`). 100% routes covered; naya route bina expectation = test fail.
- **Cross-tenant substitution:** har route jo id/email/serial/report id leta hai: A ka principal + B ka identifier → 404, aur B ka data response mein kabhi nahi (body scan for B fixture markers).
- **Body identity injection:** v1 DTOs mein `tenant_id`/owner email fields hote hi nahi (`deny_unknown_fields`); test: aise extra fields bhejo → 400, aur koi write B ke tenant mein nahi (DB assert). `member_id`/`group_id`/`device_id` jaise references B ke → 404.

### 8.3 Privilege escalation cases (har ek ka alag named test)
| # | Case | Expected |
|---|---|---|
| E1 | Admin grants admin/owner | 403 `members.rank` |
| E2 | Member/viewer calls any members.* write | 403 |
| E3 | Self role change / self capability change / self enable | 403 |
| E4 | Admin disables/deletes/resets password of another admin or owner | 403 |
| E5 | Demote/disable/delete last owner (concurrent 2 requests bhi) | 409 `members.last_owner`; exactly one owner remains |
| E6 | GA reads/manages member of another group | 404 |
| E7 | GA reads owner/admin profile ya unke devices/reports | 404 |
| E8 | GA creates group admin / assigns role | 403 |
| E9 | Member lists members → sirf self | 200 [self] |
| E10 | `can_view_reports=false` member reads others' reports (role allow kare tab bhi) | 404/empty |
| E11 | `can_manage_machines=false` device assign | 403 |
| E12 | `max_machines` exceed (parallel register) | 409 `quota.exceeded` exactly at limit |
| E13 | `max_members`/`max_groups`/`max_departments`/`max_licenses` exceed with parallel creates | exactly limit rows |
| E14 | Feature OFF: subusers/groups/user_activity/private_cloud endpoints | 403 `feature.disabled` |
| E15 | Tenant owner toggles feature / changes quota | 403 (platform only) |
| E16 | Role downgrade → same token next request | new permissions (403 where applicable) |
| E17 | Disable user → same token next request; refresh | 401; 401 |
| E18 | Locked / unverified / suspended tenant login + refresh | 403/401 |
| E19 | Remote wipe without step-up; with step-up for another device; replayed step-up; over rate limit | 403; 403; 403; 429 |
| E20 | Device token on dashboard/member/admin/platform routes | 401/403 |
| E21 | Cleaner token on member routes; staff token on tenant routes without grant; member token on platform routes | 401 / 403 / 401 |
| E22 | Token with wrong `aud`/`kid`/alg confusion (HS256 signed with public key, `none`), .NET-issued token | 401 |
| E23 | Staff without active grant reads tenant data; expired grant | 403 + audit `staff.access.denied` |
| E24 | Staff with grant: every request audited with grant id | audit row exists |
| E25 | Mass assignment: `role`, `status`, `tenant_id`, `user_role`, `is_*_enabled`, quotas in body of create/update | ignored (DB unchanged) |
| E26 | Delete member without `transfer_to` / transfer to other tenant's member | 400 / 404 |
| E27 | Ownership transfer without step-up | 403 |
| E28 | Credits consume beyond allocation / from revoked or expired lot / another tenant's pool | 409 / 409 / 404 |
| E29 | Data-layer bypass: (a) query file without `tenant_id = ?` → `sql-lint` fail; (b) tenant table with non-tenant-leading index → `schema-check` fail; (c) mapper receives row of other tenant (fault-injected) → 500 + alert, no data; (d) `sqlx::query` outside `db` crate → clippy fail | CI fail / 500 |
| E30 | Unknown permission / policy evaluation DB error | deny (403/503), never allow |
| E31 | Two concurrent last-owner demotions on MySQL **and** TiDB (no gap locks) | exactly one succeeds, 409 for other |
| E32 | Quota race (`max_members` = N, 20 parallel creates) on TiDB | exactly N rows (tenant_quotas mutex) |
| E33 | Role demoted on instance A; next request on instance B within 3 s; high-risk action immediately | permission removed ≤ poll interval; high-risk denied immediately (live read) |
| E34 | Directory lookup (licence key / public report id / membership) returns tenant B pointer while caller in tenant A | 404 (TenantTx re-check), no B data |

### 8.4 Property tests
`can_grant`/`can_manage` ke liye proptest: random actor/target roles → kabhi `target_rank >= actor_rank` allow nahi; GA kabhi group ke bahar allow nahi.

### 8.5 Gate
Phase exit tabhi jab us phase ke saare routes matrix + E-cases green hon (`MIGRATION_PLAN.md`).

---

## 9. Legacy → new mapping (data migration)

_Legacy (.NET) role/data mapping and the closed .NET RBAC decisions are kept in a private document (`docs/private/`, not in the public repo)._

## 11. Not verified
- Live DB mein `user_role`, `subuser.Role`, `SubuserRoles` values ka distribution, kitne Users rows asal mein ek hi org ke hain, `Groups` ka creator column.
- .NET `EnhancedMachines/by-mac/{mac}/erase` aaj kaun call karta hai (dashboard ya app) — v1 mein remote wipe dashboard se step-up ke saath hi hoga.
- `GroupMembers.Role` ke values.
