# Render staging setup (DSecure Rust API)

For the owner. Step by step, from an empty TiDB Cloud staging database to a running Render web service.
Updated 21 Oct 2026. Every step says whether it was **verified** (and how) or is **not verified**.
Nothing here was run against TiDB Cloud or Render: the agents that wrote it have no access to either.

Files: `render.yaml` (Blueprint), `docker/Dockerfile`, `.dockerignore`, `docs/ops/db_users.sql`,
`xtask/src/provision_keys.rs` (`cargo xtask provision-keys`), `crates/api/src/ops/` (`dsecure-api migrate`,
`dsecure-api staff-bootstrap`).

## 0. Former blockers (resolved in code, 21 Oct 2026)

| # | Was | Now |
|---|---|---|
| B1 | No migration command for a remote DB. | `dsecure-api migrate [--status]` (`crates/api/src/ops/migrate.rs`), migrator user from `MIGRATOR_DATABASE_URL` only. Run from your machine before each deploy (step 4). |
| B2 | No first-staff bootstrap, so `seed-db` had no approver. | `dsecure-api staff-bootstrap --email .. --password-env VAR` (`crates/api/src/ops/staff_bootstrap.rs`), interactive; prints the user id to use as `--approver` (step 6). |
| B3 | `dsecure_platform_admin` too long for TiDB Serverless (`<prefix>.` + name <= 32). | DB users are now `rs_mig`, `rs_app`, `rs_wrk`, `rs_ro`, `rs_padm`, `rs_ret`. The platform-admin pool accepts `CURRENT_USER()` = `rs_padm` or `<prefix>.rs_padm` only. |

Remaining open points are marked "not verified" in the steps.

**Order:** 1 database + migrator user, 2 keys file, 3 local operator shell, 4 migrate, 5 app and
platform-admin users, 6 staff-bootstrap, 7 seed-db, 8 Render service + env, 9 deploy, 10 verify,
11 keep-alive, 12 memory check. The keys file (2) comes before migrate (4) because every
`dsecure-api` command loads and validates the FULL staging configuration first, KEK variables included.

## 1. Staging database and migrator user (TiDB Cloud) — not verified

Which cluster (owner rule): the staging database `dsecure_rs_staging` goes on the **TESTING** TiDB cluster
(the one behind the .NET testing connection) or on a new cluster you create for staging. Never on the
production cluster, and never in `Cloud_Erase__App` or any other `Cloud_Erase*` database (every tool here
refuses those names). In the TiDB Cloud console open that cluster, SQL editor, as the cluster root user.

Note the cluster user prefix shown under "Connect" (looks like `xxxxxxxxxxxxxxx.root`). Below it is
written `<prefix>`. Passwords: generate long random ones, keep them only in your password manager.

```sql
CREATE DATABASE IF NOT EXISTS dsecure_rs_staging CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;

-- Migrator (docs/ops/db_users.sql section 1, database name replaced)
CREATE USER IF NOT EXISTS '<prefix>.rs_mig'@'%' IDENTIFIED BY '<MIGRATOR_PASSWORD>';
GRANT SELECT, INSERT, UPDATE, CREATE, ALTER, INDEX, DROP
  ON `dsecure_rs_staging`.* TO '<prefix>.rs_mig'@'%';
```

`REQUIRE SSL` from `db_users.sql` is left out: TiDB Cloud Serverless enforces TLS on its public endpoint
(whether it accepts `REQUIRE SSL` is not verified). The application enforces TLS itself anyway.

**URL format** (every user):

```
mysql://<prefix>.<user>:<password>@<host>:4000/dsecure_rs_staging?ssl-mode=VERIFY_IDENTITY
```

- Exactly one `ssl-mode=VERIFY_IDENTITY`; no `ssl-ca` / `sslcert` keys in the URL (refused; the CA comes
  only from `DB_TLS_CA`). Staging refuses anything else (`config` crate, verified by its unit tests).
- Percent-encode special characters in the password. The `.` in the user name is fine.
- CA bundle: in the container `DB_TLS_CA=/etc/ssl/certs/ca-certificates.crt` (Debian bundle in
  distroless/cc; TiDB Cloud Serverless uses a publicly trusted CA); on your machine a PEM bundle file
  (TiDB Cloud "Connect" dialog links one). Both not verified.

## 2. Generate the staging keys file — verified locally

On your machine, in the `dsecure-rs` folder:

```
cargo xtask provision-keys
```

- Writes `<repo>/.dev/staging.keys.env` (anchored at the repository root, whatever folder you run it
  from; `.dev/` is gitignored). The tool refuses any path inside the repository that git would not ignore,
  and refuses to run when git is not available (unless `--allow-no-git`, for a path outside any repository).
  Other location: `--out <file>`.
- Safe write: a temp file is created owner-only (unix 0600; Windows ACL reduced to your user and checked)
  BEFORE the secret is written; if the permissions cannot be set, the temp file is deleted and nothing is
  written. Then an atomic rename. A symlink as target is refused.
- Existing file: refused unless `--force`. With `--force` the old file is kept as
  `staging.keys.env.bak-<UTC time>-<hex>` (it still contains the OLD secret) and a loud warning is printed:
  if the old KEK was already used (staff-bootstrap / seed-db ran, or Render has it), data under it is
  unreadable without the old file. `seed-db` refuses a database whose DEKs were made with another KEK.
- Prints (to stderr, nothing to stdout) only the KEK id, the two JWT key ids and the file path.
- Contents: `KEK_PROVIDER=env`, `KEK_ENV_ACTIVE_ID=STAGING_<hex>`, `KEK_ENV_STAGING_<hex>=<secret>`,
  `JWT_SIGNING_KID_MEMBER`, `JWT_SIGNING_KID_STAFF`. No dev marker in any id, so the staging startup
  check (`crypto::DevKeyCheck`) accepts them.
- The signing **private** keys are not in this file: by design they exist only inside `signing_keys`,
  encrypted with a platform DEK that is wrapped by this KEK. Step 7 creates them there.
- Keep the KEK safe (password manager or offline). If it is lost, every DEK in `data_keys` and all data
  encrypted under them becomes unreadable. Never paste it into chat, tickets or this repository.

Verification: unit tests in `xtask/src/provision_keys.rs` (ids not dev fingerprints; staging
`AppConfig::load_with(.., &[&DevKeyCheck])` and `api::startup::load` accept the generated values; the
report never contains the secret, also with `--force`; no overwrite without `--force`; `--force` keeps a
backup; an injected permission failure writes nothing and leaves the old file intact; Windows ACL is
owner-only; non-ignored path refused). One manual run to a temp folder (stdout empty, secret not in
stderr) was done before the safe-write changes.

## 3. Local operator shell (Windows PowerShell) — not verified

`dsecure-api migrate` and `staff-bootstrap` run from your machine with the FULL staging configuration
(same validation as the server: TLS + CA, `DB_EXPECT_ENGINE=tidb`, dev-key refusal, legacy-DB refusal).
Use one PowerShell window for steps 4 to 7 and close it afterwards; nothing is written to disk.

```powershell
cd "D:\D-Secure Office  Work\Private\dsecure-rs"
# keys file -> environment of THIS window only (values are not printed)
Get-Content .dev\staging.keys.env | Where-Object { $_ -match '^[A-Z_][A-Z0-9_]*=' } |
  ForEach-Object { $k, $v = $_ -split '=', 2; Set-Item -Path "Env:$k" -Value $v }
# non-secret staging settings (same values as render.yaml)
$env:DSECURE_ENV = "staging"
$env:DB_EXPECT_ENGINE = "tidb"
$env:DB_TLS_CA = "C:\path\to\ca-bundle.pem"
$env:JWT_ISSUER = "https://dsecure-api-staging.onrender.com"
$env:TRUSTED_PROXY_HOPS = "1"; $env:TRUSTED_PROXY_CIDRS = "10.0.0.0/8"
$env:BLOB_BACKEND = "fs"; $env:BLOB_FS_ROOT = "$env:TEMP\dsecure-blobs"
# URLs, typed and masked (PowerShell 7). Step 4 needs DATABASE_URL + MIGRATOR_DATABASE_URL;
# steps 6-7 also PLATFORM_ADMIN_DATABASE_URL (rs_app / rs_padm exist only after step 5).
$env:MIGRATOR_DATABASE_URL       = Read-Host -MaskInput "rs_mig URL"
$env:DATABASE_URL                = Read-Host -MaskInput "rs_app URL"
$env:PLATFORM_ADMIN_DATABASE_URL = Read-Host -MaskInput "rs_padm URL"
```

Windows PowerShell 5.1 has no `-MaskInput`; per URL use (also masked):

```powershell
$s = Read-Host -AsSecureString "rs_mig URL"
$env:MIGRATOR_DATABASE_URL = [System.Net.NetworkCredential]::new("", $s).Password
Remove-Variable s
```

`DATABASE_URL` must already be set for step 4 (the configuration requires it), even though `migrate`
connects only as the migrator; the `rs_app` user itself is created in step 5.

How to run the binary locally: `cargo run -p api --release --bin dsecure-api -- <command>` (the first
build takes a while). Verified on this Windows machine only in a debug build with `-- help` (prints the
usage, exit 0); the release build and the real commands against TiDB are not verified.

## 4. Run migrations — before EVERY deploy — not verified against TiDB

Schema changes always go to the database before the code. Migrations never run at server startup
(ARCHITECTURE.md line 230, DATABASE.md §11.1), and the Render free plan has no pre-deploy hook, so you run
them from the operator shell (step 3):

```powershell
cargo run -p api --release --bin dsecure-api -- migrate --status   # exit 3 = pending, 0 = up to date
cargo run -p api --release --bin dsecure-api -- migrate            # applies them (lock row + heartbeat)
cargo run -p api --release --bin dsecure-api -- migrate --status   # expect "up to date"
```

Exit codes: 0 ok, 1 failure, 3 pending (`--status`), 75 another migrator holds the lock (retry later),
78 configuration refused. Output shows versions only. Do not apply the SQL files by hand or with
`sqlx-cli`: the runner has its own version numbers and checksums, and `/health/ready` compares them.

## 5. App and platform-admin users — not verified

After step 4 (table-level GRANTs need the tables to exist). From `docs/ops/db_users.sql`: section 2 (all
`GRANT ... TO 'rs_app'@'%'` lines) and section 4b (`rs_padm`), with `dsecure_prod` replaced by
`dsecure_rs_staging` and every `'rs_...'@'%'` by `'<prefix>.rs_...'@'%'`:

```sql
CREATE USER IF NOT EXISTS '<prefix>.rs_app'@'%'  IDENTIFIED BY '<APP_PASSWORD>';
CREATE USER IF NOT EXISTS '<prefix>.rs_padm'@'%' IDENTIFIED BY '<PLATFORM_ADMIN_PASSWORD>';
-- then every GRANT line of sections 2 and 4b, e.g.
GRANT SELECT, INSERT, UPDATE ON `dsecure_rs_staging`.`tenants` TO '<prefix>.rs_app'@'%';
GRANT SELECT, INSERT ON `dsecure_rs_staging`.`audit_events` TO '<prefix>.rs_padm'@'%';
```

To regenerate the exact lines: `cargo test -p db print_grants -- --ignored --nocapture` (prints them for
`dsecure_prod`; replace database and user names as above). The worker (`rs_wrk`), read-only (`rs_ro`)
and retention (`rs_ret`) users are not needed for this deploy: `render.yaml` runs the job runner inside
the api process (`RUN_MODE=all`) with `rs_app`.

Verify (read-only): `SHOW GRANTS FOR '<prefix>.rs_app'@'%';` must show no DELETE and no DDL.

## 6. First platform superadmin (`staff-bootstrap`) — not verified against TiDB

In the operator shell (step 3), in an **interactive terminal** (the command refuses otherwise, so the
TOTP secret and recovery codes never land in a log):

```powershell
$env:STAFF_BOOTSTRAP_PASSWORD = Read-Host -MaskInput "new staff password (min 12 chars)"
cargo run -p api --release --bin dsecure-api -- staff-bootstrap --email you@example.com --password-env STAFF_BOOTSTRAP_PASSWORD
Remove-Item Env:STAFF_BOOTSTRAP_PASSWORD
```

- Uses `DATABASE_URL` (`rs_app`) and `PLATFORM_ADMIN_DATABASE_URL` (`rs_padm`).
- Works exactly once (exit 4 otherwise). The guarantee is atomic: ONE platform-admin transaction writes
  the singleton marker row `platform_bootstrap(id = 1)` (a second, even concurrent, bootstrap fails on its
  primary key; migration `0880_0001`, so step 4 must have run with this code's migrations), re-checks
  that `platform_staff` is empty, inserts the missing platform DEKs, the `platform_superadmin` row and the
  audit row (which lists the created DEK ids and the KEK id). The "no staff yet" check before the TOTP
  step is only a cheap pre-check.
- KEK guard before anything is written (same shared code as step 7): existing platform DEKs must be
  wrapped by YOUR KEK and unwrap with it, else it stops (exit 78) and writes nothing. New DEKs are only
  committed together with the staff row, so an aborted run never leaves DEKs behind. Step 7 then
  normally reports `platform DEKs created: 0`.
- If anything fails after your TOTP code was accepted, the tool first re-checks on a fresh connection
  whether the final transaction committed anyway (a dropped connection can hide a successful COMMIT). If
  it did, you see `NOTE: ... the bootstrap IS committed ... Continuing.` and get your recovery codes as
  normal. If it did not, the new user is set back to `disabled` (no staff row, no membership).
- Re-running after an abort: on a fresh database the SAME email works again (the leftover row's email
  index was made with a key that was never committed). Only if platform DEKs already existed before the
  run does it answer "a user with this email already exists": then use another email.
- `staff-bootstrap failed: ...; ALSO could not set user <uuid> back to disabled` (`RevertFailed`, exit 1):
  that user is active but has no staff row and no membership, so nothing accepts its login. Still disable
  it. This is a manual change to existing data, so **only with the owner's explicit approval**, as
  `rs_app`, scoped to that one id (replace `<uuid>` with the printed id, hyphens are fine):

  ```sql
  UPDATE users
     SET status = 'disabled', authz_version = authz_version + 1,
         tokens_valid_after = UTC_TIMESTAMP(6), updated_at = UTC_TIMESTAMP(6), version = version + 1
   WHERE id = UUID_TO_BIN('<uuid>') AND status = 'active'
     AND NOT EXISTS (SELECT 1 FROM platform_staff WHERE user_id = UUID_TO_BIN('<uuid>'));
  -- expect "1 row affected"; 0 rows = already disabled or it IS staff: stop and check.
  ```
  Same columns as the code path (`auth_account::set_user_status`; ids are stored as the 16 UUID bytes in
  standard order, which `UUID_TO_BIN(x)` without the swap flag produces). Not run against TiDB
  (`UUID_TO_BIN` availability there not verified; fallback: `UNHEX(REPLACE('<uuid>','-',''))`).
- `... could not check whether the bootstrap of user <uuid> committed` (`OutcomeUnknown`, exit 1): the
  user was left active and the codes were shown. Check read-only:
  `SELECT HEX(user_id) FROM platform_bootstrap WHERE id = 1;` If it shows that id (without hyphens), the
  bootstrap is done. If there is no row, run `staff-bootstrap` again.
- Shows the TOTP enrolment (scan it in your authenticator), asks for a code, then prints the recovery codes
  once. Store them offline.
- At the end it prints `platform_superadmin user id: <uuid>`: that is the `--approver` for step 7.
- Unset the password variable afterwards (last line above). Details: `crates/api/src/ops/staff_bootstrap.rs`.

## 7. Signing keys into the database (`seed-db`) — verified only against a local scratch MySQL

Same operator shell. The URL is read from an environment variable whose NAME you pass; the tool never
accepts a URL on the command line (and refuses `--db-url`). `DB_TLS_CA` is read from the environment.

```powershell
cargo xtask provision-keys seed-db `
  --keys-file .dev/staging.keys.env `
  --db-url-env PLATFORM_ADMIN_DATABASE_URL `
  --approver <platform_superadmin user id from step 6> `
  --owner-approval-ref <your written approval reference, e.g. ledger id>
```

What it does, all in **one transaction / one commit**:
1. Refuses the legacy database (`Cloud_Erase__App`, any case or encoding) and any `cloud_erase*` name,
   requires `ssl-mode=VERIFY_IDENTITY` and a CA, and (on connect) checks that the server user really is
   `rs_padm` / `<prefix>.rs_padm` and the engine is TiDB.
2. KEK guard, before anything is written (`db::repo::keys::plan_platform_deks`, shared with step 6): every existing active platform DEK must be wrapped by THIS KEK
   (same KEK id, and it must unwrap). Otherwise it stops and writes nothing. This prevents a database
   with DEKs under two different KEKs, which could not be repaired without DELETE.
3. Opens the platform-admin transaction for `platform.keys.rotate` (ops-CLI variant): the claimed
   approver must be an ACTIVE `platform_superadmin` (checked inside the transaction) and the approval
   reference is mandatory.
4. Inside that transaction: re-checks the planned DEK state and creates the platform DEKs that are
   still missing (normally none after step 6), then the ES256 member and staff JWT keys with the ids from the file and an Ed25519
   report-signing key (`report-<hex>`, printed), plus one audit row. Commit. Any failure rolls back all of
   it.
5. Runs the same JWT key check the api runs at startup (`api::keys::load_jwt`).

A second run with the same file fails (key id already taken) and changes nothing. A keys file with a
different KEK is refused by the guard. Limitation: the guard sees only ACTIVE platform DEKs; a fresh
staging database has no other kind.

Audit honesty: the approver UUID is only **claimed** by whoever runs the tool with the `rs_padm`
password; there is no staff login, session or MFA behind it, so it is not cryptographically proven. The
audit row says so: `actor_kind=system`, no `actor_id`, metadata `"actor": "ops_cli"`,
`"claimed_approver"`, `"approver_proof": "claimed"`, `"owner_approval_ref"`, the key ids and the DEK ids
it created (`db::platform_admin::PlatformAdminDb::ops_tx_owner_approved`). The API path
(`admin_tx_owner_approved`) still requires an authenticated staff row.

Verification:
- `xtask` test `seed_db_on_local_scratch_as_platform_admin_user`: local MySQL scratch database
  (`db::testing`, dropped afterwards) with a scratch DB user that has ONLY the generated platform-admin
  grants. Row counts of `signing_keys`, `audit_events` and `data_keys` are unchanged after every
  refusal: non-staff approver, missing approval reference, one DEK pre-made with KEK A then seeding with
  KEK B, re-run, wrong approver, wrong KEK. Success with KEK A creates exactly the 4 missing DEKs, 3 keys
  and 1 system audit row with the claimed approver; the app user then loads the keys like startup; a
  later run with all DEKs present creates 0 DEKs, 3 keys, 1 audit row.
- `db` test `ops_cli_tx_audits_claimed_approver_and_writes_deks_atomically`: refusals of non-ops audit
  rows, missing reference, non-staff approver; the API path still refuses an ops row; a DEK inserted in the
  ops transaction disappears on rollback and stays on commit; a transaction for another permission
  cannot touch `data_keys`.
- Not run against TiDB.

Close the operator shell afterwards (it holds the URLs and the KEK in its environment).

## 8. Render: create the service from the Blueprint — not verified

1. Render dashboard -> New -> Blueprint -> connect the `dsecure-rs` GitHub repository, branch `main`.
   Render reads `render.yaml`: one Docker web service `dsecure-api-staging`, plan `free` (512 MB; keep it awake with a cron-job.org ping to `GET /health/live` every 5-10 min),
   region `singapore` (change it to the region nearest your TiDB cluster), health check `/health/ready`,
   auto deploy off.
2. Render asks for every `sync: false` value. Enter them yourself:
   - `DATABASE_URL`: the **app user** URL (`<prefix>.rs_app`), format from step 1.
   - `KEK_ENV_ACTIVE_ID`, `JWT_SIGNING_KID_MEMBER`, `JWT_SIGNING_KID_STAFF`: copy from `.dev/staging.keys.env`.
3. Service -> Environment -> Add Environment Variable (mark it secret if offered):
   key `KEK_ENV_<the KEK_ENV_ACTIVE_ID value>`, value = the secret from the same line of the file.
   A Blueprint cannot declare this key because its name is generated.
4. NOT on Render: `MIGRATOR_DATABASE_URL` and `PLATFORM_ADMIN_DATABASE_URL`. The server only needs the
   app user; the other two are used only by `migrate`, `staff-bootstrap` and `seed-db` from your machine.
5. Check the non-secret values in `render.yaml`:
   - `JWT_ISSUER` must equal the service's real public URL (`https://dsecure-api-staging.onrender.com`
     assumed; not verified).
   - `TRUSTED_PROXY_HOPS=1` / `TRUSTED_PROXY_CIDRS=10.0.0.0/8`: **UNVERIFIED assumption** about where
     Render's proxy connects from. Two risks: (1) any other host in 10/8 that can reach the container
     directly could send a fake `X-Forwarded-For` (fake client IPs for rate limits and audit IP hashes);
     (2) if the proxy is not in 10/8, the header is ignored and all clients share the proxy's rate-limit
     bucket. Check it after the first deploy (step 10, "proxy check") and narrow the range if you can.
   - `OPENAPI_PUBLIC=false`: the API description is not served publicly on staging.
   - `BLOB_BACKEND=fs`, `BLOB_FS_ROOT=/tmp/dsecure-blobs`: ephemeral disk, staging only.

Decision recorded in `render.yaml`: one container (`RUN_MODE=all`, D-02 recommendation for Phase 0-2).
The Phase 0 job runner only has outbox/idempotency jobs; a second Render service would be a second
512 MB instance. Revisit when heavy workers (PDF, imports) arrive.

## 9. Deploy — not verified

First run step 4 (`migrate --status` must say up to date). Then Render -> Manual Deploy -> Deploy latest
commit. The Docker build runs on Render's builders (`rust:1.99.1-bookworm` ->
`gcr.io/distroless/cc-debian12:nonroot`). Startup order and failure codes: `crates/api/src/startup.rs`
(exit 78 = configuration refused; the log line names the key, never the value). Common causes: dev keys
(`KEK_ENV_ACTIVE_ID` / kid refused), missing `KEK_ENV_<id>`, URL without `ssl-mode=VERIFY_IDENTITY`,
missing `DB_TLS_CA`, JWT keys not seeded (step 7), platform DEKs missing (steps 6/7).

The Docker build was not run locally (no Docker on the dev machine): image tags, build success and image
size are not verified.

## 10. Verify health — not verified

```
curl -s https://dsecure-api-staging.onrender.com/health/live
# {"status":"ok"}
curl -s -i https://dsecure-api-staging.onrender.com/health/ready
# HTTP 200, {"status":"ok","checks":{"db":"ok","keys":"ok","migrations":"ok"}}
curl -s https://dsecure-api-staging.onrender.com/.well-known/jwks.json
# two ES256 keys with the kids from the keys file
```

`/health/ready` answers 503 `degraded` while any check fails (e.g. `migrations: fail` = step 4 missing).
It also answers 503 during a short DB outage (2 s probe timeout, result cached 5 s). Because it is the
Render health check, a DB blip of a minute or so can make Render mark the instance unhealthy and restart
it (Render's exact thresholds not verified). Kept on purpose: an instance that cannot reach its database
should not get traffic. Watch the Render "Events" tab for such restarts.

Proxy check for `TRUSTED_PROXY_*` (after the first deploy; staging only; not verified). The api never logs
client IPs, so test the rate limiter instead:
1. From your PC, send failed logins (`POST /api/v1/auth/login` with an unknown email) until you get 429.
2. From a different network (e.g. a phone hotspot), send one login. A 429 there means all clients share one
   bucket: the proxy is not in `TRUSTED_PROXY_CIDRS` (risk 2).
3. Back on your PC (still limited), send the same request with the header `X-Forwarded-For: 203.0.113.7`.
   If it is no longer limited, a client-supplied header is trusted: fix `TRUSTED_PROXY_HOPS` /
   `TRUSTED_PROXY_CIDRS` before anything else (risk 1).
4. Wait for the limit window to pass before testing again.

## 11. Keep the free instance awake — not verified

The free plan sleeps after about 15 minutes without traffic (the next request waits for a cold start).
Keep it awake with a free external cron, e.g. cron-job.org:
1. Create a cron job: URL `https://dsecure-api-staging.onrender.com/health/live`, method GET, every
   5-10 minutes, no authentication, no extra headers.
2. Use `/health/live`, not `/health/ready`: `/health/live` needs no auth and runs no DB query, so the pings
   cost no TiDB request units and do not depend on the database.
3. The free plan has about 0.1 CPU (Render's figure; not verified). Argon2id password hashing (19 MiB,
   t=2 per login) will make logins slow there, possibly seconds; not measured. A login that waits more
   than 2 s for a hashing slot gets 503.
4. Free-plan monthly instance-hour limits may matter for an instance that never sleeps (not verified).

## 12. Memory check against 512 MB — not verified

Budget (ARCHITECTURE.md §12): idle RSS 30-80 MB, hard ceiling 350 MB under load, alert at 300 MB.

1. Render -> service -> Metrics -> Memory: note the idle value 10 minutes after the deploy.
2. Light load from your machine (staging only), e.g. the local load test (`docs/LOADTEST_LOCAL.md`,
   `loadtest/run.ps1`) pointed at the staging URL, or a few hundred logins, then read the peak.
3. Pass: idle < 80 MB and peak < 350 MB, no restarts ("Events" tab shows no OOM). The Prometheus
   endpoint is bound to `127.0.0.1:9464` inside the container and is not reachable from outside by design.
4. If close to the limit: lower `LOGIN_HASH_CONCURRENCY` (3 x 19 MiB Argon2) or `DB_MAX_CONNECTIONS`.

## 13. After setup

- Move `.dev/staging.keys.env` offline (password manager) or delete it once the values are in Render.
- Before every later deploy: step 3 shell + step 4 (`migrate --status`, `migrate`).
- The KEK is the root of all staging encryption: rotating it needs a re-wrap of `data_keys` (no tool yet).
- Production is different: `KEK_PROVIDER=env` and `BLOB_BACKEND=fs` are refused there.
