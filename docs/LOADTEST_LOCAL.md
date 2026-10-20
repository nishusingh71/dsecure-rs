# P0-17: local load estimate (Windows, no Docker)

Status: measured 20 Oct 2026 on the dev laptop. This is an **estimate**, not the acceptance test of
`PHASE0_SPEC.md` §9.5. The real test (512 MB cgroup, jemalloc, Render-like CPU share) still needs
Docker or the Render staging service.

## What was measured, and what it is not

| Fact | Value |
|---|---|
| Host | Windows 11, x86_64, 12 logical CPUs, no Docker |
| Build | `cargo build --release -p api -p testkit` (release profile: thin LTO, `panic = abort`, stripped) |
| Allocator | Windows system allocator. jemalloc is Linux-only here (`crates/api/Cargo.toml`), so the allocator row of P0-17 is **not** covered |
| Memory cap | **None.** There is no 512 MB cgroup / container limit on this host. The numbers show how much memory the process uses, not that it survives 512 MB |
| Server under test | the real `dsecure-api.exe` as a child process (`RUN_MODE=api`, `DSECURE_ENV=dev`, `DB_MAX_CONNECTIONS=8`, 2 tokio workers, `LOGIN_HASH_CONCURRENCY=3`, Argon2id m=19456 t=2 p=1) |
| Database | local MySQL 8.4 on 127.0.0.1:3307, scratch database `dsecure_t_*` created and dropped by the driver (TiDB never used). MySQL, not TiDB: DB latency is far lower than TiDB Serverless over TLS |
| Load generator | same machine (`dsecure-loadtest`, hyper client, keep-alive), so it competes for CPU with the server; loopback network, no TLS, no reverse proxy |
| RSS | working set of the api process (PowerShell `Get-Process`, sampled every ~50 ms) plus the OS lifetime peak (`PeakWorkingSet64`). Windows working set is close to, but not identical to, Linux RSS. The "private bytes" value printed by the driver was 2.2 MiB and is not credible; ignore it |
| Rate limits | the server's default `Rules` stay ON. Burst A uses a different client address (`X-Forwarded-For`, trusted from 127.0.0.0/8) and a different user per request so the per-IP/per-network login limits do not hide the hash pool. Burst B uses one client address |

Run it yourself (repo root, local MySQL running):

```powershell
powershell -File loadtest\run.ps1                       # 50 logins, /me at 100 rps for 30 s
powershell -File loadtest\run.ps1 -Logins 300 -Seconds 5 # push the hash pool into 503
```

Driver source: `crates/testkit/src/bin/loadtest.rs` (bin `dsecure-loadtest`). On Linux the same
driver reads `/proc/<pid>/status` (VmRSS / VmHWM), so it can be reused inside the Docker test.

## Results

### Run 1: the §9.5 scenario (50 parallel logins, `/me` 100 rps x 30 s)

```
idle RSS (max of 10 samples after 3 s): 15.7 MiB; startup peak WS 29.0 MiB
single unloaded login (Argon2 m=19456 t=2 p=1): 73 ms
burst A (distinct clients): statuses [200:50], wall 1.06 s, latency p50 588 ms max 1056 ms; peak RSS 76.7 MiB, 5 s after burst 18.3 MiB
burst B (one client IP):    statuses [200:30 429:20], wall 0.54 s; peak RSS 76.4 MiB
GET /api/v1/me 100 rps x 30 s: 3000 requests, all 200, 0 transport errors, achieved 100.0 rps
  latency ms: p50 0.74  p95 0.98  p99 1.17  max 3.64; RSS during run max 18.7 MiB
OS lifetime peak working set: 76.7 MiB
```

### Run 2: stress (300 parallel logins, `/me` 100 rps x 5 s)

```
idle RSS: 11.1 MiB; startup peak WS 29.0 MiB
single unloaded login: 219 ms (cold; run 1 measured 73 ms)
burst A (distinct clients): statuses [200:128 503:172], wall 3.37 s, latency p50 178 ms max 3358 ms; peak RSS 79.2 MiB, 5 s after burst 18.2 MiB
burst B (one client IP):    statuses [200:30 429:270], peak RSS 67.6 MiB
GET /api/v1/me 100 rps x 5 s: 500 requests, all 200; p50 0.78  p95 1.23  p99 2.89  max 7.07 ms
OS lifetime peak working set: 79.2 MiB
```

## Comparison with the targets (`PHASE0_SPEC.md` §9.5, `ARCHITECTURE.md` §12)

| Target | Measured here | Verdict on this host | Caveat |
|---|---|---|---|
| Idle RSS <= 80 MB | 11 to 16 MiB (startup peak 29 MiB) | meets it with a wide margin | Windows allocator, local MySQL, 8-connection pool not yet warm with real traffic; no OTLP exporter configured; no jemalloc |
| 50 parallel logins: RSS < 350 MB, 503 instead of OOM | peak 77 MiB for 50, 79 MiB for 300; 503 appeared at 300 (172 of 300), 429 from the per-IP limiter for one client | memory stays bounded (3 Argon2 slots x 19 MiB + queue), the 503 path works | The 50-login burst finished inside the 2 s hash-wait budget on this 12-CPU machine, so it produced 200s, not 503s. On the small Render CPU share (hash time target 150 to 300 ms, §12.8) the same burst will mostly produce 503s. RSS fell back to 18 MiB five seconds after each burst |
| `GET /me` p95 < 50 ms at 100 rps | p95 0.98 ms (run 1), 1.23 ms (run 2) | meets it | loopback, no TLS, local MySQL (a TiDB Serverless round trip is 5 to 50 ms and `/me` loads live state from the DB on a cache miss), generator on the same CPU, warm cache (one token, so one cached principal) |

Not measured here (still open for the Docker/Render test): behaviour at the 512 MB cap, jemalloc vs
mimalloc vs system allocator, Argon2 timing on the target CPU share, a mix of different tokens
(authz cache misses), TLS termination cost, upload and download memory (P0-14 has its own 50 MB
stream test), and the workers (`RUN_MODE=all`).

## Observations for the owner

- With 12 CPUs one login costs 73 to 219 ms at production parameters. The hash pool, not the
  network, is the login bottleneck: 3 slots give about 15 to 40 logins per second at best.
- A one-client burst is stopped by the per-IP limit (30 per minute) before any hashing: 270 of 300
  attempts got 429 with no extra memory.
- Peak RSS during login bursts is about 60 MiB above idle, which matches the §12.1 budget line
  (3 x 19 MiB Argon2 plus buffers).
