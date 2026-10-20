//! HTTP middleware in ARCHITECTURE.md §5 order (outer -> inner). Wiring: `app::assemble`.
//!
//! | # | Layer | Module |
//! |---|---|---|
//! | 1 | catch panic -> 500 problem | `app::panic_response` (tower-http) |
//! | 2 | request id | [`request_id`] |
//! | 3 | client IP (trusted proxies) | [`client_ip`] |
//! | 4 | request span + RED metrics | [`trace`] |
//! | 5 | in-flight limit + load shed | [`limits::inflight`] |
//! | 6 | timeout | [`limits::timeout`] |
//! | 7 | body limit | [`limits::body_limit`] |
//! | 8 | CORS | [`security::cors`] |
//! | 9 | security headers (installed right inside layer 1 so 413/503 answers get them too) | [`security::headers`] |
//! | 10 | pre-auth rate limit (login / refresh / step-up handlers) | `crate::ratelimit` |
//! | 11-12 | authn + authz (per route) | `crate::authn`, `crate::authz` |
//! | 13 | post-auth rate limit / class semaphores | not in P0-10 |
//! | 14 | idempotency (per route) | [`idempotency`] |
//! | 16 | error mapping | `crate::errors` |

pub mod client_ip;
pub mod idempotency;
pub mod limits;
pub mod request_id;
pub mod security;
pub mod trace;
