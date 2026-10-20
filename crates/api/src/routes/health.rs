//! `GET /health/live` (process up) and `GET /health/ready` (db, keys, migrations). Status words
//! only: no versions, hostnames, error text or timings (SECURITY.md §11).

use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::state::AppState;

/// Readiness must answer fast even when the DB hangs.
const CHECK_TIMEOUT: Duration = Duration::from_secs(2);
/// Probe result reuse: anonymous callers cost at most one DB round trip per instance per 5 s
/// (callers queue on one mutex, so a burst also triggers only one probe).
pub const READY_CACHE_TTL: Duration = Duration::from_secs(5);

#[derive(Serialize)]
struct Live {
    status: &'static str,
}

pub async fn live() -> Json<impl Serialize> {
    Json(Live { status: "ok" })
}

#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct Checks {
    pub db: &'static str,
    pub keys: &'static str,
    pub migrations: &'static str,
}

#[derive(Serialize)]
struct Ready {
    status: &'static str,
    checks: Checks,
}

const fn word(ok: bool) -> &'static str {
    if ok { "ok" } else { "fail" }
}

/// `(db reachable, migrations complete)`. Migrations = `db::migrate::pending` is empty (every
/// embedded migration applied with a matching checksum). Runs as the app user.
async fn probe_db(db: &db::Db) -> (bool, bool) {
    let run = async {
        let Ok(tx) = db.identity_tx().await else {
            return (false, false);
        };
        tx.rollback().await;
        let migrated = matches!(db::migrate::pending(db).await, Ok(p) if p.is_empty());
        (true, migrated)
    };
    tokio::time::timeout(CHECK_TIMEOUT, run)
        .await
        .unwrap_or((false, false))
}

pub async fn ready(State(s): State<AppState>) -> Response {
    let (db_ok, migrated) = {
        let mut cache = s.ready_cache().lock().await;
        match *cache {
            Some((at, r)) if at.elapsed() < READY_CACHE_TTL => r,
            _ => {
                let r = probe_db(s.db()).await;
                *cache = Some((std::time::Instant::now(), r));
                r
            }
        }
    };
    let keys_ok = s.keys().is_some();
    let all = db_ok && migrated && keys_ok;
    let body = Ready {
        status: if all { "ok" } else { "degraded" },
        checks: Checks {
            db: word(db_ok),
            keys: word(keys_ok),
            migrations: word(migrated),
        },
    };
    let status = if all {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(body)).into_response()
}
