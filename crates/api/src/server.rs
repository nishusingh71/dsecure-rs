//! HTTP/1.1 accept loop with connection limits (replaces `axum::serve`, which sets no hyper timer and
//! therefore no header-read timeout).
//!
//! - `max_connections`: a connection needs a semaphore permit BEFORE it is accepted; when all
//!   permits are taken new clients wait in the kernel backlog (no unbounded task growth).
//! - `header_read_timeout`: a client must send complete request headers within this time
//!   (slowloris defence; hyper http1 with a tokio timer).
//! - Every connection task is in one `JoinSet` bounded by the semaphore; graceful shutdown stops
//!   accepting, lets in-flight requests finish for `shutdown_grace`, then aborts the rest.
//! - The TCP peer goes into each request as `ConnectInfo<SocketAddr>` (client-IP layer input).

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tower::ServiceExt as _;

#[derive(Clone, Copy, Debug)]
pub struct ServerLimits {
    pub max_connections: usize,
    pub header_read_timeout: Duration,
    pub shutdown_grace: Duration,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            // Connections are cheap (no buffers until a request); requests are capped separately
            // by MAX_INFLIGHT_REQUESTS (128).
            max_connections: 512,
            header_read_timeout: Duration::from_secs(10),
            // Render sends SIGKILL ~30 s after SIGTERM.
            shutdown_grace: Duration::from_secs(25),
        }
    }
}

/// Serve `app` on `listener` until `shutdown` resolves.
pub async fn serve<F>(listener: TcpListener, app: Router, limits: ServerLimits, shutdown: F)
where
    F: Future<Output = ()> + Send,
{
    let permits = Arc::new(Semaphore::new(limits.max_connections.max(1)));
    let graceful = GracefulShutdown::new();
    let mut conns = JoinSet::new();
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        while conns.try_join_next().is_some() {}
        let permit = tokio::select! {
            p = Arc::clone(&permits).acquire_owned() => match p {
                Ok(p) => p,
                Err(_) => break,
            },
            () = &mut shutdown => break,
        };
        let (stream, peer) = tokio::select! {
            r = listener.accept() => match r {
                Ok(v) => v,
                Err(_) => {
                    // EMFILE etc.: back off instead of spinning.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        let app = app.clone();
        let svc =
            hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
                req.extensions_mut().insert(ConnectInfo::<SocketAddr>(peer));
                app.clone().oneshot(req.map(Body::new))
            });
        let mut builder = hyper::server::conn::http1::Builder::new();
        builder
            .timer(TokioTimer::new())
            .header_read_timeout(limits.header_read_timeout);
        // No upgrades (no websockets on this API).
        let conn = builder.serve_connection(TokioIo::new(stream), svc);
        let watched = graceful.watch(conn);
        conns.spawn(async move {
            let _permit = permit;
            let _ = watched.await;
        });
    }
    drop(listener);
    if tokio::time::timeout(limits.shutdown_grace, graceful.shutdown())
        .await
        .is_err()
    {
        tracing::warn!("graceful shutdown deadline passed; aborting open connections");
    }
    conns.abort_all();
    while conns.join_next().await.is_some() {}
}
