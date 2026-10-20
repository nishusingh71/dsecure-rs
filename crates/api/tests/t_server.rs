//! Server limits over real local sockets (127.0.0.1, no DB): header-read timeout closes a slow
//! client; max-connections holds a new client until a slot frees.

// Test-only crate: helpers outside #[test] fns are not covered by clippy.toml allow-*-in-tests.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use api::authn::DenyAllAuthenticator;
use api::middleware::client_ip::TrustedProxies;
use api::server::{ServerLimits, serve};
use api::{GateDeps, HttpSettings, PolicyRouter, assemble};
use auth::Policy;
use common::SystemClock;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

async fn ok() -> &'static str {
    "ok"
}

fn app() -> axum::Router {
    let routes = PolicyRouter::<()>::new().get("/t/ok", Policy::public("test"), ok);
    let http = HttpSettings {
        max_inflight: 8,
        max_json_body: 1024,
        timeout: Duration::from_secs(5),
        cors_origins: Vec::new(),
        proxies: TrustedProxies::none(),
    };
    let gate = GateDeps {
        authn: Arc::new(DenyAllAuthenticator),
        clock: Arc::new(SystemClock),
        db: None,
        auth: None,
    };
    assemble(routes, (), gate, &http).expect("router").0
}

const REQ: &[u8] = b"GET /t/ok HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";

async fn read_all(s: &mut TcpStream, within: Duration) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    match tokio::time::timeout(within, s.read_to_end(&mut buf)).await {
        Ok(_) => Some(buf),
        Err(_) => None,
    }
}

#[tokio::test]
async fn header_read_timeout_closes_slow_client() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let limits = ServerLimits {
        max_connections: 4,
        header_read_timeout: Duration::from_millis(300),
        shutdown_grace: Duration::from_secs(1),
    };
    let test = async {
        let mut slow = TcpStream::connect(addr).await.expect("connect");
        slow.write_all(b"GET /t/ok HTTP/1.1\r\nHost: t\r\n")
            .await
            .expect("partial");
        let start = Instant::now();
        let got = read_all(&mut slow, Duration::from_secs(5)).await;
        assert!(got.is_some(), "server must close the slow connection");
        assert!(
            !String::from_utf8_lossy(&got.unwrap_or_default()).contains("200 OK"),
            "incomplete request never served"
        );
        assert!(start.elapsed() < Duration::from_secs(4));
        // A normal client is served.
        let mut fast = TcpStream::connect(addr).await.expect("connect");
        fast.write_all(REQ).await.expect("req");
        let body = read_all(&mut fast, Duration::from_secs(5))
            .await
            .expect("response");
        assert!(String::from_utf8_lossy(&body).starts_with("HTTP/1.1 200"));
    };
    tokio::select! {
        () = serve(listener, app(), limits, std::future::pending()) => panic!("server ended"),
        () = test => {}
    }
}

#[tokio::test]
async fn max_connections_queue_new_clients() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let limits = ServerLimits {
        max_connections: 1,
        header_read_timeout: Duration::from_secs(30),
        shutdown_grace: Duration::from_secs(1),
    };
    let test = async {
        let holder = TcpStream::connect(addr).await.expect("connect");
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut waiting = TcpStream::connect(addr)
            .await
            .expect("connect (kernel backlog)");
        waiting.write_all(REQ).await.expect("req");
        assert!(
            read_all(&mut waiting, Duration::from_millis(300))
                .await
                .is_none(),
            "no slot: not served yet"
        );
        drop(holder);
        let body = read_all(&mut waiting, Duration::from_secs(5))
            .await
            .expect("served after the slot freed");
        assert!(String::from_utf8_lossy(&body).starts_with("HTTP/1.1 200"));
    };
    tokio::select! {
        () = serve(listener, app(), limits, std::future::pending()) => panic!("server ended"),
        () = test => {}
    }
}

#[tokio::test]
async fn graceful_shutdown_returns() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let stop = async move {
        let _ = rx.await;
    };
    let run = serve(listener, app(), ServerLimits::default(), stop);
    let trigger = async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = tx.send(());
    };
    let (_, ()) =
        tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(run, trigger) })
            .await
            .expect("serve returns after shutdown");
}
