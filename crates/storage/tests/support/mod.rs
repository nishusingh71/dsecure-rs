//! Shared test helpers (integration tests).
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use crypto::{EnvKeyProvider, InMemoryDekStore, KeyProvider, KeyRing};
use futures_util::StreamExt as _;
use futures_util::stream;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use storage::ByteStream;

pub async fn ring_with_kek(kek_byte: u8) -> Arc<KeyRing> {
    ring_with_store(kek_byte, Arc::new(InMemoryDekStore::new())).await
}

pub async fn ring_with_store(kek_byte: u8, store: Arc<InMemoryDekStore>) -> Arc<KeyRing> {
    let p: Arc<dyn KeyProvider> = Arc::new(
        EnvKeyProvider::new("k1", [("k1", STANDARD.encode([kek_byte; 32]))]).expect("provider"),
    );
    KeyRing::ensure_platform_keys(&*p, &*store)
        .await
        .expect("ensure");
    Arc::new(KeyRing::load_platform(p, store).await.expect("load"))
}

pub fn pattern(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| u8::try_from((i * 7 + i / 251) % 256).unwrap_or(0))
        .collect()
}

pub fn body_of(data: Vec<u8>, frame: usize) -> ByteStream {
    let frames: Vec<io::Result<Bytes>> = data
        .chunks(frame.max(1))
        .map(|c| Ok(Bytes::copy_from_slice(c)))
        .collect();
    stream::iter(frames).boxed()
}

pub async fn collect(mut s: ByteStream) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(b) = s.next().await {
        out.extend_from_slice(&b?);
    }
    Ok(out)
}

/// Root ke neeche saari files (relative path) - leftover check ke liye.
pub fn all_files(root: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else {
                    out.push(p);
                }
            }
        }
    }
    let mut v = Vec::new();
    walk(root, &mut v);
    v
}
