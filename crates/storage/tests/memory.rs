//! P0-14 acceptance: 50 MB stream (encrypt -> FsBlobStore put -> get -> decrypt) mein RSS delta < 5 MB.
//!
//! Alag test binary (is file mein sirf yahi test) taaki doosre tests ki allocation RSS na hilaye.
//! RSS `memory-stats` (physical memory, cross-platform) se, data pipeline ke andar har 8 chunk par
//! sample hoti hai, isliye peak (sirf end nahi) pakda jaata hai. Baseline warm-up run ke baad li jaati hai
//! (thread pool, allocator arenas, KeyRing, file handles pehle se bane hon).
// Integration test helpers ko #[test] ke bahar unwrap chahiye; sirf test crates par allow.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout
)]

mod support;

use bytes::Bytes;
use common::TenantId;
use futures_util::StreamExt as _;
use futures_util::stream;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use storage::{BlobKey, BlobStore, ByteStream, EncryptedBlobStore, FsBlobStore};
use support::ring_with_kek;

const FRAME: usize = 64 * 1024;

fn rss() -> u64 {
    memory_stats::memory_stats().map_or(0, |m| m.physical_mem as u64)
}

fn generated(total: usize, peak: Arc<AtomicU64>) -> ByteStream {
    let frames = total / FRAME;
    stream::unfold(0usize, move |i| {
        let peak = Arc::clone(&peak);
        async move {
            if i >= frames {
                return None;
            }
            if i.is_multiple_of(8) {
                peak.fetch_max(rss(), Ordering::Relaxed);
            }
            let fill = u8::try_from(i % 251).unwrap_or(0);
            Some((
                Ok::<Bytes, io::Error>(Bytes::from(vec![fill; FRAME])),
                i + 1,
            ))
        }
    })
    .boxed()
}

async fn run(
    store: &EncryptedBlobStore<FsBlobStore>,
    key: &BlobKey,
    total: usize,
    peak: &Arc<AtomicU64>,
) {
    let meta = store
        .put_stream(key, generated(total, Arc::clone(peak)), u64::MAX)
        .await
        .unwrap();
    assert_eq!(meta.size, total as u64);
    let mut s = store.get_stream(&meta.blob_ref(key)).await.unwrap();
    let mut n = 0u64;
    let mut i = 0u64;
    while let Some(b) = s.next().await {
        let b = b.unwrap();
        n += b.len() as u64;
        if i.is_multiple_of(8) {
            peak.fetch_max(rss(), Ordering::Relaxed);
        }
        i += 1;
    }
    assert_eq!(n, total as u64);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fifty_mb_through_encrypt_put_get_decrypt_keeps_rss_flat() {
    assert!(rss() > 0, "memory-stats unsupported on this platform");
    let dir = tempfile::tempdir().unwrap();
    let store = EncryptedBlobStore::new(
        FsBlobStore::new(dir.path()).unwrap(),
        ring_with_kek(1).await,
    );
    let key = BlobKey::new(TenantId::new(), "big/50mb.bin").unwrap();
    let peak = Arc::new(AtomicU64::new(0));

    // warm-up (4 MB): allocator/threads/keyring
    run(&store, &key, 4 * 1024 * 1024, &peak).await;

    let baseline = rss();
    peak.store(baseline, Ordering::Relaxed);
    run(&store, &key, 50 * 1024 * 1024, &peak).await;
    let growth = peak.load(Ordering::Relaxed).saturating_sub(baseline);
    println!(
        "baseline={} KB peak_growth={} KB",
        baseline / 1024,
        growth / 1024
    );
    assert!(
        growth < 5 * 1024 * 1024,
        "RSS grew by {} KB (limit 5120 KB)",
        growth / 1024
    );
}
