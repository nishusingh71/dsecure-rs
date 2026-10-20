//! Outbox relay + sweeper logic with in-memory stores (no database).
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)] // test helpers (clippy.toml only exempts #[test] fns)

use common::{Clock, FixedClock};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use time::OffsetDateTime;
use workers::jobs::testing::{InMemoryIdempotencyStore, InMemoryOutboxStore, InMemoryPublisher};
use workers::jobs::{IdempotencySweepJob, OutboxMessage, OutboxRelayJob};

fn clock() -> Arc<dyn Clock> {
    Arc::new(FixedClock::new(
        OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("ts"),
    ))
}

fn msg(i: i64) -> OutboxMessage {
    OutboxMessage {
        id: uuid::Uuid::now_v7(),
        tenant_id: None,
        event_type: "t.created".into(),
        aggregate_type: "t".into(),
        aggregate_id: uuid::Uuid::now_v7(),
        payload: serde_json::json!({"i": i}),
        created_at: OffsetDateTime::from_unix_timestamp(1_700_000_000 + i).expect("ts"),
        attempts: 0,
    }
}

fn fixture(
    n: i64,
) -> (
    Arc<InMemoryOutboxStore>,
    Arc<InMemoryPublisher>,
    Vec<uuid::Uuid>,
) {
    let store = Arc::new(InMemoryOutboxStore::default());
    let mut ids = Vec::new();
    for i in 0..n {
        let m = msg(i);
        ids.push(m.id);
        store.push(m);
    }
    (store, Arc::new(InMemoryPublisher::default()), ids)
}

fn relay(s: &Arc<InMemoryOutboxStore>, p: &Arc<InMemoryPublisher>, batch: u32) -> OutboxRelayJob {
    OutboxRelayJob::new(Arc::clone(s) as _, Arc::clone(p) as _, clock(), "w1".into())
        .with_limits(batch, 10)
}

#[tokio::test]
async fn relay_delivers_in_order_and_marks_sent() {
    let (store, publ, ids) = fixture(7);
    relay(&store, &publ, 3)
        .relay_once(&|| false)
        .await
        .expect("relay");
    assert_eq!(publ.effects(), ids);
    assert_eq!(store.pending(), 0);
    assert_eq!(publ.calls.load(Ordering::SeqCst), 7);
}

#[tokio::test]
async fn relay_is_at_least_once_with_no_duplicate_side_effects() {
    let (store, publ, ids) = fixture(5);
    // The 1st mark fails after its publish: event 0 is delivered again on the retry.
    store.fail_mark.store(1, Ordering::SeqCst);
    let job = relay(&store, &publ, 10);
    assert!(job.relay_once(&|| false).await.is_err());
    assert_eq!(store.pending(), 5, "nothing marked, all released");
    job.relay_once(&|| false).await.expect("retry");
    assert_eq!(
        publ.calls.load(Ordering::SeqCst),
        6,
        "event 0 delivered twice"
    );
    assert_eq!(publ.effects(), ids, "side effects once per id, in order");
    assert_eq!(store.pending(), 0);
}

#[tokio::test]
async fn publish_failure_skips_nothing_and_resumes_in_order() {
    let (store, publ, ids) = fixture(4);
    let job = relay(&store, &publ, 2);
    publ.fail_publish.store(1, Ordering::SeqCst);
    assert!(job.relay_once(&|| false).await.is_err());
    assert!(
        publ.effects().is_empty(),
        "later events must not jump the queue"
    );
    assert_eq!(store.pending(), 4);
    job.relay_once(&|| false).await.expect("resume");
    assert_eq!(publ.effects(), ids);
}

#[tokio::test]
async fn sweeper_removes_only_expired_keys_in_bounded_batches() {
    let store = Arc::new(InMemoryIdempotencyStore::default());
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("ts");
    for i in 1..=25 {
        store.add(now - time::Duration::seconds(i));
    }
    for i in 1..=5 {
        store.add(now + time::Duration::seconds(i));
    }
    let job = IdempotencySweepJob::new(Arc::clone(&store) as _, clock()).with_limits(10, 10);
    job.sweep_once(&|| false).await.expect("sweep");
    assert_eq!(store.len(), 5);
    let bounded = IdempotencySweepJob::new(Arc::clone(&store) as _, clock()).with_limits(1, 1);
    bounded.sweep_once(&|| false).await.expect("sweep");
    assert_eq!(store.len(), 5);
}
