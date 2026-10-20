//! T-AU1 and friends against the LOCAL MySQL 8.4 (see `support`). Never touches any other database.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::disallowed_methods
)]

mod support;

use audit::chain::compute_row_hash;
use audit::{
    ActorRef, AuditAction, AuditError, AuditEvent, AuditMeta, AuditSink as _, DbAuditSink,
    FailureKind, Outcome, SealConfig, SealOutcome, SinkOptions, TargetKind, TargetRef, hour_floor,
    seal_block, seal_due, verify_chain,
};
use common::{Clock, FixedClock, MembershipId, RequestId, TenantId};
use db::repo::audit::AuditRowRecord;
use db::testing::{ScratchOpts, raw_exec};
use db::{Db, OutboxEvent};
use domain::rbac::{TenantScope, Visibility};
use sqlx::Row as _;
use std::sync::Arc;
use std::time::Duration;
use storage::{BlobStore, EncryptedBlobStore, FsBlobStore};
use support::{b, count, ex, q, with_db, with_db_opts};
use time::{Duration as TD, OffsetDateTime};

fn base_hour() -> OffsetDateTime {
    hour_floor(OffsetDateTime::now_utc() - TD::days(2))
}

fn event(n: i64) -> AuditEvent {
    AuditEvent::new(
        AuditAction::MemberCreate,
        Outcome::Success,
        ActorRef::Member(MembershipId::new()),
        RequestId::new(),
    )
    .target(TargetRef::new(TargetKind::Membership, uuid::Uuid::now_v7()))
    .ip_hmac([7; 32])
    .metadata(
        AuditMeta::new()
            .with_str("reason", "unit_test")
            .unwrap()
            .with_int("n", n)
            .unwrap(),
    )
}

fn sink(db: &Db, clock: &Arc<FixedClock>) -> DbAuditSink {
    let c: Arc<dyn Clock> = clock.clone();
    DbAuditSink::new(db.clone(), c, SinkOptions::default())
}

fn outbox() -> OutboxEvent {
    OutboxEvent {
        event_type: "audit.test",
        aggregate_type: "test",
        aggregate_id: uuid::Uuid::now_v7(),
        payload: serde_json::json!({"k": 1}),
    }
}

async fn write(sink: &DbAuditSink, db: &Db, ev: AuditEvent) {
    let mut tx = db.system_tx().await.unwrap();
    sink.record_in_tx(&mut tx, ev).await.unwrap();
    tx.commit().await.unwrap();
}

async fn ids_in_order(pool: &Db) -> Vec<uuid::Uuid> {
    q(
        pool,
        "SELECT id FROM audit_events ORDER BY occurred_at, id",
        &[],
    )
    .await
    .iter()
    .map(|r| r.try_get::<uuid::Uuid, _>("id").unwrap())
    .collect()
}

fn fs_store(dir: &std::path::Path, ring: Arc<crypto::KeyRing>) -> EncryptedBlobStore<FsBlobStore> {
    EncryptedBlobStore::new(FsBlobStore::new(dir).unwrap(), ring)
}

#[tokio::test]
async fn same_tx_write_commit_keeps_rollback_removes() {
    with_db("same_tx", |db, raw| async move {
        let clock = Arc::new(FixedClock::new(OffsetDateTime::now_utc()));
        let sink = sink(&db, &clock);

        // Commit: business row + audit row both stay.
        let mut tx = db.system_tx().await.unwrap();
        db::outbox_insert_system(&mut tx, &outbox(), clock.now())
            .await
            .unwrap();
        sink.record_in_tx(&mut tx, event(1)).await.unwrap();
        tx.commit().await.unwrap();
        assert_eq!(count(&raw, "outbox_events").await, 1);
        assert_eq!(count(&raw, "audit_events").await, 1);

        // Rollback: neither stays (SystemTx).
        let mut tx = db.system_tx().await.unwrap();
        db::outbox_insert_system(&mut tx, &outbox(), clock.now())
            .await
            .unwrap();
        sink.record_in_tx(&mut tx, event(2)).await.unwrap();
        tx.rollback().await;
        assert_eq!(count(&raw, "outbox_events").await, 1);
        assert_eq!(count(&raw, "audit_events").await, 1);

        // TenantTx: tenant is pinned from the tx; rollback leaves nothing, commit keeps the row.
        let tenant = TenantId::new();
        let scope = TenantScope::for_tests(tenant, MembershipId::new(), Visibility::Tenant, None);
        let mut tx = db.tenant_tx(&scope).await.unwrap();
        db::outbox_insert(&mut tx, &outbox(), clock.now())
            .await
            .unwrap();
        sink.record_in_tx(&mut tx, event(3)).await.unwrap();
        tx.rollback().await;
        assert_eq!(count(&raw, "audit_events").await, 1);

        let mut tx = db.tenant_tx(&scope).await.unwrap();
        sink.record_in_tx(&mut tx, event(4)).await.unwrap();
        // An event naming another tenant is refused before anything is written.
        let other = event(5).tenant(TenantId::new());
        let err = sink.record_in_tx(&mut tx, other).await.unwrap_err();
        assert!(matches!(err, AuditError::TenantMismatch));
        tx.commit().await.unwrap();
        assert_eq!(count(&raw, "audit_events").await, 2);
        let t: uuid::Uuid = q(
            &raw,
            "SELECT tenant_id FROM audit_events WHERE tenant_id IS NOT NULL",
            &[],
        )
        .await
        .remove(0)
        .try_get("tenant_id")
        .unwrap();
        assert_eq!(t, tenant.0);

        sink.shutdown().await;
    })
    .await;
}

#[tokio::test]
async fn seal_anchor_verify_and_tamper_detection() {
    with_db("seal_verify", |db, raw| async move {
        let dir = tempfile::tempdir().unwrap();
        let store = fs_store(dir.path(), support::ring().await);
        let cfg = SealConfig {
            page_size: 2, // force paging inside blocks
            ..SealConfig::default()
        };
        let h = base_hour();
        let clock = Arc::new(FixedClock::new(h));
        let sink = sink(&db, &clock);

        // 3 events in hour H, 2 in H+1, 1 in H+2, none in H+3.
        for (i, mins) in [5, 20, 40, 65, 80, 130].into_iter().enumerate() {
            clock.set(h + TD::minutes(mins));
            write(&sink, &db, event(i64::try_from(i).unwrap())).await;
        }
        let now = h + TD::hours(5);

        // Genesis rule: sealing a later hour first would leave older events unsealed.
        let e = seal_block(&db, &store, &cfg, h + TD::hours(1), now)
            .await
            .unwrap_err();
        assert!(matches!(e, AuditError::Chain(_)), "{e:?}");
        // Grace period.
        let e = seal_block(&db, &store, &cfg, h, h + TD::hours(1) + TD::minutes(1))
            .await
            .unwrap_err();
        assert!(matches!(e, AuditError::TooEarly));
        // Unaligned start.
        assert!(matches!(
            seal_block(&db, &store, &cfg, h + TD::minutes(1), now).await,
            Err(AuditError::Invalid(_))
        ));

        let sealed = seal_due(&db, &store, &cfg, now, 10).await.unwrap();
        let counts: Vec<i64> = sealed.iter().map(|b| b.event_count).collect();
        assert_eq!(counts, [3, 2, 1, 0], "H..H+3 sealed, H+4 still in grace");
        assert_eq!(sealed[0].prev_block_hash, vec![0u8; 32]);
        for w in sealed.windows(2) {
            assert_eq!(w[1].prev_block_hash, w[0].block_hash);
            assert_eq!(w[1].block_start, w[0].block_end);
        }
        for b in &sealed {
            assert!(b.anchored_blob_key.is_some());
            assert!(b.anchored_blob_write_id.is_some(), "encrypted anchor has a write id");
            assert!(b.anchored_blob_digest.is_some());
        }
        // Idempotent re-run.
        let again = seal_block(&db, &store, &cfg, h, now).await.unwrap();
        assert!(matches!(&again, SealOutcome::AlreadySealed(b) if b.block_hash == sealed[0].block_hash));
        assert!(seal_due(&db, &store, &cfg, now, 10).await.unwrap().is_empty());

        let end = h + TD::hours(10);
        let ok = verify_chain(&db, Some(&store as &dyn BlobStore), h, end, 2)
            .await
            .unwrap();
        assert!(ok.ok(), "{:?}", ok.failures);
        assert_eq!((ok.blocks_checked, ok.events_checked), (4, 6));
        // A sub-range verifies too (starts with a predecessor outside the range).
        let sub = verify_chain(&db, Some(&store as &dyn BlobStore), h + TD::hours(1), end, 2)
            .await
            .unwrap();
        assert!(sub.ok() && sub.blocks_checked == 3, "{:?}", sub.failures);

        let ids = ids_in_order(&raw).await;
        assert_eq!(ids.len(), 6);
        let (r0, r1) = (ids[0], ids[1]);
        let v = || async { verify_chain(&db, Some(&store as &dyn BlobStore), h, end, 2).await.unwrap() };

        // --- field tampering, each reverted afterwards ---
        let orig = q(&raw, "SELECT occurred_at, actor_id, row_hash, CAST(metadata AS CHAR) AS m FROM audit_events WHERE id = ?", &[b(r0)]).await.remove(0);
        let o_actor: Option<uuid::Uuid> = orig.try_get("actor_id").unwrap();
        let o_hash: Vec<u8> = orig.try_get("row_hash").unwrap();
        let o_meta: String = orig.try_get("m").unwrap();

        ex(&raw, "UPDATE audit_events SET outcome = 'denied' WHERE id = ?", &[b(r0)]).await;
        let rep = v().await;
        assert!(rep.failures.iter().any(|f| f.kind == FailureKind::RowHashMismatch(r0)), "{:?}", rep.failures);
        ex(&raw, "UPDATE audit_events SET outcome = 'success' WHERE id = ?", &[b(r0)]).await;
        assert!(v().await.ok());

        ex(&raw, "UPDATE audit_events SET metadata = JSON_OBJECT('reason', 'forged') WHERE id = ?", &[b(r0)]).await;
        assert!(!v().await.ok());
        ex(&raw, "UPDATE audit_events SET metadata = CAST(? AS JSON) WHERE id = ?", &[b(&o_meta), b(r0)]).await;
        assert!(v().await.ok(), "metadata round trip must keep the hash");

        ex(&raw, "UPDATE audit_events SET actor_id = ? WHERE id = ?", &[b(uuid::Uuid::now_v7()), b(r0)]).await;
        assert!(!v().await.ok());
        ex(&raw, "UPDATE audit_events SET actor_id = ? WHERE id = ?", &[b(o_actor), b(r0)]).await;

        // Tamper + recompute the row hash: caught by the Merkle root / block hash.
        let mut forged = fetch_row(&raw, r0).await;
        forged.outcome = "failed".into();
        forged.row_hash = compute_row_hash(&forged).unwrap().to_vec();
        ex(&raw, "UPDATE audit_events SET outcome = 'failed', row_hash = ? WHERE id = ?", &[b(forged.row_hash.as_slice()), b(r0)]).await;
        let rep = v().await;
        assert!(rep.failures.iter().any(|f| f.kind == FailureKind::MerkleMismatch), "{:?}", rep.failures);
        assert!(rep.failures.iter().any(|f| f.kind == FailureKind::BlockHashMismatch));
        ex(&raw, "UPDATE audit_events SET outcome = 'success', row_hash = ? WHERE id = ?", &[b(o_hash.as_slice()), b(r0)]).await;
        assert!(v().await.ok());

        // --- reorder: swap the times of two rows of one block ---
        let t0: OffsetDateTime = q(&raw, "SELECT occurred_at FROM audit_events WHERE id = ?", &[b(r0)]).await.remove(0)
            .try_get("occurred_at")
            .unwrap();
        let t1: OffsetDateTime = q(&raw, "SELECT occurred_at FROM audit_events WHERE id = ?", &[b(r1)]).await.remove(0)
            .try_get("occurred_at")
            .unwrap();
        for (a, ta) in [(r0, t1), (r1, t0)] {
            ex(&raw, "UPDATE audit_events SET occurred_at = ? WHERE id = ?", &[b(ta), b(a)]).await;
        }
        assert!(!v().await.ok(), "swapped times = reordered rows");
        for (a, ta) in [(r0, t0), (r1, t1)] {
            ex(&raw, "UPDATE audit_events SET occurred_at = ? WHERE id = ?", &[b(ta), b(a)]).await;
        }
        assert!(v().await.ok());

        // --- reorder: swap the stored row hashes of two rows ---
        let h1: Vec<u8> = q(&raw, "SELECT row_hash FROM audit_events WHERE id = ?", &[b(r1)]).await.remove(0)
            .try_get("row_hash")
            .unwrap();
        for (a, hh) in [(r0, &h1), (r1, &o_hash)] {
            ex(&raw, "UPDATE audit_events SET row_hash = ? WHERE id = ?", &[b(hh.as_slice()), b(a)]).await;
        }
        assert!(!v().await.ok());
        for (a, hh) in [(r0, &o_hash), (r1, &h1)] {
            ex(&raw, "UPDATE audit_events SET row_hash = ? WHERE id = ?", &[b(hh.as_slice()), b(a)]).await;
        }
        assert!(v().await.ok());

        // --- forged extra row inside a sealed block (valid own hash) ---
        let mut extra = fetch_row(&raw, r0).await;
        extra.id = uuid::Uuid::now_v7();
        extra.row_hash = compute_row_hash(&extra).unwrap().to_vec();
        let mut tx = db.system_tx().await.unwrap();
        db::repo::audit::insert_event_system(&mut tx, &extra).await.unwrap();
        tx.commit().await.unwrap();
        let rep = v().await;
        assert!(rep.failures.iter().any(|f| matches!(f.kind, FailureKind::EventCountMismatch { .. })), "{:?}", rep.failures);
        ex(&raw, "DELETE FROM audit_events WHERE id = ?", &[b(extra.id)]).await;
        assert!(v().await.ok());

        // --- anchor: corrupted / missing blob ---
        let blob = find_anchor_files(dir.path());
        assert_eq!(blob.len(), 4);
        let victim = &blob[0];
        let saved = std::fs::read(victim).unwrap();
        let mut bad = saved.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 0xFF;
        std::fs::write(victim, &bad).unwrap();
        let rep = v().await;
        assert!(
            rep.failures.iter().any(|f| matches!(f.kind, FailureKind::AnchorUnreadable | FailureKind::AnchorMismatch)),
            "{:?}",
            rep.failures
        );
        std::fs::remove_file(victim).unwrap();
        assert!(!v().await.ok());
        std::fs::write(victim, &saved).unwrap();
        assert!(v().await.ok());

        // --- block tampering ---
        ex(&raw, "UPDATE audit_chain_blocks SET event_count = event_count + 1 WHERE block_start = ?", &[b(h)]).await;
        assert!(!v().await.ok());
        ex(&raw, "UPDATE audit_chain_blocks SET event_count = event_count - 1 WHERE block_start = ?", &[b(h)]).await;
        assert!(v().await.ok());

        // Deleting a block in the middle shows up as a gap / broken link.
        ex(&raw, "DELETE FROM audit_chain_blocks WHERE block_start = ?", &[b(h + TD::hours(1))]).await;
        let rep = v().await;
        assert!(rep.failures.iter().any(|f| f.kind == FailureKind::Gap), "{:?}", rep.failures);
        assert!(rep.failures.iter().any(|f| f.kind == FailureKind::PrevHashMismatch));

        // Deleting an event row breaks its block.
        ex(&raw, "DELETE FROM audit_events WHERE id = ?", &[b(ids[5])]).await;
        let rep = v().await;
        assert!(rep.failures.iter().any(|f| matches!(f.kind, FailureKind::EventCountMismatch { .. })));
        sink.shutdown().await;
    })
    .await;
}

fn find_anchor_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                if p.file_name().is_some_and(|n| n == ".tmp") {
                    continue;
                }
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "json") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

async fn fetch_row(pool: &Db, id: uuid::Uuid) -> AuditRowRecord {
    let r = q(pool, "SELECT id, occurred_at, tenant_id, actor_kind, actor_id, staff_grant_id, action, outcome, target_type, \
         target_id, request_id, ip_hmac, metadata, row_hash FROM audit_events WHERE id = ?", &[b(id)]).await.remove(0);
    AuditRowRecord {
        id: r.try_get("id").unwrap(),
        occurred_at: r.try_get("occurred_at").unwrap(),
        tenant_id: r.try_get("tenant_id").unwrap(),
        actor_kind: r.try_get("actor_kind").unwrap(),
        actor_id: r.try_get("actor_id").unwrap(),
        staff_grant_id: r.try_get("staff_grant_id").unwrap(),
        action: r.try_get("action").unwrap(),
        outcome: r.try_get("outcome").unwrap(),
        target_type: r.try_get("target_type").unwrap(),
        target_id: r.try_get("target_id").unwrap(),
        request_id: r.try_get("request_id").unwrap(),
        ip_hmac: r.try_get("ip_hmac").unwrap(),
        metadata: r.try_get("metadata").unwrap(),
        row_hash: r.try_get("row_hash").unwrap(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_writers_keep_a_valid_chain() {
    with_db_opts(
        "concurrent",
        ScratchOpts { max_connections: 8 },
        |db, raw| async move {
            let dir = tempfile::tempdir().unwrap();
            let store = fs_store(dir.path(), support::ring().await);
            let cfg = SealConfig {
                page_size: 7,
                ..SealConfig::default()
            };
            let h = base_hour();
            // Every event gets the very same microsecond: ordering must fall back to the id.
            let clock = Arc::new(FixedClock::new(h + TD::minutes(1)));
            let sink = Arc::new(sink(&db, &clock));

            let mut tasks = Vec::new();
            for w in 0..8 {
                let (db, sink) = (db.clone(), Arc::clone(&sink));
                tasks.push(tokio::spawn(async move {
                    for i in 0..25 {
                        let mut tx = db.system_tx().await.unwrap();
                        sink.record_in_tx(&mut tx, event(w * 100 + i))
                            .await
                            .unwrap();
                        tx.commit().await.unwrap();
                    }
                }));
            }
            for i in 0..25 {
                sink.record(event(9000 + i)).await.unwrap();
            }
            for t in tasks {
                t.await.unwrap();
            }
            sink.flush().await;
            assert_eq!(count(&raw, "audit_events").await, 8 * 25 + 25);

            let sealed = seal_due(&db, &store, &cfg, h + TD::hours(3), 10)
                .await
                .unwrap();
            assert_eq!(sealed.first().map(|b| b.event_count), Some(225));
            let rep = verify_chain(&db, Some(&store as &dyn BlobStore), h, h + TD::hours(3), 7)
                .await
                .unwrap();
            assert!(rep.ok(), "{:?}", rep.failures);
            assert_eq!(rep.events_checked, 225);
        },
    )
    .await;
}

#[tokio::test]
async fn channel_overflow_falls_back_to_sync_and_counts() {
    // The recorder must be installed before the first `counter!` call.
    let _ = telemetry::meters::install();
    with_db("overflow", |db, raw| async move {
        let clock = Arc::new(FixedClock::new(OffsetDateTime::now_utc()));
        let c: Arc<dyn Clock> = clock.clone();
        let sink = DbAuditSink::new(
            db.clone(),
            c,
            SinkOptions {
                queue_capacity: 2,
                batch_max: 8,
                // Writer stays idle long enough for the queue to fill up deterministically.
                writer_start_delay: Duration::from_secs(2),
            },
        );
        for i in 0..6 {
            sink.record(event(i)).await.unwrap();
        }
        assert_eq!(sink.overflow_count(), 4, "2 queued, 4 overflowed");
        // The 4 overflowed events were written synchronously, before the writer woke up.
        assert_eq!(count(&raw, "audit_events").await, 4);
        sink.flush().await;
        assert_eq!(count(&raw, "audit_events").await, 6, "nothing is lost");
        assert_eq!(sink.written_count(), 2);
        assert_eq!(sink.failed_count(), 0);

        let text = telemetry::meters::render();
        let line = text
            .lines()
            .find(|l| l.starts_with("audit_sink_overflow_total"))
            .unwrap_or_else(|| panic!("metric missing in:\n{text}"));
        let v: f64 = line.rsplit(' ').next().unwrap().parse().unwrap();
        assert!(v >= 4.0, "{line}");
        sink.shutdown().await;
    })
    .await;
}

#[tokio::test]
async fn no_pii_reaches_the_stored_row() {
    with_db("no_pii", |db, raw| async move {
        let email = "alice.fixture@example.com";
        let ip = "203.0.113.77";
        for bad in [email, ip, "login from 203.0.113.77", "2001:db8::1"] {
            assert!(AuditMeta::new().with_str("reason", bad).is_err(), "{bad}");
        }
        assert!(AuditMeta::new().with_str("email", "x").is_err());
        assert!(AuditMeta::new().with_str("client_ip", "x").is_err());

        let clock = Arc::new(FixedClock::new(OffsetDateTime::now_utc()));
        let sink = sink(&db, &clock);
        // What a caller legitimately passes: a blind-index hex and an HMAC of the IP.
        let ev = AuditEvent::new(
            AuditAction::AuthLoginFailure,
            Outcome::Failed,
            ActorRef::Anonymous,
            RequestId::new(),
        )
        .ip_hmac([0xAB; 32])
        .metadata(
            AuditMeta::new()
                .with_str("reason", "bad_password")
                .unwrap()
                .with_str("login_bidx", &"cd".repeat(16))
                .unwrap(),
        );
        sink.record(ev).await.unwrap();
        sink.flush().await;
        let row = q(&raw, "SELECT CONCAT_WS('|', CAST(metadata AS CHAR), actor_kind, action, outcome, HEX(ip_hmac)) AS dump \
             FROM audit_events", &[]).await.remove(0);
        let dump: String = row.try_get("dump").unwrap();
        assert!(!dump.contains(email) && !dump.contains(ip) && !dump.contains('@'), "{dump}");
        assert!(dump.len() < 2048);
        sink.shutdown().await;
    })
    .await;
}

/// The app user (scratch DB's own least-privilege user, per-table grants) is INSERT/SELECT only on the audit
/// tables: UPDATE and DELETE are refused by the server (1142).
#[tokio::test]
async fn app_user_cannot_update_or_delete_audit_rows() {
    let Some((env, s)) = support::scratch("app_user_grants", ScratchOpts::default()).await else {
        return;
    };
    let Some(app) = s.app().cloned() else {
        assert!(
            db::testing::skip_allowed(),
            "no scratch app user (LOCAL_MYSQL_ROOT_PASSWORD missing)"
        );
        let _ = s.drop_db(&env).await;
        return;
    };
    let id = b(uuid::Uuid::now_v7());
    for sql in [
        "DELETE FROM audit_events WHERE id = ?",
        "DELETE FROM audit_chain_blocks WHERE first_id = ?",
        "UPDATE audit_events SET outcome = outcome WHERE id = ?",
        "UPDATE audit_chain_blocks SET event_count = event_count WHERE first_id = ?",
    ] {
        let e = raw_exec(&app, sql, std::slice::from_ref(&id))
            .await
            .expect_err("must be refused");
        assert!(
            matches!(e, db::DbError::PermissionDenied { number: 1142 }),
            "{sql}: {e:?}"
        );
    }
    // INSERT still works (sanity: the refusal above is about UPDATE/DELETE, not a dead connection).
    let clock = Arc::new(FixedClock::new(OffsetDateTime::now_utc()));
    let sink = sink(&app, &clock);
    write(&sink, &app, event(1)).await;
    assert_eq!(count(s.migrator(), "audit_events").await, 1);
    sink.shutdown().await;
    let _ = s.drop_db(&env).await;
}
