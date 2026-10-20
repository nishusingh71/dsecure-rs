//! Hash chain by sealed hourly blocks (DATABASE.md §8 `audit_chain_blocks`, SECURITY.md §10).
//!
//! Design (no hot chain-head row, concurrent writers never contend):
//! - Every event row carries `row_hash = SHA-256(domain || canonical row)`, computed by the writer. The
//!   canonical row is a fixed, length-prefixed binary encoding of every column except `row_hash`
//!   (metadata as RFC 8785 canonical JSON, so MySQL's JSON normalisation does not change the hash).
//! - Rows are ordered by `(occurred_at, id)`. `seal_block` takes all rows of one UTC hour
//!   (`block_start <= occurred_at < block_end`) in that order and builds an RFC 6962 style Merkle tree
//!   over the row hashes (leaf/node domain separation).
//! - `block_hash = SHA-256(domain || start || end || first_id || last_id || count || merkle_root ||
//!   prev_block_hash)`. `prev_block_hash` links to the previous block (32 zero bytes for the genesis
//!   block), blocks are contiguous, empty hours are sealed too (so a deleted block is visible as a gap).
//! - The block is anchored: a small JSON document with the block fields is written through the given
//!   `BlobStore` (production: `EncryptedBlobStore` over S3/fs) and its `BlobRef` columns are stored with the
//!   block. A DB-only attacker who rewrites rows, blocks and links consistently is still caught by the anchor.
//! - Late commits: `occurred_at` is assigned when the row is recorded, and a transaction cannot outlive
//!   `DB_TX_TIMEOUT_MS`, so blocks are sealed only after a grace period (default 5 minutes). A row that
//!   still shows up inside a sealed block makes `verify_chain` fail (count/merkle mismatch).

use crate::event::AuditError;
use common::TenantId;
use db::Db;
use db::repo::audit::{self as repo, AuditBlockRecord, AuditRowRecord};
use futures_util::StreamExt as _;
use sha2::{Digest as _, Sha256};
use std::time::Duration;
use storage::{BlobKey, BlobRef, BlobStore, WriteId};
use time::{OffsetDateTime, UtcOffset};

pub type Hash = [u8; 32];
/// `prev_block_hash` of the genesis block.
pub const ZERO_HASH: Hash = [0; 32];

const ROW_DOMAIN: &[u8] = b"dsecure|audit|row|v1";
const BLOCK_DOMAIN: &[u8] = b"dsecure|audit|block|v1";
const EMPTY_ROOT_DOMAIN: &[u8] = b"dsecure|audit|merkle|empty|v1";
const MAX_FAILURES: usize = 32;
const BLOCK_LEN: time::Duration = time::Duration::hours(1);

struct Hasher(Sha256);

impl Hasher {
    fn new(domain: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(domain);
        Self(h)
    }

    fn put(&mut self, b: &[u8]) -> Result<(), AuditError> {
        let len = u32::try_from(b.len()).map_err(|_| AuditError::Invalid("field too large"))?;
        self.0.update(len.to_be_bytes());
        self.0.update(b);
        Ok(())
    }

    fn opt(&mut self, b: Option<&[u8]>) -> Result<(), AuditError> {
        match b {
            None => self.0.update([0u8]),
            Some(b) => {
                self.0.update([1u8]);
                self.put(b)?;
            }
        }
        Ok(())
    }

    fn int(&mut self, v: i64) {
        self.0.update(v.to_be_bytes());
    }

    fn finish(self) -> Hash {
        self.0.finalize().into()
    }
}

fn micros(t: OffsetDateTime) -> Result<i64, AuditError> {
    i64::try_from(t.unix_timestamp_nanos() / 1000).map_err(|_| AuditError::Invalid("time range"))
}

/// Truncate to the DATETIME(6) precision the database stores.
#[must_use]
pub fn trunc_micros(t: OffsetDateTime) -> OffsetDateTime {
    let t = t.to_offset(UtcOffset::UTC);
    t.replace_nanosecond(t.nanosecond() / 1000 * 1000)
        .unwrap_or(t)
}

/// `SHA-256(domain || canonical row)` of an event row (everything except `row_hash` itself).
///
/// # Errors
/// `Invalid` for an unserialisable value or an out-of-range time.
pub fn compute_row_hash(r: &AuditRowRecord) -> Result<Hash, AuditError> {
    let mut h = Hasher::new(ROW_DOMAIN);
    h.put(r.id.as_bytes())?;
    h.int(micros(r.occurred_at)?);
    h.opt(r.tenant_id.as_ref().map(|u| u.as_bytes().as_slice()))?;
    h.put(r.actor_kind.as_bytes())?;
    h.opt(r.actor_id.as_ref().map(|u| u.as_bytes().as_slice()))?;
    h.opt(r.staff_grant_id.as_ref().map(|u| u.as_bytes().as_slice()))?;
    h.put(r.action.as_bytes())?;
    h.put(r.outcome.as_bytes())?;
    h.opt(r.target_type.as_ref().map(|s| s.as_bytes()))?;
    h.opt(r.target_id.as_ref().map(|u| u.as_bytes().as_slice()))?;
    h.opt(r.request_id.as_ref().map(|u| u.as_bytes().as_slice()))?;
    h.opt(r.ip_hmac.as_deref())?;
    let meta = r
        .metadata
        .as_ref()
        .map(|v| {
            serde_json_canonicalizer::to_vec(v)
                .map_err(|_| AuditError::Invalid("metadata not canonicalisable"))
        })
        .transpose()?;
    h.opt(meta.as_deref())?;
    Ok(h.finish())
}

fn leaf_hash(row_hash: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(row_hash);
    h.finalize().into()
}

fn node_hash(l: &Hash, r: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

/// Streaming RFC 6962 Merkle tree (O(log n) memory).
#[derive(Default)]
struct Merkle {
    stack: Vec<(u32, Hash)>,
}

impl Merkle {
    fn push(&mut self, row_hash: &[u8]) {
        let mut level = 0u32;
        let mut h = leaf_hash(row_hash);
        while self.stack.last().is_some_and(|(l, _)| *l == level) {
            if let Some((_, left)) = self.stack.pop() {
                h = node_hash(&left, &h);
            }
            level += 1;
        }
        self.stack.push((level, h));
    }

    fn root(&self) -> Hash {
        let mut it = self.stack.iter().rev();
        let Some((_, last)) = it.next() else {
            return Sha256::digest(EMPTY_ROOT_DOMAIN).into();
        };
        let mut acc = *last;
        for (_, left) in it {
            acc = node_hash(left, &acc);
        }
        acc
    }
}

/// Merkle root over row hashes in order (tests, tooling).
#[must_use]
pub fn merkle_root<'a>(row_hashes: impl IntoIterator<Item = &'a [u8]>) -> Hash {
    let mut m = Merkle::default();
    for h in row_hashes {
        m.push(h);
    }
    m.root()
}

struct BlockFields<'a> {
    start: OffsetDateTime,
    end: OffsetDateTime,
    first_id: Option<uuid::Uuid>,
    last_id: Option<uuid::Uuid>,
    count: i64,
    merkle_root: &'a [u8],
    prev: &'a [u8],
}

fn compute_block_hash(b: &BlockFields<'_>) -> Result<Hash, AuditError> {
    let mut h = Hasher::new(BLOCK_DOMAIN);
    h.int(micros(b.start)?);
    h.int(micros(b.end)?);
    h.opt(b.first_id.as_ref().map(|u| u.as_bytes().as_slice()))?;
    h.opt(b.last_id.as_ref().map(|u| u.as_bytes().as_slice()))?;
    h.int(b.count);
    h.put(b.merkle_root)?;
    h.put(b.prev)?;
    Ok(h.finish())
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
}

/// The anchored document (canonical JSON). Derived only from fields covered by `block_hash`.
fn anchor_payload(b: &BlockFields<'_>, block_hash: &[u8]) -> Result<Vec<u8>, AuditError> {
    let v = serde_json::json!({
        "v": 1,
        "block_start_us": micros(b.start)?,
        "block_end_us": micros(b.end)?,
        "first_id": b.first_id.map(|u| u.hyphenated().to_string()),
        "last_id": b.last_id.map(|u| u.hyphenated().to_string()),
        "event_count": b.count,
        "merkle_root": hex(b.merkle_root),
        "prev_block_hash": hex(b.prev),
        "block_hash": hex(block_hash),
    });
    serde_json_canonicalizer::to_vec(&v).map_err(|_| AuditError::Invalid("anchor payload"))
}

fn is_hour_aligned(t: OffsetDateTime) -> bool {
    t.offset() == UtcOffset::UTC && t.minute() == 0 && t.second() == 0 && t.nanosecond() == 0
}

/// Start of the UTC hour containing `t`.
#[must_use]
pub fn hour_floor(t: OffsetDateTime) -> OffsetDateTime {
    let t = t.to_offset(UtcOffset::UTC);
    t.replace_minute(0)
        .and_then(|t| t.replace_second(0))
        .and_then(|t| t.replace_nanosecond(0))
        .unwrap_or(t)
}

struct Scan {
    count: i64,
    first: Option<uuid::Uuid>,
    last: Option<uuid::Uuid>,
    merkle: Hash,
    /// Rows whose stored `row_hash` is not the hash of their content (capped).
    bad_rows: Vec<uuid::Uuid>,
    bad_row_total: u64,
}

/// One pass over the rows of a block, page by page (each page its own short transaction).
async fn scan_block(
    db: &Db,
    start: OffsetDateTime,
    end: OffsetDateTime,
    page: u32,
) -> Result<Scan, AuditError> {
    let mut merkle = Merkle::default();
    let mut scan = Scan {
        count: 0,
        first: None,
        last: None,
        merkle: [0; 32],
        bad_rows: Vec::new(),
        bad_row_total: 0,
    };
    let mut after = None;
    loop {
        let mut tx = db.system_tx().await?;
        let rows = repo::list_events_range(&mut tx, start, end, after, page).await?;
        tx.commit().await?;
        let Some(last) = rows.last() else { break };
        after = Some((last.occurred_at, last.id));
        let full = rows.len() >= usize::try_from(page).unwrap_or(usize::MAX);
        for r in &rows {
            if compute_row_hash(r).map_or(true, |h| h.as_slice() != r.row_hash.as_slice()) {
                scan.bad_row_total += 1;
                if scan.bad_rows.len() < MAX_FAILURES {
                    scan.bad_rows.push(r.id);
                }
            }
            merkle.push(&r.row_hash);
            scan.count += 1;
            scan.first.get_or_insert(r.id);
            scan.last = Some(r.id);
        }
        if !full {
            break;
        }
    }
    scan.merkle = merkle.root();
    Ok(scan)
}

#[derive(Clone, Debug)]
pub struct SealConfig {
    /// Do not seal an hour before `block_end + grace` (late commits).
    pub grace: Duration,
    /// Rows per read page.
    pub page_size: u32,
    /// Tenant prefix of the anchor blob key. The platform pseudo-tenant: its `Reports` DEK wraps the anchors.
    pub anchor_tenant: TenantId,
}

impl SealConfig {
    pub const DEFAULT_GRACE: Duration = Duration::from_secs(300);
    pub const DEFAULT_PAGE: u32 = 1000;

    /// Defaults: platform pseudo-tenant anchors, 5 min grace, 1000-row pages.
    #[must_use]
    pub const fn platform() -> Self {
        Self::new(db::PLATFORM_TENANT_ID)
    }

    #[must_use]
    pub const fn new(anchor_tenant: TenantId) -> Self {
        Self {
            grace: Self::DEFAULT_GRACE,
            page_size: Self::DEFAULT_PAGE,
            anchor_tenant,
        }
    }
}

impl Default for SealConfig {
    fn default() -> Self {
        Self::platform()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum SealOutcome {
    Sealed(AuditBlockRecord),
    /// Somebody sealed this hour already (idempotent re-run / second worker).
    AlreadySealed(AuditBlockRecord),
}

impl SealOutcome {
    #[must_use]
    pub const fn block(&self) -> &AuditBlockRecord {
        match self {
            Self::Sealed(b) | Self::AlreadySealed(b) => b,
        }
    }
}

fn anchor_key(cfg: &SealConfig, start: OffsetDateTime) -> Result<BlobKey, AuditError> {
    let rnd = uuid::Uuid::now_v7().simple().to_string();
    let rel = format!(
        "audit/anchors/{:04}/{:02}/{:02}t{:02}-{}.json",
        start.year(),
        u8::from(start.month()),
        start.day(),
        start.hour(),
        &rnd[24..]
    );
    Ok(BlobKey::new(cfg.anchor_tenant, &rel)?)
}

/// Counter `audit_chain_alert_total{kind}`: chain problems that need a human (gap, late event, tampering).
pub const METRIC_CHAIN_ALERT: &str = "audit_chain_alert_total";

fn chain_alert(kind: &'static str) {
    metrics::counter!(METRIC_CHAIN_ALERT, "kind" => kind).increment(1);
    tracing::error!(alert = "audit.chain", kind, "audit chain alert");
}

/// Seal the UTC hour starting at `block_start` and anchor it. Idempotent. Workers call this hourly
/// (or `seal_due`). Seal refusals (`Chain` errors) raise `audit_chain_alert_total{kind="seal_refused"}`.
///
/// # Errors
/// `Invalid` (unaligned start), `TooEarly` (inside the grace period), `Chain` (gap before this block, or
/// unsealed older events at genesis, or a stored row hash that does not match its content), storage / db errors.
pub async fn seal_block(
    db: &Db,
    store: &dyn BlobStore,
    cfg: &SealConfig,
    block_start: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<SealOutcome, AuditError> {
    let r = seal_block_inner(db, store, cfg, block_start, now).await;
    if let Err(AuditError::Chain(_)) = &r {
        chain_alert("seal_refused");
    }
    r
}

async fn seal_block_inner(
    db: &Db,
    store: &dyn BlobStore,
    cfg: &SealConfig,
    block_start: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<SealOutcome, AuditError> {
    if !is_hour_aligned(block_start) {
        return Err(AuditError::Invalid("block start must be a UTC hour"));
    }
    let block_end = block_start + BLOCK_LEN;
    let grace = time::Duration::try_from(cfg.grace).unwrap_or(time::Duration::MAX);
    if block_end.saturating_add(grace) > now {
        return Err(AuditError::TooEarly);
    }
    let mut tx = db.system_tx().await?;
    if let Some(b) = repo::get_block(&mut tx, block_start).await? {
        tx.commit().await?;
        return Ok(SealOutcome::AlreadySealed(b));
    }
    let last = repo::last_block(&mut tx).await?;
    let genesis_dirty = if last.is_none() {
        repo::events_exist_before(&mut tx, block_start).await?
    } else {
        false
    };
    tx.commit().await?;
    let prev: Hash = match &last {
        Some(l) if l.block_end == block_start => l
            .block_hash
            .as_slice()
            .try_into()
            .map_err(|_| AuditError::Chain("stored block hash has a bad length"))?,
        Some(l) if l.block_start >= block_start => {
            return Err(AuditError::Chain("a later block is already sealed"));
        }
        Some(_) => return Err(AuditError::Chain("gap: previous hour is not sealed")),
        None if genesis_dirty => {
            return Err(AuditError::Chain(
                "unsealed events older than the first block",
            ));
        }
        None => ZERO_HASH,
    };

    let scan = scan_block(db, block_start, block_end, cfg.page_size.max(1)).await?;
    if scan.bad_row_total > 0 {
        tracing::error!(
            alert = "audit.row_hash_mismatch",
            rows = scan.bad_row_total,
            "refusing to seal a block with tampered rows"
        );
        return Err(AuditError::Chain("row hash mismatch, refusing to seal"));
    }
    let fields = BlockFields {
        start: block_start,
        end: block_end,
        first_id: scan.first,
        last_id: scan.last,
        count: scan.count,
        merkle_root: &scan.merkle,
        prev: &prev,
    };
    let block_hash = compute_block_hash(&fields)?;
    let payload = anchor_payload(&fields, &block_hash)?;
    let key = anchor_key(cfg, block_start)?;
    let size = payload.len() as u64;
    let body =
        futures_util::stream::once(
            async move { Ok::<_, std::io::Error>(bytes::Bytes::from(payload)) },
        )
        .boxed();
    let meta = store.put_stream(&key, body, size.max(1)).await?;
    let blob = meta.blob_ref(&key);

    let rec = AuditBlockRecord {
        block_start,
        block_end,
        first_id: scan.first,
        last_id: scan.last,
        event_count: scan.count,
        merkle_root: scan.merkle.to_vec(),
        prev_block_hash: prev.to_vec(),
        block_hash: block_hash.to_vec(),
        anchored_blob_key: Some(blob.key.as_str().to_owned()),
        anchored_blob_write_id: blob.write_id.map(|w| uuid::Uuid::from_bytes(*w.as_bytes())),
        anchored_blob_digest: blob.digest.map(|d| d.to_vec()),
        sealed_at: trunc_micros(now),
    };
    let mut tx = db.system_tx().await?;
    match repo::insert_block(&mut tx, &rec).await {
        Ok(()) => {
            tx.commit().await?;
            Ok(SealOutcome::Sealed(rec))
        }
        Err(db::DbError::Duplicate { .. }) => {
            tx.rollback().await;
            let mut tx = db.system_tx().await?;
            let existing = repo::get_block(&mut tx, block_start).await?;
            tx.commit().await?;
            existing
                .map(SealOutcome::AlreadySealed)
                .ok_or(AuditError::Chain("block vanished after duplicate"))
        }
        Err(e) => {
            tx.rollback().await;
            Err(e.into())
        }
    }
}

/// Start of the next block to seal: after the last block, or (first run) the hour of the oldest event.
///
/// # Errors
/// Db errors.
pub async fn next_block_start(db: &Db) -> Result<Option<OffsetDateTime>, AuditError> {
    let mut tx = db.system_tx().await?;
    let last = repo::last_block(&mut tx).await?;
    let first = if last.is_none() {
        repo::first_event_time(&mut tx).await?
    } else {
        None
    };
    tx.commit().await?;
    Ok(match (last, first) {
        (Some(l), _) => Some(l.block_end),
        (None, Some(t)) => Some(hour_floor(t)),
        (None, None) => None,
    })
}

/// Seal every due block (at most `max_blocks`), oldest first. Stops at the first block still in its
/// grace period. This is the function the hourly worker job calls.
///
/// # Errors
/// The first sealing error (blocks sealed before it stay sealed).
pub async fn seal_due(
    db: &Db,
    store: &dyn BlobStore,
    cfg: &SealConfig,
    now: OffsetDateTime,
    max_blocks: u32,
) -> Result<Vec<AuditBlockRecord>, AuditError> {
    let mut out = Vec::new();
    for _ in 0..max_blocks {
        let Some(start) = next_block_start(db).await? else {
            break;
        };
        match seal_block(db, store, cfg, start, now).await {
            Ok(SealOutcome::Sealed(b)) => out.push(b),
            Ok(SealOutcome::AlreadySealed(_)) => {}
            Err(AuditError::TooEarly) => break,
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FailureKind {
    /// Block is not an aligned one-hour block.
    Malformed,
    /// Previous block missing (not contiguous).
    Gap,
    /// `prev_block_hash` is not the previous block's hash.
    PrevHashMismatch,
    /// Stored `row_hash` is not the hash of the row content (row id).
    RowHashMismatch(uuid::Uuid),
    EventCountMismatch {
        stored: i64,
        actual: i64,
    },
    FirstLastMismatch,
    MerkleMismatch,
    BlockHashMismatch,
    /// Store given but the block has no anchor.
    AnchorMissing,
    /// The anchored document differs from the block (or has a bad digest / write id).
    AnchorMismatch,
    /// The anchored document could not be read.
    AnchorUnreadable,
}

impl FailureKind {
    /// Low-cardinality metric label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::Gap => "gap",
            Self::PrevHashMismatch => "prev_hash_mismatch",
            Self::RowHashMismatch(_) => "row_hash_mismatch",
            Self::EventCountMismatch { .. } => "event_count_mismatch",
            Self::FirstLastMismatch => "first_last_mismatch",
            Self::MerkleMismatch => "merkle_mismatch",
            Self::BlockHashMismatch => "block_hash_mismatch",
            Self::AnchorMissing => "anchor_missing",
            Self::AnchorMismatch => "anchor_mismatch",
            Self::AnchorUnreadable => "anchor_unreadable",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    pub block_start: OffsetDateTime,
    pub kind: FailureKind,
}

#[derive(Clone, Debug, Default)]
pub struct VerifyReport {
    pub blocks_checked: u64,
    pub events_checked: u64,
    pub failures: Vec<Failure>,
}

impl VerifyReport {
    #[must_use]
    pub fn ok(&self) -> bool {
        self.failures.is_empty()
    }

    fn fail(&mut self, block_start: OffsetDateTime, kind: FailureKind) {
        chain_alert(kind.label());
        if self.failures.len() < MAX_FAILURES {
            self.failures.push(Failure { block_start, kind });
        }
    }
}

async fn read_anchor(store: &dyn BlobStore, b: &AuditBlockRecord) -> Result<Option<Vec<u8>>, ()> {
    let Some(key) = b.anchored_blob_key.as_deref() else {
        return Ok(None);
    };
    let key = BlobKey::parse(key).map_err(|_| ())?;
    let digest = match &b.anchored_blob_digest {
        Some(d) => Some(<[u8; 32]>::try_from(d.as_slice()).map_err(|_| ())?),
        None => None,
    };
    let r = BlobRef {
        key,
        write_id: b
            .anchored_blob_write_id
            .map(|u| WriteId::from_bytes(*u.as_bytes())),
        digest,
    };
    let mut s = store.get_stream(&r).await.map_err(|_| ())?;
    let mut out = Vec::new();
    while let Some(chunk) = s.next().await {
        out.extend_from_slice(&chunk.map_err(|_| ())?);
    }
    Ok(Some(out))
}

/// Verify the sealed blocks with `from <= block_start < to`: row hashes against row content, Merkle root,
/// block hash, links to the previous block, contiguity and (when `store` is given) the anchored documents.
/// A failure is reported, never panicked on; unsealed events (after the last block) are not covered.
///
/// # Errors
/// Only infrastructure errors (db). Tampering is reported in `VerifyReport::failures`.
pub async fn verify_chain(
    db: &Db,
    store: Option<&dyn BlobStore>,
    from: OffsetDateTime,
    to: OffsetDateTime,
    page_size: u32,
) -> Result<VerifyReport, AuditError> {
    let mut report = VerifyReport::default();
    let mut prev: Option<AuditBlockRecord> = None;
    let mut first_in_range = true;
    let mut cursor = None;
    loop {
        let mut tx = db.system_tx().await?;
        let blocks = repo::list_blocks_range(&mut tx, from, to, cursor, 200).await?;
        // Predecessor of the first block in range (outside the range).
        let pred = if first_in_range {
            match blocks.first() {
                Some(b) => repo::block_before(&mut tx, b.block_start).await?,
                None => None,
            }
        } else {
            None
        };
        tx.commit().await?;
        let Some(last) = blocks.last() else { break };
        cursor = Some(last.block_start);
        if first_in_range {
            prev = pred;
            first_in_range = false;
        }
        for b in &blocks {
            verify_block(db, store, b, prev.as_ref(), page_size.max(1), &mut report).await?;
            prev = Some(b.clone());
        }
        if blocks.len() < 200 {
            break;
        }
    }
    Ok(report)
}

async fn verify_block(
    db: &Db,
    store: Option<&dyn BlobStore>,
    b: &AuditBlockRecord,
    prev: Option<&AuditBlockRecord>,
    page: u32,
    report: &mut VerifyReport,
) -> Result<(), AuditError> {
    let start = b.block_start;
    report.blocks_checked += 1;
    if !is_hour_aligned(start) || b.block_end != start + BLOCK_LEN {
        report.fail(start, FailureKind::Malformed);
        return Ok(());
    }
    // Link to the previous block.
    match prev {
        Some(p) => {
            if p.block_end != start {
                report.fail(start, FailureKind::Gap);
            }
            if b.prev_block_hash != p.block_hash {
                report.fail(start, FailureKind::PrevHashMismatch);
            }
        }
        None => {
            if b.prev_block_hash.as_slice() != ZERO_HASH.as_slice() {
                report.fail(start, FailureKind::PrevHashMismatch);
            }
        }
    }
    // Content.
    let scan = scan_block(db, start, b.block_end, page).await?;
    report.events_checked += u64::try_from(scan.count).unwrap_or(0);
    for id in &scan.bad_rows {
        report.fail(start, FailureKind::RowHashMismatch(*id));
    }
    if scan.count != b.event_count {
        report.fail(
            start,
            FailureKind::EventCountMismatch {
                stored: b.event_count,
                actual: scan.count,
            },
        );
    }
    if scan.first != b.first_id || scan.last != b.last_id {
        report.fail(start, FailureKind::FirstLastMismatch);
    }
    if scan.merkle.as_slice() != b.merkle_root.as_slice() {
        report.fail(start, FailureKind::MerkleMismatch);
    }
    let fields = BlockFields {
        start,
        end: b.block_end,
        first_id: scan.first,
        last_id: scan.last,
        count: scan.count,
        merkle_root: &scan.merkle,
        prev: &b.prev_block_hash,
    };
    let expected = compute_block_hash(&fields)?;
    if expected.as_slice() != b.block_hash.as_slice() {
        report.fail(start, FailureKind::BlockHashMismatch);
    }
    // Anchor: the blob must contain exactly the block as stored AND as recomputed.
    if let Some(store) = store {
        if b.anchored_blob_key.is_none() {
            report.fail(start, FailureKind::AnchorMissing);
        } else {
            match read_anchor(store, b).await {
                Ok(Some(bytes)) => {
                    let want = anchor_payload(&fields, &expected)?;
                    if bytes != want {
                        report.fail(start, FailureKind::AnchorMismatch);
                    }
                }
                Ok(None) => report.fail(start, FailureKind::AnchorMissing),
                Err(()) => report.fail(start, FailureKind::AnchorUnreadable),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u8) -> Vec<u8> {
        vec![n; 32]
    }

    #[test]
    fn merkle_matches_rfc6962_for_small_trees_and_is_order_sensitive() {
        let a = h(1);
        let b = h(2);
        let c = h(3);
        let la = leaf_hash(&a);
        let lb = leaf_hash(&b);
        let lc = leaf_hash(&c);
        assert_eq!(merkle_root([a.as_slice()]), la);
        assert_eq!(
            merkle_root([a.as_slice(), b.as_slice()]),
            node_hash(&la, &lb)
        );
        // n = 3: MTH = H(MTH(a,b), c)
        assert_eq!(
            merkle_root([a.as_slice(), b.as_slice(), c.as_slice()]),
            node_hash(&node_hash(&la, &lb), &lc)
        );
        assert_ne!(
            merkle_root([a.as_slice(), b.as_slice(), c.as_slice()]),
            merkle_root([b.as_slice(), a.as_slice(), c.as_slice()])
        );
        assert_ne!(merkle_root([]), merkle_root([a.as_slice()]));
    }

    #[test]
    fn hour_floor_and_alignment() {
        let t = OffsetDateTime::from_unix_timestamp(1_800_000_123).unwrap();
        let f = hour_floor(t);
        assert!(is_hour_aligned(f));
        assert!(f <= t && t - f < BLOCK_LEN);
        assert!(!is_hour_aligned(t));
    }

    #[test]
    fn row_hash_changes_with_every_field() {
        let base = AuditRowRecord {
            id: uuid::Uuid::now_v7(),
            occurred_at: trunc_micros(OffsetDateTime::now_utc()),
            tenant_id: Some(uuid::Uuid::now_v7()),
            actor_kind: "member".into(),
            actor_id: Some(uuid::Uuid::now_v7()),
            staff_grant_id: None,
            action: "auth.login.success".into(),
            outcome: "success".into(),
            target_type: Some("session".into()),
            target_id: Some(uuid::Uuid::now_v7()),
            request_id: Some(uuid::Uuid::now_v7()),
            ip_hmac: Some(vec![7; 32]),
            metadata: Some(serde_json::json!({"b": 1, "a": "x"})),
            row_hash: vec![],
        };
        let h0 = compute_row_hash(&base).unwrap();
        let mut variants = Vec::new();
        let mut v = base.clone();
        v.outcome = "failed".into();
        variants.push(v);
        let mut v = base.clone();
        v.tenant_id = None;
        variants.push(v);
        let mut v = base.clone();
        v.staff_grant_id = Some(uuid::Uuid::now_v7());
        variants.push(v);
        let mut v = base.clone();
        v.ip_hmac = None;
        variants.push(v);
        let mut v = base.clone();
        v.metadata = Some(serde_json::json!({"b": 2, "a": "x"}));
        variants.push(v);
        let mut v = base.clone();
        v.occurred_at += time::Duration::microseconds(1);
        variants.push(v);
        for v in variants {
            assert_ne!(compute_row_hash(&v).unwrap(), h0);
        }
        // Key order of the metadata object does not matter (canonical JSON).
        let mut v = base;
        v.metadata = Some(serde_json::json!({"a": "x", "b": 1}));
        assert_eq!(compute_row_hash(&v).unwrap(), h0);
    }
}
