//! `S3BlobStore` (feature `s3`): S3-compatible backend (AWS S3, Cloudflare R2, MinIO) via `object_store`.
//!
//! ## Memory (S3 par O(part), O(chunk) nahi)
//! Ek upload = ek `part_size` accumulation buffer + max `part_concurrency` parts in flight
//! = `part_size * (1 + part_concurrency)` = **~15 MB** (defaults 5 MiB, 2). Crate-level semaphore
//! (`max_concurrent_uploads`, default 2) ke saath worst case ~**30 MB** total for uploads. Yeh ek budget
//! line hai jo `docs/ARCHITECTURE.md` 12 ke table mein add honi chahiye (upload buffers: 2 x 15 MB).
//! Downloads stream hote hain (frame-by-frame, buffering nahi). `blob < part_size` ek single PUT hota hai
//! (multipart nahi, sirf <= 5 MiB buffer).
//!
//! ## Cancel / failure
//! Multipart upload ek guard (`Upload`) mein rehta hai: normal error par `abort`, aur agar put future
//! beech mein drop ho (client disconnect / timeout) to `Drop` ek cleanup task (runtime handle par) chalata
//! hai jo in-flight parts rok kar `abort` karta hai. `object_store::WriteMultipart::finish` complete
//! fail hone par abort **nahi** karta, isliye hum apna loop chalate hain aur complete error par bhi abort karte hain.
//! Process crash par abort possible nahi: **bucket par `AbortIncompleteMultipartUpload` lifecycle rule
//! (e.g. 1 day) zaroor lagao** (R2: same rule via lifecycle settings), warna orphan parts billable rehte hain.
//!
//! Encryption yahan nahi: isse `EncryptedBlobStore<S3BlobStore>` mein wrap karo. TLS = rustls + aws-lc-rs.
//! Real-network tests is crate mein nahi hain; logic `object_store::memory::InMemory` par tested hai.

use crate::error::StorageError;
use crate::key::BlobKey;
use crate::{BlobMeta, BlobRef, BlobStore, ByteStream};
use bytes::BytesMut;
use futures_util::StreamExt as _;
use object_store::aws::AmazonS3Builder;
use object_store::path::Path as ObjPath;
use object_store::{MultipartUpload, ObjectStore, ObjectStoreExt as _, PutPayload};
use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

/// S3 minimum part size (last part ke alawa).
pub const MIN_PART_SIZE: usize = 5 * 1024 * 1024;

/// Memory/concurrency limits. Per-upload memory ~ `part_size * (1 + part_concurrency)`.
#[derive(Clone, Copy, Debug)]
pub struct S3Limits {
    pub part_size: usize,
    /// Ek upload ke parts in flight.
    pub part_concurrency: usize,
    /// Crate-level: kitne uploads ek saath (semaphore); baaki wait karte hain.
    pub max_concurrent_uploads: usize,
    /// Upload permit ke liye max wait; baad mein `StorageError::Busy` (API: 503).
    pub acquire_timeout: Duration,
}

impl Default for S3Limits {
    fn default() -> Self {
        Self {
            part_size: MIN_PART_SIZE,
            part_concurrency: 2,
            max_concurrent_uploads: 2,
            acquire_timeout: Duration::from_secs(10),
        }
    }
}

/// Connection config. `Debug` credentials redact karta hai.
#[derive(Clone)]
pub struct S3Config {
    pub bucket: String,
    pub region: String,
    /// R2 / MinIO endpoint (AWS S3 par `None`).
    pub endpoint: Option<String>,
    pub access_key_id: String,
    pub secret_access_key: String,
    /// Sirf local MinIO jaisi `http://` endpoints ke liye.
    pub allow_http: bool,
    pub limits: S3Limits,
}

impl S3Config {
    #[must_use]
    pub fn new(
        bucket: impl Into<String>,
        region: impl Into<String>,
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
    ) -> Self {
        Self {
            bucket: bucket.into(),
            region: region.into(),
            endpoint: None,
            access_key_id: access_key_id.into(),
            secret_access_key: secret_access_key.into(),
            allow_http: false,
            limits: S3Limits::default(),
        }
    }
}

impl fmt::Debug for S3Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Config")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct S3BlobStore {
    store: Arc<dyn ObjectStore>,
    limits: S3Limits,
    uploads: Arc<Semaphore>,
}

impl fmt::Debug for S3BlobStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3BlobStore")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// `object_store` error -> fixed, value-free `StorageError`. Detail sirf `tracing` mein (variant label,
/// koi path/tenant/endpoint nahi).
fn backend(e: &object_store::Error) -> StorageError {
    let (label, err) = match e {
        object_store::Error::NotFound { .. } => return StorageError::NotFound,
        object_store::Error::AlreadyExists { .. } | object_store::Error::Precondition { .. } => {
            ("conflict", StorageError::Backend("conflict"))
        }
        object_store::Error::NotSupported { .. } | object_store::Error::NotImplemented { .. } => (
            "unsupported",
            StorageError::Backend("operation not supported"),
        ),
        object_store::Error::InvalidPath { .. } => {
            ("invalid_path", StorageError::Backend("invalid object path"))
        }
        _ => ("request_failed", StorageError::Backend("request failed")),
    };
    tracing::warn!(target: "storage::s3", kind = label, "object store request failed");
    err
}

impl S3BlobStore {
    /// # Errors
    /// `Backend` agar config invalid (bucket/region/endpoint) ya limits invalid.
    pub fn new(cfg: &S3Config) -> Result<Self, StorageError> {
        let mut b = AmazonS3Builder::new()
            .with_bucket_name(&cfg.bucket)
            .with_region(&cfg.region)
            .with_access_key_id(&cfg.access_key_id)
            .with_secret_access_key(&cfg.secret_access_key)
            .with_allow_http(cfg.allow_http);
        if let Some(ep) = &cfg.endpoint {
            b = b.with_endpoint(ep);
        }
        let s3 = b.build().map_err(|e| backend(&e))?;
        Self::from_store(Arc::new(s3), cfg.limits)
    }

    /// Koi bhi `ObjectStore` (tests mein `InMemory`).
    ///
    /// # Errors
    /// `Backend` agar `part_size` < 5 MiB ya koi concurrency 0.
    pub fn from_store(store: Arc<dyn ObjectStore>, limits: S3Limits) -> Result<Self, StorageError> {
        if limits.part_size < MIN_PART_SIZE
            || limits.part_concurrency == 0
            || limits.max_concurrent_uploads == 0
        {
            return Err(StorageError::Backend("invalid S3 limits"));
        }
        Ok(Self {
            store,
            limits,
            uploads: Arc::new(Semaphore::new(limits.max_concurrent_uploads)),
        })
    }

    fn path(key: &BlobKey) -> Result<ObjPath, StorageError> {
        ObjPath::parse(key.as_str())
            .map_err(|_| StorageError::InvalidKey("rejected by object path"))
    }
}

/// Multipart upload guard: error par `abort`, drop par cleanup task (in-flight parts rok ke abort).
struct Upload {
    up: Option<Box<dyn MultipartUpload>>,
    tasks: JoinSet<object_store::Result<()>>,
    /// Upload-limiter permit: cleanup khatam hone tak hold hota hai.
    permit: Option<OwnedSemaphorePermit>,
}

impl Upload {
    fn start_part(&mut self, data: bytes::Bytes) -> Result<(), StorageError> {
        let up = self
            .up
            .as_mut()
            .ok_or(StorageError::Backend("upload closed"))?;
        self.tasks.spawn(up.put_part(PutPayload::from(data)));
        Ok(())
    }

    /// Jab tak `max` se kam parts in flight na hon, ruko.
    async fn drain_to(&mut self, max: usize) -> Result<(), StorageError> {
        while self.tasks.len() > max {
            match self.tasks.join_next().await {
                Some(Ok(Ok(()))) | None => {}
                Some(Ok(Err(e))) => return Err(backend(&e)),
                Some(Err(_)) => return Err(StorageError::Backend("upload task failed")),
            }
        }
        Ok(())
    }

    async fn abort(mut self) {
        self.tasks.shutdown().await;
        if let Some(mut up) = self.up.take() {
            let _ = up.abort().await;
        }
    }

    /// Saare parts wait karo, complete karo; kisi bhi error par abort.
    async fn complete(mut self) -> Result<(), StorageError> {
        let mut res = self.drain_to(0).await;
        if res.is_ok() {
            res = match self.up.as_mut() {
                Some(up) => up.complete().await.map(|_| ()).map_err(|e| backend(&e)),
                None => Err(StorageError::Backend("upload closed")),
            };
        }
        match res {
            Ok(()) => {
                self.up = None; // Drop par abort nahi
                Ok(())
            }
            Err(e) => {
                self.abort().await;
                Err(e)
            }
        }
    }
}

impl Drop for Upload {
    fn drop(&mut self) {
        let Some(mut up) = self.up.take() else {
            return;
        };
        // Cancel/drop: async abort ke liye runtime chahiye. Handle::spawn ek cleanup task (bounded by upload
        // limiter: permit cleanup tak hold).
        let mut tasks = std::mem::take(&mut self.tasks);
        let permit = self.permit.take();
        if let Ok(h) = tokio::runtime::Handle::try_current() {
            h.spawn(async move {
                tasks.shutdown().await;
                let _ = up.abort().await;
                drop(permit);
            });
        } else {
            tracing::warn!(target: "storage::s3", "multipart upload dropped without runtime; relies on bucket lifecycle rule");
        }
    }
}

#[async_trait::async_trait]
impl BlobStore for S3BlobStore {
    async fn put_stream(
        &self,
        key: &BlobKey,
        mut body: ByteStream,
        max_bytes: u64,
    ) -> Result<BlobMeta, StorageError> {
        let path = Self::path(key)?;
        let permit = tokio::time::timeout(
            self.limits.acquire_timeout,
            Arc::clone(&self.uploads).acquire_owned(),
        )
        .await
        .map_err(|_| StorageError::Busy)?
        .map_err(|_| StorageError::Backend("upload limiter closed"))?;
        let part_size = self.limits.part_size;
        let mut buf = BytesMut::new();
        let mut upload: Option<Upload> = None;
        let mut permit = Some(permit);
        let mut total: u64 = 0;

        while let Some(item) = body.next().await {
            let chunk = match item {
                Ok(c) => c,
                Err(e) => {
                    if let Some(u) = upload {
                        u.abort().await;
                    }
                    return Err(StorageError::from_io(e));
                }
            };
            if total.saturating_add(chunk.len() as u64) > max_bytes {
                if let Some(u) = upload {
                    u.abort().await;
                }
                return Err(StorageError::TooLarge { max: max_bytes });
            }
            total += chunk.len() as u64;
            let mut data = chunk;
            while !data.is_empty() {
                if buf.is_empty() {
                    // Is buffer ko ab jitna maximum mil sakta hai: baaki chunk + limit ka bacha hissa.
                    let may_receive =
                        (data.len() as u64).saturating_add(max_bytes.saturating_sub(total));
                    buf.reserve(part_size.min(usize::try_from(may_receive).unwrap_or(part_size)));
                }
                let take = (part_size - buf.len()).min(data.len());
                buf.extend_from_slice(&data.split_to(take));
                if buf.len() < part_size {
                    continue;
                }
                // Part full: multipart lazily shuru, backpressure, part bhejo.
                if upload.is_none() {
                    let up = self
                        .store
                        .put_multipart(&path)
                        .await
                        .map_err(|e| backend(&e))?;
                    upload = Some(Upload {
                        up: Some(up),
                        tasks: JoinSet::new(),
                        permit: permit.take(),
                    });
                }
                let Some(u) = upload.as_mut() else { continue };
                let part = buf.split().freeze();
                let step = match u.drain_to(self.limits.part_concurrency - 1).await {
                    Ok(()) => u.start_part(part),
                    Err(e) => Err(e),
                };
                if let Err(e) = step {
                    if let Some(u) = upload.take() {
                        u.abort().await;
                    }
                    return Err(e);
                }
            }
        }

        match upload {
            None => {
                // Chhota blob: single PUT (multipart nahi).
                self.store
                    .put(&path, PutPayload::from(buf.freeze()))
                    .await
                    .map_err(|e| backend(&e))?;
            }
            Some(mut u) => {
                if !buf.is_empty()
                    && let Err(e) = u.start_part(buf.freeze())
                {
                    u.abort().await;
                    return Err(e);
                }
                u.complete().await?;
            }
        }
        drop(permit);
        Ok(BlobMeta {
            size: total,
            write_id: None,
            digest: None,
            kid: None,
            created_at: OffsetDateTime::now_utc(),
        })
    }

    async fn get_stream(&self, r: &BlobRef) -> Result<ByteStream, StorageError> {
        let path = Self::path(&r.key)?;
        let res = self.store.get(&path).await.map_err(|e| backend(&e))?;
        Ok(res
            .into_stream()
            .map(|r| {
                r.map_err(|e| {
                    let _ = backend(&e);
                    io::Error::other("storage backend stream error")
                })
            })
            .boxed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use common::TenantId;
    use futures_util::{TryStreamExt as _, stream};
    use object_store::memory::InMemory;
    use object_store::{
        CopyOptions, GetOptions, GetResult, ListResult, ObjectMeta, PutMultipartOptions,
        PutOptions, PutResult, UploadPart,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[derive(Debug)]
    struct CountUp {
        inner: Box<dyn MultipartUpload>,
        aborts: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl MultipartUpload for CountUp {
        fn put_part(&mut self, data: PutPayload) -> UploadPart {
            self.inner.put_part(data)
        }
        async fn complete(&mut self) -> object_store::Result<PutResult> {
            self.inner.complete().await
        }
        async fn abort(&mut self) -> object_store::Result<()> {
            self.aborts.fetch_add(1, Ordering::SeqCst);
            self.inner.abort().await
        }
    }

    /// InMemory + multipart start/abort counters.
    #[derive(Debug)]
    struct Counting {
        inner: Arc<InMemory>,
        started: Arc<AtomicUsize>,
        aborts: Arc<AtomicUsize>,
    }

    impl fmt::Display for Counting {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("Counting")
        }
    }

    #[async_trait::async_trait]
    impl ObjectStore for Counting {
        async fn put_opts(
            &self,
            l: &ObjPath,
            p: PutPayload,
            o: PutOptions,
        ) -> object_store::Result<PutResult> {
            self.inner.put_opts(l, p, o).await
        }
        async fn put_multipart_opts(
            &self,
            l: &ObjPath,
            o: PutMultipartOptions,
        ) -> object_store::Result<Box<dyn MultipartUpload>> {
            let inner = self.inner.put_multipart_opts(l, o).await?;
            self.started.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(CountUp {
                inner,
                aborts: Arc::clone(&self.aborts),
            }))
        }
        async fn get_opts(&self, l: &ObjPath, o: GetOptions) -> object_store::Result<GetResult> {
            self.inner.get_opts(l, o).await
        }
        fn delete_stream(
            &self,
            locations: futures_util::stream::BoxStream<'static, object_store::Result<ObjPath>>,
        ) -> futures_util::stream::BoxStream<'static, object_store::Result<ObjPath>> {
            self.inner.delete_stream(locations)
        }
        fn list(
            &self,
            prefix: Option<&ObjPath>,
        ) -> futures_util::stream::BoxStream<'static, object_store::Result<ObjectMeta>> {
            self.inner.list(prefix)
        }
        async fn list_with_delimiter(
            &self,
            prefix: Option<&ObjPath>,
        ) -> object_store::Result<ListResult> {
            self.inner.list_with_delimiter(prefix).await
        }
        async fn copy_opts(
            &self,
            from: &ObjPath,
            to: &ObjPath,
            o: CopyOptions,
        ) -> object_store::Result<()> {
            self.inner.copy_opts(from, to, o).await
        }
    }

    struct Fixture {
        s3: S3BlobStore,
        mem: Arc<InMemory>,
        started: Arc<AtomicUsize>,
        aborts: Arc<AtomicUsize>,
    }

    fn fixture(max_uploads: usize) -> Fixture {
        let mem = Arc::new(InMemory::new());
        let started = Arc::new(AtomicUsize::new(0));
        let aborts = Arc::new(AtomicUsize::new(0));
        let store = Counting {
            inner: Arc::clone(&mem),
            started: Arc::clone(&started),
            aborts: Arc::clone(&aborts),
        };
        let s3 = S3BlobStore::from_store(
            Arc::new(store),
            S3Limits {
                max_concurrent_uploads: max_uploads,
                ..S3Limits::default()
            },
        )
        .unwrap();
        Fixture {
            s3,
            mem,
            started,
            aborts,
        }
    }

    fn body(data: Vec<u8>) -> ByteStream {
        let frames: Vec<io::Result<Bytes>> = data
            .chunks(100_000)
            .map(|c| Ok(Bytes::copy_from_slice(c)))
            .collect();
        stream::iter(frames).boxed()
    }

    /// 6 MiB data ke baad kabhi khatam na hone wali body (cancel tests).
    fn stalled_body() -> ByteStream {
        let first: Vec<io::Result<Bytes>> = (0..6)
            .map(|_| Ok(Bytes::from(vec![1u8; 1024 * 1024])))
            .collect();
        stream::iter(first).chain(stream::pending()).boxed()
    }

    async fn count(mem: &InMemory) -> usize {
        mem.list(None).try_collect::<Vec<_>>().await.unwrap().len()
    }

    async fn wait_aborts(f: &Fixture, n: usize) {
        for _ in 0..100 {
            if f.aborts.load(Ordering::SeqCst) >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[test]
    fn config_debug_redacts_credentials_and_bad_limits_rejected() {
        let c = S3Config::new("b", "auto", "AKIA-SECRET-ID", "super-secret-key");
        let d = format!("{c:?}");
        assert!(!d.contains("AKIA-SECRET-ID") && !d.contains("super-secret-key"));
        let mem: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let bad = |l: S3Limits| S3BlobStore::from_store(Arc::clone(&mem), l).is_err();
        assert!(bad(S3Limits {
            part_size: 1024,
            ..S3Limits::default()
        }));
        assert!(bad(S3Limits {
            part_concurrency: 0,
            ..S3Limits::default()
        }));
        assert!(bad(S3Limits {
            max_concurrent_uploads: 0,
            ..S3Limits::default()
        }));
    }

    #[test]
    fn backend_errors_are_fixed_and_value_free() {
        let e = object_store::Error::Generic {
            store: "S3",
            source: "https://secret-endpoint.example/tenant-1234/key".into(),
        };
        let m = format!("{}", backend(&e));
        assert!(
            !m.contains("secret-endpoint") && !m.contains("tenant-1234"),
            "{m}"
        );
        assert_eq!(m, "storage backend error: request failed");
    }

    #[tokio::test]
    async fn roundtrip_limit_and_abort() {
        let f = fixture(2);
        let k = BlobKey::new(TenantId::new(), "r/a.bin").unwrap();
        for n in [
            0usize,
            1,
            MIN_PART_SIZE,
            MIN_PART_SIZE + 1,
            12 * 1024 * 1024,
        ] {
            let p: Vec<u8> = (0..n).map(|i| u8::try_from(i % 253).unwrap_or(0)).collect();
            let meta =
                f.s3.put_stream(&k, body(p.clone()), u64::MAX)
                    .await
                    .unwrap();
            assert_eq!(meta.size, n as u64);
            let got: Vec<Bytes> =
                f.s3.get_stream(&BlobRef::from_key(k.clone()))
                    .await
                    .unwrap()
                    .try_collect()
                    .await
                    .unwrap();
            assert_eq!(got.concat(), p, "size {n}");
        }
        // limit (multipart shuru hone ke baad): error, abort, naya object nahi
        let k2 = BlobKey::new(k.tenant(), "r/big.bin").unwrap();
        let e =
            f.s3.put_stream(&k2, body(vec![1u8; 7 * 1024 * 1024]), 6 * 1024 * 1024)
                .await
                .unwrap_err();
        assert!(matches!(e, StorageError::TooLarge { .. }), "{e:?}");
        assert!(matches!(
            f.s3.get_stream(&BlobRef::from_key(k2.clone())).await,
            Err(StorageError::NotFound)
        ));
        assert_eq!(count(&f.mem).await, 1);
        assert_eq!(f.aborts.load(Ordering::SeqCst), 1);
        // body error multipart ke beech
        let mut items: Vec<io::Result<Bytes>> = vec![Ok(Bytes::from(vec![0u8; 6 * 1024 * 1024]))];
        items.push(Err(io::Error::other("x")));
        let e =
            f.s3.put_stream(&k2, stream::iter(items).boxed(), u64::MAX)
                .await
                .unwrap_err();
        assert!(matches!(e, StorageError::Io(_)), "{e:?}");
        assert_eq!(count(&f.mem).await, 1);
        assert_eq!(f.aborts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn dropped_put_aborts_multipart_and_leaves_no_object() {
        let f = fixture(2);
        let k = BlobKey::new(TenantId::new(), "r/cancel.bin").unwrap();
        let r = tokio::time::timeout(
            Duration::from_millis(300),
            f.s3.put_stream(&k, stalled_body(), u64::MAX),
        )
        .await;
        assert!(r.is_err(), "put must still be pending (timed out)");
        wait_aborts(&f, 1).await;
        assert_eq!(f.started.load(Ordering::SeqCst), 1);
        assert_eq!(f.aborts.load(Ordering::SeqCst), 1, "abort must run on drop");
        assert_eq!(count(&f.mem).await, 0);
        // permit wapas aa gaya
        assert_eq!(f.s3.uploads.available_permits(), 2);
    }

    #[tokio::test]
    async fn busy_when_upload_permit_not_acquired_in_time() {
        let mut f = fixture(1);
        f.s3.limits.acquire_timeout = Duration::from_millis(100);
        let k1 = BlobKey::new(TenantId::new(), "r/one.bin").unwrap();
        let k2 = BlobKey::new(k1.tenant(), "r/two.bin").unwrap();
        let a = tokio::time::timeout(
            Duration::from_millis(1500),
            f.s3.put_stream(&k1, stalled_body(), u64::MAX),
        );
        let b = async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            f.s3.put_stream(&k2, body(vec![5; 10]), u64::MAX).await
        };
        let (ra, rb) = futures_util::join!(a, b);
        assert!(ra.is_err());
        assert!(matches!(rb, Err(StorageError::Busy)), "{rb:?}");
        wait_aborts(&f, 1).await;
    }

    #[tokio::test]
    async fn upload_limiter_blocks_extra_uploads() {
        let f = fixture(1);
        let k1 = BlobKey::new(TenantId::new(), "r/one.bin").unwrap();
        let k2 = BlobKey::new(k1.tenant(), "r/two.bin").unwrap();
        let a = tokio::time::timeout(
            Duration::from_millis(600),
            f.s3.put_stream(&k1, stalled_body(), u64::MAX),
        );
        let b = tokio::time::timeout(
            Duration::from_millis(250),
            f.s3.put_stream(&k2, body(vec![5; 10]), u64::MAX),
        );
        let (ra, rb) = futures_util::join!(a, b);
        assert!(ra.is_err());
        assert!(rb.is_err(), "second upload must wait for the permit");
        wait_aborts(&f, 1).await;
        // limiter free => ab chal jaata hai
        f.s3.put_stream(&k2, body(vec![5; 10]), u64::MAX)
            .await
            .unwrap();
        assert_eq!(count(&f.mem).await, 1);
    }
}
