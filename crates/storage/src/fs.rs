//! `FsBlobStore`: local filesystem backend (dev, tests, single-node).
//!
//! - Layout: `<root>/<tenant-uuid>/<seg>/.../<name>`; temp files `<root>/.tmp/<uuid>.part`
//!   (key segments `.` se shuru nahi ho sakte, isliye `.tmp` se collision nahi).
//! - Atomic write: temp file -> `sync_all` -> rename. Reader ko purana ya poora naya blob dikhta hai.
//! - Symlinks: root ke andar har existing component `symlink_metadata` se check hota hai (symlink /
//!   reparse point => `UnsafePath`), aur final parent ka canonical path root ke andar hona chahiye.
//!   Bacha hua TOCTOU window (check aur open ke beech koi local attacker symlink daale) tab hi relevant
//!   hai jab attacker ke paas root directory par write access ho; root ko sirf service user ke liye rakho.
//! - Windows par bhi chalta hai (rename existing file ko replace karta hai; handle rename se pehle close).

use crate::error::StorageError;
use crate::key::BlobKey;
use crate::{BlobMeta, BlobRef, BlobStore, ByteStream};
use bytes::Bytes;
use futures_util::StreamExt as _;
use futures_util::stream::unfold;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const READ_CHUNK: usize = 64 * 1024;
const TMP_DIR: &str = ".tmp";
/// `sweep_stale_temp` ka minimum `max_age` (live uploads ki temp files bachane ke liye).
pub const MIN_SWEEP_AGE: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone)]
pub struct FsBlobStore {
    /// Canonical root.
    root: PathBuf,
}

/// Temp file ko drop par hata do (cancel / error / panic safe). Rename ke baad `disarm`.
struct TmpGuard(Option<PathBuf>);

impl TmpGuard {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for TmpGuard {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            let _ = std::fs::remove_file(p);
        }
    }
}

impl FsBlobStore {
    /// Root dir banao/canonicalise karo (startup par sync call theek hai).
    ///
    /// # Errors
    /// `Io` agar root nahi ban saka ya symlink-resolve fail hua.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, StorageError> {
        std::fs::create_dir_all(root.as_ref())?;
        let root = std::fs::canonicalize(root.as_ref())?;
        std::fs::create_dir_all(root.join(TMP_DIR))?;
        Ok(Self { root })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `.tmp/*.part` files jo `max_age` se purani hain hata do (crash/kill ke baad bache temp files).
    /// Api/workers **startup par** call karein (chalte hue puts ki temp files na hatein, isliye
    /// `max_age >= MIN_SWEEP_AGE` = 1 ghanta zaroori hai). Returns kitni files hati.
    ///
    /// # Errors
    /// `Io(InvalidInput)` agar `max_age < MIN_SWEEP_AGE`; `Io` agar `.tmp` dir padha nahi ja saka.
    pub async fn sweep_stale_temp(&self, max_age: Duration) -> Result<usize, StorageError> {
        if max_age < MIN_SWEEP_AGE {
            return Err(StorageError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "max_age below MIN_SWEEP_AGE",
            )));
        }
        let cutoff = SystemTime::now().checked_sub(max_age);
        let mut rd = tokio::fs::read_dir(self.root.join(TMP_DIR)).await?;
        let mut removed = 0;
        while let Some(e) = rd.next_entry().await? {
            let path = e.path();
            if path.extension().and_then(|x| x.to_str()) != Some("part") {
                continue;
            }
            let Ok(md) = e.metadata().await else { continue };
            if !md.is_file() {
                continue;
            }
            let old = match (md.modified(), cutoff) {
                (Ok(m), Some(c)) => m <= c,
                // cutoff underflow (max_age bahut bada) ya mtime unknown: kuch mat hatao.
                _ => false,
            };
            if old && tokio::fs::remove_file(&path).await.is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Key ke parent dir tak safe path. `create` par missing dirs banata hai.
    async fn resolve_parent(&self, key: &BlobKey, create: bool) -> Result<PathBuf, StorageError> {
        let mut cur = self.root.clone();
        let tenant = key.tenant().as_uuid().hyphenated().to_string();
        let segs: Vec<&str> = key.segments().collect();
        let dir_parts = segs.len().saturating_sub(1);
        let parts = std::iter::once(tenant.as_str()).chain(segs.iter().copied().take(dir_parts));
        for part in parts {
            cur.push(part);
            match tokio::fs::symlink_metadata(&cur).await {
                Ok(md) if md.file_type().is_symlink() => return Err(StorageError::UnsafePath),
                Ok(md) if md.is_dir() => {}
                Ok(_) => return Err(StorageError::UnsafePath),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    if !create {
                        return Err(StorageError::NotFound);
                    }
                    match tokio::fs::create_dir(&cur).await {
                        Ok(()) => {}
                        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                        Err(e) => return Err(e.into()),
                    }
                    // race: kisi ne ab tak symlink bana diya ho to dobara dekho
                    let md = tokio::fs::symlink_metadata(&cur).await?;
                    if md.file_type().is_symlink() || !md.is_dir() {
                        return Err(StorageError::UnsafePath);
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
        let canon = tokio::fs::canonicalize(&cur).await?;
        if !canon.starts_with(&self.root) {
            return Err(StorageError::UnsafePath);
        }
        Ok(cur)
    }

    async fn resolve_file(&self, key: &BlobKey, create: bool) -> Result<PathBuf, StorageError> {
        let parent = self.resolve_parent(key, create).await?;
        let name = key
            .segments()
            .last()
            .ok_or(StorageError::InvalidKey("no object name"))?;
        Ok(parent.join(name))
    }
}

#[cfg(unix)]
async fn sync_dir(dir: &Path) {
    if let Ok(d) = tokio::fs::File::open(dir).await {
        let _ = d.sync_all().await;
    }
}

#[cfg(not(unix))]
#[allow(clippy::unused_async)]
async fn sync_dir(_dir: &Path) {
    // Windows par directory handle fsync supported nahi (rename durability NTFS journal par).
}

#[async_trait::async_trait]
impl BlobStore for FsBlobStore {
    async fn put_stream(
        &self,
        key: &BlobKey,
        mut body: ByteStream,
        max_bytes: u64,
    ) -> Result<BlobMeta, StorageError> {
        let tmp_path = self
            .root
            .join(TMP_DIR)
            .join(format!("{}.part", uuid::Uuid::now_v7().simple()));
        let mut guard = TmpGuard(Some(tmp_path.clone()));
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .await?;
        let mut written: u64 = 0;
        while let Some(item) = body.next().await {
            let chunk = item.map_err(StorageError::from_io)?;
            if written.saturating_add(chunk.len() as u64) > max_bytes {
                return Err(StorageError::TooLarge { max: max_bytes });
            }
            written += chunk.len() as u64;
            file.write_all(&chunk).await?;
        }
        file.flush().await?;
        file.sync_all().await?;
        // std handle banake drop: Windows par rename se pehle handle band hona zaroori hai.
        drop(file.into_std().await);

        let dest = self.resolve_file(key, true).await?;
        if let Ok(md) = tokio::fs::symlink_metadata(&dest).await
            && !md.is_file()
        {
            return Err(StorageError::UnsafePath);
        }
        tokio::fs::rename(&tmp_path, &dest).await?;
        guard.disarm();
        if let Some(parent) = dest.parent() {
            sync_dir(parent).await;
        }
        Ok(BlobMeta {
            size: written,
            write_id: None,
            digest: None,
            kid: None,
            created_at: OffsetDateTime::now_utc(),
        })
    }

    async fn get_stream(&self, r: &BlobRef) -> Result<ByteStream, StorageError> {
        let path = self.resolve_file(&r.key, false).await?;
        let md = tokio::fs::symlink_metadata(&path).await.map_err(map_nf)?;
        if !md.is_file() {
            return Err(StorageError::UnsafePath);
        }
        let file = tokio::fs::File::open(&path).await.map_err(map_nf)?;
        Ok(unfold(Some(file), |st| async move {
            let mut file = st?;
            let mut buf = vec![0u8; READ_CHUNK];
            match file.read(&mut buf).await {
                Ok(0) => None,
                Ok(n) => {
                    buf.truncate(n);
                    Some((Ok(Bytes::from(buf)), Some(file)))
                }
                Err(e) => Some((Err(e), None)),
            }
        })
        .boxed())
    }
}

fn map_nf(e: io::Error) -> StorageError {
    if e.kind() == io::ErrorKind::NotFound {
        StorageError::NotFound
    } else {
        StorageError::Io(e)
    }
}
