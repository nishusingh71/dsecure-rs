//! `StorageError`: koi message plaintext, key bytes, tenant id, endpoint ya filesystem path nahi rakhta.
//! Backend ki detail sirf `tracing` event mein jaati hai (fixed labels, koi value nahi).

use std::io;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// Blob key validation fail (static reason, key echo nahi hoti).
    #[error("invalid blob key: {0}")]
    InvalidKey(&'static str),
    #[error("blob not found")]
    NotFound,
    /// `max_bytes` cross hua; partial object saaf kar diya gaya.
    #[error("blob exceeds the {max} byte limit")]
    TooLarge { max: u64 },
    /// Key kisi symlink/reparse point ya file-vs-directory conflict ki taraf ja rahi hai.
    #[error("unsafe or conflicting storage path")]
    UnsafePath,
    /// Stream encryption: tag/AAD/order/truncation/wrong key/digest. Wajah jaan-boojh kar nahi batate.
    #[error("blob integrity check failed")]
    Integrity,
    /// Header magic/version/length galat.
    #[error("unsupported or malformed blob header")]
    BadHeader,
    /// Stored blob ka `write_id` caller ke expected reference se alag hai (rollback / stale object).
    #[error("blob write id does not match the expected reference")]
    WriteIdMismatch,
    /// Encrypted store ko `BlobRef.write_id` chahiye.
    #[error("blob reference has no write id")]
    MissingWriteId,
    /// Upload limiter busy (acquire timeout): API ise 503 + Retry-After banaye.
    #[error("storage busy, try again later")]
    Busy,
    #[error(transparent)]
    Crypto(#[from] crypto::CryptoError),
    #[error("storage I/O error: {0}")]
    Io(#[from] io::Error),
    /// Remote backend (S3) error: fixed label, kabhi path/tenant/endpoint nahi.
    #[error("storage backend error: {0}")]
    Backend(&'static str),
}

impl StorageError {
    /// Stream ke andar `io::Error` mein wrap hua `StorageError` wapas nikalo (warna `Io`).
    #[must_use]
    pub fn from_io(e: io::Error) -> Self {
        if e.get_ref().is_some_and(|r| r.is::<Self>()) {
            return match e.into_inner() {
                Some(inner) => match inner.downcast::<Self>() {
                    Ok(se) => *se,
                    Err(other) => Self::Io(io::Error::other(other)),
                },
                None => Self::Io(io::Error::other("lost inner error")),
            };
        }
        Self::Io(e)
    }
}

impl From<StorageError> for io::Error {
    fn from(e: StorageError) -> Self {
        match e {
            StorageError::Io(io) => io,
            other => Self::other(other),
        }
    }
}
