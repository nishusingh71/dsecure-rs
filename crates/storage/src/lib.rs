//! storage: `BlobStore` (fs + optional S3), STREAM chunked encryption, `EncryptedBlobStore`.
//!
//! Design: `docs/PHASE0_SPEC.md` 3.7, `docs/SECURITY.md` 3, `docs/ARCHITECTURE.md` 12.4.
//! Memory: O(chunk) = 64 KB fs/encryption par; S3 par O(part) (`S3Limits`, ~15 MB per upload, see `s3`).
//! Koi bhi path poori blob buffer nahi karta.
//!
//! API notes:
//! - STREAM primitives crate-private hain (key/nonce-prefix reuse ka koi raasta public nahi); sirf
//!   `EncryptedBlobStore` encrypt karta hai, har put par fresh key + nonce prefix + `write_id`.
//! - `BlobStore::get_stream` ko `BlobRef` chahiye (key + expected `write_id` + optional digest);
//!   DB row yahi store kare (`BlobMeta::blob_ref`).
//! - Stream tabhi valid hai jab wo bina error ke end tak pahunche (see `BlobStore::get_stream`).

mod digest;
pub mod encrypted;
pub mod error;
pub mod fs;
pub mod key;
#[cfg(feature = "s3")]
pub mod s3;
mod stream_crypto;

pub use encrypted::EncryptedBlobStore;
pub use error::StorageError;
pub use fs::FsBlobStore;
pub use key::BlobKey;
#[cfg(feature = "s3")]
pub use s3::{S3BlobStore, S3Config, S3Limits};
/// STREAM chunk size (plaintext) aur per-chunk tag; tests / size maths ke liye.
pub use stream_crypto::{CHUNK_SIZE, TAG_LEN};

use bytes::Bytes;
use crypto::Kid;
use futures_util::stream::BoxStream;
use std::fmt;
use std::io;
use time::OffsetDateTime;

/// Body stream type (put input / get output).
pub type ByteStream = BoxStream<'static, Result<Bytes, io::Error>>;

/// Har put ka random 128-bit id. Header mein aur wrapped-key context mein bind hota hai: purana
/// object same key par wapas rakhne (rollback) par `write_id` badal jaata hai aur get fail hota hai.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct WriteId([u8; 16]);

impl WriteId {
    /// # Errors
    /// `Crypto(Rng)`.
    pub fn generate() -> Result<Self, StorageError> {
        let mut b = [0u8; 16];
        aws_lc_rs::rand::fill(&mut b).map_err(|_| crypto::CryptoError::Rng)?;
        Ok(Self(b))
    }

    #[must_use]
    pub const fn from_bytes(b: [u8; 16]) -> Self {
        Self(b)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for WriteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WriteId({})", digest::hex(&self.0))
    }
}

impl fmt::Display for WriteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&digest::hex(&self.0))
    }
}

/// Put ke baad metadata. `size` hamesha plaintext size hai.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobMeta {
    pub size: u64,
    /// Encrypted store par `Some`; plain stores par `None`.
    pub write_id: Option<WriteId>,
    /// Plaintext ka **keyed** digest: HMAC-SHA256 jiski key is write ki random content key se
    /// (domain `"dsecure|blob-digest|v1"`) nikalti hai. Unkeyed hash nahi, isliye DB-read wala attacker
    /// known plaintext confirm nahi kar sakta (cross-tenant bhi nahi). Sirf wahi verify kar sakta hai jo
    /// content key unwrap kar sake (get par automatic). Alag writes ke digests barabar nahi hote (dedupe nahi).
    /// Plain stores par `None`.
    pub digest: Option<[u8; 32]>,
    /// Encryption kid (plain stores par `None`).
    pub kid: Option<Kid>,
    pub created_at: OffsetDateTime,
}

impl BlobMeta {
    /// DB mein store karne layak reference (key + write_id + digest).
    #[must_use]
    pub fn blob_ref(&self, key: &BlobKey) -> BlobRef {
        BlobRef {
            key: key.clone(),
            write_id: self.write_id,
            digest: self.digest,
        }
    }

    /// Lowercase hex digest.
    #[must_use]
    pub fn digest_hex(&self) -> Option<String> {
        self.digest.as_ref().map(|d| digest::hex(d))
    }
}

/// Get ke liye expected reference. `EncryptedBlobStore` ko `write_id` zaroori hai; `digest` ho to
/// stream ke end se pehle verify hota hai (mismatch => `Integrity`, aakhri chunk emit nahi hota).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobRef {
    pub key: BlobKey,
    pub write_id: Option<WriteId>,
    pub digest: Option<[u8; 32]>,
}

impl BlobRef {
    /// Sirf key (plain stores ke liye; encrypted store `MissingWriteId` dega).
    #[must_use]
    pub const fn from_key(key: BlobKey) -> Self {
        Self {
            key,
            write_id: None,
            digest: None,
        }
    }

    #[must_use]
    pub const fn new(key: BlobKey, write_id: WriteId, digest: Option<[u8; 32]>) -> Self {
        Self {
            key,
            write_id: Some(write_id),
            digest,
        }
    }
}

#[async_trait::async_trait]
pub trait BlobStore: Send + Sync {
    /// Stream ko store karo; `max_bytes` stream karte waqt enforce hota hai (exceed => `TooLarge`,
    /// partial object saaf). Atomic: reader ko ya poora naya blob dikhta hai ya purana.
    ///
    /// # Errors
    /// `TooLarge`, `Io`, `UnsafePath`, `Backend`, ya body stream ka error.
    async fn put_stream(
        &self,
        key: &BlobKey,
        body: ByteStream,
        max_bytes: u64,
    ) -> Result<BlobMeta, StorageError>;

    /// Blob ko stream karo (64 KB ke tukde).
    ///
    /// **Stream sirf tab valid hai jab wo error ke bina end tak pahunche.** Encrypted store har chunk
    /// verify karke hi emit karta hai, par truncation / digest mismatch aakhir mein pakda jaata hai,
    /// isliye pehle emit hue chunks ko tab tak "committed/valid" na maano (partial content ko kabhi
    /// parse-and-commit, cache ya forward-as-complete na karo; error par sab discard).
    ///
    /// # Errors
    /// `NotFound`, `UnsafePath`, `Io`, `Backend`; encrypted store par `MissingWriteId`, `WriteIdMismatch`,
    /// header/key errors. Decrypt/digest failures stream ke item mein aate hain.
    async fn get_stream(&self, r: &BlobRef) -> Result<ByteStream, StorageError>;
}
