//! `EncryptedBlobStore<S>`: put par STREAM-encrypt, get par decrypt (tenant `Reports` DEK).
//!
//! Key hierarchy: har put ki fresh random `ContentKey` + nonce prefix + `write_id`; content key
//! `FieldEncryptor` (KeyRing ki tenant `Reports` DEK, AAD = blobs.content_key + tenant + digest(blob key,
//! write_id)) se wrap hoke header mein jaati hai. `crypto` ki DEK bytes bahar nahi aati; kid header mein
//! rehta hai (rotation: purane blobs apni purani kid se khulte hain); crypto-shred = tenant DEK hatana.
//!
//! Rollback: overwrite allowed hai, isliye `get_stream` expected `write_id` (DB row se) maangta hai;
//! same key par purana object wapas rakhne se header ka `write_id` badal jaata hai => `WriteIdMismatch`.
//! `BlobMeta.digest` plaintext ka keyed HMAC hai (content key se derive, `lib.rs` docs).

use crate::digest::MacStream;
use crate::error::StorageError;
use crate::key::BlobKey;
use crate::stream_crypto::{
    ContentKey, DigestCheck, StreamHeader, encrypt_stream, max_ciphertext_len, open_header,
};
use crate::{BlobMeta, BlobRef, BlobStore, ByteStream, WriteId};
use crypto::{AesGcmFieldEncryptor, FieldContext, FieldEncryptor, KeyPurpose, KeyRing};
use futures_util::StreamExt as _;
use std::io;
use std::sync::{Arc, Mutex, PoisonError};

#[derive(Clone)]
pub struct EncryptedBlobStore<S: BlobStore> {
    inner: S,
    encryptor: Arc<dyn FieldEncryptor>,
}

impl<S: BlobStore> std::fmt::Debug for EncryptedBlobStore<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EncryptedBlobStore")
    }
}

impl<S: BlobStore> EncryptedBlobStore<S> {
    #[must_use]
    pub fn new(inner: S, ring: Arc<KeyRing>) -> Self {
        Self {
            inner,
            encryptor: Arc::new(AesGcmFieldEncryptor::new(ring)),
        }
    }

    /// Custom `FieldEncryptor` (tests / alternate wrapping).
    #[must_use]
    pub fn with_encryptor(inner: S, encryptor: Arc<dyn FieldEncryptor>) -> Self {
        Self { inner, encryptor }
    }

    #[must_use]
    pub const fn inner(&self) -> &S {
        &self.inner
    }
}

/// Wrapped content key ka AAD row id: SHA-256(blob key || 0 || write_id) ke pehle 16 bytes.
fn row_id(key: &BlobKey, write_id: WriteId) -> uuid::Uuid {
    let mut input = Vec::with_capacity(key.as_str().len() + 17);
    input.extend_from_slice(key.as_str().as_bytes());
    input.push(0);
    input.extend_from_slice(write_id.as_bytes());
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &input);
    let mut b = [0u8; 16];
    b.copy_from_slice(d.as_ref().get(..16).unwrap_or(&[0u8; 16]));
    uuid::Uuid::from_bytes(b)
}

fn ctx(key: &BlobKey, write_id: WriteId) -> FieldContext<'static> {
    FieldContext::new(
        "blobs",
        "content_key",
        Some(key.tenant()),
        row_id(key, write_id),
        KeyPurpose::Reports,
    )
}

type Tap = Arc<Mutex<Option<MacStream>>>;

#[async_trait::async_trait]
impl<S: BlobStore> BlobStore for EncryptedBlobStore<S> {
    async fn put_stream(
        &self,
        key: &BlobKey,
        body: ByteStream,
        max_bytes: u64,
    ) -> Result<BlobMeta, StorageError> {
        // Fresh per-put material: content key, nonce prefix (StreamHeader::new) aur write_id.
        let ck = ContentKey::generate()?;
        let write_id = WriteId::generate()?;
        let wrapped = self
            .encryptor
            .encrypt(ck.as_bytes(), &ctx(key, write_id))
            .await?;
        let kid = self.encryptor.kid_of(&wrapped)?;
        let header = StreamHeader::new(kid.clone(), write_id, wrapped)?;
        let header_len = header.encoded_len();
        let digest_key = ck.digest_key();

        // Plaintext tap: size limit + keyed digest (encrypt se pehle).
        let tap: Tap = Arc::new(Mutex::new(Some(MacStream::new(&digest_key))));
        let tap_in = Arc::clone(&tap);
        let tapped: ByteStream = body
            .map(move |item| {
                let b = item?;
                let mut g = tap_in.lock().unwrap_or_else(PoisonError::into_inner);
                let h = g
                    .as_mut()
                    .ok_or_else(|| io::Error::other("tap already finished"))?;
                if h.size().saturating_add(b.len() as u64) > max_bytes {
                    return Err(io::Error::from(StorageError::TooLarge { max: max_bytes }));
                }
                h.update(&b);
                Ok(b)
            })
            .boxed();

        // ck + header yahin consume hote hain (single use).
        let enc = encrypt_stream(tapped, ck, key, header)?;
        let inner_max = max_ciphertext_len(max_bytes, header_len);
        let meta = self
            .inner
            .put_stream(key, enc, inner_max)
            .await
            .map_err(|e| match e {
                StorageError::TooLarge { .. } => StorageError::TooLarge { max: max_bytes },
                other => other,
            })?;
        let mac = tap
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .ok_or(StorageError::Integrity)?;
        let (size, digest) = mac.finish();
        Ok(BlobMeta {
            size,
            write_id: Some(write_id),
            digest: Some(digest),
            kid: Some(kid),
            created_at: meta.created_at,
        })
    }

    async fn get_stream(&self, r: &BlobRef) -> Result<ByteStream, StorageError> {
        let expected = r.write_id.ok_or(StorageError::MissingWriteId)?;
        let key = &r.key;
        let raw = self
            .inner
            .get_stream(&BlobRef::from_key(key.clone()))
            .await?;
        let body = open_header(raw).await?;
        // Rollback / stale object: header ka write_id DB ke expected se alag => refuse (key unwrap se pehle).
        if body.header().write_id() != expected {
            return Err(StorageError::WriteIdMismatch);
        }
        let kid = body.header().kid().clone();
        // Header kid aur wrapped envelope ki kid same honi chahiye (inconsistent header = tamper).
        if self.encryptor.kid_of(body.header().wrapped_key())? != kid {
            return Err(StorageError::Integrity);
        }
        let ck_bytes = self
            .encryptor
            .decrypt(body.header().wrapped_key(), &ctx(key, expected))
            .await?;
        let ck = ContentKey::from_slice(&ck_bytes)?;
        let check = r.digest.map(|expected| DigestCheck {
            key: ck.digest_key(),
            expected,
        });
        body.decrypt(&ck, key, check)
    }
}
