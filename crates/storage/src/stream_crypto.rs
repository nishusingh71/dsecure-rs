//! STREAM chunked AES-256-GCM (SECURITY.md section 3). Memory O(chunk): 2 x 64 KB buffers.
//!
//! **Crate-private**: key aur nonce prefix ka reuse public API se ho hi nahi sakta. `ContentKey` aur
//! `StreamHeader` (random nonce prefix) `Clone` nahi hain aur `encrypt_stream` unhe by value consume karta
//! hai: ek key + prefix = ek stream. `EncryptedBlobStore` har put par fresh pair banata hai.
//!
//! Format (`DSB1`):
//! ```text
//! header = "DSB1" | ver u8 (=2) | kid_len u8 | kid | nonce_prefix [8] | write_id [16]
//!          | wrapped_len u16 BE | wrapped_key
//! body   = chunk_0 | ... | chunk_n        (har chunk = ciphertext || 16-byte tag)
//! ```
//! Plaintext chunk 64 KB; sirf aakhri chunk chhota (ya poora) ho sakta hai. Empty plaintext = ek final
//! chunk jisme sirf tag hai. Nonce = `nonce_prefix[8] || index u32 BE`. AAD = domain || blob key
//! || poora header (kid + write_id included) || `index u32 BE` || `last` byte. Isse:
//! - truncation / extra data / reorder / duplicate / wrong key or kid or write_id => fail;
//! - rollback: write_id header + wrapped-key context mein bound hai (`encrypted.rs` expected id check karta hai).
//!
//! Decrypt par bad chunk ka plaintext kabhi emit nahi hota; optional keyed digest end par verify hota hai
//! (mismatch par aakhri chunk emit nahi hota).

use crate::digest::MacStream;
use crate::error::StorageError;
use crate::key::BlobKey;
use crate::{ByteStream, WriteId};
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::hmac;
use bytes::Bytes;
use crypto::Kid;
use futures_util::StreamExt as _;
use futures_util::stream::unfold;
use std::io;
use zeroize::Zeroizing;

pub const CHUNK_SIZE: usize = 64 * 1024;
pub const TAG_LEN: usize = 16;
const MAGIC: &[u8; 4] = b"DSB1";
/// v2 (v1 = pehle ka format bina write_id; ab `BadHeader`).
const VERSION: u8 = 2;
const PREFIX_LEN: usize = 8;
const WRITE_ID_LEN: usize = 16;
const MAX_WRAPPED: usize = 1024;
const AAD_DOMAIN: &[u8] = b"dsecure-stream-v1";
const DIGEST_LABEL: &[u8] = b"dsecure|blob-digest|v1";

/// Per-blob random 256-bit content key (drop par zeroize). Not `Clone`.
pub struct ContentKey(Zeroizing<[u8; 32]>);

impl ContentKey {
    pub fn generate() -> Result<Self, StorageError> {
        let mut k = Zeroizing::new([0u8; 32]);
        aws_lc_rs::rand::fill(&mut k[..]).map_err(|_| crypto::CryptoError::Rng)?;
        Ok(Self(k))
    }

    pub fn from_slice(b: &[u8]) -> Result<Self, StorageError> {
        let arr: [u8; 32] = b.try_into().map_err(|_| StorageError::Integrity)?;
        Ok(Self(Zeroizing::new(arr)))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Plaintext digest ki HMAC key: `HMAC(ck, "dsecure|blob-digest|v1")` (content key se domain-separated).
    pub fn digest_key(&self) -> hmac::Key {
        let base = hmac::Key::new(hmac::HMAC_SHA256, self.as_bytes());
        let derived = hmac::sign(&base, DIGEST_LABEL);
        hmac::Key::new(hmac::HMAC_SHA256, derived.as_ref())
    }
}

impl std::fmt::Debug for ContentKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ContentKey([redacted])")
    }
}

/// Stream header: version, kid, random nonce prefix, write id, wrapped content key. Not `Clone`.
#[derive(Debug)]
pub struct StreamHeader {
    kid: Kid,
    nonce_prefix: [u8; PREFIX_LEN],
    write_id: WriteId,
    wrapped_key: Vec<u8>,
}

impl StreamHeader {
    /// Naya header (fresh random nonce prefix).
    pub fn new(kid: Kid, write_id: WriteId, wrapped_key: Vec<u8>) -> Result<Self, StorageError> {
        if wrapped_key.is_empty() || wrapped_key.len() > MAX_WRAPPED {
            return Err(StorageError::BadHeader);
        }
        let mut nonce_prefix = [0u8; PREFIX_LEN];
        aws_lc_rs::rand::fill(&mut nonce_prefix).map_err(|_| crypto::CryptoError::Rng)?;
        Ok(Self {
            kid,
            nonce_prefix,
            write_id,
            wrapped_key,
        })
    }

    pub const fn kid(&self) -> &Kid {
        &self.kid
    }

    pub const fn write_id(&self) -> WriteId {
        self.write_id
    }

    pub fn wrapped_key(&self) -> &[u8] {
        &self.wrapped_key
    }

    pub fn encoded_len(&self) -> usize {
        4 + 1 + 1 + self.kid.as_str().len() + PREFIX_LEN + WRITE_ID_LEN + 2 + self.wrapped_key.len()
    }

    /// Wire bytes (yahi bytes har chunk ke AAD mein jaate hain).
    pub fn encode(&self) -> Vec<u8> {
        let kid = self.kid.as_str().as_bytes();
        let mut v = Vec::with_capacity(self.encoded_len());
        v.extend_from_slice(MAGIC);
        v.push(VERSION);
        // Kid::parse 1..=32 bytes guarantee karta hai.
        v.push(u8::try_from(kid.len()).unwrap_or(u8::MAX));
        v.extend_from_slice(kid);
        v.extend_from_slice(&self.nonce_prefix);
        v.extend_from_slice(self.write_id.as_bytes());
        // wrapped_key <= MAX_WRAPPED constructor/parser enforce karte hain.
        v.extend_from_slice(
            &u16::try_from(self.wrapped_key.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        v.extend_from_slice(&self.wrapped_key);
        v
    }
}

/// Upper bound (exact) on stored bytes for `plain_len` plaintext: header + plain + 16/chunk.
pub fn max_ciphertext_len(plain_len: u64, header_len: usize) -> u64 {
    let chunks = plain_len.div_ceil(CHUNK_SIZE as u64).max(1);
    (header_len as u64)
        .saturating_add(plain_len)
        .saturating_add(chunks.saturating_mul(TAG_LEN as u64))
}

/// AEAD with STREAM nonce/AAD schedule.
struct ChunkCipher {
    key: LessSafeKey,
    prefix: [u8; PREFIX_LEN],
    aad_base: Vec<u8>,
}

impl ChunkCipher {
    fn new(
        ck: &ContentKey,
        blob_key: &BlobKey,
        header_bytes: &[u8],
        prefix: [u8; PREFIX_LEN],
    ) -> Result<Self, StorageError> {
        let unbound = UnboundKey::new(&AES_256_GCM, ck.as_bytes())
            .map_err(|_| crypto::CryptoError::EncryptFailed)?;
        let bk = blob_key.as_str().as_bytes();
        let mut aad_base = Vec::with_capacity(AAD_DOMAIN.len() + 2 + bk.len() + header_bytes.len());
        aad_base.extend_from_slice(AAD_DOMAIN);
        aad_base.extend_from_slice(&u16::try_from(bk.len()).unwrap_or(u16::MAX).to_be_bytes());
        aad_base.extend_from_slice(bk);
        aad_base.extend_from_slice(header_bytes);
        Ok(Self {
            key: LessSafeKey::new(unbound),
            prefix,
            aad_base,
        })
    }

    fn nonce_and_aad(&self, index: u32, last: bool) -> (Nonce, Vec<u8>) {
        let mut n = [0u8; NONCE_LEN];
        n[..PREFIX_LEN].copy_from_slice(&self.prefix);
        n[PREFIX_LEN..].copy_from_slice(&index.to_be_bytes());
        let mut aad = Vec::with_capacity(self.aad_base.len() + 5);
        aad.extend_from_slice(&self.aad_base);
        aad.extend_from_slice(&index.to_be_bytes());
        aad.push(u8::from(last));
        (Nonce::assume_unique_for_key(n), aad)
    }

    /// `buf` plaintext -> ciphertext || tag (in place).
    fn seal(&self, index: u32, last: bool, buf: &mut Vec<u8>) -> Result<(), StorageError> {
        let (nonce, aad) = self.nonce_and_aad(index, last);
        self.key
            .seal_in_place_append_tag(nonce, Aad::from(aad.as_slice()), buf)
            .map_err(|_| StorageError::Crypto(crypto::CryptoError::EncryptFailed))
    }

    /// `buf` ciphertext || tag -> plaintext (in place). Fail par `buf` ka content use nahi hota.
    fn open(&self, index: u32, last: bool, buf: &mut Vec<u8>) -> Result<(), StorageError> {
        if buf.len() < TAG_LEN {
            return Err(StorageError::Integrity);
        }
        let (nonce, aad) = self.nonce_and_aad(index, last);
        let n = self
            .key
            .open_in_place(nonce, Aad::from(aad.as_slice()), buf.as_mut_slice())
            .map_err(|_| StorageError::Integrity)?
            .len();
        buf.truncate(n);
        Ok(())
    }
}

/// Stream se "kam se kam `want` bytes tak" bharne wala reader (arbitrary frame sizes handle karta hai).
struct ByteSource {
    inner: ByteStream,
    rest: Bytes,
}

impl ByteSource {
    fn new(inner: ByteStream) -> Self {
        Self {
            inner,
            rest: Bytes::new(),
        }
    }

    /// `buf` ko `want` bytes tak bharo; EOF par kam par ruk jaata hai.
    async fn fill(&mut self, buf: &mut Vec<u8>, want: usize) -> io::Result<()> {
        while buf.len() < want {
            if self.rest.is_empty() {
                match self.inner.next().await {
                    Some(r) => self.rest = r?,
                    None => return Ok(()),
                }
                continue;
            }
            let take = (want - buf.len()).min(self.rest.len());
            buf.extend_from_slice(&self.rest.split_to(take));
        }
        Ok(())
    }

    /// Exactly `n` bytes ya `BadHeader`.
    async fn read_exact(&mut self, n: usize) -> Result<Vec<u8>, StorageError> {
        let mut v = Vec::with_capacity(n);
        self.fill(&mut v, n).await.map_err(StorageError::from_io)?;
        if v.len() == n {
            Ok(v)
        } else {
            Err(StorageError::BadHeader)
        }
    }
}

/// Header parse ho chuka; ab body decrypt hone ko taiyar (key resolve karne ke baad).
pub struct EncryptedBody {
    header: StreamHeader,
    raw_header: Vec<u8>,
    src: ByteSource,
}

/// Decrypt par end-of-stream digest check.
pub struct DigestCheck {
    pub key: hmac::Key,
    pub expected: [u8; 32],
}

/// Header padho (stream ko header ke baad tak consume karta hai).
pub async fn open_header(body: ByteStream) -> Result<EncryptedBody, StorageError> {
    let mut src = ByteSource::new(body);
    let mut raw = src.read_exact(MAGIC.len() + 2).await?;
    if raw.get(..4) != Some(&MAGIC[..]) || raw.get(4) != Some(&VERSION) {
        return Err(StorageError::BadHeader);
    }
    let kid_len = usize::from(*raw.get(5).ok_or(StorageError::BadHeader)?);
    if kid_len == 0 || kid_len > Kid::MAX_LEN {
        return Err(StorageError::BadHeader);
    }
    let kid_bytes = src.read_exact(kid_len).await?;
    raw.extend_from_slice(&kid_bytes);
    let kid = Kid::parse(String::from_utf8(kid_bytes).map_err(|_| StorageError::BadHeader)?)
        .map_err(|_| StorageError::BadHeader)?;
    let prefix_bytes = src.read_exact(PREFIX_LEN).await?;
    raw.extend_from_slice(&prefix_bytes);
    let nonce_prefix: [u8; PREFIX_LEN] = prefix_bytes
        .as_slice()
        .try_into()
        .map_err(|_| StorageError::BadHeader)?;
    let wid_bytes = src.read_exact(WRITE_ID_LEN).await?;
    raw.extend_from_slice(&wid_bytes);
    let write_id = WriteId::from_bytes(
        wid_bytes
            .as_slice()
            .try_into()
            .map_err(|_| StorageError::BadHeader)?,
    );
    let len_bytes = src.read_exact(2).await?;
    raw.extend_from_slice(&len_bytes);
    let wrapped_len = usize::from(u16::from_be_bytes([
        *len_bytes.first().ok_or(StorageError::BadHeader)?,
        *len_bytes.get(1).ok_or(StorageError::BadHeader)?,
    ]));
    if wrapped_len == 0 || wrapped_len > MAX_WRAPPED {
        return Err(StorageError::BadHeader);
    }
    let wrapped_key = src.read_exact(wrapped_len).await?;
    raw.extend_from_slice(&wrapped_key);
    Ok(EncryptedBody {
        header: StreamHeader {
            kid,
            nonce_prefix,
            write_id,
            wrapped_key,
        },
        raw_header: raw,
        src,
    })
}

impl EncryptedBody {
    pub const fn header(&self) -> &StreamHeader {
        &self.header
    }

    /// Decrypting stream. Har item verified plaintext chunk hai; pehle error par stream ruk jaata hai.
    /// `check` ho to aakhri chunk se pehle keyed digest verify hota hai.
    pub fn decrypt(
        self,
        ck: &ContentKey,
        blob_key: &BlobKey,
        check: Option<DigestCheck>,
    ) -> Result<ByteStream, StorageError> {
        let cipher = ChunkCipher::new(ck, blob_key, &self.raw_header, self.header.nonce_prefix)?;
        let st = DecState {
            src: self.src,
            cipher,
            cur: Vec::with_capacity(CHUNK_SIZE + TAG_LEN),
            next: Vec::with_capacity(CHUNK_SIZE + TAG_LEN),
            mac: check.map(|c| (MacStream::new(&c.key), c.expected)),
            index: 0,
            started: false,
            done: false,
        };
        Ok(unfold(st, |mut st| async move {
            if st.done {
                return None;
            }
            match dec_step(&mut st).await {
                Ok(Some(b)) => Some((Ok(b), st)),
                Ok(None) => None,
                Err(e) => {
                    st.done = true;
                    Some((Err(io::Error::from(e)), st))
                }
            }
        })
        .boxed())
    }
}

struct DecState {
    src: ByteSource,
    cipher: ChunkCipher,
    cur: Vec<u8>,
    next: Vec<u8>,
    mac: Option<(MacStream, [u8; 32])>,
    index: u32,
    started: bool,
    done: bool,
}

async fn dec_step(st: &mut DecState) -> Result<Option<Bytes>, StorageError> {
    const FULL: usize = CHUNK_SIZE + TAG_LEN;
    if !st.started {
        st.src
            .fill(&mut st.cur, FULL)
            .await
            .map_err(StorageError::from_io)?;
        st.started = true;
    }
    let last = if st.cur.len() < FULL {
        true
    } else {
        st.next.clear();
        st.src
            .fill(&mut st.next, FULL)
            .await
            .map_err(StorageError::from_io)?;
        st.next.is_empty()
    };
    let mut out = std::mem::take(&mut st.cur);
    // Header ke baad koi chunk na ho (kata hua) => len 0 < TAG => Integrity.
    st.cipher.open(st.index, last, &mut out)?;
    if let Some((mac, _)) = st.mac.as_mut() {
        mac.update(&out);
    }
    if last {
        st.done = true;
        if let Some((mac, expected)) = st.mac.take() {
            let (_, got) = mac.finish();
            if aws_lc_rs::constant_time::verify_slices_are_equal(&got, &expected).is_err() {
                return Err(StorageError::Integrity);
            }
        }
    } else {
        st.cur = std::mem::replace(&mut st.next, Vec::with_capacity(FULL));
        st.index = st.index.checked_add(1).ok_or(StorageError::Integrity)?;
    }
    if out.is_empty() {
        return Ok(None);
    }
    Ok(Some(Bytes::from(out)))
}

/// Plaintext stream -> `header || chunks`. Pehla item header hai. `ck` aur `header` consume hote hain
/// (single-use): ek key + nonce prefix se sirf ek stream.
pub fn encrypt_stream(
    body: ByteStream,
    ck: ContentKey,
    blob_key: &BlobKey,
    header: StreamHeader,
) -> Result<ByteStream, StorageError> {
    let raw = header.encode();
    let cipher = ChunkCipher::new(&ck, blob_key, &raw, header.nonce_prefix)?;
    drop(ck);
    let st = EncState {
        src: ByteSource::new(body),
        cipher,
        header: Some(Bytes::from(raw)),
        cur: Vec::with_capacity(CHUNK_SIZE + TAG_LEN),
        next: Vec::with_capacity(CHUNK_SIZE + TAG_LEN),
        index: 0,
        started: false,
        done: false,
    };
    Ok(unfold(st, |mut st| async move {
        if st.done && st.header.is_none() {
            return None;
        }
        match enc_step(&mut st).await {
            Ok(Some(b)) => Some((Ok(b), st)),
            Ok(None) => None,
            Err(e) => {
                st.done = true;
                st.header = None;
                Some((Err(io::Error::from(e)), st))
            }
        }
    })
    .boxed())
}

struct EncState {
    src: ByteSource,
    cipher: ChunkCipher,
    header: Option<Bytes>,
    cur: Vec<u8>,
    next: Vec<u8>,
    index: u32,
    started: bool,
    done: bool,
}

async fn enc_step(st: &mut EncState) -> Result<Option<Bytes>, StorageError> {
    if let Some(h) = st.header.take() {
        return Ok(Some(h));
    }
    if st.done {
        return Ok(None);
    }
    if !st.started {
        st.src
            .fill(&mut st.cur, CHUNK_SIZE)
            .await
            .map_err(StorageError::from_io)?;
        st.started = true;
    }
    let last = if st.cur.len() < CHUNK_SIZE {
        true
    } else {
        st.next.clear();
        st.src
            .fill(&mut st.next, CHUNK_SIZE)
            .await
            .map_err(StorageError::from_io)?;
        st.next.is_empty()
    };
    let mut out = std::mem::take(&mut st.cur);
    st.cipher.seal(st.index, last, &mut out)?;
    if last {
        st.done = true;
    } else {
        st.cur = std::mem::replace(&mut st.next, Vec::with_capacity(CHUNK_SIZE + TAG_LEN));
        st.index = st.index.checked_add(1).ok_or(StorageError::Integrity)?;
    }
    Ok(Some(Bytes::from(out)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::TenantId;
    use futures_util::TryStreamExt as _;
    use futures_util::stream;

    const KEY_BYTES: [u8; 32] = [42; 32];

    fn plain(n: usize) -> Vec<u8> {
        (0..n).map(|i| u8::try_from(i % 251).unwrap()).collect()
    }

    fn body(data: &[u8], frame: usize) -> ByteStream {
        let frames: Vec<io::Result<Bytes>> = if data.is_empty() {
            vec![]
        } else {
            data.chunks(frame)
                .map(|c| Ok(Bytes::copy_from_slice(c)))
                .collect()
        };
        stream::iter(frames).boxed()
    }

    fn blob_key() -> BlobKey {
        BlobKey::new(TenantId::new(), "r/x.bin").unwrap()
    }

    /// Fresh header (fresh random nonce prefix) har call par.
    fn fresh_header() -> StreamHeader {
        StreamHeader::new(
            Kid::parse("kid-1").unwrap(),
            WriteId::generate().unwrap(),
            vec![7u8; 60],
        )
        .unwrap()
    }

    fn key() -> ContentKey {
        ContentKey::from_slice(&KEY_BYTES).unwrap()
    }

    /// Har call par naya header => (key, prefix) kabhi dobara nahi; key `ck` by value consume hoti hai.
    async fn enc(data: &[u8], ck: ContentKey, bk: &BlobKey) -> (Vec<u8>, usize) {
        let h = fresh_header();
        let hl = h.encoded_len();
        let s = encrypt_stream(body(data, 10_000), ck, bk, h).unwrap();
        let parts: Vec<Bytes> = s.try_collect().await.unwrap();
        (parts.concat(), hl)
    }

    async fn dec(
        ct: &[u8],
        ck: &ContentKey,
        bk: &BlobKey,
        check: Option<DigestCheck>,
    ) -> (Vec<u8>, Option<StorageError>) {
        let eb = match open_header(body(ct, 7_000)).await {
            Ok(e) => e,
            Err(e) => return (vec![], Some(e)),
        };
        let mut s = eb.decrypt(ck, bk, check).unwrap();
        let mut out = vec![];
        while let Some(item) = s.next().await {
            match item {
                Ok(b) => out.extend_from_slice(&b),
                Err(e) => return (out, Some(StorageError::from_io(e))),
            }
        }
        (out, None)
    }

    #[tokio::test]
    async fn roundtrip_sizes() {
        let bk = blob_key();
        for n in [
            0usize,
            1,
            CHUNK_SIZE - 1,
            CHUNK_SIZE,
            CHUNK_SIZE + 1,
            2 * CHUNK_SIZE,
            5 * 1024 * 1024,
        ] {
            let p = plain(n);
            let (ct, hl) = enc(&p, key(), &bk).await;
            assert_eq!(
                ct.len() as u64,
                max_ciphertext_len(n as u64, hl),
                "size {n}"
            );
            let (out, err) = dec(&ct, &key(), &bk, None).await;
            assert!(err.is_none(), "size {n}: {err:?}");
            assert_eq!(out, p, "size {n}");
        }
    }

    #[tokio::test]
    async fn every_encryption_uses_a_fresh_nonce_prefix() {
        let bk = blob_key();
        let (a, _) = enc(&plain(10), key(), &bk).await;
        let (b, _) = enc(&plain(10), key(), &bk).await;
        // header ke baad ka ciphertext alag (prefix alag) bhale hi key aur plaintext same hon
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn truncation_at_every_boundary_fails() {
        let bk = blob_key();
        let p = plain(3 * CHUNK_SIZE + 10);
        let (ct, hl) = enc(&p, key(), &bk).await;
        let full = CHUNK_SIZE + TAG_LEN;
        for cut in [
            hl + full,
            hl + 2 * full,
            hl + 3 * full,
            hl + 3 * full + 5,
            hl,
            ct.len() - 1,
        ] {
            let (out, err) = dec(&ct[..cut], &key(), &bk, None).await;
            assert!(
                matches!(err, Some(StorageError::Integrity)),
                "cut {cut}: {err:?}"
            );
            assert!(out.len() % CHUNK_SIZE == 0 && out.len() < p.len());
            assert_eq!(out, p[..out.len()]);
        }
    }

    #[tokio::test]
    async fn reorder_duplicate_extra_and_bitflip_fail() {
        let bk = blob_key();
        let p = plain(3 * CHUNK_SIZE + 10);
        let (ct, hl) = enc(&p, key(), &bk).await;
        let full = CHUNK_SIZE + TAG_LEN;
        let chunk = |i: usize| ct[hl + i * full..hl + (i + 1) * full].to_vec();
        let last = ct[hl + 3 * full..].to_vec();
        let build = |parts: &[&[u8]]| {
            let mut v = ct[..hl].to_vec();
            for q in parts {
                v.extend_from_slice(q);
            }
            v
        };
        let (c0, c1, c2) = (chunk(0), chunk(1), chunk(2));
        let cases = [
            ("reorder", build(&[&c1, &c0, &c2, &last])),
            ("duplicate", build(&[&c0, &c0, &c1, &c2, &last])),
            ("drop middle", build(&[&c0, &c2, &last])),
            ("extra after final", {
                let mut v = ct.clone();
                v.extend_from_slice(&c0);
                v
            }),
            ("extra byte", {
                let mut v = ct.clone();
                v.push(0);
                v
            }),
        ];
        for (name, bad) in cases {
            let (out, err) = dec(&bad, &key(), &bk, None).await;
            assert!(
                matches!(err, Some(StorageError::Integrity)),
                "{name}: {err:?}"
            );
            assert!(out.len() < p.len(), "{name}");
        }
        for pos in [hl + 5, hl + full + CHUNK_SIZE + 3, ct.len() - 1, 6, hl - 3] {
            let mut bad = ct.clone();
            bad[pos] ^= 1;
            let (out, err) = dec(&bad, &key(), &bk, None).await;
            assert!(err.is_some(), "flip {pos}");
            assert!(out.len() < p.len());
        }
        let mut bad = ct.clone();
        bad[hl + full + 100] ^= 1;
        let (out, err) = dec(&bad, &key(), &bk, None).await;
        assert!(matches!(err, Some(StorageError::Integrity)));
        assert_eq!(out, p[..CHUNK_SIZE]);
    }

    #[tokio::test]
    async fn wrong_key_blob_key_header_and_write_id_fail() {
        let bk = blob_key();
        let (ct, _) = enc(&plain(100), key(), &bk).await;
        let other_key = ContentKey::generate().unwrap();
        let (_, e) = dec(&ct, &other_key, &bk, None).await;
        assert!(matches!(e, Some(StorageError::Integrity)));
        let other = BlobKey::new(bk.tenant(), "r/y.bin").unwrap();
        let (_, e) = dec(&ct, &key(), &other, None).await;
        assert!(matches!(e, Some(StorageError::Integrity)));
        // kid byte badla (same length) => AAD mismatch
        let mut bad = ct.clone();
        bad[6] ^= 0x01;
        let (_, e) = dec(&bad, &key(), &bk, None).await;
        assert!(matches!(e, Some(StorageError::Integrity)));
        // write_id byte badla => AAD mismatch
        let mut bad = ct.clone();
        bad[6 + 5 + PREFIX_LEN + 3] ^= 0x01;
        let (_, e) = dec(&bad, &key(), &bk, None).await;
        assert!(matches!(e, Some(StorageError::Integrity)));
        let mut bad = ct.clone();
        bad[0] = b'X';
        let (_, e) = dec(&bad, &key(), &bk, None).await;
        assert!(matches!(e, Some(StorageError::BadHeader)));
        for v in [1u8, 3] {
            let mut bad = ct.clone();
            bad[4] = v;
            let (_, e) = dec(&bad, &key(), &bk, None).await;
            assert!(matches!(e, Some(StorageError::BadHeader)), "version {v}");
        }
        let (_, e) = dec(&ct[..9], &key(), &bk, None).await;
        assert!(matches!(e, Some(StorageError::BadHeader)));
    }

    #[tokio::test]
    async fn digest_check_passes_and_fails_before_last_chunk() {
        let bk = blob_key();
        let p = plain(2 * CHUNK_SIZE + 7);
        let (ct, _) = enc(&p, key(), &bk).await;
        let mut m = MacStream::new(&key().digest_key());
        m.update(&p);
        let (_, good) = m.finish();
        let mk = |d: [u8; 32]| {
            Some(DigestCheck {
                key: key().digest_key(),
                expected: d,
            })
        };
        let (out, err) = dec(&ct, &key(), &bk, mk(good)).await;
        assert!(err.is_none());
        assert_eq!(out, p);
        let mut wrong = good;
        wrong[0] ^= 1;
        let (out, err) = dec(&ct, &key(), &bk, mk(wrong)).await;
        assert!(matches!(err, Some(StorageError::Integrity)));
        // aakhri chunk emit nahi hua
        assert_eq!(out.len(), 2 * CHUNK_SIZE);
    }

    #[test]
    fn size_formula() {
        assert_eq!(max_ciphertext_len(0, 10), 10 + 16);
        assert_eq!(max_ciphertext_len(1, 10), 10 + 1 + 16);
        assert_eq!(
            max_ciphertext_len(CHUNK_SIZE as u64, 0),
            (CHUNK_SIZE + 16) as u64
        );
        assert_eq!(
            max_ciphertext_len(CHUNK_SIZE as u64 + 1, 0),
            (CHUNK_SIZE + 33) as u64
        );
        assert_eq!(fresh_header().encode().len(), fresh_header().encoded_len());
    }
}
