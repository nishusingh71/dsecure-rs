//! Chhota AES-256-GCM helper (aws-lc-rs) jo field encryption aur KEK wrapping dono share karte hain.
//!
//! Nonce hamesha caller deta hai (random 96-bit); key reuse ke saath nonce reuse se bachna caller ki
//! zimmedari hai. Random 96-bit nonce ke saath ek key par ~2^32 messages tak safe margin (NIST SP 800-38D);
//! DEK rotation (SECURITY.md section 2.1) isi liye yearly hai.

use crate::error::CryptoError;
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use zeroize::Zeroizing;

pub const NONCE: usize = NONCE_LEN;
pub const TAG: usize = 16;

pub fn random_nonce() -> Result<[u8; NONCE], CryptoError> {
    let mut n = [0u8; NONCE];
    aws_lc_rs::rand::fill(&mut n).map_err(|_| CryptoError::Rng)?;
    Ok(n)
}

fn key(key: &[u8; 32]) -> Result<LessSafeKey, CryptoError> {
    let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| CryptoError::EncryptFailed)?;
    Ok(LessSafeKey::new(unbound))
}

/// Returns `ciphertext || tag`.
pub fn seal(
    k: &[u8; 32],
    nonce: [u8; NONCE],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let key = key(k)?;
    let mut buf = Vec::with_capacity(plaintext.len() + TAG);
    buf.extend_from_slice(plaintext);
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad),
        &mut buf,
    )
    .map_err(|_| CryptoError::EncryptFailed)?;
    Ok(buf)
}

/// Input `ciphertext || tag`; output plaintext (zeroizing). Koi bhi failure = `DecryptFailed`.
pub fn open(
    k: &[u8; 32],
    nonce: [u8; NONCE],
    aad: &[u8],
    ct_and_tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if ct_and_tag.len() < TAG {
        return Err(CryptoError::DecryptFailed);
    }
    let key = key(k).map_err(|_| CryptoError::DecryptFailed)?;
    let mut buf = Zeroizing::new(ct_and_tag.to_vec());
    let n = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            buf.as_mut_slice(),
        )
        .map_err(|_| CryptoError::DecryptFailed)?
        .len();
    buf.truncate(n);
    Ok(buf)
}
