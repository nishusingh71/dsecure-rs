//! Dev-key helpers: dev marker fingerprint (production refuse karta hai) + key generators (xtask `dev-keys`).
//!
//! Dev KEK id format: `DEV_<FP16>_<8 random hex>` (sab uppercase, env var name safe). `FP16` = pehle 16 hex
//! chars of `SHA-256("dsecure-dev-key-marker-v1")`: ek stable, public constant. Production config
//! `is_dev_fingerprint(kek_ref)` true hone par start hi nahi hota. Yeh accident se bachaata hai,
//! attacker se nahi (attacker KEK id khud likh sakta hai, par uske paas to env hi hai).

use crate::error::CryptoError;
use crate::keys::hex;
use crate::signing::{Ed25519Signer, Es256Signer};
use aws_lc_rs::digest;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use std::sync::LazyLock;

const DEV_MARKER: &[u8] = b"dsecure-dev-key-marker-v1";

static DEV_FP: LazyLock<String> = LazyLock::new(|| {
    let d = digest::digest(&digest::SHA256, DEV_MARKER);
    hex(d.as_ref()).chars().take(16).collect()
});

/// 16 lowercase hex chars; stable across runs.
#[must_use]
pub fn dev_marker_fingerprint() -> &'static str {
    &DEV_FP
}

/// True agar `kek_ref` (ya koi bhi key label) dev marker rakhta hai (case-insensitive).
#[must_use]
pub fn is_dev_fingerprint(kek_ref: &str) -> bool {
    kek_ref
        .to_ascii_lowercase()
        .contains(dev_marker_fingerprint())
}

/// Fresh dev KEK id (marker embedded).
///
/// # Errors
/// `CryptoError::Rng`.
pub fn dev_kek_id() -> Result<String, CryptoError> {
    let mut r = [0u8; 4];
    aws_lc_rs::rand::fill(&mut r).map_err(|_| CryptoError::Rng)?;
    Ok(format!(
        "DEV_{}_{}",
        dev_marker_fingerprint().to_ascii_uppercase(),
        hex(&r).to_ascii_uppercase()
    ))
}

/// Random 32-byte KEK, base64 (standard). Caller ise sirf file/env mein likhe, kabhi log na kare.
///
/// # Errors
/// `CryptoError::Rng`.
pub fn generate_kek_b64() -> Result<zeroize::Zeroizing<String>, CryptoError> {
    let mut k = zeroize::Zeroizing::new([0u8; 32]);
    aws_lc_rs::rand::fill(&mut k[..]).map_err(|_| CryptoError::Rng)?;
    Ok(zeroize::Zeroizing::new(STANDARD.encode(k.as_slice())))
}

/// Dev signing key ka kid (dev marker embedded, KEK jaisa): `dev-<fp16>-<role>`, e.g. `dev-d67d...-member`.
/// Staging/production config check (`DevKeyCheck`) aise kid refuse karta hai.
#[must_use]
pub fn dev_signing_kid(role: &str) -> String {
    format!("dev-{}-{role}", dev_marker_fingerprint())
}

/// Generated dev signing key material (PKCS#8 DER) + public key.
pub struct GeneratedSigningKey {
    pub pkcs8: zeroize::Zeroizing<Vec<u8>>,
    pub public_key: Vec<u8>,
}

impl std::fmt::Debug for GeneratedSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GeneratedSigningKey([redacted])")
    }
}

/// # Errors
/// `CryptoError::Signature` / `Rng` agar generation fail.
pub fn generate_ed25519() -> Result<GeneratedSigningKey, CryptoError> {
    let pkcs8 = Ed25519Signer::generate_pkcs8()?;
    let public_key = Ed25519Signer::from_pkcs8("tmp", &pkcs8)?
        .public_key_bytes()
        .to_vec();
    Ok(GeneratedSigningKey { pkcs8, public_key })
}

/// # Errors
/// `CryptoError::Signature` agar generation fail.
pub fn generate_es256() -> Result<GeneratedSigningKey, CryptoError> {
    let pkcs8 = Es256Signer::generate_pkcs8()?;
    let public_key = Es256Signer::from_pkcs8("tmp", &pkcs8)?
        .public_key_bytes()
        .to_vec();
    Ok(GeneratedSigningKey { pkcs8, public_key })
}

/// Public fingerprint: first 8 bytes of SHA-256(bytes), hex. Public/non-secret material ke liye.
#[must_use]
pub fn fingerprint8(public_bytes: &[u8]) -> String {
    let d = digest::digest(&digest::SHA256, public_bytes);
    hex(d.as_ref().get(..8).unwrap_or(d.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_constant() {
        assert_eq!(dev_marker_fingerprint().len(), 16);
        assert_eq!(dev_marker_fingerprint(), dev_marker_fingerprint());
        // known-answer: agar marker ya hash badla to production ke dev-refusal ka matlab badal jaata hai.
        let d = digest::digest(&digest::SHA256, b"dsecure-dev-key-marker-v1");
        assert!(hex(d.as_ref()).starts_with(dev_marker_fingerprint()));
    }

    #[test]
    fn dev_ids_are_detected_and_others_not() {
        let id = dev_kek_id().expect("id");
        assert!(is_dev_fingerprint(&id));
        assert!(is_dev_fingerprint(&format!("env:{id}")));
        assert!(!is_dev_fingerprint("env:prod-2026a"));
        assert!(id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
    }

    #[test]
    fn generated_keys_are_random_and_valid() {
        let a = generate_kek_b64().expect("a");
        let b = generate_kek_b64().expect("b");
        assert_ne!(a, b);
        assert_eq!(STANDARD.decode(&a).expect("b64").len(), 32);
        assert!(is_dev_fingerprint(&dev_signing_kid("member")));
        assert!(!is_dev_fingerprint("member-2026a"));
        assert_eq!(generate_ed25519().expect("ed").public_key.len(), 32);
        assert_eq!(generate_es256().expect("es").public_key.len(), 65);
        assert_eq!(fingerprint8(b"x").len(), 16);
    }
}
