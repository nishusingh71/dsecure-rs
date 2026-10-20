//! Signing: `Signer` trait, Ed25519 (certificates, offline licences), ES256 (JWT), verify, JCS helper.
//!
//! - Ed25519: signature 64 bytes, public key 32 bytes raw.
//! - ES256: ECDSA P-256 + SHA-256, **fixed** `r||s` signature (64 bytes, JWT/JWS format), public key
//!   65 bytes uncompressed SEC1 point.
//! - Private keys sirf PKCS#8 bytes se load hoti hain; `Debug` kabhi key bytes nahi dikhata.

use crate::error::CryptoError;
use aws_lc_rs::digest;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, ED25519, EcdsaKeyPair,
    Ed25519KeyPair, KeyPair, UnparsedPublicKey,
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SigAlg {
    Ed25519,
    Es256,
}

impl SigAlg {
    /// JOSE `alg` name (Ed25519 ke liye `EdDSA`).
    #[must_use]
    pub const fn jose_name(self) -> &'static str {
        match self {
            Self::Ed25519 => "EdDSA",
            Self::Es256 => "ES256",
        }
    }
}

#[async_trait::async_trait]
pub trait Signer: Send + Sync {
    fn kid(&self) -> &str;
    fn alg(&self) -> SigAlg;
    async fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn public_key(&self) -> &[u8];
}

/// P-256 group order n and n/2 (big-endian). ECDSA (r, s) aur (r, n - s) dono valid hote hain (malleability);
/// hum sirf low-S (s <= n/2) accept karte hain aur signer hamesha low-S banata hai.
/// Note: token revocation `jti` par chalti hai, signature bytes par nahi, phir bhi malleable signature accept nahi karte.
const P256_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];
const P256_HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

fn is_high_s(s: &[u8]) -> bool {
    s > &P256_HALF_N[..]
}

/// `n - s` (big-endian, s in 1..n).
fn negate_s(s: &[u8]) -> Option<[u8; 32]> {
    let s: &[u8; 32] = s.try_into().ok()?;
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut d = i16::from(P256_N[i]) - i16::from(s[i]) - borrow;
        if d < 0 {
            d += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out[i] = u8::try_from(d).ok()?;
    }
    Some(out)
}

/// Signature verify (constant-time inside aws-lc). Malformed key/sig = `false`. ES256: high-S reject.
#[must_use]
pub fn verify(alg: SigAlg, public_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    match alg {
        SigAlg::Ed25519 => UnparsedPublicKey::new(&ED25519, public_key)
            .verify(msg, sig)
            .is_ok(),
        SigAlg::Es256 => {
            sig.len() == 64
                && !is_high_s(&sig[32..])
                && UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_key)
                    .verify(msg, sig)
                    .is_ok()
        }
    }
}

pub struct Ed25519Signer {
    kid: String,
    pair: Ed25519KeyPair,
    public: Vec<u8>,
}

impl std::fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519Signer")
            .field("kid", &self.kid)
            .field("private_key", &"[redacted]")
            .finish()
    }
}

impl Ed25519Signer {
    /// New random PKCS#8 (v2) document.
    ///
    /// # Errors
    /// `CryptoError::Signature` agar generation fail.
    pub fn generate_pkcs8() -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| CryptoError::Signature("ed25519 key generation failed"))?;
        Ok(Zeroizing::new(doc.as_ref().to_vec()))
    }

    /// # Errors
    /// `CryptoError::Signature` agar PKCS#8 invalid.
    pub fn from_pkcs8(kid: impl Into<String>, pkcs8: &[u8]) -> Result<Self, CryptoError> {
        // Sirf PKCS#8 v2 (public key ke saath, consistency checked). v1/unchecked fallback jaan-boojh kar nahi.
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8)
            .map_err(|_| CryptoError::Signature("invalid ed25519 pkcs8 key"))?;
        let public = pair.public_key().as_ref().to_vec();
        Ok(Self {
            kid: kid.into(),
            pair,
            public,
        })
    }

    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public
    }

    /// Sync sign (Ed25519 deterministic, microseconds).
    #[must_use]
    pub fn sign_sync(&self, msg: &[u8]) -> Vec<u8> {
        self.pair.sign(msg).as_ref().to_vec()
    }
}

#[async_trait::async_trait]
impl Signer for Ed25519Signer {
    fn kid(&self) -> &str {
        &self.kid
    }
    fn alg(&self) -> SigAlg {
        SigAlg::Ed25519
    }
    async fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(self.sign_sync(msg))
    }
    fn public_key(&self) -> &[u8] {
        &self.public
    }
}

pub struct Es256Signer {
    kid: String,
    pair: EcdsaKeyPair,
    public: Vec<u8>,
}

impl std::fmt::Debug for Es256Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Es256Signer")
            .field("kid", &self.kid)
            .field("private_key", &"[redacted]")
            .finish()
    }
}

impl Es256Signer {
    /// New random PKCS#8 document.
    ///
    /// # Errors
    /// `CryptoError::Signature` agar generation fail.
    pub fn generate_pkcs8() -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let doc =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .map_err(|_| CryptoError::Signature("es256 key generation failed"))?;
        Ok(Zeroizing::new(doc.as_ref().to_vec()))
    }

    /// # Errors
    /// `CryptoError::Signature` agar PKCS#8 invalid ya P-256 nahi.
    pub fn from_pkcs8(kid: impl Into<String>, pkcs8: &[u8]) -> Result<Self, CryptoError> {
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8)
            .map_err(|_| CryptoError::Signature("invalid es256 pkcs8 key"))?;
        let public = pair.public_key().as_ref().to_vec();
        Ok(Self {
            kid: kid.into(),
            pair,
            public,
        })
    }

    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public
    }

    /// Sync sign (ECDSA randomised; signature fixed r||s, 64 bytes).
    ///
    /// # Errors
    /// `CryptoError::Signature` agar sign fail.
    pub fn sign_sync(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let sig = self
            .pair
            .sign(&SystemRandom::new(), msg)
            .map_err(|_| CryptoError::Signature("es256 signing failed"))?;
        let mut out = sig.as_ref().to_vec();
        if out.len() != 64 {
            return Err(CryptoError::Signature("es256 signature length"));
        }
        // Low-S normalise: s > n/2 ho to s = n - s.
        if is_high_s(&out[32..]) {
            let neg = negate_s(&out[32..]).ok_or(CryptoError::Signature("es256 normalise"))?;
            out[32..].copy_from_slice(&neg);
        }
        Ok(out)
    }
}

#[async_trait::async_trait]
impl Signer for Es256Signer {
    fn kid(&self) -> &str {
        &self.kid
    }
    fn alg(&self) -> SigAlg {
        SigAlg::Es256
    }
    async fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.sign_sync(msg)
    }
    fn public_key(&self) -> &[u8] {
        &self.public
    }
}

/// RFC 8785 (JCS) canonical JSON bytes.
///
/// Note: numbers `serde_json::Value` ke f64/i64/u64 se aate hain; certificate payload mein 2^53 se bade
/// integers string mein bhejo (JCS/ES6 number rule).
///
/// # Errors
/// `CryptoError::CanonicalJson` agar serialise fail.
pub fn canonical_json(value: &serde_json::Value) -> Result<Vec<u8>, CryptoError> {
    serde_json_canonicalizer::to_vec(value).map_err(|_| CryptoError::CanonicalJson)
}

/// Domain separator for report certificates (SECURITY.md section 7).
pub const CERT_DOMAIN: &[u8] = b"dsecure-cert-v1\n";

/// Message jo certificate Ed25519 signature ke liye sign hota hai: `"dsecure-cert-v1\n" || SHA-256(JCS)`.
///
/// # Errors
/// `CryptoError::CanonicalJson`.
pub fn certificate_signing_input(payload: &serde_json::Value) -> Result<Vec<u8>, CryptoError> {
    let jcs = canonical_json(payload)?;
    let h = digest::digest(&digest::SHA256, &jcs);
    let mut m = Vec::with_capacity(CERT_DOMAIN.len() + 32);
    m.extend_from_slice(CERT_DOMAIN);
    m.extend_from_slice(h.as_ref());
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ed() -> Ed25519Signer {
        Ed25519Signer::from_pkcs8("ed-1", &Ed25519Signer::generate_pkcs8().expect("gen"))
            .expect("load")
    }
    fn es() -> Es256Signer {
        Es256Signer::from_pkcs8("es-1", &Es256Signer::generate_pkcs8().expect("gen")).expect("load")
    }

    #[tokio::test]
    async fn ed25519_sign_verify() {
        let s = ed();
        assert_eq!(s.kid(), "ed-1");
        assert_eq!(s.alg(), SigAlg::Ed25519);
        assert_eq!(s.public_key().len(), 32);
        let sig = s.sign(b"hello").await.expect("sign");
        assert_eq!(sig.len(), 64);
        assert!(verify(SigAlg::Ed25519, s.public_key(), b"hello", &sig));
        assert!(!verify(SigAlg::Ed25519, s.public_key(), b"hellO", &sig));
        let other = ed();
        assert!(!verify(SigAlg::Ed25519, other.public_key(), b"hello", &sig));
        let mut bad = sig.clone();
        bad[0] ^= 1;
        assert!(!verify(SigAlg::Ed25519, s.public_key(), b"hello", &bad));
        assert!(!verify(
            SigAlg::Ed25519,
            s.public_key(),
            b"hello",
            &sig[..63]
        ));
        assert!(!verify(SigAlg::Ed25519, &[0u8; 5], b"hello", &sig));
    }

    #[tokio::test]
    async fn es256_sign_verify() {
        let s = es();
        assert_eq!(s.alg(), SigAlg::Es256);
        assert_eq!(s.public_key().len(), 65);
        let sig = s.sign(b"payload").await.expect("sign");
        assert_eq!(sig.len(), 64);
        assert!(verify(SigAlg::Es256, s.public_key(), b"payload", &sig));
        assert!(!verify(SigAlg::Es256, s.public_key(), b"payloaD", &sig));
        let other = es();
        assert!(!verify(SigAlg::Es256, other.public_key(), b"payload", &sig));
        // algorithm confusion: Ed25519 verify ES256 sig/key par fail
        assert!(!verify(SigAlg::Ed25519, s.public_key(), b"payload", &sig));
        let mut bad = sig.clone();
        bad[63] ^= 1;
        assert!(!verify(SigAlg::Es256, s.public_key(), b"payload", &bad));
    }

    #[test]
    fn es256_signer_always_low_s_and_high_s_rejected() {
        let s = es();
        for i in 0..200 {
            let msg = format!("message {i}");
            let sig = s.sign_sync(msg.as_bytes()).expect("sign");
            assert!(!is_high_s(&sig[32..]), "signer must emit low-S");
            assert!(verify(SigAlg::Es256, s.public_key(), msg.as_bytes(), &sig));
            // malleated twin (r, n - s): crypto-valid par hum reject karte hain.
            let mut twin = sig.clone();
            twin[32..].copy_from_slice(&negate_s(&sig[32..]).expect("neg"));
            assert!(is_high_s(&twin[32..]));
            assert!(
                UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, s.public_key())
                    .verify(msg.as_bytes(), &twin)
                    .is_ok(),
                "twin must be a cryptographically valid signature (proves the test is meaningful)"
            );
            assert!(!verify(
                SigAlg::Es256,
                s.public_key(),
                msg.as_bytes(),
                &twin
            ));
        }
    }

    #[test]
    fn negate_s_known_values() {
        let mut one = [0u8; 32];
        one[31] = 1;
        let mut expect = P256_N;
        expect[31] -= 1;
        assert_eq!(negate_s(&one).expect("n"), expect);
        assert!(negate_s(&[0u8; 5]).is_none());
        assert!(!is_high_s(&P256_HALF_N));
        let mut over = P256_HALF_N;
        over[31] += 1;
        assert!(is_high_s(&over));
    }

    #[test]
    fn bad_pkcs8_rejected_and_cross_alg_rejected() {
        assert!(Ed25519Signer::from_pkcs8("x", b"junk").is_err());
        assert!(Es256Signer::from_pkcs8("x", b"junk").is_err());
        let ed_doc = Ed25519Signer::generate_pkcs8().expect("gen");
        assert!(Es256Signer::from_pkcs8("x", &ed_doc).is_err());
    }

    #[test]
    fn loaded_key_reproduces_public_key() {
        let doc = Ed25519Signer::generate_pkcs8().expect("gen");
        let a = Ed25519Signer::from_pkcs8("a", &doc).expect("a");
        let b = Ed25519Signer::from_pkcs8("b", &doc).expect("b");
        assert_eq!(a.public_key(), b.public_key());
        // Ed25519 deterministic
        assert_eq!(a.sign_sync(b"m"), b.sign_sync(b"m"));
    }

    #[test]
    fn debug_has_no_key_bytes() {
        let doc = Ed25519Signer::generate_pkcs8().expect("gen");
        let s = Ed25519Signer::from_pkcs8("k", &doc).expect("s");
        let dbg = format!("{s:?}");
        assert!(dbg.contains("[redacted]"));
        for w in doc.windows(8) {
            let h: String = w.iter().map(|b| format!("{b:02x}")).collect();
            assert!(!dbg.contains(&h));
        }
        let doc2 = Es256Signer::generate_pkcs8().expect("gen");
        let e = Es256Signer::from_pkcs8("k", &doc2).expect("e");
        let dbg = format!("{e:?}");
        assert!(dbg.contains("[redacted]") && !dbg.contains("public"));
    }

    // RFC 8785 section 3.2.2 (sample) / Appendix B number serialisation.
    #[test]
    fn jcs_rfc8785_sample() {
        // String value Rust se (source mein json unicode escapes nahi): euro, $, U+000F, LF, A, ', B, ", \, \, ", /
        let numbers = "[333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001]";
        let v = json!({
            "numbers": serde_json::from_str::<serde_json::Value>(numbers).expect("json"),
            "string": "\u{20ac}$\u{f}\nA'B\"\\\\\"/",
            "literals": [null, true, false]
        });
        let out = String::from_utf8(canonical_json(&v).expect("jcs")).expect("utf8");
        assert_eq!(
            out,
            "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"string\":\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}"
        );
    }

    // RFC 8785 section 3.2.3: keys UTF-16 code unit order mein sort hote hain.
    #[test]
    fn jcs_rfc8785_key_sorting() {
        let input = r#"{
            "€": "Euro Sign",
            "\r": "Carriage Return",
            "דּ": "Hebrew Letter Dalet With Dagesh",
            "1": "One",
            "😀": "Emoji: Grinning Face",
            "\u0080": "Control",
            "ö": "Latin Small Letter O With Diaeresis"
        }"#;
        let v: serde_json::Value = serde_json::from_str(input).expect("json");
        let out = String::from_utf8(canonical_json(&v).expect("jcs")).expect("utf8");
        let order = [
            "Carriage Return",
            "One",
            "Control",
            "Latin Small Letter O With Diaeresis",
            "Euro Sign",
            "Emoji: Grinning Face",
            "Hebrew Letter Dalet With Dagesh",
        ];
        let mut last = 0;
        for name in order {
            let pos = out.find(name).expect("present");
            assert!(pos > last, "{name} out of order in {out}");
            last = pos;
        }
    }

    #[test]
    fn jcs_basic_properties() {
        // key order input par depend nahi karta, whitespace nahi.
        let a = canonical_json(&json!({"b": 1, "a": [1, 2, {"z": null, "y": true}]})).expect("a");
        let b: serde_json::Value =
            serde_json::from_str(r#"{ "a" : [1,2,{"y":true,"z":null}], "b":1 }"#).expect("b");
        assert_eq!(a, canonical_json(&b).expect("b"));
        assert_eq!(a, br#"{"a":[1,2,{"y":true,"z":null}],"b":1}"#);
        // RFC 8785 Appendix B spot checks
        assert_eq!(canonical_json(&json!(1e21)).expect("n"), b"1e+21");
        assert_eq!(canonical_json(&json!(-0.0)).expect("n"), b"0");
        assert_eq!(canonical_json(&json!(1.5)).expect("n"), b"1.5");
        assert_eq!(canonical_json(&json!(100)).expect("n"), b"100");
    }

    #[test]
    fn certificate_signing_input_is_domain_separated() {
        let m = certificate_signing_input(&json!({"a": 1})).expect("m");
        assert!(m.starts_with(CERT_DOMAIN));
        assert_eq!(m.len(), CERT_DOMAIN.len() + 32);
        // key order change = same input
        let m2 =
            certificate_signing_input(&serde_json::from_str(r#"{"a":1}"#).expect("j")).expect("m2");
        assert_eq!(m, m2);
        let m3 = certificate_signing_input(&json!({"a": 2})).expect("m3");
        assert_ne!(m, m3);
    }
}
