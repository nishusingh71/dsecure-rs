//! `CryptoError`: sab crypto failures ek type mein.
//!
//! Rule: koi bhi message key bytes, plaintext, password ya PII nahi rakhta. Variants mein sirf
//! static strings, kid / kek id (non-secret labels) aur purpose aate hain.

use crate::keys::{KeyPurpose, Kid};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// Key material galat shape/length ka hai (bytes kabhi echo nahi hote).
    #[error("invalid key material: {0}")]
    InvalidKey(&'static str),
    /// KEK id jo provider ke paas nahi hai.
    #[error("unknown KEK `{0}`")]
    UnknownKek(String),
    /// Wrapped DEK unwrap nahi hua (galat KEK ya tampered bytes). Fail closed, koi detail nahi.
    #[error("key unwrap failed")]
    UnwrapFailed,
    /// Randomness source fail hua.
    #[error("random number generator failure")]
    Rng,
    /// Encrypt fail hua (key/context level).
    #[error("encryption failed")]
    EncryptFailed,
    /// Decrypt/authentication fail. Wajah jaan-boojh kar nahi batate (oracle nahi).
    #[error("decryption failed")]
    DecryptFailed,
    /// Stored value envelope parse nahi hua.
    #[error("malformed ciphertext envelope: {0}")]
    MalformedEnvelope(&'static str),
    /// Envelope ka version/flags support nahi.
    #[error("unsupported ciphertext version or flags")]
    UnsupportedVersion,
    /// Kid format (1..=32 bytes, `[A-Za-z0-9_.-]`) galat.
    #[error("invalid key id: {0}")]
    InvalidKid(&'static str),
    /// `FieldContext` (table/column/purpose/tenant) galat.
    #[error("invalid field context: {0}")]
    InvalidContext(&'static str),
    /// Is kid ki DEK store mein nahi mili.
    #[error("data key `{0}` not found")]
    KeyNotFound(Kid),
    /// Is purpose/tenant ki koi active DEK nahi (platform keys fail closed).
    #[error("no active data key for purpose `{}`", .0.as_str())]
    NoActiveKey(KeyPurpose),
    /// DEK ka purpose/tenant caller ke context se match nahi karta (cross-tenant guard).
    #[error("data key scope mismatch")]
    KeyScopeMismatch,
    /// Blind-index key abhi cache mein load nahi (pehle `prepare_tenant` chalao).
    #[error("blind index key not loaded for tenant")]
    KeyNotLoaded,
    /// Blind index ka kind/scope combination allowed nahi.
    #[error("invalid blind index scope: {0}")]
    InvalidScope(&'static str),
    /// Raw value normalise/validate nahi hui (value kabhi echo nahi hoti).
    #[error("invalid input for blind index: {0}")]
    InvalidInput(&'static str),
    /// `DekStore` ka error (store implementer message mein secrets na daale).
    #[error("key store error: {0}")]
    Store(String),
    /// Insert conflict (active key already exists).
    #[error("key store conflict")]
    Conflict,
    /// Password hash params invalid ya prod floor se kam.
    #[error("invalid password hashing parameters: {0}")]
    HashParams(&'static str),
    /// Stored hash ka cost (m/t/p) allowed cap se upar: hostile/oversized hash, verify nahi kiya (failed verify maano).
    #[error("stored password hash cost exceeds allowed cap")]
    HashCostExceeded,
    /// Stored password hash parse nahi hua.
    #[error("malformed password hash")]
    MalformedHash,
    /// Hash/verify slot timeout ke andar nahi mila; API ise 503 banata hai.
    #[error("password hashing capacity busy")]
    Busy,
    /// Signing key/signature problem.
    #[error("signature error: {0}")]
    Signature(&'static str),
    /// Canonical JSON (JCS) fail.
    #[error("canonical json error")]
    CanonicalJson,
    /// Background task join failure etc.
    #[error("internal crypto error: {0}")]
    Internal(&'static str),
}
