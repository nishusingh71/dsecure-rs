//! crypto: key hierarchy, field encryption, blind indexes, password hashing, signing.
//!
//! Design: `docs/SECURITY.md` sections 2, 3, 7; stored value format `docs/DATABASE.md` section 3.
//! Koi key material ya plaintext `Debug`/error/log mein nahi aata. Env access yahan nahi hota
//! (`config` crate keys pass karta hai).

pub mod blind_index;
pub mod config_check;
pub mod dek_store;
pub mod devkeys;
pub mod envelope_format;
pub mod error;
pub mod field;
mod gcm;
pub mod kek_env;
pub mod keyring;
pub mod keys;
pub mod password;
pub mod signing;

pub use blind_index::{BlindIndexer, BlindKind, BlindScope, HmacBlindIndexer};
pub use config_check::DevKeyCheck;
pub use dek_store::{DekStore, InMemoryDekStore};
pub use devkeys::{dev_marker_fingerprint, is_dev_fingerprint};
pub use error::CryptoError;
pub use field::{AesGcmFieldEncryptor, FieldContext, FieldEncryptor};
pub use kek_env::{EnvKeyProvider, KeyProvider};
pub use keyring::{DEFAULT_MAX_TENANT_DEKS_CACHED, KeyRing};
pub use keys::{Dek, KeyPurpose, Kid, WrapContext, WrappedDek};
pub use password::{Argon2Params, Argon2idHasher, ParamPolicy, PasswordHasher, VerifyOutcome};
pub use signing::{
    Ed25519Signer, Es256Signer, SigAlg, Signer, canonical_json, certificate_signing_input, verify,
};
