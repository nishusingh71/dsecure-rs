//! Core key types: `KeyPurpose`, `Kid`, `Dek`, `WrappedDek`.

use crate::error::CryptoError;
use std::fmt;
use zeroize::Zeroizing;

/// Key ka kaam. Har purpose ki alag DEK (SECURITY.md section 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyPurpose {
    Identity,
    Pii,
    Reports,
    Secrets,
    BidxEmail,
    BidxLicense,
    BidxTenant,
    Audit,
}

impl KeyPurpose {
    pub const ALL: [Self; 8] = [
        Self::Identity,
        Self::Pii,
        Self::Reports,
        Self::Secrets,
        Self::BidxEmail,
        Self::BidxLicense,
        Self::BidxTenant,
        Self::Audit,
    ];

    /// Platform-wide purposes (tenant `None`), startup par load hote hain.
    pub const PLATFORM: [Self; 5] = [
        Self::Identity,
        Self::Secrets,
        Self::BidxEmail,
        Self::BidxLicense,
        Self::Audit,
    ];

    /// Stable snake_case name (DB `data_keys.purpose`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Pii => "pii",
            Self::Reports => "reports",
            Self::Secrets => "secrets",
            Self::BidxEmail => "bidx_email",
            Self::BidxLicense => "bidx_license",
            Self::BidxTenant => "bidx_tenant",
            Self::Audit => "audit",
        }
    }

    /// Tenant purposes: ek tenant ki alag DEK (crypto-shredding unit).
    #[must_use]
    pub const fn is_tenant_scoped(self) -> bool {
        matches!(self, Self::Pii | Self::Reports | Self::BidxTenant)
    }

    /// Chhota label jo kid mein jaata hai (kid <= 32 bytes rakhne ke liye).
    const fn kid_label(self) -> &'static str {
        match self {
            Self::Identity => "id",
            Self::Pii => "pii",
            Self::Reports => "rep",
            Self::Secrets => "sec",
            Self::BidxEmail => "bxe",
            Self::BidxLicense => "bxl",
            Self::BidxTenant => "bxt",
            Self::Audit => "aud",
        }
    }
}

impl std::str::FromStr for KeyPurpose {
    type Err = CryptoError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|p| p.as_str() == s)
            .ok_or(CryptoError::InvalidContext("unknown key purpose"))
    }
}

/// Key id: envelope header mein plain ASCII jaata hai, isliye non-secret label.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct Kid(pub String);

impl Kid {
    pub const MAX_LEN: usize = 32;

    /// Validate: 1..=32 bytes, sirf `[A-Za-z0-9_.-]` (`|` jaise separators AAD ambiguity se bachne ke liye bahar).
    ///
    /// # Errors
    /// `CryptoError::InvalidKid` agar rule toota.
    pub fn parse(s: impl Into<String>) -> Result<Self, CryptoError> {
        let s = s.into();
        Self::validate(&s)?;
        Ok(Self(s))
    }

    pub(crate) fn validate(s: &str) -> Result<(), CryptoError> {
        if s.is_empty() || s.len() > Self::MAX_LEN {
            return Err(CryptoError::InvalidKid("length must be 1..=32 bytes"));
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
        {
            return Err(CryptoError::InvalidKid("only [A-Za-z0-9_.-] allowed"));
        }
        Ok(())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Nayi random kid: `p-<label>-<8hex>` ya `t-<12hex of tenant>-<label>-<8hex>` (<= 27 bytes).
    ///
    /// # Errors
    /// `CryptoError::Rng` agar randomness nahi mili.
    pub fn generate(
        purpose: KeyPurpose,
        tenant: Option<common::TenantId>,
    ) -> Result<Self, CryptoError> {
        let mut r = [0u8; 4];
        aws_lc_rs::rand::fill(&mut r).map_err(|_| CryptoError::Rng)?;
        let rnd = hex(&r);
        let kid = match tenant {
            // UUID v7 ka aakhri hissa random hota hai, isliye tenants ke beech short id collide nahi karti.
            Some(t) => {
                let simple = t.as_uuid().simple().to_string();
                let tail = simple.get(20..).unwrap_or(&simple);
                format!("t-{tail}-{}-{rnd}", purpose.kid_label())
            }
            None => format!("p-{}-{rnd}", purpose.kid_label()),
        };
        Self::parse(kid)
    }
}

impl fmt::Display for Kid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // String par write! kabhi fail nahi hota.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// 256-bit data encryption key. Drop par zeroize; `Debug` kabhi bytes nahi dikhata.
pub struct Dek(Zeroizing<[u8; 32]>);

impl Dek {
    pub const LEN: usize = 32;

    /// Fresh random DEK.
    ///
    /// # Errors
    /// `CryptoError::Rng`.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut k = Zeroizing::new([0u8; 32]);
        aws_lc_rs::rand::fill(&mut k[..]).map_err(|_| CryptoError::Rng)?;
        Ok(Self(k))
    }

    /// Exactly 32 bytes chahiye.
    ///
    /// # Errors
    /// `CryptoError::InvalidKey` agar length 32 nahi.
    pub fn from_slice(b: &[u8]) -> Result<Self, CryptoError> {
        if b.len() != Self::LEN {
            return Err(CryptoError::InvalidKey("DEK must be 32 bytes"));
        }
        // Stack par koi bina-zeroize copy nahi: seedha Zeroizing array mein.
        let mut k = Zeroizing::new([0u8; 32]);
        k.copy_from_slice(b);
        Ok(Self(k))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Dek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Dek([redacted])")
    }
}

/// Wrap/unwrap ki identity: wrapped blob isi (kid, purpose, tenant) ke liye valid hai (AAD mein bind hota hai).
/// Isse DB-write attacker wrapped bytes ek row se doosri row mein swap nahi kar sakta.
#[derive(Clone, Copy, Debug)]
pub struct WrapContext<'a> {
    pub kid: &'a Kid,
    pub purpose: KeyPurpose,
    pub tenant: Option<common::TenantId>,
}

/// KEK se wrapped DEK. `kek_ref` batata hai kaun si KEK se wrap hua (rewrap/rotation ke liye).
#[derive(Clone, PartialEq, Eq)]
pub struct WrappedDek {
    pub kek_ref: String,
    pub bytes: Vec<u8>,
}

impl fmt::Debug for WrappedDek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WrappedDek")
            .field("kek_ref", &self.kek_ref)
            .field("len", &self.bytes.len())
            .finish()
    }
}
