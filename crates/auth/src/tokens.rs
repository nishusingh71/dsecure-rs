//! `TokenIssuer` / `TokenVerifier` (PHASE0_SPEC §3.4): ES256 allowlist, realm-bound key set with kid
//! lookup (rotation: add the new kid, keep the old one verify-only until max access TTL passes).

use std::collections::HashMap;
use std::sync::Arc;

use common::Clock;
use crypto::{SigAlg, Signer};

use crate::claims::{AccessClaims, Audience, Realm, VerifiedClaims};
use crate::error::{AuthError, Rejection};
use crate::jws;

/// Max clock skew accepted on `exp` / `nbf` / `iat` (SECURITY.md §5: 30 s max).
pub const MAX_LEEWAY_SECS: i64 = 30;
/// No access token may live longer than this, whatever a key holder signs.
pub const MAX_ACCESS_LIFETIME_SECS: i64 = 3600;
/// Uncompressed SEC1 P-256 point length.
const P256_PUBLIC_LEN: usize = 65;

#[async_trait::async_trait]
pub trait TokenIssuer: Send + Sync {
    /// Sign `c` with the key of its audience realm. Async because `crypto::Signer` is (KMS later).
    async fn issue_access(&self, c: &AccessClaims) -> Result<String, AuthError>;
}

pub trait TokenVerifier: Send + Sync {
    /// Verify signature, kid, realm, iss, aud in `expected`, typ, times and claim shape.
    ///
    /// # Errors
    /// `AuthError::Unauthenticated(reason)`.
    fn verify(&self, token: &str, expected: &[Audience]) -> Result<VerifiedClaims, AuthError>;
}

/// ES256 issuer: one signer per realm (member/device key, staff key, optional cleaner key).
pub struct Es256Issuer {
    member: Arc<dyn Signer>,
    staff: Arc<dyn Signer>,
    cleaner: Option<Arc<dyn Signer>>,
}

impl std::fmt::Debug for Es256Issuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Es256Issuer")
            .field("member_kid", &self.member.kid())
            .field("staff_kid", &self.staff.kid())
            .finish_non_exhaustive()
    }
}

impl Es256Issuer {
    /// # Errors
    /// `Internal` if a signer is not ES256, has an invalid kid, or member and staff share a kid.
    pub fn new(
        member: Arc<dyn Signer>,
        staff: Arc<dyn Signer>,
        cleaner: Option<Arc<dyn Signer>>,
    ) -> Result<Self, AuthError> {
        let all = [Some(&member), Some(&staff), cleaner.as_ref()];
        for s in all.into_iter().flatten() {
            if s.alg() != SigAlg::Es256 || !jws::valid_kid(s.kid()) {
                return Err(AuthError::Internal(
                    "jwt signer must be ES256 with a valid kid",
                ));
            }
        }
        if member.kid() == staff.kid()
            || cleaner
                .as_ref()
                .is_some_and(|c| c.kid() == member.kid() || c.kid() == staff.kid())
        {
            return Err(AuthError::Internal("jwt realms must use distinct keys"));
        }
        Ok(Self {
            member,
            staff,
            cleaner,
        })
    }

    fn signer(&self, realm: Realm) -> Option<&Arc<dyn Signer>> {
        match realm {
            Realm::Member => Some(&self.member),
            Realm::Staff => Some(&self.staff),
            Realm::Cleaner => self.cleaner.as_ref(),
        }
    }
}

#[async_trait::async_trait]
impl TokenIssuer for Es256Issuer {
    async fn issue_access(&self, c: &AccessClaims) -> Result<String, AuthError> {
        c.check_shape().map_err(AuthError::Unauthenticated)?;
        if c.exp - c.iat > MAX_ACCESS_LIFETIME_SECS || c.exp <= c.iat {
            return Err(AuthError::Internal("access token lifetime out of range"));
        }
        let signer = self
            .signer(c.aud.realm())
            .ok_or(AuthError::Internal("no signer for realm"))?;
        let payload =
            serde_json::to_vec(c).map_err(|_| AuthError::Internal("claims serialisation"))?;
        let input = jws::signing_input(signer.kid(), &payload)
            .map_err(|_| AuthError::Internal("invalid signer kid"))?;
        let sig = signer
            .sign(input.as_bytes())
            .await
            .map_err(|_| AuthError::Internal("jwt signing failed"))?;
        if sig.len() != jws::ES256_SIG_LEN {
            return Err(AuthError::Internal("jwt signature length"));
        }
        Ok(jws::assemble(&input, &sig))
    }
}

#[derive(Clone)]
struct VerifyKey {
    realm: Realm,
    public_key: Vec<u8>,
}

/// Public verification keys by kid, each bound to ONE realm.
#[derive(Clone, Default)]
pub struct KeySet {
    keys: HashMap<String, VerifyKey>,
}

impl std::fmt::Debug for KeySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeySet")
            .field("kids", &self.keys.len())
            .finish()
    }
}

impl KeySet {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a verify key (uncompressed SEC1 P-256 point, 65 bytes).
    ///
    /// # Errors
    /// `Internal` for an invalid kid, a duplicate kid, or a malformed key.
    pub fn insert(&mut self, kid: &str, realm: Realm, public_key: &[u8]) -> Result<(), AuthError> {
        if !jws::valid_kid(kid) {
            return Err(AuthError::Internal("invalid kid"));
        }
        if public_key.len() != P256_PUBLIC_LEN || public_key.first() != Some(&0x04) {
            return Err(AuthError::Internal(
                "es256 public key must be an uncompressed P-256 point",
            ));
        }
        if self.keys.contains_key(kid) {
            return Err(AuthError::Internal("duplicate kid"));
        }
        self.keys.insert(
            kid.to_owned(),
            VerifyKey {
                realm,
                public_key: public_key.to_vec(),
            },
        );
        Ok(())
    }

    /// Convenience: the public key of a signer.
    ///
    /// # Errors
    /// See [`KeySet::insert`].
    pub fn insert_signer(&mut self, signer: &dyn Signer, realm: Realm) -> Result<(), AuthError> {
        if signer.alg() != SigAlg::Es256 {
            return Err(AuthError::Internal("jwt keys are ES256 only"));
        }
        self.insert(signer.kid(), realm, signer.public_key())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// ES256 verifier.
pub struct Es256Verifier {
    keys: KeySet,
    issuer: String,
    clock: Arc<dyn Clock>,
    leeway: i64,
}

impl std::fmt::Debug for Es256Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Es256Verifier")
            .field("keys", &self.keys)
            .field("leeway", &self.leeway)
            .finish_non_exhaustive()
    }
}

impl Es256Verifier {
    /// `leeway_secs` is clamped to `0..=30`.
    #[must_use]
    pub fn new(
        keys: KeySet,
        issuer: impl Into<String>,
        clock: Arc<dyn Clock>,
        leeway_secs: i64,
    ) -> Self {
        Self {
            keys,
            issuer: issuer.into(),
            clock,
            leeway: leeway_secs.clamp(0, MAX_LEEWAY_SECS),
        }
    }

    fn check(&self, token: &str, expected: &[Audience]) -> Result<VerifiedClaims, Rejection> {
        let parts = jws::parse(token)?;
        let key = self
            .keys
            .keys
            .get(&parts.kid)
            .ok_or(Rejection::UnknownKid)?;
        if !crypto::verify(
            SigAlg::Es256,
            &key.public_key,
            parts.signing_input.as_bytes(),
            &parts.sig,
        ) {
            return Err(Rejection::BadSignature);
        }
        let claims: AccessClaims =
            serde_json::from_slice(&parts.payload).map_err(|_| Rejection::Malformed)?;
        if claims.iss != self.issuer {
            return Err(Rejection::WrongIssuer);
        }
        if !expected.contains(&claims.aud) {
            return Err(Rejection::WrongAudience);
        }
        // A key only vouches for its own realm: staff key cannot mint member tokens and vice versa.
        if claims.aud.realm() != key.realm {
            return Err(Rejection::RealmMismatch);
        }
        claims.check_shape()?;
        let now = self.clock.now().unix_timestamp();
        if claims.exp <= now - self.leeway {
            return Err(Rejection::Expired);
        }
        if claims.nbf > now + self.leeway {
            return Err(Rejection::NotYetValid);
        }
        if claims.iat > now + self.leeway || claims.auth_time > now + self.leeway {
            return Err(Rejection::IssuedInFuture);
        }
        if claims.exp - claims.iat > MAX_ACCESS_LIFETIME_SECS || claims.exp <= claims.iat {
            return Err(Rejection::LifetimeTooLong);
        }
        Ok(VerifiedClaims::new(claims, parts.kid))
    }
}

impl TokenVerifier for Es256Verifier {
    fn verify(&self, token: &str, expected: &[Audience]) -> Result<VerifiedClaims, AuthError> {
        self.check(token, expected)
            .map_err(AuthError::Unauthenticated)
    }
}
