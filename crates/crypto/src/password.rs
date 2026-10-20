//! `PasswordHasher`: Argon2id (PHC strings) + legacy bcrypt verify (rehash flagged).
//!
//! - Params injected (`Argon2Params`); `ParamPolicy::Production` OWASP floor (m>=19456 KiB, t>=2, p>=1) enforce karta hai.
//! - Memory bound: `Semaphore(LOGIN_HASH_CONCURRENCY)`; slot `acquire_timeout` mein na mile to `CryptoError::Busy`
//!   (API 503 + Retry-After). Work `spawn_blocking` mein; permit blocking task ke saath hi release hota hai
//!   (caller future cancel ho jaaye tab bhi bound toota nahi).
//! - Password sirf `SecretString`; kabhi log/error mein nahi.
//! - Legacy `$2a$`/`$2b$`/`$2y$` bcrypt verify hota hai aur `needs_rehash = true`; plaintext/unknown formats
//!   `MalformedHash` (koi plaintext fallback nahi).

use crate::error::CryptoError;
use argon2::PasswordHasher as _;
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordVerifier, Version};
use secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyOutcome {
    Valid { needs_rehash: bool },
    Invalid,
}

#[async_trait::async_trait]
pub trait PasswordHasher: Send + Sync {
    async fn hash(&self, pw: SecretString) -> Result<String, CryptoError>;
    async fn verify(
        &self,
        pw: SecretString,
        phc_or_bcrypt: &str,
    ) -> Result<VerifyOutcome, CryptoError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2Params {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Argon2Params {
    /// OWASP Password Storage Cheat Sheet minimum (Argon2id m=19 MiB, t=2, p=1).
    pub const PROD_FLOOR: Self = Self {
        m_kib: 19_456,
        t: 2,
        p: 1,
    };
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self::PROD_FLOOR
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParamPolicy {
    /// staging/production: floor enforce.
    Production,
    /// dev/test: sirf validity (tests fast chalane ke liye chhote params).
    Relaxed,
}

const MAX_PASSWORD_BYTES: usize = 1024;
const MAX_BCRYPT_COST: u32 = 14;
// Caps/budget `common::limits` se (config validation bhi wahi use karta hai).
use common::limits::{
    ARGON2_MAX_M_KIB, ARGON2_MAX_P, ARGON2_MAX_T, LOGIN_HASH_CONCURRENCY_MAX, argon2_budget_ok,
    argon2_verify_max_m_kib,
};

/// Test-only: hashing closure ke andar kitne ek saath chal rahe hain, uska real maximum.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct Probe {
    in_flight: std::sync::atomic::AtomicUsize,
    pub(crate) max_seen: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
pub(crate) struct ProbeGuard(Arc<Probe>);

#[cfg(test)]
impl Probe {
    fn enter(self: &Arc<Self>) -> ProbeGuard {
        use std::sync::atomic::Ordering::SeqCst;
        let now = self.in_flight.fetch_add(1, SeqCst) + 1;
        self.max_seen.fetch_max(now, SeqCst);
        ProbeGuard(Arc::clone(self))
    }
}

#[cfg(test)]
impl Drop for ProbeGuard {
    fn drop(&mut self) {
        self.0
            .in_flight
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

pub struct Argon2idHasher {
    cfg: Argon2Params,
    params: Params,
    sem: Arc<Semaphore>,
    acquire_timeout: Duration,
    #[cfg(test)]
    probe: Arc<Probe>,
}

impl std::fmt::Debug for Argon2idHasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Argon2idHasher")
            .field("params", &self.cfg)
            .field("available_permits", &self.sem.available_permits())
            .finish_non_exhaustive()
    }
}

impl Argon2idHasher {
    /// # Errors
    /// `HashParams` agar params floor (Production) / caps / argon2 validity todte hain ya `concurrency == 0`.
    pub fn new(
        cfg: Argon2Params,
        concurrency: usize,
        acquire_timeout: Duration,
        policy: ParamPolicy,
    ) -> Result<Self, CryptoError> {
        if concurrency == 0 {
            return Err(CryptoError::HashParams("concurrency must be >= 1"));
        }
        if policy == ParamPolicy::Production {
            let f = Argon2Params::PROD_FLOOR;
            if cfg.m_kib < f.m_kib || cfg.t < f.t || cfg.p < f.p {
                return Err(CryptoError::HashParams(
                    "below production floor (m>=19456, t>=2, p>=1)",
                ));
            }
        }
        if cfg.m_kib > ARGON2_MAX_M_KIB || cfg.t > ARGON2_MAX_T || cfg.p > ARGON2_MAX_P {
            return Err(CryptoError::HashParams(
                "above cap (m<=262144, t<=10, p<=4)",
            ));
        }
        let conc32 = u32::try_from(concurrency)
            .ok()
            .filter(|c| *c <= LOGIN_HASH_CONCURRENCY_MAX)
            .ok_or(CryptoError::HashParams("concurrency above cap (<=16)"))?;
        if !argon2_budget_ok(cfg.m_kib, conc32) {
            return Err(CryptoError::HashParams(
                "m_kib x concurrency exceeds the 128 MiB hashing memory budget",
            ));
        }
        let params = Params::new(cfg.m_kib, cfg.t, cfg.p, None)
            .map_err(|_| CryptoError::HashParams("rejected by argon2"))?;
        Ok(Self {
            cfg,
            params,
            sem: Arc::new(Semaphore::new(concurrency)),
            acquire_timeout,
            #[cfg(test)]
            probe: Arc::default(),
        })
    }

    #[must_use]
    pub const fn params(&self) -> Argon2Params {
        self.cfg
    }

    #[cfg(test)]
    pub(crate) fn semaphore(&self) -> Arc<Semaphore> {
        Arc::clone(&self.sem)
    }

    async fn permit(&self) -> Result<tokio::sync::OwnedSemaphorePermit, CryptoError> {
        match tokio::time::timeout(self.acquire_timeout, Arc::clone(&self.sem).acquire_owned())
            .await
        {
            Ok(Ok(p)) => Ok(p),
            Ok(Err(_)) => Err(CryptoError::Internal("hash semaphore closed")),
            Err(_) => Err(CryptoError::Busy),
        }
    }
}

fn is_bcrypt(h: &str) -> bool {
    ["$2a$", "$2b$", "$2y$"].iter().any(|p| h.starts_with(p))
}

fn bcrypt_cost(h: &str) -> Option<u32> {
    h.get(4..6)?.parse().ok()
}

#[async_trait::async_trait]
impl PasswordHasher for Argon2idHasher {
    async fn hash(&self, pw: SecretString) -> Result<String, CryptoError> {
        if pw.expose_secret().len() > MAX_PASSWORD_BYTES {
            return Err(CryptoError::InvalidInput("password too long"));
        }
        let permit = self.permit().await?;
        let params = self.params.clone();
        #[cfg(test)]
        let probe = Arc::clone(&self.probe);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            #[cfg(test)]
            let _in_flight = probe.enter();
            let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            argon
                .hash_password(pw.expose_secret().as_bytes())
                .map(|h| h.to_string())
                .map_err(|_| CryptoError::Internal("argon2 hashing failed"))
        })
        .await
        .map_err(|_| CryptoError::Internal("hash task failed"))?
    }

    async fn verify(
        &self,
        pw: SecretString,
        phc_or_bcrypt: &str,
    ) -> Result<VerifyOutcome, CryptoError> {
        // Format pehle check (sasta, permit nahi chahiye): galat format ya oversized password = no hashing work.
        enum Kind {
            Bcrypt,
            Argon2 { rehash: bool },
        }
        let kind = if is_bcrypt(phc_or_bcrypt) {
            match bcrypt_cost(phc_or_bcrypt) {
                Some(c) if (4..=MAX_BCRYPT_COST).contains(&c) => Kind::Bcrypt,
                _ => return Err(CryptoError::MalformedHash),
            }
        } else if phc_or_bcrypt.starts_with("$argon2id$") {
            let parsed =
                PasswordHash::new(phc_or_bcrypt).map_err(|_| CryptoError::MalformedHash)?;
            let p = Params::try_from(&parsed).map_err(|_| CryptoError::MalformedHash)?;
            // Stored hash ka m configured se zyada (max(m, min(2m, 64 MiB))) nahi: DB-write attacker 512 MB box
            // ko giant-m hash se OOM na kar sake. Rejected = failed verify (caller `Err` ko login fail maane), no hashing.
            if p.m_cost() > argon2_verify_max_m_kib(self.cfg.m_kib)
                || p.m_cost() > ARGON2_MAX_M_KIB
                || p.t_cost() > ARGON2_MAX_T
                || p.p_cost() > ARGON2_MAX_P
            {
                return Err(CryptoError::HashCostExceeded);
            }
            let version_ok = parsed.version.is_none_or(|v| v == 0x13);
            let rehash = !version_ok
                || p.m_cost() != self.cfg.m_kib
                || p.t_cost() != self.cfg.t
                || p.p_cost() != self.cfg.p;
            Kind::Argon2 { rehash }
        } else {
            return Err(CryptoError::MalformedHash);
        };
        if pw.expose_secret().len() > MAX_PASSWORD_BYTES {
            return Ok(VerifyOutcome::Invalid);
        }

        let permit = self.permit().await?;
        let stored = phc_or_bcrypt.to_owned();
        #[cfg(test)]
        let probe = Arc::clone(&self.probe);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            #[cfg(test)]
            let _in_flight = probe.enter();
            let ok = match kind {
                Kind::Bcrypt => bcrypt::verify(pw.expose_secret().as_bytes(), &stored)
                    .map_err(|_| CryptoError::MalformedHash)?,
                Kind::Argon2 { .. } => {
                    let parsed =
                        PasswordHash::new(&stored).map_err(|_| CryptoError::MalformedHash)?;
                    // Params hash string se aate hain (configured se nahi).
                    Argon2::default()
                        .verify_password(pw.expose_secret().as_bytes(), &parsed)
                        .is_ok()
                }
            };
            Ok(if ok {
                VerifyOutcome::Valid {
                    needs_rehash: match kind {
                        Kind::Bcrypt => true,
                        Kind::Argon2 { rehash } => rehash,
                    },
                }
            } else {
                VerifyOutcome::Invalid
            })
        })
        .await
        .map_err(|_| CryptoError::Internal("verify task failed"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast() -> Argon2Params {
        Argon2Params {
            m_kib: 64,
            t: 1,
            p: 1,
        }
    }

    fn hasher(conc: usize, timeout_ms: u64) -> Argon2idHasher {
        Argon2idHasher::new(
            fast(),
            conc,
            Duration::from_millis(timeout_ms),
            ParamPolicy::Relaxed,
        )
        .expect("hasher")
    }

    fn pw(s: &str) -> SecretString {
        SecretString::from(s.to_owned())
    }

    #[tokio::test]
    async fn hash_verify_round_trip() {
        let h = hasher(2, 2000);
        let phc = h.hash(pw("correct horse battery")).await.expect("hash");
        assert!(phc.starts_with("$argon2id$v=19$m=64,t=1,p=1$"), "{phc}");
        assert_eq!(
            h.verify(pw("correct horse battery"), &phc)
                .await
                .expect("v"),
            VerifyOutcome::Valid {
                needs_rehash: false
            }
        );
        assert_eq!(
            h.verify(pw("wrong"), &phc).await.expect("v"),
            VerifyOutcome::Invalid
        );
        // salt random
        let phc2 = h.hash(pw("correct horse battery")).await.expect("hash2");
        assert_ne!(phc, phc2);
        assert!(!phc.contains("correct horse"));
    }

    #[tokio::test]
    async fn weaker_params_flag_rehash() {
        let old = hasher(1, 2000);
        let phc = old.hash(pw("pw-123456789012")).await.expect("hash");
        let newer = Argon2idHasher::new(
            Argon2Params {
                m_kib: 128,
                t: 1,
                p: 1,
            },
            1,
            Duration::from_secs(2),
            ParamPolicy::Relaxed,
        )
        .expect("n");
        assert_eq!(
            newer.verify(pw("pw-123456789012"), &phc).await.expect("v"),
            VerifyOutcome::Valid { needs_rehash: true }
        );
    }

    #[tokio::test]
    async fn bcrypt_legacy_verifies_and_needs_rehash() {
        let h = hasher(2, 2000);
        let hashed = bcrypt::hash("legacy-pass", 4).expect("bcrypt");
        assert!(hashed.starts_with("$2b$"));
        assert_eq!(
            h.verify(pw("legacy-pass"), &hashed).await.expect("v"),
            VerifyOutcome::Valid { needs_rehash: true }
        );
        assert_eq!(
            h.verify(pw("nope"), &hashed).await.expect("v"),
            VerifyOutcome::Invalid
        );
        // $2a$ / $2y$ prefixes (same body)
        for prefix in ["$2a$", "$2y$"] {
            let alt = format!("{prefix}{}", &hashed[4..]);
            assert_eq!(
                h.verify(pw("legacy-pass"), &alt).await.expect("v"),
                VerifyOutcome::Valid { needs_rehash: true },
                "{prefix}"
            );
        }
    }

    #[tokio::test]
    async fn malformed_and_plaintext_hashes_rejected() {
        let h = hasher(1, 500);
        for bad in [
            "",
            "plaintext-password",
            "$argon2id$garbage",
            "$argon2i$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo",
            "$2b$99$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234",
            "$2b$xx$short",
        ] {
            assert!(
                matches!(
                    h.verify(pw("x"), bad).await,
                    Err(CryptoError::MalformedHash)
                ),
                "{bad}"
            );
        }
    }

    #[tokio::test]
    async fn oversized_password_rejected_cheaply() {
        let h = hasher(1, 500);
        let huge = pw(&"a".repeat(5000));
        assert!(matches!(
            h.hash(huge.clone()).await,
            Err(CryptoError::InvalidInput(_))
        ));
        let phc = h.hash(pw("ok-password-123")).await.expect("hash");
        assert_eq!(
            h.verify(huge, &phc).await.expect("v"),
            VerifyOutcome::Invalid
        );
    }

    #[test]
    fn production_floor_enforced_by_constructor() {
        let mk = |m, t, p| {
            Argon2idHasher::new(
                Argon2Params { m_kib: m, t, p },
                1,
                Duration::from_secs(1),
                ParamPolicy::Production,
            )
        };
        assert!(mk(19_456, 2, 1).is_ok());
        assert!(mk(65_536, 3, 2).is_ok());
        assert!(matches!(mk(19_455, 2, 1), Err(CryptoError::HashParams(_))));
        assert!(matches!(mk(19_456, 1, 1), Err(CryptoError::HashParams(_))));
        assert!(matches!(mk(19_456, 2, 0), Err(CryptoError::HashParams(_))));
        assert!(matches!(mk(8, 1, 1), Err(CryptoError::HashParams(_))));
        // caps
        assert!(mk(1_000_000, 2, 1).is_err());
        assert!(mk(19_456, 99, 1).is_err());
        // relaxed policy allows small, but still validates
        let relaxed = |m, t, p| {
            Argon2idHasher::new(
                Argon2Params { m_kib: m, t, p },
                1,
                Duration::from_secs(1),
                ParamPolicy::Relaxed,
            )
        };
        assert!(relaxed(64, 1, 1).is_ok());
        assert!(relaxed(1, 1, 1).is_err());
        assert!(
            Argon2idHasher::new(fast(), 0, Duration::from_secs(1), ParamPolicy::Relaxed).is_err()
        );
        assert_eq!(Argon2Params::default(), Argon2Params::PROD_FLOOR);
    }

    /// T-C4: slot na mile to Busy (timeout), slot free hote hi kaam chalta hai.
    #[tokio::test]
    async fn semaphore_busy_on_timeout() {
        let h = hasher(1, 30);
        let phc = h.hash(pw("pw-for-busy-test")).await.expect("hash");
        let held = h.semaphore().acquire_owned().await.expect("permit");
        assert!(matches!(h.hash(pw("x")).await, Err(CryptoError::Busy)));
        assert!(matches!(
            h.verify(pw("x"), &phc).await,
            Err(CryptoError::Busy)
        ));
        drop(held);
        assert!(h.verify(pw("pw-for-busy-test"), &phc).await.is_ok());
    }

    #[tokio::test]
    async fn semaphore_waiter_proceeds_when_slot_frees() {
        let h = Arc::new(
            Argon2idHasher::new(fast(), 1, Duration::from_secs(5), ParamPolicy::Relaxed)
                .expect("h"),
        );
        let held = h.semaphore().acquire_owned().await.expect("permit");
        let h2 = Arc::clone(&h);
        let mut waiter = tokio::task::JoinSet::new();
        waiter.spawn(async move { h2.hash(pw("waiting-password")).await });
        let early = tokio::time::timeout(Duration::from_millis(80), waiter.join_next()).await;
        assert!(early.is_err(), "N+1th request ko wait karna chahiye");
        drop(held);
        let phc = waiter
            .join_next()
            .await
            .expect("task")
            .expect("join")
            .expect("hash ok");
        assert!(phc.starts_with("$argon2id$"));
        assert_eq!(
            h.semaphore().available_permits(),
            1,
            "permit return hona chahiye"
        );
    }

    /// L-4: hashing closure ke andar ka real maximum (atomic counter) bound se zyada nahi.
    #[tokio::test]
    async fn concurrency_is_bounded_under_load() {
        let bound = 3usize;
        let h = Arc::new(
            Argon2idHasher::new(
                Argon2Params {
                    m_kib: 16_384,
                    t: 3,
                    p: 1,
                },
                bound,
                Duration::from_secs(60),
                ParamPolicy::Relaxed,
            )
            .expect("h"),
        );
        let mut set = tokio::task::JoinSet::new();
        for i in 0..12 {
            let h = Arc::clone(&h);
            set.spawn(async move { h.hash(pw(&format!("password-number-{i}"))).await });
        }
        while let Some(r) = set.join_next().await {
            assert!(r.expect("join").is_ok());
        }
        let max = h.probe.max_seen.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            max <= bound,
            "real concurrency {max} exceeded bound {bound}"
        );
        assert!(max >= 2, "load test should actually overlap (saw {max})");
        assert_eq!(h.semaphore().available_permits(), bound);
    }

    /// Legacy bcrypt sirf pehle 72 bytes dekhta hai (documented legacy behaviour).
    #[tokio::test]
    async fn bcrypt_truncates_at_72_bytes_legacy_behaviour() {
        let h = hasher(1, 2000);
        let base = "a".repeat(72);
        let hashed = bcrypt::hash(format!("{base}XXXX"), 4).expect("bcrypt");
        // 72 ke baad ka hissa ignore: sirf prefix se bhi verify ho jaata hai.
        assert_eq!(
            h.verify(pw(&format!("{base}YYYY")), &hashed)
                .await
                .expect("v"),
            VerifyOutcome::Valid { needs_rehash: true }
        );
        assert_eq!(
            h.verify(pw(&base), &hashed).await.expect("v"),
            VerifyOutcome::Valid { needs_rehash: true }
        );
        // pehle 72 bytes mein farq ho to Invalid.
        let other = format!("b{}", &base[1..]);
        assert_eq!(
            h.verify(pw(&other), &hashed).await.expect("v"),
            VerifyOutcome::Invalid
        );
        // Argon2id mein koi truncation nahi.
        let phc = h.hash(pw(&format!("{base}XXXX"))).await.expect("hash");
        assert_eq!(
            h.verify(pw(&format!("{base}YYYY")), &phc).await.expect("v"),
            VerifyOutcome::Invalid
        );
    }

    /// CR-4: stored hash ka m configured se bahut upar = HashCostExceeded (hashing se pehle), t/p caps bhi.
    #[tokio::test]
    async fn stored_hash_cost_caps_enforced() {
        let prod = Argon2idHasher::new(
            Argon2Params::PROD_FLOOR,
            3,
            Duration::from_millis(200),
            ParamPolicy::Production,
        )
        .expect("prod");
        let phc = |m: u32, t: u32, p: u32| {
            format!("$argon2id$v=19$m={m},t={t},p={p}$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo")
        };
        // cap = max(19456, min(38912, 65536)) = 38912
        for bad in [
            phc(38_913, 2, 1),
            phc(4_194_304, 1, 1),
            phc(19_456, 11, 1),
            phc(19_456, 2, 5),
        ] {
            assert!(
                matches!(
                    prod.verify(pw("x"), &bad).await,
                    Err(CryptoError::HashCostExceeded)
                ),
                "{bad}"
            );
        }
        // cap par (38912) rejected nahi hota (hash galat hai to Invalid, error nahi).
        assert_eq!(
            prod.verify(pw("x"), &phc(38_912, 2, 1)).await.expect("v"),
            VerifyOutcome::Invalid
        );
        // permit abhi bhi free (rejection ne hashing slot nahi liya)
        assert_eq!(prod.semaphore().available_permits(), 3);

        // chhota config: cap 2x (64 -> 128)
        let h = hasher(1, 500);
        assert!(matches!(
            h.verify(pw("x"), &phc(129, 1, 1)).await,
            Err(CryptoError::HashCostExceeded)
        ));
        let bigger = Argon2idHasher::new(
            Argon2Params {
                m_kib: 128,
                t: 1,
                p: 1,
            },
            1,
            Duration::from_secs(2),
            ParamPolicy::Relaxed,
        )
        .expect("bigger");
        let stored = bigger.hash(pw("pw-123456789012")).await.expect("hash");
        assert_eq!(
            h.verify(pw("pw-123456789012"), &stored).await.expect("v"),
            VerifyOutcome::Valid { needs_rehash: true },
            "2x cap ke andar wala purana/bada hash verify hota hai"
        );
    }

    #[test]
    fn budget_and_caps_enforced_by_constructor() {
        let mk = |m, conc| {
            Argon2idHasher::new(
                Argon2Params {
                    m_kib: m,
                    t: 2,
                    p: 1,
                },
                conc,
                Duration::from_secs(1),
                ParamPolicy::Production,
            )
        };
        assert!(mk(19_456, 6).is_ok());
        assert!(matches!(mk(19_456, 7), Err(CryptoError::HashParams(_))));
        assert!(mk(131_072, 1).is_ok());
        assert!(matches!(mk(131_072, 2), Err(CryptoError::HashParams(_))));
        assert!(matches!(mk(262_144, 1), Err(CryptoError::HashParams(_))));
        assert!(matches!(mk(262_145, 1), Err(CryptoError::HashParams(_))));
        let relaxed = Argon2idHasher::new(
            Argon2Params {
                m_kib: 64,
                t: 1,
                p: 1,
            },
            17,
            Duration::from_secs(1),
            ParamPolicy::Relaxed,
        );
        assert!(matches!(relaxed, Err(CryptoError::HashParams(_))));
    }

    #[test]
    fn debug_never_shows_password() {
        let secret = pw("super-secret-pw");
        assert!(!format!("{secret:?}").contains("super-secret"));
        let h = hasher(1, 10);
        assert!(!format!("{h:?}").contains("secret"));
    }
}
