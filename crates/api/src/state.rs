//! Shared handler state (cheap `Clone`, one `Arc`).

use std::sync::Arc;

use auth::AuthService;
use config::Environment;
use crypto::{BlindIndexer, KeyPurpose, KeyRing};
use zeroize::Zeroizing;

use crate::ratelimit::PreAuthLimiter;

/// HKDF label of the cursor HMAC subkey (platform `Secrets` DEK).
pub const CURSOR_KEY_LABEL: &str = "api-cursor";

/// Auth endpoint dependencies (login / refresh / logout / step-up).
#[derive(Clone)]
pub struct AuthHttp {
    pub service: Arc<AuthService>,
    pub limiter: Arc<PreAuthLimiter>,
    /// Email blind index for the IP+email rate-limit bucket (never the raw email).
    pub indexer: Arc<dyn BlindIndexer>,
}

/// Serialised JWKS + build time.
/// Last readiness probe result + time.
pub(crate) type ReadyCache = tokio::sync::Mutex<Option<(std::time::Instant, (bool, bool))>>;
pub(crate) type JwksCache = tokio::sync::Mutex<Option<(std::time::Instant, Arc<Vec<u8>>)>>;

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

struct Inner {
    environment: Environment,
    db: db::Db,
    /// `None` = platform keys not loaded -> `/health/ready` 503 (startup normally refuses earlier).
    keys: Option<Arc<KeyRing>>,
    /// Cursor HMAC key (`common::Cursor`), see [`cursor_key_from`].
    cursor_key: Zeroizing<[u8; 32]>,
    /// `None` = auth endpoints answer 503.
    auth: Option<AuthHttp>,
    /// Serialised JWKS + when it was built (short cache: one DB read per minute at most).
    jwks: JwksCache,
    /// Last DB readiness probe `(db, migrations)` + when (see `routes::health`).
    ready: ReadyCache,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("environment", &self.0.environment)
            .field("keys_loaded", &self.0.keys.is_some())
            .field("auth", &self.0.auth.is_some())
            .finish_non_exhaustive()
    }
}

/// Cursor key = HKDF subkey of the ACTIVE platform `Secrets` DEK, label [`CURSOR_KEY_LABEL`]:
/// identical on every instance and across restarts. Rotation of that DEK changes the key: cursors
/// issued before the rotation then fail with 400 `cursor_invalid` and the client restarts the
/// listing (chosen over a previous-kid grace window: simpler, and a cursor is a short-lived value).
///
/// # Errors
/// Key ring errors.
pub async fn cursor_key_from(ring: &KeyRing) -> Result<Zeroizing<[u8; 32]>, crypto::CryptoError> {
    ring.derive_subkey(KeyPurpose::Secrets, None, CURSOR_KEY_LABEL)
        .await
}

impl AppState {
    #[must_use]
    pub fn new(
        environment: Environment,
        db: db::Db,
        keys: Option<Arc<KeyRing>>,
        cursor_key: Zeroizing<[u8; 32]>,
    ) -> Self {
        Self(Arc::new(Inner {
            environment,
            db,
            keys,
            cursor_key,
            auth: None,
            jwks: tokio::sync::Mutex::new(None),
            ready: tokio::sync::Mutex::new(None),
        }))
    }

    /// Same state with auth endpoint deps (call before cloning the state into the router).
    #[must_use]
    pub fn with_auth(self, auth: AuthHttp) -> Self {
        let inner = Arc::try_unwrap(self.0).unwrap_or_else(|arc| Inner {
            environment: arc.environment,
            db: arc.db.clone(),
            keys: arc.keys.clone(),
            cursor_key: arc.cursor_key.clone(),
            auth: arc.auth.clone(),
            jwks: tokio::sync::Mutex::new(None),
            ready: tokio::sync::Mutex::new(None),
        });
        Self(Arc::new(Inner {
            auth: Some(auth),
            ..inner
        }))
    }

    #[must_use]
    pub fn environment(&self) -> Environment {
        self.0.environment
    }

    #[must_use]
    pub fn db(&self) -> &db::Db {
        &self.0.db
    }

    #[must_use]
    pub fn keys(&self) -> Option<&Arc<KeyRing>> {
        self.0.keys.as_ref()
    }

    #[must_use]
    pub fn cursor_key(&self) -> &[u8] {
        &self.0.cursor_key[..]
    }

    #[must_use]
    pub fn auth(&self) -> Option<&AuthHttp> {
        self.0.auth.as_ref()
    }

    pub(crate) fn ready_cache(&self) -> &ReadyCache {
        &self.0.ready
    }

    pub(crate) fn jwks_cache(&self) -> &JwksCache {
        &self.0.jwks
    }
}
