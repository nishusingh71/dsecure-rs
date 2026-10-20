//! `PrincipalStateLoader` (PHASE0_SPEC §3.4, DATABASE.md §4.4, RBAC.md §6.3/§6.4).
//!
//! - Input is always [`VerifiedClaims`] (only `Es256Verifier` makes them).
//! - Live state = ONE indexed statement (`db::repo::auth_state`): session, user, membership, tenant,
//!   capabilities, groups, GA groups, features and the tenant epoch, read in one snapshot.
//! - Cache: bounded moka (`AUTHZ_CACHE_ENTRIES`) keyed `(session, membership, token authz_version)`;
//!   an entry is used only while `epoch_seen == EpochMap::current(tenant)` AND the epoch poller ran
//!   successfully within 10 s, and only for the same user. Otherwise: live load (never deny because
//!   of the cache).
//! - Time-dependent checks (session expiry, `tokens_valid_after` vs token `iat`) run on EVERY call,
//!   cache hit or not.
//! - `Freshness::Live` (high-risk policies) always bypasses the cache.
//! - Staff (always live): MFA must be completed on the session (fail closed until MFA lands in
//!   P0-11), absolute 8 h and idle 30 min limits; each load refreshes `last_seen_at` (throttled).
//! - This module is the ONLY caller of `AuthenticatedActor::__from_authenticated`.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use common::{Clock, MembershipId, SessionId, TenantId, UserId};
use db::Db;
use db::repo::auth_state::{
    self, CapabilityRow, DeviceLiveRow, MemberLiveRow, SessionLive, StaffLiveRow, UserLive,
};
use db::repo::memberships::MembershipStatus;
use db::repo::users::UserStatus;
use domain::rbac::{
    ActorState, AuthenticatedActor, Capabilities, DeviceActor, DeviceScope, Feature, FeatureSet,
    GroupIds, MemberStatus, StaffRole, TenantRole,
};
use moka::sync::Cache;
use time::{Duration, OffsetDateTime};

use crate::claims::{Audience, PrincipalKind, VerifiedClaims};
use crate::error::{AuthError, Rejection};
use crate::principal::{DevicePrincipal, MemberPrincipal, Principal, StaffPrincipal};
use crate::settings::AuthSettings;

/// Cache use for one evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Freshness {
    /// Epoch-validated cache allowed.
    Cached,
    /// Always read live (high-risk actions, refresh, step-up).
    Live,
}

#[async_trait::async_trait]
pub trait PrincipalStateLoader: Send + Sync {
    /// Member principal from verified claims + live state.
    async fn load_member(
        &self,
        claims: &VerifiedClaims,
        fresh: Freshness,
    ) -> Result<MemberPrincipal, AuthError>;

    /// Device principal from verified device claims + live credential/operator state.
    async fn load_device(
        &self,
        claims: &VerifiedClaims,
        fresh: Freshness,
    ) -> Result<DevicePrincipal, AuthError>;

    /// Staff principal (always live: staff traffic is small and every staff request is audited).
    async fn load_staff(&self, claims: &VerifiedClaims) -> Result<StaffPrincipal, AuthError>;

    /// Dispatch on the token kind.
    async fn load(
        &self,
        claims: &VerifiedClaims,
        fresh: Freshness,
    ) -> Result<Principal, AuthError> {
        match claims.kind() {
            PrincipalKind::Member => self.load_member(claims, fresh).await.map(Principal::Member),
            PrincipalKind::Device => self
                .load_device(claims, fresh)
                .await
                .map(|d| Principal::Device(Box::new(d))),
            PrincipalKind::Staff => self.load_staff(claims).await.map(Principal::Staff),
            // No cleaner identity model yet (D-11): never accepted.
            PrincipalKind::Cleaner => Err(AuthError::Unauthenticated(Rejection::KindMismatch)),
        }
    }
}

type MemberKey = (SessionId, MembershipId, u64);
type DeviceKey = (uuid::Uuid, MembershipId, u64);

#[derive(Debug)]
struct CachedMember {
    user: UserId,
    row: MemberLiveRow,
    epoch: u64,
}

#[derive(Debug)]
struct CachedDevice {
    row: DeviceLiveRow,
    epoch: u64,
}

/// Counters for tests and metrics.
#[derive(Debug, Default)]
pub struct LoaderStats {
    pub live_loads: AtomicU64,
    pub cache_hits: AtomicU64,
}

/// Staff session limits (RBAC.md §3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StaffLimits {
    pub(crate) max: Duration,
    pub(crate) idle: Duration,
}

impl StaffLimits {
    pub(crate) const fn from_settings(s: &AuthSettings) -> Self {
        Self {
            max: s.staff_session_max,
            idle: s.staff_session_idle,
        }
    }
}

/// DB-backed loader with the bounded authz cache.
pub struct DbPrincipalLoader {
    db: Db,
    clock: Arc<dyn Clock>,
    members: Cache<MemberKey, Arc<CachedMember>>,
    devices: Cache<DeviceKey, Arc<CachedDevice>>,
    stale_after: Duration,
    staff: StaffLimits,
    touch_throttle: Duration,
    stats: LoaderStats,
}

impl std::fmt::Debug for DbPrincipalLoader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbPrincipalLoader")
            .field("members", &self.members.entry_count())
            .field("devices", &self.devices.entry_count())
            .finish_non_exhaustive()
    }
}

impl DbPrincipalLoader {
    #[must_use]
    pub fn new(db: Db, clock: Arc<dyn Clock>, settings: &AuthSettings) -> Self {
        let n = settings.authz_cache_entries.max(1);
        Self {
            db,
            clock,
            members: Cache::builder()
                .max_capacity(n)
                .time_to_live(settings.authz_cache_ttl)
                .support_invalidation_closures()
                .build(),
            devices: Cache::builder()
                .max_capacity((n / 4).max(1))
                .time_to_live(settings.authz_cache_ttl)
                .build(),
            stale_after: settings.epoch_stale_after,
            staff: StaffLimits::from_settings(settings),
            touch_throttle: settings.session_touch_throttle,
            stats: LoaderStats::default(),
        }
    }

    #[must_use]
    pub const fn stats(&self) -> &LoaderStats {
        &self.stats
    }

    /// Local, immediate invalidation (logout / revoke on this instance). Other instances follow via
    /// the epoch bump of the same revoke.
    pub fn invalidate_session(&self, session: SessionId) {
        if self
            .members
            .invalidate_entries_if(move |k, _| k.0 == session)
            .is_err()
        {
            self.members.invalidate_all();
        }
    }

    /// Cache usable for `tenant` with `epoch_seen`?
    fn epoch_valid(&self, tenant: TenantId, epoch_seen: u64, now: OffsetDateTime) -> bool {
        let epochs = self.db.epochs();
        let fresh = epochs
            .last_ok()
            .is_some_and(|t| now - t <= self.stale_after && t <= now + self.stale_after);
        fresh && epochs.current(tenant) == Some(epoch_seen)
    }

    async fn member_row(&self, claims: &VerifiedClaims) -> Result<MemberLiveRow, AuthError> {
        let (Some(tenant), Some(membership), Some(session)) =
            (claims.tenant(), claims.membership(), claims.session())
        else {
            return Err(AuthError::Unauthenticated(Rejection::MissingClaim));
        };
        let mut tx = self
            .db
            .identity_tx()
            .await
            .map_err(|e| AuthError::from_db(&e))?;
        let row =
            auth_state::member_live(&mut tx, session, claims.user(), tenant, membership).await;
        tx.rollback().await;
        self.stats.live_loads.fetch_add(1, Ordering::Relaxed);
        row.map_err(|e| AuthError::from_db(&e))?
            .ok_or(AuthError::Unauthenticated(Rejection::SessionMissing))
    }

    async fn device_row(&self, claims: &VerifiedClaims) -> Result<DeviceLiveRow, AuthError> {
        let (Some(tenant), Some(cred)) = (claims.tenant(), claims.credential()) else {
            return Err(AuthError::Unauthenticated(Rejection::MissingClaim));
        };
        let mut tx = self
            .db
            .identity_tx()
            .await
            .map_err(|e| AuthError::from_db(&e))?;
        let row = auth_state::device_live(&mut tx, tenant, cred, claims.device()).await;
        tx.rollback().await;
        self.stats.live_loads.fetch_add(1, Ordering::Relaxed);
        row.map_err(|e| AuthError::from_db(&e))?
            .ok_or(AuthError::Unauthenticated(Rejection::CredentialRevoked))
    }
}

#[async_trait::async_trait]
impl PrincipalStateLoader for DbPrincipalLoader {
    async fn load_member(
        &self,
        claims: &VerifiedClaims,
        fresh: Freshness,
    ) -> Result<MemberPrincipal, AuthError> {
        if claims.kind() != PrincipalKind::Member {
            return Err(AuthError::Unauthenticated(Rejection::KindMismatch));
        }
        let (Some(tenant), Some(membership), Some(session)) =
            (claims.tenant(), claims.membership(), claims.session())
        else {
            return Err(AuthError::Unauthenticated(Rejection::MissingClaim));
        };
        let now = self.clock.now();
        let key = (session, membership, claims.authz_version());
        if fresh == Freshness::Cached
            && let Some(hit) = self.members.get(&key)
            && hit.user == claims.user()
            && self.epoch_valid(tenant, hit.epoch, now)
        {
            self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
            return build_member(&hit.row, claims, now);
        }
        let row = self.member_row(claims).await?;
        let principal = build_member(&row, claims, now)?;
        if let Some(epoch) = row.epoch {
            self.db.epochs().observe(tenant, epoch);
            self.members.insert(
                key,
                Arc::new(CachedMember {
                    user: claims.user(),
                    row,
                    epoch,
                }),
            );
        }
        Ok(principal)
    }

    async fn load_device(
        &self,
        claims: &VerifiedClaims,
        fresh: Freshness,
    ) -> Result<DevicePrincipal, AuthError> {
        if claims.kind() != PrincipalKind::Device || claims.audience() != Audience::Device {
            return Err(AuthError::Unauthenticated(Rejection::KindMismatch));
        }
        let (Some(tenant), Some(owner), Some(cred)) =
            (claims.tenant(), claims.membership(), claims.credential())
        else {
            return Err(AuthError::Unauthenticated(Rejection::MissingClaim));
        };
        let now = self.clock.now();
        let key = (cred, owner, claims.authz_version());
        if fresh == Freshness::Cached
            && let Some(hit) = self.devices.get(&key)
            && self.epoch_valid(tenant, hit.epoch, now)
        {
            self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
            return build_device(&hit.row, claims);
        }
        let row = self.device_row(claims).await?;
        let principal = build_device(&row, claims)?;
        if let Some(epoch) = row.epoch {
            self.db.epochs().observe(tenant, epoch);
            self.devices
                .insert(key, Arc::new(CachedDevice { row, epoch }));
        }
        Ok(principal)
    }

    async fn load_staff(&self, claims: &VerifiedClaims) -> Result<StaffPrincipal, AuthError> {
        if claims.kind() != PrincipalKind::Staff || claims.audience() != Audience::Platform {
            return Err(AuthError::Unauthenticated(Rejection::KindMismatch));
        }
        let Some(session) = claims.session() else {
            return Err(AuthError::Unauthenticated(Rejection::MissingClaim));
        };
        let now = self.clock.now();
        let mut tx = self
            .db
            .identity_tx()
            .await
            .map_err(|e| AuthError::from_db(&e))?;
        let row = match auth_state::staff_live(&mut tx, session, claims.user()).await {
            Ok(Some(r)) => r,
            Ok(None) => {
                tx.rollback().await;
                return Err(AuthError::Unauthenticated(Rejection::SessionMissing));
            }
            Err(e) => {
                tx.rollback().await;
                return Err(AuthError::from_db(&e));
            }
        };
        self.stats.live_loads.fetch_add(1, Ordering::Relaxed);
        let principal = match build_staff(&row, claims, now, self.staff) {
            Ok(p) => p,
            Err(e) => {
                tx.rollback().await;
                return Err(e);
            }
        };
        // Idle tracking (throttled single-row write in the same short tx).
        auth_state::touch_session(&mut tx, session, now, self.touch_throttle)
            .await
            .map_err(|e| AuthError::from_db(&e))?;
        tx.commit().await.map_err(|e| AuthError::from_db(&e))?;
        Ok(principal)
    }
}

fn ts(secs: i64) -> Result<OffsetDateTime, AuthError> {
    OffsetDateTime::from_unix_timestamp(secs)
        .map_err(|_| AuthError::Unauthenticated(Rejection::Malformed))
}

const fn reject(r: Rejection) -> AuthError {
    AuthError::Unauthenticated(r)
}

const fn client_kind_for(aud: Audience) -> &'static str {
    match aud {
        Audience::Web => "web",
        Audience::App => "desktop_app",
        Audience::Platform => "platform_console",
        Audience::Device | Audience::Cleaner => "",
    }
}

/// Session + user checks shared by member and staff (RBAC.md §6.3 "har request").
/// `issued_at`: token / refresh-token issue time, compared with `tokens_valid_after`.
pub(crate) fn check_session_user(
    s: &SessionLive,
    u: &UserLive,
    kind: &str,
    aud: Audience,
    issued_at: Option<OffsetDateTime>,
    now: OffsetDateTime,
) -> Result<(), AuthError> {
    if s.revoked_at.is_some() {
        return Err(reject(Rejection::SessionRevoked));
    }
    if s.expires_at <= now {
        return Err(reject(Rejection::SessionExpired));
    }
    if s.principal_kind != kind || s.client_kind != client_kind_for(aud) {
        return Err(reject(Rejection::KindMismatch));
    }
    if u.status != UserStatus::Active {
        return Err(reject(Rejection::UserInactive));
    }
    if u.email_verified_at.is_none() {
        return Err(reject(Rejection::EmailUnverified));
    }
    if let (Some(valid_after), Some(at)) = (u.tokens_valid_after, issued_at)
        && at <= valid_after
    {
        return Err(reject(Rejection::TokensRevoked));
    }
    Ok(())
}

pub(crate) fn parse_features(names: &[String]) -> FeatureSet {
    let mut f = FeatureSet::none();
    for n in names {
        // Unknown names stay OFF (fail closed).
        if let Some(feat) = Feature::ALL.into_iter().find(|x| x.as_str() == n) {
            f = f.with(feat, true);
        }
    }
    f
}

fn caps_for(role: TenantRole, row: Option<CapabilityRow>) -> Capabilities {
    row.map_or_else(
        || Capabilities::default_for(role),
        |c| Capabilities {
            can_view_reports: c.can_view_reports,
            can_manage_machines: c.can_manage_machines,
            can_assign_licenses: c.can_assign_licenses,
            // Negative = corrupt: treat as 0 machines (most restrictive).
            max_machines: c.max_machines.map(|m| u32::try_from(m).unwrap_or(0)),
            credit_allocation: None,
        },
    )
}

fn actor(
    tenant: TenantId,
    membership: MembershipId,
    role: TenantRole,
    groups: &GroupIds,
    ga_groups: &GroupIds,
) -> AuthenticatedActor {
    // The ONLY call site in the workspace (see module docs).
    AuthenticatedActor::__from_authenticated(ActorState {
        tenant,
        membership,
        role,
        status: MemberStatus::Active,
        groups: groups.clone(),
        ga_groups: ga_groups.clone(),
    })
}

/// Live member checks + principal construction (runs on cache hits too).
pub(crate) fn build_member(
    row: &MemberLiveRow,
    claims: &VerifiedClaims,
    now: OffsetDateTime,
) -> Result<MemberPrincipal, AuthError> {
    check_member_row(row, claims.audience(), Some(ts(claims.iat())?), now)?;
    if Some(row.tenant) != claims.tenant()
        || Some(row.membership) != claims.membership()
        || Some(row.session.id) != claims.session()
    {
        return Err(reject(Rejection::StateMismatch));
    }
    Ok(MemberPrincipal {
        actor: actor(
            row.tenant,
            row.membership,
            row.role,
            &row.groups,
            &row.ga_groups,
        ),
        user: claims.user(),
        session: row.session.id,
        caps: caps_for(row.role, row.caps),
        features: parse_features(&row.features),
        authz_version: row.membership_authz_version,
        mfa_at: row.session.mfa_at,
        audience: claims.audience(),
    })
}

/// Checks on a member live row (login, refresh, request).
pub(crate) fn check_member_row(
    row: &MemberLiveRow,
    aud: Audience,
    issued_at: Option<OffsetDateTime>,
    now: OffsetDateTime,
) -> Result<(), AuthError> {
    check_session_user(&row.session, &row.user, "member", aud, issued_at, now)?;
    if row.membership_status != MembershipStatus::Active {
        return Err(reject(Rejection::MembershipInactive));
    }
    if row.tenant_status != "active" {
        return Err(reject(Rejection::TenantInactive));
    }
    Ok(())
}

/// Staff checks: session/user, staff row, MFA (fail closed), absolute and idle limits.
pub(crate) fn check_staff_row(
    row: &StaffLiveRow,
    issued_at: Option<OffsetDateTime>,
    now: OffsetDateTime,
    limits: StaffLimits,
) -> Result<StaffRole, AuthError> {
    check_session_user(
        &row.session,
        &row.user,
        "staff",
        Audience::Platform,
        issued_at,
        now,
    )?;
    if row.staff_revoked_at.is_some() {
        return Err(reject(Rejection::StaffRevoked));
    }
    if row.session.mfa_at.is_none() {
        return Err(reject(Rejection::MfaRequired));
    }
    if now - row.session.created_at > limits.max {
        return Err(reject(Rejection::SessionExpired));
    }
    if now - row.session.last_seen_at > limits.idle {
        return Err(reject(Rejection::SessionIdle));
    }
    StaffRole::parse(&row.staff_role).ok_or(reject(Rejection::StaffRevoked))
}

fn build_staff(
    row: &StaffLiveRow,
    claims: &VerifiedClaims,
    now: OffsetDateTime,
    limits: StaffLimits,
) -> Result<StaffPrincipal, AuthError> {
    let role = check_staff_row(row, Some(ts(claims.iat())?), now, limits)?;
    Ok(StaffPrincipal {
        user: claims.user(),
        role,
        session: row.session.id,
        mfa_at: row.session.mfa_at,
        grant: None,
    })
}

fn build_device(
    row: &DeviceLiveRow,
    claims: &VerifiedClaims,
) -> Result<DevicePrincipal, AuthError> {
    if row.credential_revoked_at.is_some() {
        return Err(reject(Rejection::CredentialRevoked));
    }
    if row.tenant_status != "active" {
        return Err(reject(Rejection::TenantInactive));
    }
    // Operator disabled / user inactive = device token invalid (RBAC.md §4.11).
    if row.operator_status != MembershipStatus::Active
        || row.operator_user_status != UserStatus::Active
        || row.operator_email_verified_at.is_none()
    {
        return Err(reject(Rejection::OperatorInactive));
    }
    if Some(row.tenant) != claims.tenant()
        || Some(row.operator) != claims.membership()
        || Some(row.credential_id) != claims.credential()
        || row.device != claims.device()
    {
        return Err(reject(Rejection::StateMismatch));
    }
    let scopes = row
        .scopes
        .split_ascii_whitespace()
        .filter_map(DeviceScope::parse)
        .collect();
    let operator = actor(
        row.tenant,
        row.operator,
        row.operator_role,
        &row.groups,
        &row.ga_groups,
    );
    let device_actor = DeviceActor {
        tenant: row.tenant,
        device: row.device,
        owner: Some(row.operator),
        scopes,
        operator: Some(operator.state().clone()),
    };
    Ok(DevicePrincipal {
        device: row.device,
        credential: row.credential_id,
        device_actor,
        operator,
        caps: caps_for(row.operator_role, row.caps),
        features: parse_features(&row.features),
        product_code: row.product_code.clone(),
    })
}

/// One poll round of the authz epochs (bounded batch, see `db::Db::poll_epochs`).
///
/// # Errors
/// `Unavailable` / `Internal` (the map keeps its old values and the cache goes stale -> bypass).
pub async fn poll_epochs_once(db: &Db, clock: &dyn Clock) -> Result<usize, AuthError> {
    db.poll_epochs(clock.now())
        .await
        .map_err(|e| AuthError::from_db(&e))
}

/// Epoch poller loop: every `every` until `shutdown` resolves. The caller runs it with its bounded
/// spawn helper (auth never spawns). Failures are logged and retried next tick; a poller that stays
/// down makes every cache lookup fall through to a live load (never a deny).
pub async fn run_epoch_poller<F>(
    db: Db,
    clock: Arc<dyn Clock>,
    every: std::time::Duration,
    shutdown: F,
) where
    F: Future<Output = ()> + Send,
{
    let mut tick = tokio::time::interval(every);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => break,
            _ = tick.tick() => {
                if let Err(e) = poll_epochs_once(&db, clock.as_ref()).await {
                    tracing::warn!(alert = "auth.epoch_poll_failed", code = e.code(), "authz epoch poll failed");
                }
            }
        }
    }
}

/// Crate-internal fixtures for unit tests (go through the same `actor()` helper).
#[cfg(test)]
pub(crate) mod test_support {
    use super::{AuthenticatedActor, actor};
    use crate::claims::Audience;
    use crate::principal::{DevicePrincipal, MemberPrincipal, StaffPrincipal};
    use common::{DeviceId, MembershipId, SessionId, TenantId, UserId};
    use domain::rbac::{
        Capabilities, DeviceActor, DeviceScope, FeatureSet, GroupIds, StaffRole, TenantRole,
    };

    pub(crate) fn member(
        tenant: TenantId,
        role: TenantRole,
        features: FeatureSet,
    ) -> MemberPrincipal {
        let a: AuthenticatedActor = actor(
            tenant,
            MembershipId::new(),
            role,
            &GroupIds::new(),
            &GroupIds::new(),
        );
        MemberPrincipal {
            actor: a,
            user: UserId::new(),
            session: SessionId::new(),
            caps: Capabilities::default_for(role),
            features,
            authz_version: 1,
            mfa_at: None,
            audience: Audience::Web,
        }
    }

    pub(crate) fn device(tenant: TenantId, scopes: &[DeviceScope]) -> DevicePrincipal {
        let op = actor(
            tenant,
            MembershipId::new(),
            TenantRole::Member,
            &GroupIds::new(),
            &GroupIds::new(),
        );
        let device = DeviceId::new();
        DevicePrincipal {
            device,
            credential: uuid::Uuid::now_v7(),
            device_actor: DeviceActor {
                tenant,
                device,
                owner: Some(op.state().membership),
                scopes: scopes.iter().copied().collect(),
                operator: Some(op.state().clone()),
            },
            operator: op,
            caps: Capabilities::default_for(TenantRole::Member),
            features: FeatureSet::none(),
            product_code: "drive".to_owned(),
        }
    }

    pub(crate) fn staff(role: StaffRole) -> StaffPrincipal {
        StaffPrincipal {
            user: UserId::new(),
            role,
            session: SessionId::new(),
            mfa_at: None,
            grant: None,
        }
    }
}
