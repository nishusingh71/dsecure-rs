//! auth: tokens, principal live state, `Policy` and the authz decision (PHASE0_SPEC §3.4, P0-09).
//!
//! Security shape (SECURITY.md §5, RBAC.md §6):
//! - Access tokens: compact JWS, **ES256 only** (own minimal JWS on `crypto::Signer`, see [`jws`]),
//!   `kid` lookup in a [`KeySet`] where every key is bound to ONE realm (member/device, staff,
//!   cleaner), so a staff token can never verify on a member audience and vice versa.
//! - Refresh tokens: opaque 256-bit random, only an HMAC is stored, rotation on every use, reuse of a
//!   used token revokes the whole family + the session.
//! - Every request re-reads live state (session, user, membership, tenant) through
//!   [`DbPrincipalLoader`] (ONE indexed query, bounded moka cache, authz-epoch invalidation);
//!   high-risk policies always read live.
//! - [`Policy::evaluate`] delegates to `domain::decide*` and returns a sealed `TenantScope`; any
//!   error is `Denied` (fail closed).
//! - Step-up: separate single-use token bound to session + action + target, consumed atomically
//!   in the DB ([`stepup`]); staff realm refused until MFA (P0-11).
//! - Callers only ever see generic errors; detailed reasons go to an [`AuthEventSink`].

pub mod authorize;
pub mod claims;
pub mod error;
pub mod jws;
pub mod loader;
pub mod lockout;
pub mod login;
pub mod mfa;
pub mod policy;
pub mod principal;
pub mod refresh;
pub mod settings;
pub mod sink;
pub mod staff;
pub mod stepup;
pub mod tokens;
pub mod totp;

pub use authorize::{Authorization, authorize};
pub use claims::{AccessClaims, Amr, Audience, PrincipalKind, Realm, VerifiedClaims};
pub use error::{AuthError, LoginError, Rejection};
pub use loader::{
    DbPrincipalLoader, Freshness, PrincipalStateLoader, poll_epochs_once, run_epoch_poller,
};
pub use login::{AuthDeps, AuthService, LoginRequest, TokenPair};
pub use mfa::{MfaInput, RecoveryCodes, TotpEnrolment};
pub use policy::{Authorized, Authz, Denied, DenyCode, EvalContext, Policy, PolicyError};
pub use principal::{
    CleanerPrincipal, DevicePrincipal, MemberPrincipal, Principal, StaffPrincipal,
};
pub use refresh::{RefreshHasher, RefreshSecret};
pub use settings::AuthSettings;
pub use sink::{AuthEvent, AuthEventKind, AuthEventSink, NoopSink, TracingSink};
pub use staff::{DbStaffGrantVerifier, StaffGrantVerifier, staff_db_error};
pub use stepup::{StepUpProof, StepUpSecret};
pub use tokens::{Es256Issuer, Es256Verifier, KeySet, TokenIssuer, TokenVerifier};

#[cfg(test)]
mod authorize_tests;
#[cfg(test)]
mod policy_tests;
#[cfg(test)]
mod tokens_tests;
