//! Typed repositories. Rule (PHASE0_SPEC §3.5): every public fn takes `&mut TenantTx` /
//! `&mut IdentityTx` / `&mut PlatformTx` / `&mut SystemTx` first; tenant-class SQL binds the tenant
//! only from `TenantTx` (never a caller argument); every tenant row goes through the L6 assert.

pub mod audit;
pub mod auth_account;
pub mod auth_credentials;
pub mod auth_devices;
pub mod auth_mfa;
pub mod auth_state;
pub mod auth_step_up;
pub mod counters;
pub mod groups;
pub mod keys;
pub mod memberships;
pub mod sessions;
pub mod signing_keys;
pub mod tenants;
pub mod users;
