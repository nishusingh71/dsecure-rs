//! testkit (P0-16): shared fixtures for integration tests.
//!
//! - [`engines`]: LOCAL MySQL scratch DB only (`db::testing::ScratchDb`). TiDB / containers are not
//!   wired here (owner rule: no TiDB from agents); `with_scratch` refuses the TiDB engine mode.
//! - [`world`]: `World` builder = real auth stack + two tenants + every role + device + staff, with
//!   a token per principal minted by the real issuer.
//! - [`principals`]: the fixture principal list (`Persona`).
//! - [`matrix`]: T-R2 authz matrix harness, table driven over `api::route_policies`.
//! - [`cross_tenant`]: tenant B against tenant A checks (HTTP + `domain::decide`).
//!
//! Test-only crate: `expect`/`unwrap`/`panic` are allowed (a failed fixture must stop the test).
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

pub mod cross_tenant;
pub mod engines;
pub mod matrix;
pub mod principals;
pub mod world;

pub use engines::{ScratchHandle, with_scratch};
pub use matrix::{MatrixReport, Probe, ProbeTable, run_matrix};
pub use principals::{Persona, PersonaKind};
pub use world::{ISS, PW, World};
