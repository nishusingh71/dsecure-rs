//! Route handlers. Registration (with policies) happens only in `app::build_routes`.

pub mod auth;
#[cfg(all(feature = "dev-fixtures", debug_assertions))]
pub mod dev_fixtures;
pub mod health;
pub mod jwks;
pub mod me;
pub mod openapi;
