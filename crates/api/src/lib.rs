//! api (P0-10): HTTP surface skeleton. Deny-by-default routing (`router::PolicyRouter`), the
//! ARCHITECTURE.md §5 middleware stack, RFC 9457 errors, limits/load shed, health.
//!
//! Auth integration lives only in [`authn`] + [`authz`] (the `auth` crate is still moving).

pub mod app;
pub mod authn;
pub mod authz;
pub mod errors;
pub mod json;
pub mod keys;
pub mod middleware;
pub mod ops;
pub mod ratelimit;
pub mod router;
pub mod routes;
pub mod server;
pub mod startup;
pub mod state;

pub use app::{HttpSettings, RouteOptions, assemble, build_routes, route_policies};
pub use authz::{Authz, Caller, GateDeps};
pub use errors::ApiError;
pub use router::{PolicyRouter, RouteEntry, RoutePolicyReport, RouterError};
pub use state::{AppState, AuthHttp};
