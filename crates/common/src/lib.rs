//! common: IO-free primitives shared by every crate (ids, redaction, errors, cursor, clock, env helpers).

pub mod clock;
pub mod config_util;
pub mod cursor;
pub mod email;
pub mod error;
pub mod ids;
pub mod limits;
pub mod redact;

pub use clock::{Clock, FixedClock, SystemClock};
pub use cursor::{Cursor, Page, PageOut};
pub use email::Email;
pub use error::{AppError, AppErrorKind, FieldError};
pub use ids::{DeviceId, GrantId, GroupId, MembershipId, RequestId, SessionId, TenantId, UserId};
pub use redact::Redacted;
