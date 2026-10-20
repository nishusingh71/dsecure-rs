//! Time source abstraction so time-dependent logic is testable.

use std::sync::{Mutex, PoisonError};
use time::{Duration, OffsetDateTime};

pub trait Clock: Send + Sync {
    fn now(&self) -> OffsetDateTime;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// Test clock: time sirf tab badalta hai jab test `set` / `advance` kare.
#[derive(Debug)]
pub struct FixedClock(Mutex<OffsetDateTime>);

impl FixedClock {
    #[must_use]
    pub const fn new(at: OffsetDateTime) -> Self {
        Self(Mutex::new(at))
    }

    pub fn set(&self, at: OffsetDateTime) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = at;
    }

    pub fn advance(&self, by: Duration) {
        let mut g = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        *g += by;
    }
}

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(secs).expect("valid ts")
    }

    #[test]
    fn fixed_clock_is_stable_and_advances() {
        let c = FixedClock::new(at(1_800_000_000));
        assert_eq!(c.now(), c.now());
        c.advance(Duration::minutes(5));
        assert_eq!(c.now(), at(1_800_000_300));
        c.set(at(1_900_000_000));
        assert_eq!(c.now(), at(1_900_000_000));
    }

    #[test]
    fn system_clock_is_recent() {
        assert!(SystemClock.now().year() >= 2026);
    }

    #[test]
    fn usable_as_trait_object() {
        let c: Box<dyn Clock> = Box::new(SystemClock);
        let _ = c.now();
    }
}
