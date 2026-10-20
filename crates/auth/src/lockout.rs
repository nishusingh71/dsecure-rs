//! Lockout policy (RBAC.md §6.3), pure functions.
//!
//! - 10 counted failures lock the account for 15 min; each further failure that comes while the
//!   counter is "hot" doubles the lock (15m, 30m, 1h ... capped at 24h).
//! - Decay: the counter is hot only while the latest of (last failure, lock end) is within
//!   [`WINDOW`]. Older failures do not count: the next failure starts again at 1 and an expired lock
//!   is cleared. So a victim is never locked permanently by slow guessing; a locked account always
//!   unlocks after its period (attempts during a lock are refused before they are counted).
//! - Success resets everything.
//!
//! Attempts are reserved under `SELECT ... FOR UPDATE` BEFORE the real password verify
//! (`AuthService`), so N parallel guesses can never get more than [`THRESHOLD`] real verifies.

use time::{Duration, OffsetDateTime};

pub const THRESHOLD: i32 = 10;
pub const WINDOW: Duration = Duration::minutes(15);
pub const BASE_LOCK: Duration = Duration::minutes(15);
pub const MAX_LOCK: Duration = Duration::hours(24);

/// Is the account locked at `now`?
#[must_use]
pub fn is_locked(locked_until: Option<OffsetDateTime>, now: OffsetDateTime) -> bool {
    locked_until.is_some_and(|t| t > now)
}

/// New `(failed_attempts, locked_until)` after one more counted failure (caller already refused the
/// attempt if the account is locked).
#[must_use]
pub fn after_failure(
    prev_attempts: i32,
    last_failed_at: Option<OffsetDateTime>,
    prev_locked_until: Option<OffsetDateTime>,
    now: OffsetDateTime,
) -> (i32, Option<OffsetDateTime>) {
    let latest = match (last_failed_at, prev_locked_until) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    };
    let decayed = !is_locked(prev_locked_until, now) && latest.is_none_or(|t| now - t > WINDOW);
    let attempts = if decayed {
        1
    } else {
        prev_attempts.saturating_add(1)
    };
    let locked = if attempts >= THRESHOLD {
        let exp = u32::try_from(attempts - THRESHOLD).unwrap_or(0).min(16);
        let factor = i32::try_from(1u32 << exp).unwrap_or(i32::MAX);
        let lock = BASE_LOCK
            .checked_mul(factor)
            .map_or(MAX_LOCK, |d| d.min(MAX_LOCK));
        let until = now + lock;
        Some(prev_locked_until.map_or(until, |p| p.max(until)))
    } else if decayed {
        None
    } else {
        prev_locked_until
    };
    (attempts, locked)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("ts")
    }

    #[test]
    fn progression_then_cap() {
        let now = t0();
        let mut attempts = 0;
        let mut last = None;
        let mut locked = None;
        for i in 1..=9 {
            (attempts, locked) = after_failure(attempts, last, locked, now);
            last = Some(now);
            assert_eq!(attempts, i);
            assert!(!is_locked(locked, now));
        }
        (attempts, locked) = after_failure(attempts, last, locked, now);
        assert_eq!(attempts, 10);
        assert_eq!(locked, Some(now + Duration::minutes(15)));
        // right after the lock ends the counter is still hot: next failure doubles
        let later = now + Duration::minutes(16);
        let (a, l) = after_failure(attempts, last, locked, later);
        assert_eq!(a, 11);
        assert_eq!(l, Some(later + Duration::minutes(30)));
        let (_, capped) = after_failure(40, Some(now), None, now);
        assert_eq!(capped, Some(now + MAX_LOCK));
    }

    #[test]
    fn old_failures_decay_and_locks_end() {
        let now = t0();
        let old = Some(now - Duration::minutes(16));
        assert_eq!(after_failure(5, old, None, now), (1, None));
        // lock long over and quiet for more than the window: back to 1, lock cleared
        let lock_end = Some(now - Duration::minutes(20));
        assert_eq!(
            after_failure(30, Some(now - Duration::hours(3)), lock_end, now),
            (1, None)
        );
        // slow guessing (1 per 20 min) never accumulates to a lock
        let mut a = 0;
        let mut last = None;
        let mut l = None;
        let mut t = now;
        for _ in 0..50 {
            (a, l) = after_failure(a, last, l, t);
            last = Some(t);
            t += Duration::minutes(20);
        }
        assert_eq!((a, l), (1, None));
    }
}
