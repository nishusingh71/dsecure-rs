//! Shared resource caps (512 MB box). Config validation aur `crypto` constructor dono yahi constants use karte hain.

/// Argon2id memory cap per hash (KiB).
pub const ARGON2_MAX_M_KIB: u32 = 262_144;
pub const ARGON2_MAX_T: u32 = 10;
pub const ARGON2_MAX_P: u32 = 4;
/// Sab concurrent login hashes ka total memory budget: `m_kib * LOGIN_HASH_CONCURRENCY` (128 MiB).
pub const ARGON2_BUDGET_KIB: u64 = 131_072;
/// Sanity cap on `LOGIN_HASH_CONCURRENCY` (budget usually isko pehle rok deta hai).
pub const LOGIN_HASH_CONCURRENCY_MAX: u32 = 16;
/// Stored PHC hash ke m ki hard upper limit se pehle ka "2x configured" cap (KiB).
pub const ARGON2_VERIFY_DOUBLE_CAP_KIB: u32 = 65_536;

/// True agar `m_kib * concurrency` budget ke andar hai.
#[must_use]
pub fn argon2_budget_ok(m_kib: u32, concurrency: u32) -> bool {
    u64::from(m_kib) * u64::from(concurrency) <= ARGON2_BUDGET_KIB
}

/// Verify ke waqt stored hash ka maximum allowed `m`:
/// `max(configured, min(2 * configured, 65536))`. Isse purane (kam) aur thode zyada params verify hote hain,
/// par DB-write attacker 512 MB box ko giant `m` wale hash se OOM nahi kar sakta.
#[must_use]
pub fn argon2_verify_max_m_kib(configured_m_kib: u32) -> u32 {
    configured_m_kib.max(
        configured_m_kib
            .saturating_mul(2)
            .min(ARGON2_VERIFY_DOUBLE_CAP_KIB),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget() {
        assert!(argon2_budget_ok(19_456, 3));
        assert!(argon2_budget_ok(19_456, 6));
        assert!(!argon2_budget_ok(19_456, 7));
        assert!(argon2_budget_ok(131_072, 1));
        assert!(!argon2_budget_ok(262_144, 1));
        assert!(!argon2_budget_ok(u32::MAX, u32::MAX));
    }

    #[test]
    fn verify_cap() {
        assert_eq!(argon2_verify_max_m_kib(19_456), 38_912);
        assert_eq!(argon2_verify_max_m_kib(64), 128);
        assert_eq!(argon2_verify_max_m_kib(40_000), 65_536);
        assert_eq!(argon2_verify_max_m_kib(100_000), 100_000);
        assert_eq!(argon2_verify_max_m_kib(u32::MAX), u32::MAX);
    }
}
