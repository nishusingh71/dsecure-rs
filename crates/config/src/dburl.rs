//! Strict inspection of `DATABASE_URL` (shared with the db crate, which should re-check the
//! parsed `MySqlConnectOptions` at connect time as a second line of defence).
//!
//! sqlx-mysql matches query keys case-sensitively (`sslmode` | `ssl-mode`), percent-decodes keys,
//! drops the `#fragment`, ignores unknown keys and defaults to PREFERRED. So we parse the same way
//! and refuse anything ambiguous instead of guessing.

use percent_encoding::percent_decode_str;
use url::Url;

/// Database name that must never be used by the new system (legacy .NET database).
pub const LEGACY_DB_NAME: &str = "Cloud_Erase__App";

/// Result of inspecting a URL; no value is ever copied into a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsCheck {
    /// Exactly one `ssl-mode`/`sslmode` key (exact case) with value `VERIFY_IDENTITY`, no fragment.
    Verified,
    NotVerified,
    /// Duplicate ssl keys, a mis-cased/encoded ssl key, or a fragment: ambiguous, always rejected.
    Ambiguous,
}

fn is_ssl_key_lenient(k: &str) -> bool {
    let l = k.to_ascii_lowercase();
    l == "sslmode" || l == "ssl-mode"
}

/// Parse and classify the TLS settings of a MySQL URL (`query_pairs` decodes keys, like sqlx).
#[must_use]
pub fn tls_check(raw: &str) -> TlsCheck {
    let Ok(u) = Url::parse(raw) else {
        return TlsCheck::NotVerified;
    };
    if u.fragment().is_some() {
        return TlsCheck::Ambiguous;
    }
    let mut seen = 0_u32;
    let mut verified = false;
    for (k, v) in u.query_pairs() {
        if is_ssl_key_lenient(&k) {
            seen += 1;
            if k != "ssl-mode" && k != "sslmode" {
                return TlsCheck::Ambiguous;
            }
            verified = v == "VERIFY_IDENTITY";
        }
    }
    match (seen, verified) {
        (1, true) => TlsCheck::Verified,
        (0 | 1, _) => TlsCheck::NotVerified,
        _ => TlsCheck::Ambiguous,
    }
}

/// True only for [`TlsCheck::Verified`].
#[must_use]
pub fn has_verified_tls(raw: &str) -> bool {
    tls_check(raw) == TlsCheck::Verified
}

/// Database name from the URL path, percent-decoded once and twice (catches double encoding).
#[must_use]
pub fn database_names(raw: &str) -> Vec<String> {
    let Ok(u) = Url::parse(raw) else {
        return Vec::new();
    };
    let path = u.path().trim_start_matches('/');
    let once = percent_decode_str(path).decode_utf8_lossy().into_owned();
    let twice = percent_decode_str(&once).decode_utf8_lossy().into_owned();
    vec![once, twice]
}

/// Cut at the first NUL/control character (the server sees the NUL-terminated prefix).
fn before_control(n: &str) -> &str {
    n.split(|c: char| c.is_control()).next().unwrap_or_default()
}

/// Does the URL point at the legacy database (case-insensitive, after percent-decoding, and
/// also when junk follows a NUL/control character)?
#[must_use]
pub fn targets_legacy_db(raw: &str) -> bool {
    database_names(raw).iter().any(|n| {
        before_control(n)
            .trim_matches('/')
            .eq_ignore_ascii_case(LEGACY_DB_NAME)
    })
}

/// Allowed database names: `^[A-Za-z0-9_$]{1,64}$` (after one percent-decode).
#[must_use]
pub fn is_valid_db_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

/// URL keys that must not be set in `DATABASE_URL` (`DB_TLS_CA` is the only CA source).
fn is_forbidden_key(k: &str) -> bool {
    matches!(
        k.to_ascii_lowercase().as_str(),
        "ssl-ca" | "sslca" | "ssl-cert" | "sslcert" | "ssl-key" | "sslkey" | "socket"
    )
}

/// True if the URL carries a forbidden cert/socket key (case-insensitive, after decoding).
#[must_use]
pub fn has_forbidden_keys(raw: &str) -> bool {
    Url::parse(raw).is_ok_and(|u| u.query_pairs().any(|(k, _)| is_forbidden_key(&k)))
}

/// URL parses, scheme is mysql/mariadb, the database name is a strict identifier
/// (so NUL/control/encoded junk is refused) and no cert/socket keys are present.
#[must_use]
pub fn is_mysql_url(raw: &str) -> bool {
    let Ok(u) = Url::parse(raw) else {
        return false;
    };
    if !matches!(u.scheme(), "mysql" | "mariadb") || has_forbidden_keys(raw) {
        return false;
    }
    let path = u.path().trim_start_matches('/');
    let name = percent_decode_str(path).decode_utf8_lossy();
    is_valid_db_name(&name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(db: &str) -> String {
        format!("mysql://u:p@h:4000/{db}?ssl-mode=VERIFY_IDENTITY")
    }

    #[test]
    fn nul_and_control_names_refused_and_flagged_legacy() {
        for db in [
            "Cloud_Erase__App%00",
            "Cloud_Erase__App%00x",
            "Cloud_Erase__App%00junk",
            "Cloud_Erase__App%2500",
            "Cloud_Erase__App%0A",
            "Cloud_Erase__App%09",
            "db%00",
            "",
            &"a".repeat(65),
            "db-name",
            "db%20x",
        ] {
            assert!(!is_mysql_url(&url(db)), "should be refused: {db:?}");
        }
        assert!(targets_legacy_db(&url("Cloud_Erase__App%00")));
        assert!(targets_legacy_db(&url("cloud_erase__app%00junk")));
        assert!(targets_legacy_db(&url("CLOUD_ERASE__APP%0A")));
        assert!(targets_legacy_db(&url("Cloud_Erase__App%09x")));
    }

    #[test]
    fn valid_names_accepted() {
        for db in ["db", "dsecure_new", "a$b_9", &"a".repeat(64), "Cloud%5FNew"] {
            assert!(is_mysql_url(&url(db)), "should be accepted: {db}");
        }
        assert!(!targets_legacy_db(&url("dsecure_new")));
    }

    #[test]
    fn cert_and_socket_keys_refused() {
        for k in [
            "ssl-ca", "sslca", "ssl-cert", "sslcert", "ssl-key", "sslkey", "socket", "SSL-CA",
            "Socket", "ssl%2Dca", "SSLKEY",
        ] {
            let u = format!("mysql://u:p@h:4000/db?ssl-mode=VERIFY_IDENTITY&{k}=/x");
            assert!(has_forbidden_keys(&u), "{k}");
            assert!(!is_mysql_url(&u), "{k}");
        }
        assert!(!has_forbidden_keys(&url("db")));
    }
}
