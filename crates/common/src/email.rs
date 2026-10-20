//! `Email`: normalised, validated, never printed by `Debug`.
//!
//! Normalisation: trim -> Unicode NFKC -> lowercase -> NFKC again (idempotent).
//! Validation (deliberately simple, not full RFC 5322):
//! - total length <= 254, exactly one `@`, local part 1..=64 bytes;
//! - local part: ASCII letters/digits and ``!#$%&'*+/=?^_`{|}~.-``; no leading/trailing/double `.`;
//! - domain: at least two dot-separated labels, each 1..=63 chars of `a-z0-9-`, not starting or
//!   ending with `-`; internationalised (non-ASCII) domains must be given as punycode.
//!
//! Errors never echo the input (it is PII).

use crate::error::{AppError, FieldError};
use std::fmt;
use unicode_normalization::UnicodeNormalization;

#[derive(Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String")]
pub struct Email(String);

impl Email {
    /// Normalise and validate.
    ///
    /// # Errors
    /// `AppError::BadRequest` with code `invalid_email` if the rule above fails.
    pub fn parse(raw: &str) -> Result<Self, AppError> {
        let norm: String = raw
            .trim()
            .nfkc()
            .collect::<String>()
            .to_lowercase()
            .nfkc()
            .collect();
        if is_valid(&norm) {
            Ok(Self(norm))
        } else {
            Err(
                AppError::bad_request("invalid_email", "email address is invalid").with_field(
                    FieldError::new("email", "invalid", "must be a valid email address"),
                ),
            )
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn domain(&self) -> &str {
        self.0.rsplit_once('@').map_or("", |(_, d)| d)
    }
}

impl TryFrom<String> for Email {
    type Error = AppError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl fmt::Debug for Email {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Email([redacted])")
    }
}

fn is_valid(s: &str) -> bool {
    if s.len() > 254 || !s.is_ascii() {
        return false;
    }
    let mut parts = s.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    valid_local(local) && valid_domain(domain)
}

fn valid_local(l: &str) -> bool {
    if l.is_empty() || l.len() > 64 || l.starts_with('.') || l.ends_with('.') || l.contains("..") {
        return false;
    }
    l.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b".!#$%&'*+/=?^_`{|}~-".contains(&b))
}

fn valid_domain(d: &str) -> bool {
    let labels: Vec<&str> = d.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises_trim_case_and_nfkc() {
        let e = Email::parse("  Alice.Smith@Example.COM \n").expect("ok");
        assert_eq!(e.as_str(), "alice.smith@example.com");
        // fullwidth characters fold to ASCII under NFKC
        let w = Email::parse("\u{FF21}\u{FF22}@example.com").expect("ok");
        assert_eq!(w.as_str(), "ab@example.com");
        assert_eq!(e.domain(), "example.com");
    }

    #[test]
    fn equal_after_normalisation() {
        assert_eq!(
            Email::parse("A@B.io").expect("ok"),
            Email::parse(" a@b.IO").expect("ok")
        );
    }

    #[test]
    fn rejects_invalid() {
        for bad in [
            "",
            "plain",
            "a@",
            "@b.com",
            "a@b",
            "a@@b.com",
            "a b@c.com",
            "a..b@c.com",
            ".a@c.com",
            "a.@c.com",
            "a@-b.com",
            "a@b-.com",
            "a@b..com",
            "a@b.c_m",
            "ünï@example.com",
            "a@exämple.com",
        ] {
            assert!(Email::parse(bad).is_err(), "should reject {bad:?}");
        }
        let long_local = format!("{}@example.com", "a".repeat(65));
        assert!(Email::parse(&long_local).is_err());
        let long_total = format!("a@{}.com", "b".repeat(250));
        assert!(Email::parse(&long_total).is_err());
    }

    #[test]
    fn error_does_not_echo_input() {
        let err = Email::parse("secret-user-input").expect_err("invalid");
        assert!(!err.to_string().contains("secret-user-input"));
        assert!(!format!("{err:?}").contains("secret-user-input"));
    }

    #[test]
    fn debug_is_redacted() {
        let e = Email::parse("alice@example.com").expect("ok");
        assert!(!format!("{e:?}").contains("alice"));
        assert!(!format!("{:?}", Some(&e)).contains("example"));
    }

    #[test]
    fn serde_validates_on_deserialize() {
        let e: Email = serde_json::from_str("\"Bob@Example.com\"").expect("de");
        assert_eq!(
            serde_json::to_string(&e).expect("ser"),
            "\"bob@example.com\""
        );
        assert!(serde_json::from_str::<Email>("\"nope\"").is_err());
    }

    #[test]
    fn normalisation_is_idempotent() {
        let once = Email::parse("  X@Y.Org ").expect("ok");
        let twice = Email::parse(once.as_str()).expect("ok");
        assert_eq!(once, twice);
    }
}
