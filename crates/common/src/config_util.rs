//! Typed env readers. This module is the ONLY place allowed to touch `std::env::var`
//! (clippy `disallowed_methods` forbids it elsewhere). Errors name the key, never the value.

use std::collections::HashMap;
use std::str::FromStr;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("missing required env var `{key}`")]
    Missing { key: String },
    #[error("env var `{key}` is not valid unicode")]
    NotUnicode { key: String },
    #[error("env var `{key}` is invalid: expected {expected}")]
    Invalid { key: String, expected: &'static str },
}

enum Source {
    Process,
    Map(HashMap<String, String>),
}

/// Reads config from the process environment, or from a fixed map (tests).
pub struct Env(Source);

impl Env {
    #[must_use]
    pub const fn process() -> Self {
        Self(Source::Process)
    }

    /// In-memory source for tests (no global env mutation needed).
    #[must_use]
    pub fn from_pairs<I, K, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        Self(Source::Map(
            pairs
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        ))
    }

    // Single allowed use of std::env::var in the whole workspace.
    #[allow(clippy::disallowed_methods)]
    fn raw(&self, key: &str) -> Result<Option<String>, ConfigError> {
        match &self.0 {
            Source::Process => match std::env::var(key) {
                Ok(v) => Ok(Some(v)),
                Err(std::env::VarError::NotPresent) => Ok(None),
                Err(std::env::VarError::NotUnicode(_)) => Err(ConfigError::NotUnicode {
                    key: key.to_owned(),
                }),
            },
            Source::Map(m) => Ok(m.get(key).cloned()),
        }
    }

    /// Optional string; empty string counts as unset.
    ///
    /// # Errors
    /// `NotUnicode` if the value is not valid unicode.
    pub fn optional(&self, key: &str) -> Result<Option<String>, ConfigError> {
        Ok(self.raw(key)?.filter(|v| !v.is_empty()))
    }

    /// Required string.
    ///
    /// # Errors
    /// `Missing` if unset or empty, `NotUnicode` if unreadable.
    pub fn required(&self, key: &str) -> Result<String, ConfigError> {
        self.optional(key)?.ok_or_else(|| ConfigError::Missing {
            key: key.to_owned(),
        })
    }

    /// Required value parsed via `FromStr`.
    ///
    /// # Errors
    /// `Missing`, `NotUnicode`, or `Invalid` (the value itself is not included in the error).
    pub fn parse_required<T: FromStr>(
        &self,
        key: &str,
        expected: &'static str,
    ) -> Result<T, ConfigError> {
        parse(key, &self.required(key)?, expected)
    }

    /// Parsed value or `default` when unset.
    ///
    /// # Errors
    /// `Invalid` if set but unparsable (no silent fallback to default).
    pub fn parse_or<T: FromStr>(
        &self,
        key: &str,
        default: T,
        expected: &'static str,
    ) -> Result<T, ConfigError> {
        match self.optional(key)? {
            Some(v) => parse(key, &v, expected),
            None => Ok(default),
        }
    }

    /// Boolean: only exact `true` / `false` accepted; unset -> `default`.
    ///
    /// # Errors
    /// `Invalid` for anything else (e.g. `1`, `yes`, `TRUE`): fail closed, no guessing.
    pub fn bool_or(&self, key: &str, default: bool) -> Result<bool, ConfigError> {
        self.parse_or(key, default, "`true` or `false`")
    }
}

fn parse<T: FromStr>(key: &str, v: &str, expected: &'static str) -> Result<T, ConfigError> {
    v.trim().parse().map_err(|_| ConfigError::Invalid {
        key: key.to_owned(),
        expected,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> Env {
        Env::from_pairs([
            ("A_STR", "hello"),
            ("A_NUM", "42"),
            ("A_BAD_NUM", "super-secret-value"),
            ("A_EMPTY", ""),
            ("A_BOOL", "true"),
            ("A_BAD_BOOL", "yes"),
        ])
    }

    #[test]
    fn required_and_optional() {
        let e = env();
        assert_eq!(e.required("A_STR").expect("ok"), "hello");
        assert_eq!(e.optional("NOPE").expect("ok"), None);
        assert_eq!(e.optional("A_EMPTY").expect("ok"), None);
        assert_eq!(
            e.required("NOPE"),
            Err(ConfigError::Missing { key: "NOPE".into() })
        );
        assert!(matches!(
            e.required("A_EMPTY"),
            Err(ConfigError::Missing { .. })
        ));
    }

    #[test]
    fn typed_parse() {
        let e = env();
        assert_eq!(e.parse_required::<u16>("A_NUM", "a u16").expect("ok"), 42);
        assert_eq!(e.parse_or::<u32>("NOPE", 7, "a u32").expect("ok"), 7);
        assert!(e.bool_or("A_BOOL", false).expect("ok"));
        assert!(!e.bool_or("NOPE", false).expect("ok"));
    }

    #[test]
    fn invalid_values_are_rejected_without_leaking_value() {
        let e = env();
        let err = e
            .parse_required::<u16>("A_BAD_NUM", "a u16")
            .expect_err("bad");
        let msg = err.to_string();
        assert!(msg.contains("A_BAD_NUM"));
        assert!(!msg.contains("super-secret-value"));
        assert!(!format!("{err:?}").contains("super-secret-value"));
        assert!(e.bool_or("A_BAD_BOOL", false).is_err());
        assert!(e.parse_or::<u16>("A_BAD_NUM", 1, "a u16").is_err());
    }

    #[test]
    fn process_source_reads_missing_as_none() {
        let e = Env::process();
        assert_eq!(
            e.optional("DSECURE_TEST_KEY_THAT_DOES_NOT_EXIST")
                .expect("ok"),
            None
        );
    }
}
