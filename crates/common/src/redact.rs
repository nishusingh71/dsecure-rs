//! `Redacted<T>`: wrapper so secrets/PII never leak through `Debug`, `Display` or serialisation.
//!
//! Design decision: `Serialize` is implemented and always writes the literal string
//! `"[redacted]"` (never the inner value). Reason: a struct holding a `Redacted<T>` field can
//! still derive `Serialize` (for logs / error payloads) with no risk of leaking. The price is
//! that serialisation is lossy, so `Redacted<T>` must not be used for data that has to be
//! persisted via serde. `Deserialize` is transparent (reads the real value, e.g. from config).
//! The inner value is reachable only via the explicit [`Redacted::expose`] / [`Redacted::into_inner`].

use std::fmt;

pub const REDACTED: &str = "[redacted]";

#[derive(Clone, Default)]
pub struct Redacted<T>(T);

impl<T> Redacted<T> {
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Explicit access to the inner value; call sites are easy to grep and review.
    #[must_use]
    pub const fn expose(&self) -> &T {
        &self.0
    }

    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl<T> serde::Serialize for Redacted<T> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(REDACTED)
    }
}

impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for Redacted<T> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        T::deserialize(d).map(Self)
    }
}

impl<T> From<T> for Redacted<T> {
    fn from(v: T) -> Self {
        Self(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_display_hide_value() {
        let r = Redacted::new("hunter2".to_string());
        assert_eq!(format!("{r:?}"), "[redacted]");
        assert_eq!(format!("{r}"), "[redacted]");
        assert!(!format!("{:#?}", Some(&r)).contains("hunter2"));
    }

    #[test]
    fn serialize_never_leaks() {
        let r = Redacted::new("hunter2".to_string());
        let json = serde_json::to_string(&r).expect("ser");
        assert_eq!(json, "\"[redacted]\"");
    }

    #[test]
    fn nested_in_derived_struct_does_not_leak() {
        #[derive(serde::Serialize, Debug)]
        struct Login {
            user: &'static str,
            password: Redacted<String>,
        }
        let l = Login {
            user: "u",
            password: Redacted::new("hunter2".into()),
        };
        assert!(!serde_json::to_string(&l).expect("ser").contains("hunter2"));
        assert!(!format!("{l:?}").contains("hunter2"));
        assert_eq!(l.user, "u");
    }

    #[test]
    fn deserialize_reads_value_and_expose_returns_it() {
        let r: Redacted<String> = serde_json::from_str("\"secret\"").expect("de");
        assert_eq!(r.expose(), "secret");
        assert_eq!(r.into_inner(), "secret");
    }
}
