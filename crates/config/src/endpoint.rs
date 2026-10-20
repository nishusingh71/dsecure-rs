//! `Endpoint`: a URL-ish string whose `Debug` never shows userinfo, path or query
//! (they may carry tokens, e.g. `https://user:token@host/?sas=...`). Only scheme + host + port.

use std::fmt;

use url::Url;

#[derive(Clone, PartialEq, Eq)]
pub struct Endpoint(String);

impl Endpoint {
    #[must_use]
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// Full value, for the code that actually connects.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn is_blank(&self) -> bool {
        self.0.trim().is_empty()
    }
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match Url::parse(&self.0) {
            Ok(u) if u.host_str().is_some() => {
                write!(f, "{}://{}", u.scheme(), u.host_str().unwrap_or_default())?;
                if let Some(p) = u.port() {
                    write!(f, ":{p}")?;
                }
                Ok(())
            }
            _ => f.write_str("[redacted]"),
        }
    }
}
