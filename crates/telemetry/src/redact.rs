//! Redaction rules (P9 / SECURITY.md §10): field names and value patterns.
//!
//! Regex nahi: ek hi pass ka scanner, taaki per-event kaam bounded rahe (O(n) input, input pehle truncate hota hai).

use std::net::{Ipv4Addr, Ipv6Addr};

/// Replacement text for anything sensitive.
pub const REDACTED: &str = "[redacted]";

/// Keys jinke naam mein ye substring ho (lowercase, `-`/`.` ko `_` maan kar).
const SENSITIVE_SUBSTRINGS: &[&str] = &[
    "totp",
    "recovery",
    "mfa",
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "cookie",
    "email",
    "phone",
    "connection_string",
    "connectionstring",
    "database_url",
    "databaseurl",
    "api_key",
    "apikey",
    "private_key",
    "privatekey",
    "credential",
    "forwarded_for",
];

/// Short words jo sirf poore `_`-segment ke roop mein match hote hain (taaki "footprint" mein "otp" na pakde).
const SENSITIVE_SEGMENTS: &[&str] = &["ip", "otp", "pwd", "pw", "pin", "xff", "ssn", "cvv", "addr"];

/// Keys jinke baad ki poori value (rest of text) mask hoti hai, jaise `Authorization: Bearer x y`.
const REST_KEYS: &[&str] = &[
    "authorization",
    "proxy_authorization",
    "cookie",
    "set_cookie",
];

/// `code` wale keys jo secret nahi hain (HTTP/exit/error codes); baaki `code`, `*_code` (otp, recovery, verification) redact.
const SAFE_CODE_KEYS: &[&str] = &[
    "status_code",
    "http_status_code",
    "http_code",
    "response_code",
    "error_code",
    "exit_code",
];

const MAX_KEY_LEN: usize = 64;

fn normalize_key(key: &str) -> Option<String> {
    if key.is_empty() || key.len() > MAX_KEY_LEN {
        return None;
    }
    Some(
        key.chars()
            .map(|c| match c {
                '-' | '.' | ' ' => '_',
                c => c.to_ascii_lowercase(),
            })
            .collect(),
    )
}

/// Kya ye field/key naam sensitive hai (value `[redacted]` honi chahiye)?
pub fn is_sensitive_key(key: &str) -> bool {
    let Some(norm) = normalize_key(key) else {
        return false;
    };
    SENSITIVE_SUBSTRINGS.iter().any(|s| norm.contains(s))
        || (norm.split('_').any(|seg| seg == "code") && !SAFE_CODE_KEYS.contains(&norm.as_str()))
        || norm.split('_').any(|seg| SENSITIVE_SEGMENTS.contains(&seg))
}

fn is_rest_key(key: &str) -> bool {
    normalize_key(key).is_some_and(|n| REST_KEYS.contains(&n.as_str()))
}

fn is_delim(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '"' | '\''
                | ','
                | ';'
                | '('
                | ')'
                | '['
                | ']'
                | '{'
                | '}'
                | '<'
                | '>'
                | '='
                | '|'
                | '`'
                | '\\'
        )
}

fn is_uuid(t: &str) -> bool {
    let b = t.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

fn looks_like_email(t: &str) -> bool {
    match t.split_once('@') {
        Some((local, domain)) => {
            !local.is_empty()
                && !domain.contains('@')
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
        }
        None => false,
    }
}

fn looks_like_ip(t: &str) -> bool {
    if t.len() < 3 || t.len() > 64 {
        return false;
    }
    if t.parse::<Ipv4Addr>().is_ok() {
        return true;
    }
    if let Some((host, port)) = t.rsplit_once(':')
        && !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
        && host.parse::<Ipv4Addr>().is_ok()
    {
        return true;
    }
    t.matches(':').count() >= 2 && t.trim_matches(['[', ']']).parse::<Ipv6Addr>().is_ok()
}

fn looks_like_url_with_userinfo(t: &str) -> bool {
    match t.split_once("://") {
        Some((_, rest)) => rest.split('/').next().unwrap_or("").contains('@'),
        None => false,
    }
}

fn looks_like_long_secret(t: &str) -> bool {
    if t.len() < 32 || t.starts_with('/') || is_uuid(t) {
        return false;
    }
    let mut digit = false;
    let mut alpha = false;
    for c in t.chars() {
        match c {
            '0'..='9' => digit = true,
            'a'..='z' | 'A'..='Z' => alpha = true,
            '+' | '/' | '_' | '-' | '=' | '.' => {}
            _ => return false,
        }
    }
    digit && alpha
}

/// Value ka shape secret jaisa hai (JWT, email, IP, URL with userinfo, long base64/hex)?
pub fn value_looks_sensitive(token: &str) -> bool {
    let t = token.trim_end_matches(['.', '!', '?']);
    if t.is_empty() {
        return false;
    }
    (t.starts_with("eyJ") && t.len() >= 16)
        || looks_like_url_with_userinfo(t)
        || looks_like_email(t)
        || looks_like_ip(t)
        || looks_like_long_secret(t)
}

#[derive(Default)]
struct ScanState {
    /// Pichla token sensitive key tha, separator ka intezar.
    pending: bool,
    /// Separator (`:` / `=`) mil gaya, agla token value hai.
    armed: bool,
    /// Key rest-of-text type hai (authorization, cookie).
    rest_key: bool,
    /// Rest-of-text mask mode on.
    rest: bool,
    bearer_next: bool,
}

/// `input` ko scan karke sensitive hisse `[redacted]` se badal kar `out` mein append karta hai.
pub fn mask_text(input: &str, out: &mut String) {
    let mut st = ScanState::default();
    let mut iter = input.char_indices().peekable();
    while let Some(&(start, c)) = iter.peek() {
        let delim = is_delim(c);
        let mut end = start;
        while let Some(&(i, ch)) = iter.peek() {
            if is_delim(ch) != delim {
                break;
            }
            end = i + ch.len_utf8();
            iter.next();
        }
        let run = &input[start..end];
        if delim {
            if st.rest {
                continue;
            }
            out.push_str(run);
            if st.pending && run.contains('=') {
                st.armed = true;
            }
            continue;
        }
        if st.rest {
            continue;
        }
        handle_token(run, &mut st, out);
    }
}

fn handle_token(run: &str, st: &mut ScanState, out: &mut String) {
    let core = run.trim_end_matches(':');
    let colons = run.len() - core.len();
    if core.is_empty() {
        // sirf ':' wala token = separator
        out.push_str(run);
        if st.pending {
            st.armed = true;
        }
        return;
    }
    if st.armed {
        out.push_str(REDACTED);
        st.armed = false;
        st.pending = false;
        if st.rest_key {
            // authorization/cookie: baaki poora text bhi mask (REDACTED ek hi baar likha gaya)
            st.rest = true;
        }
        if core.eq_ignore_ascii_case("bearer") || core.eq_ignore_ascii_case("basic") {
            st.bearer_next = true;
        }
        return;
    }
    if st.bearer_next {
        out.push_str(REDACTED);
        st.bearer_next = false;
        return;
    }
    if core.eq_ignore_ascii_case("bearer") || core.eq_ignore_ascii_case("basic") {
        out.push_str(run);
        st.bearer_next = true;
        st.pending = false;
        return;
    }
    // `key:value` ek hi token mein (password:hunter2)
    if let Some((k, v)) = core.split_once(':')
        && !v.is_empty()
        && !v.starts_with("//")
        && is_sensitive_key(k.trim_start_matches(|c: char| !c.is_alphanumeric()))
    {
        out.push_str(k);
        out.push(':');
        out.push_str(REDACTED);
        out.push_str(&run[core.len()..]);
        st.pending = false;
        if is_rest_key(k) {
            st.rest = true;
        }
        return;
    }
    if value_looks_sensitive(core) {
        out.push_str(REDACTED);
        out.push_str(&run[core.len()..]);
        st.pending = false;
        return;
    }
    let key = core.trim_matches(|c: char| !(c.is_alphanumeric() || c == '_' || c == '-'));
    if is_sensitive_key(key) {
        out.push_str(run);
        st.pending = true;
        st.armed = colons > 0;
        st.rest_key = is_rest_key(key);
        return;
    }
    st.pending = false;
    st.rest_key = false;
    out.push_str(run);
}

/// Convenience: naya `String` return karta hai.
pub fn masked(input: &str) -> String {
    let mut s = String::with_capacity(input.len());
    mask_text(input, &mut s);
    s
}
