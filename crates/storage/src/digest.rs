//! Streaming helpers: keyed content MAC (HMAC-SHA256 via aws-lc-rs) aur hex.

use aws_lc_rs::hmac;
use std::fmt::Write as _;

/// Streaming HMAC-SHA256 + byte counter (plaintext par, put/get dono mein).
pub struct MacStream {
    ctx: hmac::Context,
    size: u64,
}

impl MacStream {
    pub fn new(key: &hmac::Key) -> Self {
        Self {
            ctx: hmac::Context::with_key(key),
            size: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.ctx.update(data);
        self.size += data.len() as u64;
    }

    pub const fn size(&self) -> u64 {
        self.size
    }

    pub fn finish(self) -> (u64, [u8; 32]) {
        let tag = self.ctx.sign();
        let mut out = [0u8; 32];
        out.copy_from_slice(tag.as_ref());
        (self.size, out)
    }
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}
