//! Layer 3: client IP sirf trusted proxies se (SECURITY.md §9: spoofed `X-Forwarded-For` ignore).
//!
//! Algorithm: TCP peer se shuru; har hop par agar current address trusted proxy hai
//! (`TRUSTED_PROXY_CIDRS` mein), to `X-Forwarded-For` ki sabse right wali entry lo. CIDR list khali =
//! kisi par trust nahi (peer IP hi client; `X-Forwarded-For` ignore), hops kuch bhi ho. Max
//! `TRUSTED_PROXY_HOPS` hops. Koi entry parse na ho to wahin ruk jao.
//! `ClientIp` kabhi log/metric/span mein nahi jaata (Debug redacted); sirf rate limit/audit HMAC ke liye.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::Response;
use ipnet::IpNet;

const XFF: &str = "x-forwarded-for";
/// Bound the work on hostile headers.
const MAX_XFF_ENTRIES: usize = 32;

#[derive(Clone, Debug)]
pub struct TrustedProxies {
    hops: u8,
    cidrs: Vec<IpNet>,
}

/// Invalid CIDR entry (index only, never the value).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("TRUSTED_PROXY_CIDRS entry #{0} is not a valid CIDR")]
pub struct BadCidr(pub usize);

impl TrustedProxies {
    /// # Errors
    /// [`BadCidr`] for an unparsable entry (config validation should already have refused it).
    pub fn new(hops: u8, cidrs: &[String]) -> Result<Self, BadCidr> {
        let mut out = Vec::with_capacity(cidrs.len());
        for (i, c) in cidrs.iter().enumerate() {
            let c = c.trim();
            let net = c
                .parse::<IpNet>()
                .or_else(|_| c.parse::<IpAddr>().map(IpNet::from))
                .map_err(|_| BadCidr(i))?;
            out.push(net);
        }
        Ok(Self { hops, cidrs: out })
    }

    #[must_use]
    pub const fn none() -> Self {
        Self {
            hops: 0,
            cidrs: Vec::new(),
        }
    }

    fn trusted(&self, ip: IpAddr) -> bool {
        // Empty list = trust no one (never "trust everybody").
        self.cidrs.iter().any(|n| n.contains(&ip))
    }

    /// Resolve the client address from the TCP peer and the `X-Forwarded-For` headers.
    #[must_use]
    pub fn resolve(&self, peer: Option<IpAddr>, headers: &HeaderMap) -> Option<IpAddr> {
        let mut ip = peer?.to_canonical();
        if self.hops == 0 {
            return Some(ip);
        }
        let mut chain: Vec<Option<IpAddr>> = headers
            .get_all(XFF)
            .iter()
            .flat_map(|v| v.to_str().unwrap_or("?").split(','))
            .map(|s| s.trim().parse::<IpAddr>().ok().map(|a| a.to_canonical()))
            .collect();
        if chain.len() > MAX_XFF_ENTRIES {
            chain.drain(..chain.len() - MAX_XFF_ENTRIES);
        }
        for _ in 0..self.hops {
            if !self.trusted(ip) {
                break;
            }
            match chain.pop() {
                Some(Some(next)) => ip = next,
                _ => break,
            }
        }
        Some(ip)
    }
}

/// Request extension. `Debug` never prints the address.
#[derive(Clone, Copy)]
pub struct ClientIp(pub Option<IpAddr>);

impl std::fmt::Debug for ClientIp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClientIp([redacted])")
    }
}

pub async fn layer(
    State(proxies): State<Arc<TrustedProxies>>,
    mut req: Request,
    next: Next,
) -> Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    let ip = proxies.resolve(peer, req.headers());
    req.extensions_mut().insert(ClientIp(ip));
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn h(xff: &[&str]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for v in xff {
            m.append(XFF, HeaderValue::from_str(v).expect("hv"));
        }
        m
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    #[test]
    fn zero_hops_ignores_forwarded_for() {
        let t = TrustedProxies::new(0, &[]).expect("tp");
        assert_eq!(
            t.resolve(Some(ip("10.0.0.5")), &h(&["1.2.3.4"])),
            Some(ip("10.0.0.5"))
        );
    }

    #[test]
    fn empty_cidr_list_trusts_no_one() {
        let t = TrustedProxies::new(2, &[]).expect("tp");
        assert_eq!(
            t.resolve(Some(ip("10.0.0.5")), &h(&["1.2.3.4", "5.6.7.8"])),
            Some(ip("10.0.0.5"))
        );
    }

    #[test]
    fn spoofed_header_from_untrusted_peer_is_ignored() {
        let t = TrustedProxies::new(1, &["10.0.0.0/8".into()]).expect("tp");
        assert_eq!(
            t.resolve(Some(ip("203.0.113.9")), &h(&["1.2.3.4"])),
            Some(ip("203.0.113.9"))
        );
    }

    #[test]
    fn trusted_proxy_takes_rightmost_entry_only() {
        let t = TrustedProxies::new(1, &["10.0.0.0/8".into()]).expect("tp");
        // client prepends a fake entry; the proxy appends the real one.
        assert_eq!(
            t.resolve(Some(ip("10.1.2.3")), &h(&["6.6.6.6, 198.51.100.7"])),
            Some(ip("198.51.100.7"))
        );
    }

    #[test]
    fn two_hops_and_garbage() {
        let t = TrustedProxies::new(2, &["10.0.0.0/8".into(), "192.168.1.1".into()]).expect("tp");
        assert_eq!(
            t.resolve(
                Some(ip("10.0.0.1")),
                &h(&["6.6.6.6", "198.51.100.7, 192.168.1.1"])
            ),
            Some(ip("198.51.100.7"))
        );
        assert_eq!(
            t.resolve(Some(ip("10.0.0.1")), &h(&["not-an-ip"])),
            Some(ip("10.0.0.1"))
        );
        assert_eq!(t.resolve(None, &h(&["1.2.3.4"])), None);
    }

    #[test]
    fn bad_cidr_reports_index_only() {
        assert_eq!(
            TrustedProxies::new(1, &["10.0.0.0/8".into(), "secret-ish".into()]).err(),
            Some(BadCidr(1))
        );
    }

    #[test]
    fn debug_is_redacted() {
        assert_eq!(
            format!("{:?}", ClientIp(Some(ip("1.2.3.4")))),
            "ClientIp([redacted])"
        );
    }
}
