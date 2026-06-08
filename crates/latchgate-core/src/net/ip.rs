//! IP classification and SSRF protection.
//!
//! All egress paths (provider HTTP calls, webhook delivery) share a single
//! implementation of IP classification and DNS-pinned SSRF protection. Callers
//! configure policy via [`SsrfCheckOptions`] — the defaults are strict
//! (scheme + port enforcement, no localhost bypass).
//!
//! # DNS TOCTOU mitigation
//!
//! [`resolve_and_check_ssrf`] returns a pinned `(SocketAddr, hostname)`. The
//! caller passes both to `reqwest::ClientBuilder::resolve()` so the HTTP
//! client connects directly to the verified address without a second DNS
//! lookup, while preserving the original hostname for TLS SNI validation.

use std::net::{IpAddr, SocketAddr};

use url::Url;

/// SSRF check policy.
///
/// Different callers have different security postures:
///
/// - **Providers** enforce strict defaults (attacker-influenced URLs).
/// - **Webhooks** use strict defaults with `allow_dev_localhost` in dev mode
///   (operator-configured URLs, but local receivers are useful during
///   development).
///
/// All fields default to the most restrictive setting.
#[derive(Debug, Clone)]
pub struct SsrfCheckOptions {
    /// Reject schemes other than `http` and `https`. Default: `true`.
    pub enforce_scheme: bool,

    /// Restrict to standard web ports (443, 80).
    ///
    /// Exotic ports (6379, 8080, 9200, 25, …) are common SSRF targets
    /// against internal services. Legitimate APIs run on 443/80.
    /// Default: `true`.
    pub enforce_port_allowlist: bool,

    /// Allow `localhost`, `127.0.0.1`, and `[::1]` in development.
    ///
    /// When `true`, the private-IP check is skipped for these three
    /// hostnames only. All other private/reserved ranges remain blocked.
    /// Default: `false`.
    pub allow_dev_localhost: bool,
}

impl Default for SsrfCheckOptions {
    fn default() -> Self {
        Self {
            enforce_scheme: true,
            enforce_port_allowlist: true,
            allow_dev_localhost: false,
        }
    }
}

impl SsrfCheckOptions {
    /// Strict defaults — equivalent to `Default::default()`.
    pub fn strict() -> Self {
        Self::default()
    }
}

/// SSRF check failure.
///
/// Callers map this into their own error enum at the call site.
#[derive(Debug, thiserror::Error)]
pub enum SsrfError {
    /// The URL, scheme, port, or resolved IP was rejected by policy.
    #[error("SSRF blocked: {reason}")]
    Blocked { reason: String },

    /// DNS resolution failed (network error, NXDOMAIN, etc.).
    ///
    /// This is separated from [`Blocked`](SsrfError::Blocked) so callers
    /// can distinguish transient DNS failures (potentially retryable) from
    /// permanent policy rejections (never retryable).
    #[error("DNS resolution failed for {host}: {source}")]
    DnsResolution {
        host: String,
        source: std::io::Error,
    },
}

impl SsrfError {
    /// Whether the error represents a transient failure that may succeed on
    /// retry. DNS resolution failures are retryable; policy rejections are not.
    pub fn is_retryable(&self) -> bool {
        matches!(self, SsrfError::DnsResolution { .. })
    }
}

/// Ports permitted when port enforcement is enabled.
///
/// Internal services (Redis on 6379, Elasticsearch on 9200, admin panels on
/// 8080, SMTP on 25) are common SSRF targets. Restricting to standard web
/// ports closes this vector without affecting legitimate API calls.
const ALLOWED_PORTS: &[u16] = &[443, 80];

/// Check whether an IP address is private, loopback, link-local, or otherwise
/// reserved.
///
/// These addresses must never be reachable via egress paths — a URL that
/// DNS-resolves to `169.254.169.254` (cloud metadata) would leak instance
/// credentials.
///
/// # Coverage
///
/// - **IPv4:** loopback (127.0.0.0/8), private (RFC 1918), link-local
///   (169.254.0.0/16, includes cloud metadata), CGNAT (100.64.0.0/10),
///   IETF protocol (192.0.0.0/24), documentation/test-net ranges
///   (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), multicast
///   (224.0.0.0/4), reserved (240.0.0.0/4), broadcast (255.255.255.255),
///   unspecified (0.0.0.0).
///
/// - **IPv6:** loopback (::1), unspecified (::), link-local (fe80::/10),
///   unique local / ULA (fc00::/7), multicast (ff00::/8), and
///   IPv4-mapped addresses (::ffff:0:0/96) — checked recursively against
///   the IPv4 rules.
#[must_use]
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()                                                     // 127.0.0.0/8
                || v4.is_private()                                               // 10/8, 172.16/12, 192.168/16
                || v4.is_link_local()                                            // 169.254.0.0/16
                || v4.is_broadcast()                                             // 255.255.255.255
                || v4.is_unspecified()                                           // 0.0.0.0
                || v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64       // 100.64.0.0/10 (CGNAT)
                || v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 0   // 192.0.0.0/24 (IETF)
                || v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 2   // 192.0.2.0/24 (TEST-NET-1)
                || v4.octets()[0] == 198 && v4.octets()[1] == 51 && v4.octets()[2] == 100 // 198.51.100.0/24 (TEST-NET-2)
                || v4.octets()[0] == 203 && v4.octets()[1] == 0 && v4.octets()[2] == 113  // 203.0.113.0/24 (TEST-NET-3)
                || v4.octets()[0] >= 224 // 224/4 multicast + 240/4 reserved
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()                                  // ::1
                || v6.is_unspecified()                        // ::
                || v6.segments()[0] & 0xffc0 == 0xfe80        // fe80::/10 link-local
                || v6.segments()[0] & 0xfe00 == 0xfc00        // fc00::/7 ULA (fc:: and fd::)
                || v6.segments()[0] & 0xff00 == 0xff00        // ff00::/8 multicast
                // IPv4-mapped IPv6 (::ffff:0:0/96) — check inner v4.
                || matches!(v6.to_ipv4_mapped(), Some(v4) if is_private_ip(IpAddr::V4(v4)))
        }
    }
}

/// Resolve the host of a URL via DNS, enforce SSRF protections per `options`,
/// and return a pinned `(SocketAddr, hostname)` for the caller to use with
/// `reqwest::ClientBuilder::resolve()`.
///
/// # Security properties
///
/// 1. **Scheme enforcement** (if enabled): only `http` and `https`. Exotic
///    schemes (`file://`, `ftp://`, `gopher://`, `data:`) are rejected before
///    DNS resolution.
///
/// 2. **Port enforcement** (if enabled): only 443 and 80. Internal services
///    on exotic ports are unreachable.
///
/// 3. **Private IP rejection**: every resolved address is checked against
///    [`is_private_ip`]. All addresses must be public — not just the first.
///
/// 4. **DNS pinning**: the caller uses the returned `SocketAddr` with
///    `reqwest::resolve()` to close the DNS rebinding TOCTOU window. Reqwest
///    connects directly to the verified address without a second lookup, while
///    preserving the original hostname for TLS SNI validation.
///
/// 5. **Dev localhost bypass** (if enabled): `localhost`, `127.0.0.1`, and
///    `[::1]` skip the private-IP check. All other private ranges remain
///    blocked even in dev mode.
pub async fn resolve_and_check_ssrf(
    url: &str,
    options: &SsrfCheckOptions,
) -> Result<(SocketAddr, String), SsrfError> {
    let parsed = Url::parse(url).map_err(|e| SsrfError::Blocked {
        reason: format!("invalid URL: {e}"),
    })?;

    // SECURITY: reject exotic schemes before touching the network.
    if options.enforce_scheme {
        match parsed.scheme() {
            "https" | "http" => {}
            other => {
                return Err(SsrfError::Blocked {
                    reason: format!("scheme '{other}' is not allowed (only http/https)"),
                });
            }
        }
    }

    let host = parsed.host_str().ok_or_else(|| SsrfError::Blocked {
        reason: "URL has no host".into(),
    })?;

    let port = parsed.port_or_known_default().unwrap_or(443);

    // SECURITY: reject non-standard ports before DNS resolution.
    if options.enforce_port_allowlist && !ALLOWED_PORTS.contains(&port) {
        return Err(SsrfError::Blocked {
            reason: format!("port {port} is not allowed (permitted: {ALLOWED_PORTS:?})"),
        });
    }

    let resolve_target = format!("{host}:{port}");

    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&resolve_target)
        .await
        .map_err(|e| SsrfError::DnsResolution {
            host: host.into(),
            source: e,
        })?
        .collect();

    if addrs.is_empty() {
        return Err(SsrfError::Blocked {
            reason: format!("DNS resolution returned no addresses for {host}"),
        });
    }

    // SECURITY: dev-mode localhost bypass. Only the three canonical
    // localhost identifiers are eligible — never broader private ranges.
    let skip_private_check = options.allow_dev_localhost
        && (host == "localhost" || host == "127.0.0.1" || host == "[::1]");

    if !skip_private_check {
        for addr in &addrs {
            if is_private_ip(addr.ip()) {
                return Err(SsrfError::Blocked {
                    reason: format!("{host} resolved to private/reserved address {}", addr.ip()),
                });
            }
        }
    }

    // Pin to the first verified public address.
    //
    // NOTE: all resolved addresses are checked for private IPs above, but
    // only the first is pinned for transport. This is strictly more
    // restrictive than pinning all (an attacker cannot exploit unpinned
    // addresses since they are all validated). Multi-address pinning is not
    // supported by reqwest's `.resolve()` API.
    Ok((addrs[0], host.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // =======================================================================
    // is_private_ip — IPv4
    // =======================================================================

    #[test]
    fn blocks_loopback_v4() {
        assert!(is_private_ip("127.0.0.1".parse().unwrap()));
        assert!(is_private_ip("127.0.0.0".parse().unwrap()));
        assert!(is_private_ip("127.255.255.255".parse().unwrap()));
        assert!(is_private_ip("127.0.42.1".parse().unwrap()));
    }

    #[test]
    fn blocks_rfc1918() {
        assert!(is_private_ip("10.0.0.1".parse().unwrap()));
        assert!(is_private_ip("10.255.255.255".parse().unwrap()));
        assert!(is_private_ip("172.16.0.1".parse().unwrap()));
        assert!(is_private_ip("172.31.255.255".parse().unwrap()));
        assert!(is_private_ip("192.168.0.1".parse().unwrap()));
        assert!(is_private_ip("192.168.1.1".parse().unwrap()));
        assert!(is_private_ip("192.168.255.255".parse().unwrap()));
    }

    #[test]
    fn blocks_link_local_v4() {
        // 169.254.169.254 = AWS/GCP/Azure metadata endpoint.
        assert!(is_private_ip("169.254.169.254".parse().unwrap()));
        assert!(is_private_ip("169.254.0.1".parse().unwrap()));
        assert!(is_private_ip("169.254.255.255".parse().unwrap()));
    }

    #[test]
    fn blocks_cgnat() {
        assert!(is_private_ip("100.64.0.0".parse().unwrap()));
        assert!(is_private_ip("100.64.0.1".parse().unwrap()));
        assert!(is_private_ip("100.127.255.255".parse().unwrap()));
        // Just outside CGNAT range.
        assert!(!is_private_ip("100.128.0.0".parse().unwrap()));
    }

    // RFC 1918 boundary: 172.16.0.0/12 ends at 172.31.255.255.
    #[test]
    fn rfc1918_172_boundary() {
        assert!(is_private_ip("172.16.0.1".parse().unwrap()));
        assert!(is_private_ip("172.31.255.255".parse().unwrap()));
        assert!(!is_private_ip("172.32.0.1".parse().unwrap()));
    }

    #[test]
    fn blocks_multicast_and_reserved_v4() {
        assert!(is_private_ip("224.0.0.1".parse().unwrap()));
        assert!(is_private_ip("239.255.255.255".parse().unwrap()));
        assert!(is_private_ip("240.0.0.1".parse().unwrap()));
        assert!(is_private_ip("255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn blocks_unspecified_v4() {
        assert!(is_private_ip("0.0.0.0".parse().unwrap()));
    }

    #[test]
    fn blocks_documentation_ranges() {
        assert!(is_private_ip("192.0.2.1".parse().unwrap())); // TEST-NET-1
        assert!(is_private_ip("198.51.100.1".parse().unwrap())); // TEST-NET-2
        assert!(is_private_ip("203.0.113.1".parse().unwrap())); // TEST-NET-3
    }

    #[test]
    fn blocks_cloud_metadata_v4() {
        assert!(is_private_ip("169.254.169.254".parse().unwrap()));
    }

    #[test]
    fn allows_public_v4() {
        assert!(!is_private_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip("1.1.1.1".parse().unwrap()));
        assert!(!is_private_ip("93.184.216.34".parse().unwrap()));
        assert!(!is_private_ip("104.16.0.1".parse().unwrap()));
    }

    // =======================================================================
    // is_private_ip — IPv6
    // =======================================================================

    #[test]
    fn blocks_loopback_v6() {
        assert!(is_private_ip("::1".parse().unwrap()));
    }

    #[test]
    fn blocks_unspecified_v6() {
        assert!(is_private_ip("::".parse().unwrap()));
    }

    #[test]
    fn blocks_link_local_v6() {
        assert!(is_private_ip("fe80::1".parse().unwrap()));
    }

    #[test]
    fn blocks_ula_v6() {
        assert!(is_private_ip("fc00::1".parse().unwrap()));
        assert!(is_private_ip("fd00::1".parse().unwrap()));
        assert!(is_private_ip("fd12:3456::1".parse().unwrap()));
    }

    #[test]
    fn blocks_multicast_v6() {
        assert!(is_private_ip("ff02::1".parse().unwrap()));
        assert!(is_private_ip("ff05::2".parse().unwrap()));
    }

    #[test]
    fn allows_public_v6() {
        assert!(!is_private_ip("2606:4700::6810:85e5".parse().unwrap()));
        assert!(!is_private_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    // =======================================================================
    // is_private_ip — IPv4-mapped IPv6
    // =======================================================================

    #[test]
    fn blocks_ipv4_mapped_private() {
        assert!(is_private_ip("::ffff:127.0.0.1".parse().unwrap()));
        assert!(is_private_ip("::ffff:10.0.0.1".parse().unwrap()));
        assert!(is_private_ip("::ffff:192.168.1.1".parse().unwrap()));
        assert!(is_private_ip("::ffff:169.254.169.254".parse().unwrap()));
    }

    #[test]
    fn allows_ipv4_mapped_public() {
        assert!(!is_private_ip("::ffff:8.8.8.8".parse().unwrap()));
    }

    // =======================================================================
    // resolve_and_check_ssrf — scheme enforcement
    // =======================================================================

    #[tokio::test]
    async fn rejects_file_scheme() {
        let err = resolve_and_check_ssrf("file:///etc/passwd", &SsrfCheckOptions::strict())
            .await
            .unwrap_err();
        assert!(matches!(err, SsrfError::Blocked { .. }));
        assert!(!err.is_retryable());
    }

    #[tokio::test]
    async fn rejects_ftp_scheme() {
        let err = resolve_and_check_ssrf("ftp://evil.com/data", &SsrfCheckOptions::strict())
            .await
            .unwrap_err();
        assert!(matches!(err, SsrfError::Blocked { .. }));
    }

    #[tokio::test]
    async fn rejects_gopher_scheme() {
        let err = resolve_and_check_ssrf("gopher://evil.com/", &SsrfCheckOptions::strict())
            .await
            .unwrap_err();
        assert!(matches!(err, SsrfError::Blocked { .. }));
    }

    // =======================================================================
    // resolve_and_check_ssrf — port enforcement
    // =======================================================================

    #[tokio::test]
    async fn rejects_exotic_port_8080() {
        let err = resolve_and_check_ssrf("https://example.com:8080/", &SsrfCheckOptions::strict())
            .await
            .unwrap_err();
        assert!(matches!(err, SsrfError::Blocked { .. }));
        let SsrfError::Blocked { reason } = &err else {
            unreachable!()
        };
        assert!(
            reason.contains("8080"),
            "error should name the port: {reason}"
        );
    }

    #[tokio::test]
    async fn rejects_redis_port() {
        let err = resolve_and_check_ssrf("https://example.com:6379/", &SsrfCheckOptions::strict())
            .await
            .unwrap_err();
        assert!(matches!(err, SsrfError::Blocked { .. }));
    }

    #[tokio::test]
    async fn rejects_elasticsearch_port() {
        let err = resolve_and_check_ssrf("http://example.com:9200/", &SsrfCheckOptions::strict())
            .await
            .unwrap_err();
        assert!(matches!(err, SsrfError::Blocked { .. }));
    }

    #[tokio::test]
    async fn rejects_smtp_port() {
        let err = resolve_and_check_ssrf("http://example.com:25/", &SsrfCheckOptions::strict())
            .await
            .unwrap_err();
        assert!(matches!(err, SsrfError::Blocked { .. }));
    }

    #[tokio::test]
    async fn allows_port_443() {
        // Will fail DNS (example.invalid) but must pass the port check.
        let err =
            resolve_and_check_ssrf("https://example.invalid:443/", &SsrfCheckOptions::strict())
                .await
                .unwrap_err();
        // Expect DNS failure, not port rejection.
        let msg = err.to_string();
        assert!(
            msg.contains("DNS") || msg.contains("resolution"),
            "443 must pass port check; expected DNS error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn allows_port_80() {
        let err = resolve_and_check_ssrf("http://example.invalid:80/", &SsrfCheckOptions::strict())
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("DNS") || msg.contains("resolution"),
            "80 must pass port check; expected DNS error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn default_https_port_is_443() {
        // No explicit port — defaults to 443 which is allowed.
        let err =
            resolve_and_check_ssrf("https://example.invalid/path", &SsrfCheckOptions::strict())
                .await
                .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("DNS") || msg.contains("resolution"),
            "default https port must be 443; expected DNS error, got: {msg}"
        );
    }

    // =======================================================================
    // resolve_and_check_ssrf — private IP via DNS
    // =======================================================================

    #[tokio::test]
    async fn blocks_localhost_dns() {
        let result =
            resolve_and_check_ssrf("http://127.0.0.1:80/metadata", &SsrfCheckOptions::strict())
                .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn blocks_ipv6_loopback() {
        let result = resolve_and_check_ssrf("http://[::1]:80/", &SsrfCheckOptions::strict()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn returns_pinned_addr_for_public_ip() {
        // 1.1.1.1 is public and should pass all checks.
        let result =
            resolve_and_check_ssrf("http://1.1.1.1:80/path?q=1", &SsrfCheckOptions::strict()).await;
        match result {
            Ok((addr, hostname)) => {
                assert_eq!(hostname, "1.1.1.1");
                assert_eq!(addr.ip(), "1.1.1.1".parse::<IpAddr>().unwrap());
            }
            // DNS may fail in CI environments without network.
            Err(SsrfError::DnsResolution { .. }) => {}
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    // =======================================================================
    // resolve_and_check_ssrf — dev localhost bypass
    // =======================================================================

    #[tokio::test]
    async fn dev_localhost_bypass_allows_127() {
        let opts = SsrfCheckOptions {
            allow_dev_localhost: true,
            ..SsrfCheckOptions::strict()
        };
        let result = resolve_and_check_ssrf("http://127.0.0.1:80/hook", &opts).await;
        // Should pass SSRF check (not blocked as private).
        // May fail DNS in some environments, but must NOT be SsrfError::Blocked.
        match result {
            Ok(_) => {}                                // success
            Err(SsrfError::DnsResolution { .. }) => {} // acceptable in CI
            Err(SsrfError::Blocked { reason }) => {
                panic!("dev localhost bypass should allow 127.0.0.1, got blocked: {reason}");
            }
        }
    }

    #[tokio::test]
    async fn dev_localhost_bypass_still_blocks_private_ranges() {
        let opts = SsrfCheckOptions {
            allow_dev_localhost: true,
            ..SsrfCheckOptions::strict()
        };
        // 10.0.0.1 is not localhost — must still be blocked.
        let result = resolve_and_check_ssrf("http://10.0.0.1:80/internal", &opts).await;
        assert!(result.is_err());
        if let Err(SsrfError::Blocked { reason }) = &result {
            assert!(
                reason.contains("private") || reason.contains("reserved"),
                "expected private IP rejection, got: {reason}"
            );
        }
        // DnsResolution is also acceptable (10.0.0.1 might not resolve).
    }

    #[tokio::test]
    async fn strict_mode_blocks_localhost() {
        let result =
            resolve_and_check_ssrf("http://127.0.0.1:80/hook", &SsrfCheckOptions::strict()).await;
        assert!(result.is_err());
    }

    // =======================================================================
    // SsrfError — retryability
    // =======================================================================

    #[test]
    fn blocked_is_not_retryable() {
        let err = SsrfError::Blocked {
            reason: "private IP".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn dns_resolution_is_retryable() {
        let err = SsrfError::DnsResolution {
            host: "example.com".into(),
            source: std::io::Error::other("timeout"),
        };
        assert!(err.is_retryable());
    }

    // =======================================================================
    // SsrfCheckOptions — defaults are strict
    // =======================================================================

    #[test]
    fn default_options_are_strict() {
        let opts = SsrfCheckOptions::default();
        assert!(opts.enforce_scheme);
        assert!(opts.enforce_port_allowlist);
        assert!(!opts.allow_dev_localhost);
    }
}
