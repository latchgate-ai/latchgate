//! External dependency reachability checks (Redis, OPA, etc.).

use std::net::SocketAddr;
use std::time::Duration;

use latchgate_config::Config;

use super::Check;

pub(super) async fn await_check_redis(config: &Config) -> Check {
    let url = match config.storage.redis_url.as_deref() {
        Some(url) => url,
        None => return Check::skip("redis", "not configured (using embedded SQLite)"),
    };
    let addr = url
        .trim_start_matches("redis://")
        .trim_start_matches("rediss://")
        .split('/')
        .next()
        .and_then(|s| s.split('@').next_back())
        .unwrap_or("127.0.0.1:6379");

    let addr: SocketAddr = match addr.parse() {
        Ok(a) => a,
        Err(_) => match format!("{addr}:6379").parse() {
            Ok(a) => a,
            Err(_) => return Check::error("redis", format!("cannot parse address from {url}")),
        },
    };

    match tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_)) => Check::ok("redis", format!("reachable at {url}")),
        Ok(Err(e)) => Check::error(
            "redis",
            format!("not reachable at {url}: {e} — run: make dev"),
        ),
        Err(_) => Check::error(
            "redis",
            format!("connection timeout ({url}) — run: make dev"),
        ),
    }
}

pub(super) async fn await_check_opa(config: &Config) -> Check {
    let Some(ref opa_url) = config.policy.opa_url else {
        return Check::ok("opa", "embedded mode (regorus) — no external OPA required");
    };

    let health_url = format!("{}/health", opa_url.trim_end_matches('/'));
    match tokio::time::timeout(Duration::from_secs(2), reqwest::get(&health_url)).await {
        Ok(Ok(resp)) if resp.status().is_success() => {
            Check::ok("opa", format!("reachable at {opa_url}"))
        }
        Ok(Ok(resp)) => Check::warn(
            "opa",
            format!(
                "OPA responded {} at {opa_url} — check bundle load",
                resp.status(),
            ),
        ),
        Ok(Err(e)) => Check::error(
            "opa",
            format!("not reachable at {opa_url}: {e} — run: make dev"),
        ),
        Err(_) => Check::error(
            "opa",
            format!("connection timeout ({opa_url}) — run: make dev"),
        ),
    }
}

/// Verify egress proxy reachability and warn when unconfigured in production.
///
/// Defense-in-depth: the egress proxy is a second, independent enforcement
/// layer for outbound HTTP from WASM providers. Without it, a single bug in
/// kernel domain validation grants unrestricted egress.
pub(super) async fn await_check_egress_proxy(config: &Config) -> Check {
    match &config.egress.egress_proxy_url {
        Some(url) => {
            let addr = url
                .trim_start_matches("http://")
                .trim_start_matches("https://")
                .split('/')
                .next()
                .unwrap_or("127.0.0.1:3128");

            let addr: SocketAddr = match addr.parse() {
                Ok(a) => a,
                Err(_) => match format!("{addr}:3128").parse() {
                    Ok(a) => a,
                    Err(_) => {
                        return Check::error(
                            "egress_proxy",
                            format!("cannot parse address from {url}"),
                        )
                    }
                },
            };

            match tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(addr))
                .await
            {
                Ok(Ok(_)) => Check::ok("egress_proxy", format!("reachable at {url}")),
                Ok(Err(e)) => Check::error(
                    "egress_proxy",
                    format!("not reachable at {url}: {e} — is Squid running?"),
                ),
                Err(_) => Check::error(
                    "egress_proxy",
                    format!("connection timeout ({url}) — is Squid running?"),
                ),
            }
        }
        None => {
            if config.dev_mode() {
                Check::skip("egress_proxy", "skipped (dev) — kernel-only egress control")
            } else {
                Check::warn(
                    "egress_proxy",
                    "not configured — strongly recommended in production. \
                     Set egress_proxy_url in latchgate.toml for defense-in-depth egress control.",
                )
            }
        }
    }
}
