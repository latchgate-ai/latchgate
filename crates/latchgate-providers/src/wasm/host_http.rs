//! Host implementation for `latchgate:io/http` — outbound HTTP requests.
//!
//! SECURITY: every outbound HTTP request goes through sink validation,
//! SSRF protection (DNS pinning + private IP rejection), credential
//! injection, and I/O budget enforcement.
//!
//! # Egress allowlist propagation retry
//!
//! When the gate runs behind an egress proxy (Squid), a newly-learned
//! domain is written to the proxy's allowlist and the proxy is reloaded
//! (`squid -k reconfigure`). That reload is asynchronous on the proxy's
//! side: it acknowledges the signal before the new config is live. An
//! execution fired immediately after an approval-time domain learn can
//! therefore race ahead of the reload and be denied by the proxy.
//!
//! A proxy denial is provably side-effect-free: the request never reaches
//! the target. For HTTPS the denied `CONNECT` fails at tunnel
//! establishment (`reqwest::Error::is_connect`); for plaintext HTTP the
//! proxy returns its own error response carrying `X-Squid-Error`. In both
//! cases the origin is never contacted, so re-sending the *same* request
//! is safe regardless of the action's idempotency.

use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, warn};

use super::latchgate;
use super::WasmHostState;

/// Maximum number of *retries* (additional attempts beyond the first) for a
/// proxy-stage denial. Total sends = 1 + EGRESS_RETRY_MAX.
const EGRESS_RETRY_MAX: u32 = 3;

/// Base backoff before the first retry. Doubles each attempt:
/// 100ms → 200ms → 400ms (~700ms total worst case before giving up).
const EGRESS_RETRY_BASE: Duration = Duration::from_millis(100);

impl latchgate::provider::io_http::Host for WasmHostState {
    async fn request(
        &mut self,
        req: latchgate::provider::io_http::HttpRequest,
    ) -> Result<latchgate::provider::io_http::HttpResponse, String> {
        debug!(
            trace_id = %self.host_io.trace_id,
            method = %req.method,
            url = %crate::host_io::safe_url_for_log(&req.url),
            "host_io.http: request"
        );

        // ── Phase 1: validate preconditions ──────────────────────────
        self.validate_http_preconditions(&req.url)?;

        // ── Phase 2: SSRF-safe client ────────────────────────────────
        // Extract fields from self before the async call — &self must not
        // be held across an .await (WasmHostState contains non-Sync fields).
        let trace_id_owned = Arc::clone(&self.host_io.trace_id);
        let use_proxy = self.host_io.egress_proxy_url.is_some();
        let proxy_client = self.resources.http_proxy_client.clone();
        let (http_client, hostname) =
            build_ssrf_safe_client(&req.url, &trace_id_owned, use_proxy, proxy_client).await?;

        // ── Phase 3: build request with sanitised headers + credentials
        let builder = self.build_outbound_request(&http_client, &req, &hostname)?;

        // ── Phase 4: send with egress-propagation retry ──────────────
        let proxied = use_proxy;
        let mut response = send_with_egress_retry(builder, proxied, &trace_id_owned).await?;

        // ── Phase 5: record observed effect ──────────────────────────
        let status = response.status().as_u16();
        record_observed_effect(&mut self.host_io, &req.url, status);

        // ── Phase 6: read response with size cap ─────────────────────
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let body =
            read_capped_response_body(&mut response, self.host_io.max_host_response_bytes).await?;

        Ok(latchgate::provider::io_http::HttpResponse {
            status,
            headers,
            body,
        })
    }
}

// Security-boundary helpers

impl WasmHostState {
    /// Phase 1: Import allowlist, I/O budget, sink allowlist, and HTTPS
    /// enforcement for credential-bearing requests.
    ///
    /// SECURITY: all checks are fail-closed and execute before any network
    /// I/O. Order matters: import → budget → sink → HTTPS. The budget is
    /// consumed even if a later check fails, preventing budget-free probing.
    fn validate_http_preconditions(&mut self, url: &str) -> Result<(), String> {
        if let Err(e) = self.host_io.check_import_allowed("latchgate:io/http") {
            return Err(format!("{e}"));
        }
        if let Err(e) = self.host_io.consume_io_call() {
            return Err(format!("{e}"));
        }
        if let Err(e) = self.host_io.validate_sink(url) {
            return Err(format!("{e}"));
        }

        // SECURITY: enforce HTTPS when the host will inject credentials.
        // Plaintext HTTP would expose secrets to any on-path observer.
        // Checked before SSRF/DNS resolution so the rejection is instant
        // and leaks no timing information.
        if self.host_io.has_credential_secrets() {
            let scheme = url::Url::parse(url)
                .map_err(|e| format!("invalid URL: {e}"))?
                .scheme()
                .to_string();
            if scheme != "https" {
                return Err("secret-bearing outbound requests require https".to_string());
            }
        }

        Ok(())
    }

    /// Phase 3: Build the outbound HTTP request with sanitised headers and
    /// host-injected credentials.
    ///
    /// SECURITY: provider-supplied credential headers (Authorization, Cookie,
    /// etc.) are stripped — the host layer is the sole authority for credential
    /// injection. Credentials are injected from decrypted secrets by
    /// convention: `AUTHORIZATION`, `BEARER_TOKEN`, `API_KEY`.
    fn build_outbound_request(
        &self,
        client: &reqwest::Client,
        req: &latchgate::provider::io_http::HttpRequest,
        _hostname: &str,
    ) -> Result<reqwest::RequestBuilder, String> {
        let method: reqwest::Method = req.method.parse().map_err(|e| format!("bad method: {e}"))?;
        let mut builder = client.request(method, &req.url);

        if req.timeout_ms > 0 {
            builder = builder.timeout(Duration::from_millis(req.timeout_ms as u64));
        }

        // Strip credential headers from provider input.
        for (key, value) in &req.headers {
            if crate::host_io::is_credential_header(key) {
                warn!(
                    trace_id = %self.host_io.trace_id,
                    header = %key,
                    "provider supplied credential header — stripped"
                );
                continue;
            }
            builder = builder.header(key.as_str(), value.as_str());
        }

        // Host-layer credential injection from decrypted secrets.
        if let Some(auth) = self.host_io.get_secret("AUTHORIZATION") {
            builder = builder.header("Authorization", auth);
        } else if let Some(bearer) = self.host_io.get_secret("BEARER_TOKEN") {
            builder = builder.header("Authorization", format!("Bearer {bearer}"));
        }
        if let Some(api_key) = self.host_io.get_secret("API_KEY") {
            builder = builder.header("X-Api-Key", api_key);
        }

        if let Some(ref body) = req.body {
            builder = builder.body(body.clone());
        }

        Ok(builder)
    }
}

// Standalone transport helpers (no WasmHostState dependency)

/// Phase 2: Resolve DNS, reject private IPs (SSRF protection), and build
/// the HTTP client — either proxy-backed or direct with DNS pinning.
///
/// Standalone (not a method) so that `&WasmHostState` is never held across
/// an `.await` — required because `WasmHostState` contains non-`Sync` WASI
/// fields and the wasmtime-generated trait requires `Send` futures.
///
/// SECURITY: DNS is resolved once and pinned at the transport layer,
/// closing the TOCTOU window between resolution and connection. The
/// original hostname is preserved for TLS SNI validation.
async fn build_ssrf_safe_client(
    url: &str,
    trace_id: &str,
    use_proxy: bool,
    proxy_client: Option<reqwest::Client>,
) -> Result<(reqwest::Client, String), String> {
    let (pinned_addr, hostname) = latchgate_core::net::resolve_and_check_ssrf(
        url,
        &latchgate_core::net::SsrfCheckOptions::strict(),
    )
    .await
    .map_err(|e| {
        warn!(
            %trace_id,
            url = %crate::host_io::safe_url_for_log(url),
            error = %e,
            "SSRF check blocked outbound HTTP request"
        );
        format!("{e}")
    })?;

    let client = if use_proxy {
        proxy_client.ok_or_else(|| {
            "egress proxy configured but proxy HTTP client not initialised \
             (init_http_proxy not called at startup)"
                .to_string()
        })?
    } else {
        reqwest::Client::builder()
            .user_agent("latchgate/0.1")
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .resolve(&hostname, pinned_addr)
            .build()
            .map_err(|e| format!("pinned HTTP client: {e}"))?
    };

    Ok((client, hostname))
}

/// Send an HTTP request with bounded egress-propagation retry.
///
/// Retries only the proxy-stage denial case (see module-level docs): the
/// request provably never reached the origin, so re-sending is safe even
/// for non-idempotent actions. The happy path performs exactly one send.
async fn send_with_egress_retry(
    builder: reqwest::RequestBuilder,
    proxied: bool,
    trace_id: &str,
) -> Result<reqwest::Response, String> {
    let mut attempt = 0u32;
    loop {
        let send_builder = builder
            .try_clone()
            .ok_or_else(|| "request body not cloneable for retry".to_string())?;

        match send_builder.send().await {
            Ok(resp) => {
                if proxied && attempt < EGRESS_RETRY_MAX && is_proxy_denial_response(&resp) {
                    debug!(
                        %trace_id,
                        status = resp.status().as_u16(),
                        attempt,
                        "egress proxy denied request; allowlist likely \
                         mid-propagation — retrying"
                    );
                    egress_backoff(attempt).await;
                    attempt += 1;
                    continue;
                }
                return Ok(resp);
            }
            Err(e) => {
                if proxied && attempt < EGRESS_RETRY_MAX && e.is_connect() {
                    debug!(
                        %trace_id,
                        attempt,
                        error = %e,
                        "egress proxy connect failed; allowlist likely \
                         mid-propagation — retrying"
                    );
                    egress_backoff(attempt).await;
                    attempt += 1;
                    continue;
                }
                return Err(format!("HTTP request failed: {e}"));
            }
        }
    }
}

/// Record the HTTP status as a host-observed effect for BFT cross-checking.
fn record_observed_effect(host_io: &mut crate::host_io::HostState, url: &str, status: u16) {
    let target = url::Url::parse(url)
        .map(|u| format!("{}://{}", u.scheme(), u.host_str().unwrap_or("unknown")))
        .unwrap_or_else(|_| "unknown".into());
    host_io
        .record_observed_effect(crate::host_io::HostObservedEffect::HttpStatus { status, target });
}

/// Read the response body with a hard size cap.
///
/// SECURITY: prevents OOM from malicious or misconfigured upstreams.
/// Content-Length is checked for early rejection; the chunked read enforces
/// the cap regardless (Content-Length can be absent or spoofed).
async fn read_capped_response_body(
    response: &mut reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    if let Some(cl) = response.content_length() {
        if (cl as usize) > max_bytes {
            return Err(format!(
                "response Content-Length ({cl} bytes) exceeds limit ({max_bytes} bytes)"
            ));
        }
    }

    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("read body: {e}"))?
    {
        if body.len() + chunk.len() > max_bytes {
            return Err(format!(
                "response body exceeds limit of {max_bytes} bytes (read aborted)"
            ));
        }
        body.extend_from_slice(&chunk);
    }

    Ok(body)
}

// Egress propagation retry helpers

/// True when a response was generated by the egress proxy itself to deny the
/// request, rather than returned by the origin.
///
/// Keyed on `X-Squid-Error`, which Squid sets only on responses it generates
/// (access denied, service unavailable) — never on responses proxied through
/// from an origin. This avoids misclassifying a genuine origin `403`/`503`
/// (which carries a real response and means the target *was* contacted) as a
/// retryable proxy denial.
fn is_proxy_denial_response(resp: &reqwest::Response) -> bool {
    headers_indicate_proxy_denial(resp.headers())
}

/// Core of [`is_proxy_denial_response`], split out for unit testing without
/// constructing a full `reqwest::Response`.
fn headers_indicate_proxy_denial(headers: &reqwest::header::HeaderMap) -> bool {
    headers.contains_key("x-squid-error")
}

/// Exponential backoff for egress propagation retries: 100ms, 200ms, 400ms,
/// with ±25% jitter to avoid synchronised retries across concurrent
/// approvals. Bounded by `EGRESS_RETRY_MAX`.
async fn egress_backoff(attempt: u32) {
    let base_ms = (EGRESS_RETRY_BASE.as_millis() as u64) << attempt.min(16);
    let jitter_span = (base_ms / 4).max(1);
    // Cheap, non-cryptographic jitter from the wall clock — no RNG dependency.
    let entropy = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    let jitter = entropy % (2 * jitter_span + 1);
    let delay = base_ms.saturating_sub(jitter_span).saturating_add(jitter);
    tokio::time::sleep(Duration::from_millis(delay.max(1))).await;
}

// Tests — HTTP response size enforcement

#[cfg(test)]
mod tests {
    use super::super::HostResources;
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    use crate::host_io::{HostState, HostStateConfig};

    /// Network-dependent tests run only when `LATCHGATE_TEST_NETWORK=1`.
    /// Silently skipped otherwise — no failure, no noise.
    macro_rules! require_network {
        () => {
            if std::env::var("LATCHGATE_TEST_NETWORK").is_err() {
                eprintln!(
                    "SKIP {}: set LATCHGATE_TEST_NETWORK=1 to run",
                    module_path!()
                );
                return;
            }
        };
    }

    fn http_host_state(max_response_bytes: usize) -> WasmHostState {
        let host_io = HostState::new(HostStateConfig {
            allowed_sinks: vec!["httpbin.org".into()],
            approved_secrets: vec![],
            decrypted_secrets: HashMap::new(),
            trace_id: Arc::from("test-http-truncation"),
            max_io_calls: 10,
            max_host_response_bytes: max_response_bytes,
            allowed_imports: vec!["latchgate:io/http".into()],
            database_config: None,
            egress_proxy_url: None,
            fs_config: None,
            max_log_calls: None,
            max_log_message_bytes: None,
        });

        WasmHostState::new(host_io, HostResources::none(), 64)
    }

    fn http_get(url: &str) -> latchgate::provider::io_http::HttpRequest {
        latchgate::provider::io_http::HttpRequest {
            method: "GET".into(),
            url: url.into(),
            headers: vec![],
            body: None,
            timeout_ms: 10_000,
        }
    }

    // Response body truncation (network)

    /// A 10 KB response with max_host_response_bytes = 256 must be rejected.
    /// Exercises the streaming chunked-read truncation path.
    #[tokio::test]
    async fn response_body_exceeding_limit_is_rejected() {
        require_network!();
        let mut state = http_host_state(256);
        let req = http_get("https://httpbin.org/bytes/10000");

        let err = latchgate::provider::io_http::Host::request(&mut state, req)
            .await
            .unwrap_err();

        assert!(
            err.contains("exceeds limit"),
            "expected truncation error, got: {err}"
        );
    }

    /// A response within the limit succeeds normally.
    #[tokio::test]
    async fn response_within_limit_succeeds() {
        require_network!();
        let mut state = http_host_state(1_000_000);
        let req = http_get("https://httpbin.org/bytes/100");

        let resp = latchgate::provider::io_http::Host::request(&mut state, req)
            .await
            .unwrap();

        assert_eq!(resp.status, 200);
        assert!(resp.body.len() <= 1_000_000);
    }

    // SSRF enforcement at the host boundary

    /// Private IP targets are blocked even when the sink is "allowed".
    #[tokio::test]
    async fn ssrf_blocks_private_ip_targets() {
        let host_io = HostState::new(HostStateConfig {
            allowed_sinks: vec!["127.0.0.1".into()],
            approved_secrets: vec![],
            decrypted_secrets: HashMap::new(),
            trace_id: Arc::from("test-ssrf"),
            max_io_calls: 10,
            max_host_response_bytes: 1_000_000,
            allowed_imports: vec!["latchgate:io/http".into()],
            database_config: None,
            egress_proxy_url: None,
            fs_config: None,
            max_log_calls: None,
            max_log_message_bytes: None,
        });
        let mut state = WasmHostState::new(host_io, HostResources::none(), 64);

        let req = http_get("http://127.0.0.1:9999/secret");

        let err = latchgate::provider::io_http::Host::request(&mut state, req)
            .await
            .unwrap_err();

        assert!(
            err.contains("SSRF")
                || err.contains("private")
                || err.contains("blocked")
                || err.contains("loopback"),
            "private IP must be blocked by SSRF check, got: {err}"
        );
    }

    // Import gating at the host boundary

    /// HTTP request is rejected when latchgate:io/http is not in allowed_imports.
    #[tokio::test]
    async fn http_rejected_when_import_not_declared() {
        let host_io = HostState::new(HostStateConfig {
            allowed_sinks: vec!["httpbin.org".into()],
            approved_secrets: vec![],
            decrypted_secrets: HashMap::new(),
            trace_id: Arc::from("test-import-gate"),
            max_io_calls: 10,
            max_host_response_bytes: 1_000_000,
            allowed_imports: vec![], // HTTP not declared
            database_config: None,
            egress_proxy_url: None,
            fs_config: None,
            max_log_calls: None,
            max_log_message_bytes: None,
        });
        let mut state = WasmHostState::new(host_io, HostResources::none(), 64);

        let req = http_get("https://httpbin.org/get");

        let err = latchgate::provider::io_http::Host::request(&mut state, req)
            .await
            .unwrap_err();

        assert!(
            err.contains("not declared") || err.contains("import"),
            "undeclared import must be rejected, got: {err}"
        );
    }

    // Sink validation at the host boundary

    /// HTTP request to an undeclared sink is rejected before any network call.
    #[tokio::test]
    async fn http_rejected_for_undeclared_sink() {
        let mut state = http_host_state(1_000_000);

        let req = http_get("https://evil.com/steal");

        let err = latchgate::provider::io_http::Host::request(&mut state, req)
            .await
            .unwrap_err();

        assert!(
            err.contains("sink") || err.contains("not allowed") || err.contains("not in"),
            "undeclared sink must be rejected, got: {err}"
        );
    }

    // Credential header stripping (network)

    /// Provider-supplied Authorization header is stripped by the host.
    /// Verified via httpbin.org/headers which echoes received headers.
    #[tokio::test]
    async fn credential_header_stripped_from_provider_request() {
        require_network!();
        let mut state = http_host_state(1_000_000);

        let req = latchgate::provider::io_http::HttpRequest {
            method: "GET".into(),
            url: "https://httpbin.org/headers".into(),
            headers: vec![
                ("Authorization".into(), "Bearer stolen-token".into()),
                ("X-Custom".into(), "safe-value".into()),
            ],
            body: None,
            timeout_ms: 10_000,
        };

        let resp = latchgate::provider::io_http::Host::request(&mut state, req)
            .await
            .unwrap();

        let body_str = String::from_utf8_lossy(&resp.body);

        assert!(
            !body_str.contains("stolen-token"),
            "provider-supplied Authorization must be stripped, but httpbin echoed it back"
        );
    }

    // IO budget enforcement at the host boundary

    /// IO budget of 1 allows one request, second is denied.
    #[tokio::test]
    async fn io_budget_enforced_at_host_boundary() {
        let host_io = HostState::new(HostStateConfig {
            allowed_sinks: vec!["httpbin.org".into()],
            approved_secrets: vec![],
            decrypted_secrets: HashMap::new(),
            trace_id: Arc::from("test-io-budget"),
            max_io_calls: 1,
            max_host_response_bytes: 1_000_000,
            allowed_imports: vec!["latchgate:io/http".into()],
            database_config: None,
            egress_proxy_url: None,
            fs_config: None,
            max_log_calls: None,
            max_log_message_bytes: None,
        });
        let mut state = WasmHostState::new(host_io, HostResources::none(), 64);

        // First call consumes the budget. It will fail downstream at
        // SSRF or DNS, but consume_io_call fires first — budget is spent.
        let req1 = http_get("https://httpbin.org/get");
        let _ = latchgate::provider::io_http::Host::request(&mut state, req1).await;

        // Second call must fail at budget check.
        let req2 = http_get("https://httpbin.org/get");
        let err = latchgate::provider::io_http::Host::request(&mut state, req2)
            .await
            .unwrap_err();

        assert!(
            err.contains("budget") || err.contains("exhausted") || err.contains("io_call"),
            "second call must fail at IO budget, got: {err}"
        );
    }

    // Egress propagation retry — proxy-denial detection (no network)

    #[test]
    fn squid_error_header_detected_as_proxy_denial() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-squid-error", "ERR_ACCESS_DENIED 0".parse().unwrap());
        assert!(headers_indicate_proxy_denial(&headers));
    }

    #[test]
    fn origin_403_without_squid_header_is_not_proxy_denial() {
        // A genuine origin 403 carries no X-Squid-Error → must NOT be retried,
        // because the request reached the target (a real response came back).
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("server", "nginx".parse().unwrap());
        headers.insert("via", "1.1 some-cdn".parse().unwrap());
        assert!(!headers_indicate_proxy_denial(&headers));
    }

    // HTTPS enforcement for secret-bearing requests

    fn secret_bearing_host_state(url_sink: &str) -> WasmHostState {
        use zeroize::Zeroizing;

        let host_io = HostState::new(HostStateConfig {
            allowed_sinks: vec![Arc::from(url_sink)],
            approved_secrets: vec!["BEARER_TOKEN".into()],
            decrypted_secrets: HashMap::from([(
                "BEARER_TOKEN".to_string(),
                Zeroizing::new("secret-value".to_string()),
            )]),
            trace_id: Arc::from("test-https-enforce"),
            max_io_calls: 10,
            max_host_response_bytes: 1_000_000,
            allowed_imports: vec!["latchgate:io/http".into()],
            database_config: None,
            egress_proxy_url: None,
            fs_config: None,
            max_log_calls: None,
            max_log_message_bytes: None,
        });
        WasmHostState::new(host_io, HostResources::none(), 64)
    }

    /// Plaintext HTTP with host-injected credentials must be rejected
    /// before any network I/O occurs.
    #[tokio::test]
    async fn http_with_secrets_rejected() {
        let mut state = secret_bearing_host_state("api.example.com");
        let req = http_get("http://api.example.com/resource");

        let err = latchgate::provider::io_http::Host::request(&mut state, req)
            .await
            .unwrap_err();

        assert!(
            err.contains("https") && err.contains("secret"),
            "plaintext HTTP with secrets must be rejected, got: {err}"
        );
    }

    /// HTTPS with host-injected credentials passes the scheme check.
    /// (Will fail downstream at DNS/SSRF since example.com is not routable
    /// in CI, but the scheme enforcement must not fire.)
    #[tokio::test]
    async fn https_with_secrets_passes_scheme_check() {
        let mut state = secret_bearing_host_state("api.example.com");
        let req = http_get("https://api.example.com/resource");

        let result = latchgate::provider::io_http::Host::request(&mut state, req).await;

        // The request will fail at DNS/SSRF — that's expected.
        // What matters: the error is NOT about secrets/https.
        match result {
            Ok(_) => {} // Would only happen with real network — fine.
            Err(e) => {
                assert!(
                    !e.contains("secret"),
                    "HTTPS with secrets must not be rejected by scheme check, got: {e}"
                );
            }
        }
    }

    /// Plaintext HTTP without secrets is allowed (e.g. public web_read actions).
    #[tokio::test]
    async fn http_without_secrets_allowed() {
        let mut state = http_host_state(1_000_000);
        let req = http_get("http://httpbin.org/get");

        let result = latchgate::provider::io_http::Host::request(&mut state, req).await;

        // Will fail at DNS/SSRF — that's expected.
        // What matters: the error is NOT about secrets/https.
        match result {
            Ok(_) => {}
            Err(e) => {
                assert!(
                    !e.contains("secret"),
                    "HTTP without secrets must not trigger scheme enforcement, got: {e}"
                );
            }
        }
    }
}
