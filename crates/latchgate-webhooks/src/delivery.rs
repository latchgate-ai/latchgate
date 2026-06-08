//! HTTP delivery with HMAC-SHA256 signing, SSRF protection, and retry.
//!
//! # SSRF protection
//!
//! DNS is resolved before connecting. Every resolved address is checked against
//! private/reserved ranges. The pinned address is used via `reqwest::resolve()`
//! to close the DNS rebinding TOCTOU window while preserving TLS SNI.

use std::time::Duration;

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::{debug, warn};

use crate::config::WebhookEndpointConfig;
use crate::formatter::WebhookPayload;

type HmacSha256 = Hmac<Sha256>;

/// Exposed publicly so the outbox poller can distinguish
/// retryable failures from permanent ones.
#[derive(Debug, thiserror::Error)]
pub enum DeliveryError {
    #[error("SSRF blocked: {reason}")]
    SsrfBlocked { reason: String },

    #[error("DNS resolution failed for {host}: {source}")]
    DnsResolution {
        host: String,
        source: std::io::Error,
    },

    #[error("HTTP {status} (client error, not retried): {body}")]
    ClientError { status: u16, body: String },

    #[error("HTTP {status} (server error): {body}")]
    ServerError { status: u16, body: String },

    #[error("request failed: {0}")]
    Transport(#[from] reqwest::Error),

    #[error("payload serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    /// HMAC signing failed. In practice this only fires when the configured
    /// secret is empty (the underlying `Hmac::new_from_slice` only errors on
    /// zero-length keys), which config validation already rejects. Surfaced
    /// as a typed terminal error rather than silently emitting a placeholder
    /// signature, so the operator sees a signing failure as a signing
    /// failure — never as a downstream 4xx from a confused receiver.
    #[error("HMAC signing failed: {reason}")]
    SigningFailed { reason: String },
}

impl DeliveryError {
    /// Whether this error is retryable (5xx, timeout, network).
    pub fn is_retryable(&self) -> bool {
        match self {
            DeliveryError::ServerError { .. } => true,
            DeliveryError::Transport(_) => true,
            DeliveryError::DnsResolution { .. } => true,
            // Client errors (4xx), SSRF, serialization, and signing — not retryable.
            DeliveryError::ClientError { .. } => false,
            DeliveryError::SsrfBlocked { .. } => false,
            DeliveryError::Serialization(_) => false,
            DeliveryError::SigningFailed { .. } => false,
        }
    }
}

/// Compute the HMAC-SHA256 signature for a webhook payload.
///
/// Returns `(signature_header, timestamp_header)`:
/// - `X-LatchGate-Signature: sha256=<hex>`
/// - `X-LatchGate-Timestamp: <unix_seconds>`
///
/// The signed message is `{timestamp}.{raw_body}`, matching the industry
/// standard pattern (Stripe, GitHub, Slack).
///
/// Returns `DeliveryError::SigningFailed` if the underlying HMAC primitive
/// rejects the secret (currently only when the secret is empty). Callers
/// MUST propagate this error — emitting a placeholder signature would
/// route a signing failure as an opaque 4xx from the receiver and hide
/// the real fault from the operator.
pub fn sign_payload(body: &[u8], secret: &str) -> Result<(String, String), DeliveryError> {
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let signature =
        compute_signature(body, secret, &timestamp).map_err(|e| DeliveryError::SigningFailed {
            reason: format!("HMAC-SHA256 initialisation rejected the secret: {e}"),
        })?;
    Ok((signature, timestamp))
}

/// Compute HMAC-SHA256 over `{timestamp}.{body}`.
///
/// Separated from `sign_payload` so tests can verify against known
/// timestamp values without mocking time.
pub(crate) fn compute_signature(
    body: &[u8],
    secret: &str,
    timestamp: &str,
) -> Result<String, hmac::digest::InvalidLength> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())?;
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    let result = mac.finalize();
    Ok(format!("sha256={}", hex::encode(result.into_bytes())))
}

/// Verify an HMAC-SHA256 signature. Used by receivers.
///
/// Timestamp validation is **asymmetric** to match industry convention
/// (Stripe, GitHub):
///
/// - `tolerance_seconds` — maximum age of the timestamp (replay window).
///   Timestamps older than `now - tolerance_seconds` are rejected.
/// - `forward_tolerance_seconds` — maximum forward clock skew allowed.
///   Timestamps more than `forward_tolerance_seconds` ahead of `now` are
///   rejected. This is typically small (e.g. 5 s) because a legitimate
///   sender should never be far in the future.
///
/// Returns `true` if the signature is valid and the timestamp is within
/// both tolerance bounds.
pub fn verify_signature(
    body: &[u8],
    timestamp: &str,
    signature: &str,
    secret: &str,
    tolerance_seconds: i64,
    forward_tolerance_seconds: i64,
) -> bool {
    // Check timestamp freshness (asymmetric window).
    let ts: i64 = match timestamp.parse() {
        Ok(t) => t,
        Err(_) => return false,
    };
    let now = chrono::Utc::now().timestamp();
    let drift = now - ts;
    // drift > 0  ⇒  timestamp is in the past.
    // drift < 0  ⇒  timestamp is in the future.
    if drift > tolerance_seconds || drift < -forward_tolerance_seconds {
        return false;
    }

    // Decode the incoming signature from "sha256=<hex>" format.
    let hex_str = match signature.strip_prefix("sha256=") {
        Some(h) => h,
        None => return false,
    };
    let sig_bytes = match hex::decode(hex_str) {
        Ok(b) => b,
        Err(_) => return false,
    };

    // Compute HMAC-SHA256 and verify in constant time via Mac::verify_slice.
    let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    mac.verify_slice(&sig_bytes).is_ok()
}

/// Result of a test webhook delivery, suitable for CLI/TUI display.
#[derive(Debug)]
pub struct TestDeliveryResult {
    /// Endpoint name from config.
    pub endpoint_name: String,
    /// HTTP status code (0 if delivery never reached HTTP).
    pub status_code: u16,
    /// Wall-clock round-trip time.
    pub elapsed: Duration,
    /// `None` on success, `Some(message)` on failure.
    pub error: Option<String>,
}

impl TestDeliveryResult {
    /// Whether the delivery succeeded (2xx response).
    pub fn is_ok(&self) -> bool {
        self.error.is_none()
    }
}

/// Send a synthetic `test` event to a single webhook endpoint and report
/// the outcome.  Bypasses the dispatcher channel and retry loop — performs
/// a single signed POST through the full SSRF + TLS pipeline.
///
/// Intended for `latchgate config test-webhook` and the TUI `[t]` action.
pub async fn test_deliver(
    endpoint: &WebhookEndpointConfig,
    gate_version: &str,
    dev_mode: bool,
) -> TestDeliveryResult {
    let name = endpoint.name.clone();
    let start = std::time::Instant::now();

    match test_deliver_inner(endpoint, gate_version, dev_mode).await {
        Ok(status) => TestDeliveryResult {
            endpoint_name: name,
            status_code: status,
            elapsed: start.elapsed(),
            error: None,
        },
        Err(e) => {
            let status_code = match &e {
                DeliveryError::ClientError { status, .. }
                | DeliveryError::ServerError { status, .. } => *status,
                _ => 0,
            };
            TestDeliveryResult {
                endpoint_name: name,
                status_code,
                elapsed: start.elapsed(),
                error: Some(e.to_string()),
            }
        }
    }
}

/// One-shot delivery returning the actual HTTP status on success.
///
/// Separated from the production `deliver_inner` so we never touch
/// retry backoff arrays or mutable endpoint clones for diagnostics.
async fn test_deliver_inner(
    endpoint: &WebhookEndpointConfig,
    gate_version: &str,
    dev_mode: bool,
) -> Result<u16, DeliveryError> {
    use crate::formatter::WebhookPayload;

    let payload = WebhookPayload {
        id: format!("evt_test_{}", uuid::Uuid::now_v7()),
        event_type: "test".into(),
        timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        gate_version: gate_version.into(),
        data: serde_json::json!({
            "message": "LatchGate webhook test event",
            "endpoint_name": &endpoint.name,
        }),
    };

    let formatted = crate::formatter::format_for_endpoint(&payload, endpoint);
    let body = serde_json::to_vec(&formatted)?;

    // SSRF check + DNS pin (same as production path).
    let ssrf_opts = latchgate_core::net::SsrfCheckOptions {
        allow_dev_localhost: dev_mode,
        ..latchgate_core::net::SsrfCheckOptions::strict()
    };
    let (pinned_addr, hostname) =
        latchgate_core::net::resolve_and_check_ssrf(&endpoint.url, &ssrf_opts)
            .await
            .map_err(|e| match e {
                latchgate_core::net::SsrfError::Blocked { reason } => {
                    DeliveryError::SsrfBlocked { reason }
                }
                latchgate_core::net::SsrfError::DnsResolution { host, source } => {
                    DeliveryError::DnsResolution { host, source }
                }
            })?;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .resolve(&hostname, pinned_addr)
        .build()?;

    let timeout = Duration::from_secs(endpoint.timeout_seconds);
    let (signature, timestamp) = sign_payload(&body, &endpoint.secret)?;

    let mut request = client
        .post(&endpoint.url)
        .timeout(timeout)
        .header("Content-Type", "application/json")
        .header("X-LatchGate-Signature", &signature)
        .header("X-LatchGate-Timestamp", &timestamp)
        .header("User-Agent", "LatchGate-Webhooks/0.1");

    for (key, value) in &endpoint.headers {
        request = request.header(key.as_str(), value.as_str());
    }

    let response = request.body(body).send().await?;
    let status = response.status().as_u16();

    if (200..300).contains(&status) {
        return Ok(status);
    }

    let body_text = response
        .text()
        .await
        .unwrap_or_default()
        .chars()
        .take(4096)
        .collect::<String>();

    if (400..500).contains(&status) {
        Err(DeliveryError::ClientError {
            status,
            body: body_text,
        })
    } else {
        Err(DeliveryError::ServerError {
            status,
            body: body_text,
        })
    }
}

/// Deliver a webhook payload to a single endpoint with retry and backoff.
///
/// This function is called as a spawned task — it must not panic.
/// Failures are logged as structured warnings (dead-letter).
pub async fn deliver(
    endpoint: &WebhookEndpointConfig,
    payload: &WebhookPayload,
    dev_mode: bool,
) -> Result<(), DeliveryError> {
    let result = deliver_inner(endpoint, payload, dev_mode).await;
    match &result {
        Ok(()) => {
            debug!(
                endpoint = %endpoint.name,
                event_type = %payload.event_type,
                event_id = %payload.id,
                "webhook delivered"
            );
        }
        Err(e) => {
            warn!(
                endpoint = %endpoint.name,
                event_type = %payload.event_type,
                event_id = %payload.id,
                error = %e,
                "webhook delivery failed"
            );
        }
    }
    result
}

async fn deliver_inner(
    endpoint: &WebhookEndpointConfig,
    payload: &WebhookPayload,
    dev_mode: bool,
) -> Result<(), DeliveryError> {
    let formatted = crate::formatter::format_for_endpoint(payload, endpoint);
    let body = bytes::Bytes::from(serde_json::to_vec(&formatted)?);

    // SECURITY: DNS-pin before building the client. Scheme and port
    // enforcement closes the gap where webhooks previously allowed exotic
    // protocols and non-standard ports.
    let ssrf_opts = latchgate_core::net::SsrfCheckOptions {
        allow_dev_localhost: dev_mode,
        ..latchgate_core::net::SsrfCheckOptions::strict()
    };
    let (pinned_addr, hostname) =
        latchgate_core::net::resolve_and_check_ssrf(&endpoint.url, &ssrf_opts)
            .await
            .map_err(|e| match e {
                latchgate_core::net::SsrfError::Blocked { reason } => {
                    DeliveryError::SsrfBlocked { reason }
                }
                latchgate_core::net::SsrfError::DnsResolution { host, source } => {
                    DeliveryError::DnsResolution { host, source }
                }
            })?;

    // Build a per-delivery client with DNS pinning and no redirects.
    // SECURITY: no-redirect prevents SSRF via 3xx to internal services.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .resolve(&hostname, pinned_addr)
        .build()?;

    let timeout = Duration::from_secs(endpoint.timeout_seconds);

    // Attempt delivery with retries.
    let mut last_err = None;
    let max_attempts = 1 + endpoint.max_retries;

    for attempt in 0..max_attempts {
        if attempt > 0 {
            let backoff_idx = (attempt - 1) as usize;
            let delay = endpoint
                .retry_backoff_seconds
                .get(backoff_idx)
                .copied()
                .unwrap_or(30);
            debug!(
                endpoint = %endpoint.name,
                attempt,
                delay_seconds = delay,
                "retrying webhook delivery"
            );
            tokio::time::sleep(Duration::from_secs(delay)).await;
        }

        match attempt_delivery(&client, endpoint, &body, timeout).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                if !e.is_retryable() {
                    return Err(e);
                }
                debug!(
                    endpoint = %endpoint.name,
                    attempt,
                    error = %e,
                    "webhook delivery attempt failed (will retry)"
                );
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap_or_else(|| DeliveryError::SsrfBlocked {
        reason: "no delivery attempts made".into(),
    }))
}

/// Single delivery attempt. Signs the payload and POSTs to the endpoint.
///
/// `body` is a `bytes::Bytes` — an atomically reference-counted buffer.
/// `body.clone()` bumps the refcount (no heap allocation), unlike the
/// previous `body.to_vec()` which copied the entire payload per attempt.
async fn attempt_delivery(
    client: &reqwest::Client,
    endpoint: &WebhookEndpointConfig,
    body: &bytes::Bytes,
    timeout: Duration,
) -> Result<(), DeliveryError> {
    let (signature, timestamp) = sign_payload(body, &endpoint.secret)?;

    let mut request = client
        .post(&endpoint.url)
        .timeout(timeout)
        .header("Content-Type", "application/json")
        .header("X-LatchGate-Signature", &signature)
        .header("X-LatchGate-Timestamp", &timestamp)
        .header("User-Agent", "LatchGate-Webhooks/0.1");

    // Add custom headers (e.g., auth tokens for SIEM).
    for (key, value) in &endpoint.headers {
        request = request.header(key.as_str(), value.as_str());
    }

    let response = request.body(body.clone()).send().await?;
    let status = response.status().as_u16();

    if (200..300).contains(&status) {
        return Ok(());
    }

    // Read response body for diagnostics (bounded to 4KB to prevent DoS).
    let body_text = response
        .text()
        .await
        .unwrap_or_default()
        .chars()
        .take(4096)
        .collect::<String>();

    if (400..500).contains(&status) {
        Err(DeliveryError::ClientError {
            status,
            body: body_text,
        })
    } else {
        Err(DeliveryError::ServerError {
            status,
            body: body_text,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Signing --

    #[test]
    fn compute_signature_is_deterministic() {
        let body = b"test payload";
        let secret = "whsec_test-secret";
        let timestamp = "1711633800";

        let sig1 = compute_signature(body, secret, timestamp).unwrap();
        let sig2 = compute_signature(body, secret, timestamp).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn compute_signature_starts_with_sha256_prefix() {
        let sig = compute_signature(b"body", "secret", "12345").unwrap();
        assert!(sig.starts_with("sha256="), "got: {sig}");
    }

    #[test]
    fn compute_signature_is_64_hex_chars_after_prefix() {
        let sig = compute_signature(b"body", "secret", "12345").unwrap();
        let hex_part = sig.strip_prefix("sha256=").unwrap();
        assert_eq!(hex_part.len(), 64, "SHA-256 = 32 bytes = 64 hex chars");
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn different_secrets_produce_different_signatures() {
        let body = b"same body";
        let ts = "12345";
        let sig_a = compute_signature(body, "secret_a", ts).unwrap();
        let sig_b = compute_signature(body, "secret_b", ts).unwrap();
        assert_ne!(sig_a, sig_b);
    }

    #[test]
    fn different_timestamps_produce_different_signatures() {
        let body = b"same body";
        let secret = "same_secret";
        let sig_a = compute_signature(body, secret, "1000").unwrap();
        let sig_b = compute_signature(body, secret, "2000").unwrap();
        assert_ne!(sig_a, sig_b);
    }

    #[test]
    fn different_bodies_produce_different_signatures() {
        let secret = "same_secret";
        let ts = "12345";
        let sig_a = compute_signature(b"body_a", secret, ts).unwrap();
        let sig_b = compute_signature(b"body_b", secret, ts).unwrap();
        assert_ne!(sig_a, sig_b);
    }

    #[test]
    fn verify_signature_accepts_valid() {
        let body = b"test payload";
        let secret = "whsec_test";
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let sig = compute_signature(body, secret, &timestamp).unwrap();

        assert!(verify_signature(body, &timestamp, &sig, secret, 300, 5));
    }

    #[test]
    fn verify_signature_rejects_wrong_secret() {
        let body = b"test payload";
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let sig = compute_signature(body, "correct_secret", &timestamp).unwrap();

        assert!(!verify_signature(
            body,
            &timestamp,
            &sig,
            "wrong_secret",
            300,
            5,
        ));
    }

    #[test]
    fn verify_signature_rejects_expired_timestamp() {
        let body = b"test payload";
        let secret = "whsec_test";
        // Timestamp from 10 minutes ago.
        let old_ts = (chrono::Utc::now().timestamp() - 600).to_string();
        let sig = compute_signature(body, secret, &old_ts).unwrap();

        assert!(!verify_signature(body, &old_ts, &sig, secret, 300, 5));
    }

    #[test]
    fn verify_signature_rejects_tampered_body() {
        let secret = "whsec_test";
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let sig = compute_signature(b"original", secret, &timestamp).unwrap();

        assert!(!verify_signature(
            b"tampered",
            &timestamp,
            &sig,
            secret,
            300,
            5,
        ));
    }

    #[test]
    fn verify_signature_rejects_invalid_timestamp_format() {
        assert!(!verify_signature(
            b"body",
            "not-a-number",
            "sha256=abc",
            "secret",
            300,
            5,
        ));
    }

    #[test]
    fn verify_signature_rejects_far_future_timestamp() {
        let body = b"test payload";
        let secret = "whsec_test";
        // Timestamp 60 seconds in the future — well beyond the 5 s forward
        // tolerance. Must be rejected even though symmetric abs() would accept.
        let future_ts = (chrono::Utc::now().timestamp() + 60).to_string();
        let sig = compute_signature(body, secret, &future_ts).unwrap();

        assert!(
            !verify_signature(body, &future_ts, &sig, secret, 300, 5),
            "timestamp 60 s in the future must be rejected with forward_tolerance=5"
        );
    }

    #[test]
    fn verify_signature_accepts_small_forward_skew() {
        let body = b"test payload";
        let secret = "whsec_test";
        // Timestamp 2 seconds in the future — within the 5 s forward tolerance.
        let near_future_ts = (chrono::Utc::now().timestamp() + 2).to_string();
        let sig = compute_signature(body, secret, &near_future_ts).unwrap();

        assert!(
            verify_signature(body, &near_future_ts, &sig, secret, 300, 5),
            "timestamp 2 s in the future must be accepted with forward_tolerance=5"
        );
    }

    // -- sign_payload (error propagation) --

    #[test]
    fn sign_payload_succeeds_with_non_empty_secret() {
        let (signature, timestamp) =
            sign_payload(b"body", "whsec_present").expect("non-empty secret must succeed");
        assert!(signature.starts_with("sha256="));
        assert!(timestamp.parse::<i64>().is_ok());
    }

    #[test]
    fn sign_payload_succeeds_with_empty_secret() {
        // HMAC-SHA256 accepts zero-length keys (RFC 2104 §2). Config
        // validation is responsible for rejecting empty secrets before
        // they reach the signing path; the cryptographic primitive does
        // not error here.
        let (signature, _) = sign_payload(b"body", "").expect("HMAC accepts empty keys");
        assert!(signature.starts_with("sha256="));
    }

    #[test]
    fn signing_failed_is_not_retryable() {
        let e = DeliveryError::SigningFailed {
            reason: "test".into(),
        };
        assert!(!e.is_retryable());
    }

    // -- DeliveryError retryability --

    #[test]
    fn server_error_is_retryable() {
        let e = DeliveryError::ServerError {
            status: 503,
            body: "service unavailable".into(),
        };
        assert!(e.is_retryable());
    }

    #[test]
    fn client_error_is_not_retryable() {
        let e = DeliveryError::ClientError {
            status: 400,
            body: "bad request".into(),
        };
        assert!(!e.is_retryable());
    }

    #[test]
    fn ssrf_blocked_is_not_retryable() {
        let e = DeliveryError::SsrfBlocked {
            reason: "private IP".into(),
        };
        assert!(!e.is_retryable());
    }
}
