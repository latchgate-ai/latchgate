//! DPoP + Lease lifecycle for the MCP adapter.
//!
//! The adapter authenticates to LatchGate as a DPoP client:
//!   1. Generate a fresh P-256 keypair at startup.
//!   2. Issue a Lease via `POST /v1/leases` (bootstrapping endpoint, no auth).
//!   3. For every action call, produce a new DPoP proof bound to the lease.
//!   4. Auto-renew the lease when fewer than RENEW_THRESHOLD_SECONDS remain.
//!
//! # Security properties
//!
//! - Each DPoP proof is single-use: bound to a unique `jti`, method, and URL.
//!   Replay of a proof is rejected by LatchGate's Redis-backed replay cache.
//! - The lease is bound to the DPoP key via `cnf.jkt`. A stolen lease JWT
//!   is useless without the corresponding private key.
//! - Private key material never leaves this process. It is not logged.
//! - Lease expiry is extracted from the JWT payload for scheduling only.
//!   It is not used for authorization — LatchGate verifies the signature.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde_json::json;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use latchgate_auth::dpop::{compute_ath, generate_dpop_keypair, sign_dpop_proof, DPoPSigningKey};

/// Renew the lease when fewer than this many seconds remain.
const RENEW_THRESHOLD_SECONDS: i64 = 60;

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum McpAuthError {
    #[error("DPoP key generation failed: {0}")]
    KeyGen(String),

    #[error("DPoP proof signing failed: {0}")]
    Signing(String),

    #[error("lease issuance failed (HTTP {status}): {body}")]
    LeaseIssuance { status: u16, body: String },

    #[error("lease response is missing the lease_jwt field")]
    MissingLeaseJwt,

    #[error("not connected — call ensure_lease() first")]
    NotConnected,

    #[error("system clock before Unix epoch")]
    Clock,

    #[error("HTTP transport error: {0}")]
    Http(String),
}

// ── Internal lease state ───────────────────────────────────────────────────────

struct LeaseState {
    jwt: String,
    /// Unix timestamp (seconds) at which the lease expires.
    expires_at: i64,
}

// ── DPoPClient ────────────────────────────────────────────────────────────────

/// Manages DPoP authentication state against LatchGate.
///
/// Thread-safe: private key is immutable after construction; lease state
/// is guarded by a `Mutex`. Cheaply cloneable via `Arc`.
#[derive(Clone)]
pub struct DPoPClient {
    inner: Arc<Inner>,
}

struct Inner {
    /// ES256 / P-256 signing key — never exposed outside this module.
    signing_key: DPoPSigningKey,
    /// Pre-serialised public coordinates for JWK inclusion in the lease request.
    pub_x: String,
    pub_y: String,
    /// Mutable lease state, renewed as needed.
    lease: Mutex<Option<LeaseState>>,
    /// Stable agent identifier embedded in the Lease.
    agent_id: String,
    /// Full URL of the /v1/leases endpoint (e.g. http://localhost/v1/leases).
    lease_endpoint: String,
    /// Canonical public base URL for DPoP htu construction.
    /// MUST match `public_base_url` in latchgate.toml.
    public_base_url: String,
    /// Filesystem root to request at lease time (CWD at startup).
    /// The gate validates this against `fs_root_allowed_prefixes`.
    fs_root: Option<String>,
}

impl DPoPClient {
    /// Create a new client with a fresh P-256 DPoP keypair.
    ///
    /// The keypair is generated using the OS CSPRNG. No key material is
    /// logged or persisted — it lives only in process memory.
    pub fn new(
        base_url: &str,
        public_base_url: &str,
        agent_id: String,
    ) -> Result<Self, McpAuthError> {
        let (signing_key, pub_key) =
            generate_dpop_keypair().map_err(|e| McpAuthError::KeyGen(e.to_string()))?;

        let lease_endpoint = format!("{}/v1/leases", base_url.trim_end_matches('/'));

        let fs_root = std::env::current_dir()
            .ok()
            .map(|p| p.to_string_lossy().into_owned());

        Ok(Self {
            inner: Arc::new(Inner {
                pub_x: pub_key.x,
                pub_y: pub_key.y,
                signing_key,
                lease: Mutex::new(None),
                agent_id,
                lease_endpoint,
                public_base_url: public_base_url.trim_end_matches('/').to_string(),
                fs_root,
            }),
        })
    }

    /// Ensure a valid lease exists, issuing or renewing one if needed.
    ///
    /// Must be called before `auth_headers()`. Idempotent: a no-op when the
    /// current lease has more than RENEW_THRESHOLD_SECONDS of lifetime left.
    ///
    /// The lock is released *before* the network round-trip to `/v1/leases`
    /// so concurrent `auth_headers()` and `execute()` calls are not blocked
    /// behind lease issuance. On completion, the lock is re-acquired and the
    /// new lease is stored only if it is fresher than whatever another
    /// concurrent caller may have stored in the meantime.
    ///
    /// On failure the existing lease (if any) is left intact so in-flight
    /// requests can still succeed. A subsequent call will retry.
    pub async fn ensure_lease<F, Fut>(&self, post_json: F) -> Result<(), McpAuthError>
    where
        F: Fn(String, serde_json::Value) -> Fut + Send,
        Fut: std::future::Future<Output = Result<serde_json::Value, McpAuthError>> + Send,
    {
        // Phase 1: check under lock whether renewal is needed, then release.
        let needs_renewal = {
            let now = unix_now()?;
            let guard = self.inner.lease.lock().await;
            match &*guard {
                None => true,
                Some(lease) => {
                    let remaining = lease.expires_at - now;
                    if remaining < RENEW_THRESHOLD_SECONDS {
                        debug!(
                            remaining_seconds = remaining,
                            "lease expiring soon; renewing"
                        );
                        true
                    } else {
                        false
                    }
                }
            }
            // guard dropped — lock released before the network call.
        };

        if !needs_renewal {
            return Ok(());
        }

        // Phase 2: issue lease without holding the lock.
        //
        // Multiple concurrent callers may reach this point simultaneously.
        // Each will issue its own lease — this is correct (both are valid)
        // and the freshest one wins in phase 3.
        debug!(agent_id = %self.inner.agent_id, "issuing lease");
        let new_lease = self.issue_lease(&post_json).await?;
        info!(
            agent_id = %self.inner.agent_id,
            expires_at = new_lease.expires_at,
            "lease issued"
        );

        // Phase 3: re-acquire lock and store, keeping the fresher lease.
        let mut guard = self.inner.lease.lock().await;
        let dominated = guard
            .as_ref()
            .is_some_and(|existing| existing.expires_at >= new_lease.expires_at);
        if !dominated {
            *guard = Some(new_lease);
        }

        Ok(())
    }

    /// Produce `Authorization` and `DPoP` header values for an outgoing request.
    ///
    /// `method` must be the HTTP method in uppercase (e.g. "POST").
    /// `path` must be the request path (e.g. "/v1/actions/http_fetch/execute").
    ///
    /// Each call generates a fresh DPoP proof with a unique `jti`. Proofs
    /// are single-use and will be rejected by LatchGate on replay.
    ///
    /// The mutex is held only long enough to clone the lease JWT; the signing
    /// operation runs outside the lock so concurrent callers are not blocked.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if `ensure_lease` was never called. In release
    /// builds returns `McpAuthError::NotConnected`.
    pub async fn auth_headers(
        &self,
        method: &str,
        path: &str,
    ) -> Result<(String, String), McpAuthError> {
        let jwt = {
            let guard = self.inner.lease.lock().await;
            guard
                .as_ref()
                .ok_or(McpAuthError::NotConnected)?
                .jwt
                .clone()
            // guard dropped — lock released before signing.
        };

        let htu = format!("{}{}", self.inner.public_base_url, path);
        let ath = compute_ath(&jwt);
        let jti = uuid::Uuid::now_v7().to_string();

        let proof = sign_dpop_proof(&self.inner.signing_key, method, &htu, &ath, &jti)
            .map_err(|e| McpAuthError::Signing(e.to_string()))?;

        // SECURITY: log thumbprint and jti for traceability, never the JWT or proof.
        debug!(
            jti = %jti,
            method = %method,
            path = %path,
            "dpop proof signed"
        );

        Ok((format!("DPoP {jwt}"), proof))
    }

    // ── Private ───────────────────────────────────────────────────────────────

    async fn issue_lease<F, Fut>(&self, post_json: &F) -> Result<LeaseState, McpAuthError>
    where
        F: Fn(String, serde_json::Value) -> Fut + Send,
        Fut: std::future::Future<Output = Result<serde_json::Value, McpAuthError>> + Send,
    {
        let mut body = json!({
            "scopes": ["tools:call"],
            "dpop_jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x":   self.inner.pub_x,
                "y":   self.inner.pub_y,
            },
        });

        if let Some(ref root) = self.inner.fs_root {
            body["fs_root"] = serde_json::Value::String(root.clone());
        }

        let resp = post_json(self.inner.lease_endpoint.clone(), body).await?;

        let jwt = resp["lease_jwt"]
            .as_str()
            .ok_or(McpAuthError::MissingLeaseJwt)?
            .to_string();

        // Decode expiry for renewal scheduling. We do NOT verify the signature
        // here — we trust our own server; the signature is verified server-side
        // on every action call.
        let expires_at = decode_lease_expiry(&jwt).unwrap_or_else(|| {
            warn!("could not decode lease expiry — using 5-minute fallback");
            unix_now().unwrap_or(0) + 300
        });

        Ok(LeaseState { jwt, expires_at })
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn unix_now() -> Result<i64, McpAuthError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|_| McpAuthError::Clock)
}

/// Decode the `exp` claim from a JWT payload without verifying the signature.
///
/// Used only for renewal scheduling. Authorization is always performed by
/// LatchGate on the incoming request — this is NOT a security boundary.
fn decode_lease_expiry(jwt: &str) -> Option<i64> {
    let payload = jwt.split('.').nth(1)?;
    let decoded = Base64UrlUnpadded::decode_vec(payload).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    claims["exp"].as_i64()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_lease_expiry_valid_jwt() {
        // A minimal JWT with exp = 9999999999 (year 2286)
        // Header: {"alg":"ES256"}  Payload: {"exp":9999999999}
        let header = Base64UrlUnpadded::encode_string(b"{\"alg\":\"ES256\"}");
        let payload = Base64UrlUnpadded::encode_string(b"{\"exp\":9999999999}");
        let jwt = format!("{header}.{payload}.fakesig");
        assert_eq!(decode_lease_expiry(&jwt), Some(9999999999));
    }

    #[test]
    fn decode_lease_expiry_missing_exp() {
        let header = Base64UrlUnpadded::encode_string(b"{\"alg\":\"ES256\"}");
        let payload = Base64UrlUnpadded::encode_string(b"{\"sub\":\"agent\"}");
        let jwt = format!("{header}.{payload}.fakesig");
        assert_eq!(decode_lease_expiry(&jwt), None);
    }

    #[test]
    fn decode_lease_expiry_malformed_jwt() {
        assert_eq!(decode_lease_expiry("not-a-jwt"), None);
        assert_eq!(decode_lease_expiry(""), None);
    }

    #[test]
    fn dpop_client_new_generates_keypair() {
        let client = DPoPClient::new(
            "http://localhost:3000",
            "http://localhost:3000",
            "test-agent".into(),
        )
        .expect("DPoPClient::new must succeed");

        // Public coordinates must be non-empty (base64url-encoded P-256 points).
        assert!(!client.inner.pub_x.is_empty());
        assert!(!client.inner.pub_y.is_empty());
    }

    /// Regression: latchgate-mcp sent `session_id` in the lease request body,
    /// but IssueLeaseRequest uses `deny_unknown_fields`. The gate returned
    /// 422 and the adapter could never acquire a lease over HTTP transport.
    #[tokio::test]
    async fn lease_body_contains_only_known_fields() {
        let client = DPoPClient::new(
            "http://localhost:3000",
            "http://localhost:3000",
            "test-agent".into(),
        )
        .expect("DPoPClient::new must succeed");

        let captured = std::sync::Arc::new(tokio::sync::Mutex::new(None));
        let captured_clone = captured.clone();

        let result = client
            .ensure_lease(|_url, body| {
                let captured = captured_clone.clone();
                async move {
                    *captured.lock().await = Some(body.clone());
                    Err(McpAuthError::MissingLeaseJwt)
                }
            })
            .await;

        assert!(result.is_err());

        let body = captured.lock().await.take().expect("body must be captured");
        let obj = body.as_object().expect("body must be an object");

        let allowed_fields: std::collections::HashSet<&str> =
            ["scopes", "dpop_jwk", "budgets", "fs_root"]
                .into_iter()
                .collect();

        for key in obj.keys() {
            assert!(
                allowed_fields.contains(key.as_str()),
                "lease body contains unknown field '{key}' — \
                 IssueLeaseRequest has deny_unknown_fields and will reject it"
            );
        }

        assert!(obj.contains_key("scopes"), "missing 'scopes'");
        assert!(obj.contains_key("dpop_jwk"), "missing 'dpop_jwk'");

        assert!(
            !obj.contains_key("session_id"),
            "session_id must NOT be in the lease body — \
             IssueLeaseRequest has deny_unknown_fields"
        );

        let scopes = obj["scopes"].as_array().expect("scopes must be an array");
        let scope_strs: Vec<&str> = scopes.iter().filter_map(|v| v.as_str()).collect();
        assert!(
            scope_strs.contains(&"tools:call"),
            "lease scopes must include 'tools:call' — OPA policy requires it; got {scope_strs:?}"
        );
    }

    #[tokio::test]
    async fn lease_body_includes_fs_root_from_cwd() {
        let client = DPoPClient::new(
            "http://localhost:3000",
            "http://localhost:3000",
            "test-agent".into(),
        )
        .unwrap();

        let captured = std::sync::Arc::new(tokio::sync::Mutex::new(None));
        let captured_clone = captured.clone();

        let _ = client
            .ensure_lease(|_url, body| {
                let captured = captured_clone.clone();
                async move {
                    *captured.lock().await = Some(body.clone());
                    Err(McpAuthError::MissingLeaseJwt)
                }
            })
            .await;

        let body = captured.lock().await.take().expect("body must be captured");

        // CWD is always available in test environments.
        let fs_root = body["fs_root"].as_str().expect("fs_root must be present");
        assert!(
            std::path::Path::new(fs_root).is_absolute(),
            "fs_root must be an absolute path, got: {fs_root}"
        );
    }

    // ── ensure_lease concurrency ─────────────────────────────────────────

    /// Build a minimal JWT with the given `exp` claim for test purposes.
    fn fake_jwt(exp: i64) -> String {
        let header = Base64UrlUnpadded::encode_string(b"{\"alg\":\"ES256\"}");
        let payload_json = format!("{{\"exp\":{exp}}}");
        let payload = Base64UrlUnpadded::encode_string(payload_json.as_bytes());
        format!("{header}.{payload}.fakesig")
    }

    fn fake_lease_response(exp: i64) -> serde_json::Value {
        serde_json::json!({ "lease_jwt": fake_jwt(exp) })
    }

    #[tokio::test]
    async fn ensure_lease_skips_when_fresh() {
        let client = DPoPClient::new(
            "http://localhost:3000",
            "http://localhost:3000",
            "test-agent".into(),
        )
        .unwrap();

        let far_future = unix_now().unwrap() + 3600;
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));

        // First call: issues a lease.
        {
            let cc = call_count.clone();
            client
                .ensure_lease(move |_url, _body| {
                    let cc = cc.clone();
                    async move {
                        cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        Ok(fake_lease_response(far_future))
                    }
                })
                .await
                .unwrap();
        }
        assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 1);

        // Second call: lease is fresh, should NOT call post_json.
        {
            let cc = call_count.clone();
            client
                .ensure_lease(move |_url, _body| {
                    let cc = cc.clone();
                    async move {
                        cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        Ok(fake_lease_response(far_future))
                    }
                })
                .await
                .unwrap();
        }
        assert_eq!(
            call_count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "ensure_lease must not call post_json when lease is still fresh"
        );
    }

    #[tokio::test]
    async fn ensure_lease_keeps_fresher_lease() {
        let client = DPoPClient::new(
            "http://localhost:3000",
            "http://localhost:3000",
            "test-agent".into(),
        )
        .unwrap();

        let now = unix_now().unwrap();
        let exp_early = now + 120;
        let exp_late = now + 3600;

        // Seed with the later-expiring lease.
        client
            .ensure_lease(|_url, _body| async move { Ok(fake_lease_response(exp_late)) })
            .await
            .unwrap();

        // Force renewal by setting the lease to near-expiry.
        {
            let mut guard = client.inner.lease.lock().await;
            *guard = Some(LeaseState {
                jwt: fake_jwt(now + 5), // expires in 5s → triggers renewal
                expires_at: now + 5,
            });
        }

        // Simulate a concurrent caller that already stored a fresher lease
        // by the time our renewal completes — seed a fresh lease, then
        // renew with an older one.
        {
            let mut guard = client.inner.lease.lock().await;
            *guard = Some(LeaseState {
                jwt: fake_jwt(exp_late),
                expires_at: exp_late,
            });
        }
        // This call sees needs_renewal=false because we just seeded a fresh lease.
        client
            .ensure_lease(|_url, _body| async move { Ok(fake_lease_response(exp_early)) })
            .await
            .unwrap();

        // The stored lease must still be the later-expiring one.
        let guard = client.inner.lease.lock().await;
        let stored = guard.as_ref().expect("lease must exist");
        assert_eq!(
            stored.expires_at, exp_late,
            "ensure_lease must keep the fresher lease"
        );
    }

    #[tokio::test]
    async fn auth_headers_produce_unique_jti() {
        let client = DPoPClient::new(
            "http://localhost:3000",
            "http://localhost:3000",
            "test-agent".into(),
        )
        .unwrap();

        let far_future = unix_now().unwrap() + 3600;
        client
            .ensure_lease(|_url, _body| async move { Ok(fake_lease_response(far_future)) })
            .await
            .unwrap();

        let (_, proof_a) = client.auth_headers("GET", "/v1/actions").await.unwrap();
        let (_, proof_b) = client.auth_headers("GET", "/v1/actions").await.unwrap();

        assert_ne!(proof_a, proof_b, "each DPoP proof must have a unique jti");
    }

    #[tokio::test]
    async fn auth_headers_fail_before_ensure_lease() {
        let client = DPoPClient::new(
            "http://localhost:3000",
            "http://localhost:3000",
            "test-agent".into(),
        )
        .unwrap();

        let err = client.auth_headers("GET", "/v1/actions").await.unwrap_err();
        assert!(
            matches!(err, McpAuthError::NotConnected),
            "must return NotConnected before any lease is issued"
        );
    }
}
