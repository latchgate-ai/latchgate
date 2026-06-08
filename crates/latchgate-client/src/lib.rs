//! Thin HTTP client for CLI => Gate communication.
//!
//! Supports Unix Domain Socket (default, preferred) and TCP transports,
//! driven by the active [`latchgate_config::Config`].
//!
//! # Operator authentication
//!
//! Two schemes are supported, matching the server's `verify_operator_auth`:
//!
//! - **DPoP**: `Authorization: DPoP <token>` + `DPoP: <proof>`.
//!   Requires an operator API key and a P-256 private key. The CLI constructs
//!   a fresh DPoP proof for every request, binding `htm`, `htu`, `ath`, and
//!   a unique `jti`.
//!
//! All operator commands require `--operator-private-key`.

pub mod auth;
mod endpoints;
pub(crate) mod transport;

pub use auth::{auto_discover_operator_auth, OperatorAuth};
pub use transport::Transport;

use serde_json::Value;
use thiserror::Error;

use latchgate_auth::{compute_ath, sign_dpop_proof};
use latchgate_config::Config;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("gate not reachable: {0}")]
    NotReachable(String),

    #[error("HTTP error {status}: {body}")]
    Http { status: u16, body: String },

    #[error("invalid response: {0}")]
    InvalidResponse(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("DPoP proof signing failed: {0}")]
    DpopSigningFailed(String),
}

/// Parameters for `GET /v1/audit/events`.
///
#[derive(Debug, Default, serde::Serialize)]
pub struct AuditParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

impl AuditParams {
    pub fn to_query(&self) -> String {
        serde_urlencoded::to_string(self).unwrap_or_default()
    }
}

pub(crate) fn query_path(base: &str, params: &[(&str, &str)]) -> String {
    if params.is_empty() {
        return base.to_string();
    }
    let qs = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params)
        .finish();
    format!("{base}?{qs}")
}

struct AuthHeaders {
    authorization: String,
    dpop_proof: Option<String>,
}

fn build_auth_headers(
    auth: &OperatorAuth,
    method: &str,
    full_url: &str,
) -> Result<AuthHeaders, ClientError> {
    let OperatorAuth { token, signing_key } = auth;
    let ath = compute_ath(token);
    let jti = uuid::Uuid::now_v7().to_string();
    let proof = sign_dpop_proof(signing_key, method, full_url, &ath, &jti)
        .map_err(|e| ClientError::DpopSigningFailed(e.to_string()))?;

    Ok(AuthHeaders {
        authorization: format!("DPoP {token}"),
        dpop_proof: Some(proof),
    })
}

pub struct GateClient {
    transport: Transport,
}

impl GateClient {
    /// Build a client from the active config.
    pub fn from_config(config: &Config) -> Result<Self, ClientError> {
        Ok(Self {
            transport: Transport::from_config(config)?,
        })
    }

    /// Full URL for DPoP `htu` binding.
    fn full_url(&self, path: &str) -> String {
        self.transport.full_url(path)
    }

    // ── Core request helpers ────────────────────────────────────────────────

    /// Unauthenticated GET, parsed as JSON.
    async fn get_json(&self, path: &str) -> Result<Value, ClientError> {
        let body = self.get(path).await?;
        Self::parse_json(&body)
    }

    /// Authenticated GET, parsed as JSON.
    async fn get_json_auth(&self, path: &str, auth: &OperatorAuth) -> Result<Value, ClientError> {
        let body = self.request_authenticated("GET", path, &[], auth).await?;
        Self::parse_json(&body)
    }

    /// Authenticated GET, extracting a named JSON array field.
    async fn get_array_auth(
        &self,
        path: &str,
        field: &'static str,
        auth: &OperatorAuth,
    ) -> Result<Vec<Value>, ClientError> {
        let body = self.request_authenticated("GET", path, &[], auth).await?;
        Self::parse_json_array(&body, field)
    }

    /// Authenticated POST with optional JSON body, parsed as JSON.
    async fn post_json_auth(
        &self,
        path: &str,
        body: Option<&Value>,
        auth: &OperatorAuth,
    ) -> Result<Value, ClientError> {
        let payload = body.map(|v| v.to_string().into_bytes()).unwrap_or_default();
        let resp = self
            .request_authenticated("POST", path, &payload, auth)
            .await?;
        if resp.is_empty() {
            return Ok(Value::Null);
        }
        Self::parse_json(&resp)
    }

    /// Authenticated DELETE with optional JSON body, parsed as JSON.
    async fn delete_json_auth(
        &self,
        path: &str,
        body: Option<&Value>,
        auth: &OperatorAuth,
    ) -> Result<Value, ClientError> {
        let payload = body.map(|v| v.to_string().into_bytes()).unwrap_or_default();
        let resp = self
            .request_authenticated("DELETE", path, &payload, auth)
            .await?;
        if resp.is_empty() {
            return Ok(Value::Null);
        }
        Self::parse_json(&resp)
    }

    // ── Transport ─────────────────────────────────────────────────────────────

    async fn get(&self, path: &str) -> Result<String, ClientError> {
        let (_status, body) = self.transport.request("GET", path, &[], &[]).await?;
        Ok(body)
    }

    /// Authenticated HTTP request with DPoP proof generation.
    async fn request_authenticated(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        auth: &OperatorAuth,
    ) -> Result<String, ClientError> {
        let full_url = self.full_url(path);
        let headers = build_auth_headers(auth, method, &full_url)?;
        let mut h: Vec<(&str, &str)> = vec![("authorization", &headers.authorization)];
        if let Some(ref proof) = headers.dpop_proof {
            h.push(("dpop", proof));
        }
        let (_status, resp) = self.transport.request(method, path, body, &h).await?;
        Ok(resp)
    }

    fn parse_json(body: &str) -> Result<Value, ClientError> {
        serde_json::from_str(body).map_err(|e| ClientError::InvalidResponse(e.to_string()))
    }

    fn parse_json_array(body: &str, field: &'static str) -> Result<Vec<Value>, ClientError> {
        let json = Self::parse_json(body)?;
        json[field]
            .as_array()
            .cloned()
            .ok_or_else(|| ClientError::InvalidResponse(format!("missing '{field}' field")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_path_empty_params_returns_base() {
        assert_eq!(query_path("/v1/foo", &[]), "/v1/foo");
    }

    #[test]
    fn query_path_encodes_values() {
        let result = query_path(
            "/v1/foo",
            &[("key", "hello world"), ("t", "2024-01-01T00:00:00+00:00")],
        );
        assert!(result.starts_with("/v1/foo?"));
        assert!(result.contains("key=hello+world") || result.contains("key=hello%20world"));
        assert!(!result.contains(":00"));
    }

    #[test]
    fn audit_params_empty_produces_empty_query() {
        let params = AuditParams::default();
        assert_eq!(params.to_query(), "");
    }

    #[test]
    fn audit_params_encodes_set_fields() {
        let params = AuditParams {
            trace_id: Some("abc-123".into()),
            limit: Some(50),
            ..Default::default()
        };
        let qs = params.to_query();
        assert!(qs.contains("trace_id=abc-123"));
        assert!(qs.contains("limit=50"));
        assert!(!qs.contains("event_type"));
    }
}
