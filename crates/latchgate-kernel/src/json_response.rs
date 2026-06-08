//! Zero-allocation JSON response builder for HTTP error and status bodies.
//!
//! Every HTTP response body in LatchGate follows the shape
//! `{"error":"<code>", ...}` (errors) or `{"<key>":"<value>", ...}` (status
//! responses like 202 Approval). This module builds the JSON directly into
//! a pre-sized `String`, avoiding `serde_json::Value`, `BTreeMap`, and the
//! `serde_json::to_vec` serialization pass entirely.
//!
//! All user-controlled values are JSON-escaped via
//! [`latchgate_core::json_escape_into`] to prevent injection.
//!
//! # Usage
//!
//! ```ignore
//! // Simple error: {"error":"unauthorized"}
//! JsonResponse::new(StatusCode::UNAUTHORIZED, "unauthorized")
//!
//! // Error with detail: {"error":"bad_request","detail":"missing field"}
//! JsonResponse::new(StatusCode::BAD_REQUEST, "bad_request")
//!     .field("detail", "missing field")
//!
//! // Non-error response: {"decision":"pending_approval","approval_id":"..."}
//! JsonResponse::with_key(StatusCode::ACCEPTED, "decision", "pending_approval")
//!     .field("approval_id", &id)
//!
//! // Extra headers (rate limiting):
//! JsonResponse::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited")
//!     .header("retry-after", "1")
//! ```

use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

/// `application/json` header value, created once at program start.
static JSON_CT: HeaderValue = HeaderValue::from_static("application/json");

/// Pre-serialized JSON response body with optional extra headers.
///
/// All string values are JSON-escaped at the boundary — callers pass
/// raw strings and the builder handles escaping.
pub struct JsonResponse {
    status: StatusCode,
    /// Partial JSON body, open (no trailing `}`). Example state after
    /// `new(200, "ok").field("k", "v")`: `{"error":"ok","k":"v"`
    body: String,
    extra_headers: Vec<(&'static str, &'static str)>,
}

impl JsonResponse {
    /// Start a standard error response: `{"error":"<code>"`.
    ///
    /// The `code` is a machine-readable error identifier (e.g. `"unauthorized"`,
    /// `"rate_limited"`). JSON-escaped for defense-in-depth.
    pub fn new(status: StatusCode, code: &str) -> Self {
        Self::with_key(status, "error", code)
    }

    /// Start a response with an arbitrary first key: `{"<key>":"<value>"`.
    ///
    /// Used for non-error responses (e.g. 202 Approval with `"decision"`).
    pub fn with_key(status: StatusCode, key: &str, value: &str) -> Self {
        let mut body = String::with_capacity(8 + key.len() + value.len());
        body.push_str("{\"");
        latchgate_core::json_escape_into(&mut body, key);
        body.push_str("\":\"");
        latchgate_core::json_escape_into(&mut body, value);
        body.push('"');
        Self {
            status,
            body,
            extra_headers: Vec::new(),
        }
    }

    /// Append a JSON field: `,"<key>":"<value>"`.
    ///
    /// Both key and value are JSON-escaped. Can be chained.
    #[inline]
    pub fn field(mut self, key: &str, value: &str) -> Self {
        self.body.push_str(",\"");
        latchgate_core::json_escape_into(&mut self.body, key);
        self.body.push_str("\":\"");
        latchgate_core::json_escape_into(&mut self.body, value);
        self.body.push('"');
        self
    }

    /// Add an extra HTTP header to the response.
    ///
    /// Used for `Retry-After` on 429 responses. Values are static strings
    /// to avoid allocation.
    #[inline]
    pub fn header(mut self, name: &'static str, value: &'static str) -> Self {
        self.extra_headers.push((name, value));
        self
    }
}

impl std::fmt::Debug for JsonResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonResponse")
            .field("status", &self.status.as_u16())
            .finish_non_exhaustive()
    }
}

impl IntoResponse for JsonResponse {
    fn into_response(self) -> Response {
        let mut body = self.body;
        body.push('}');

        if self.extra_headers.is_empty() {
            return (self.status, [(CONTENT_TYPE, JSON_CT.clone())], body).into_response();
        }

        let mut resp = (self.status, [(CONTENT_TYPE, JSON_CT.clone())], body).into_response();
        for (name, value) in &self.extra_headers {
            resp.headers_mut()
                .insert(*name, HeaderValue::from_static(value));
        }
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn body_string(resp: Response) -> String {
        let bytes = to_bytes(resp.into_body(), 65536).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn simple_error_format() {
        let resp = JsonResponse::new(StatusCode::UNAUTHORIZED, "unauthorized").into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_string(resp).await, r#"{"error":"unauthorized"}"#,);
    }

    #[tokio::test]
    async fn chained_fields() {
        let resp = JsonResponse::new(StatusCode::FORBIDDEN, "policy_denied")
            .field("principal", "agent-1")
            .field("action_id", "web_read")
            .into_response();
        let body = body_string(resp).await;
        assert_eq!(
            body,
            r#"{"error":"policy_denied","principal":"agent-1","action_id":"web_read"}"#,
        );
    }

    #[tokio::test]
    async fn with_key_non_error() {
        let resp = JsonResponse::with_key(StatusCode::ACCEPTED, "decision", "pending_approval")
            .field("approval_id", "apr-1")
            .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        assert_eq!(
            body_string(resp).await,
            r#"{"decision":"pending_approval","approval_id":"apr-1"}"#,
        );
    }

    #[tokio::test]
    async fn json_escaping() {
        let resp = JsonResponse::new(StatusCode::BAD_REQUEST, "bad")
            .field("detail", "has \"quotes\" and \nnewlines")
            .into_response();
        assert_eq!(
            body_string(resp).await,
            r#"{"error":"bad","detail":"has \"quotes\" and \nnewlines"}"#,
        );
    }

    #[tokio::test]
    async fn content_type_is_json() {
        let resp = JsonResponse::new(StatusCode::INTERNAL_SERVER_ERROR, "x").into_response();
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/json",
        );
    }

    #[tokio::test]
    async fn extra_header() {
        let resp = JsonResponse::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited")
            .header("retry-after", "2")
            .into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers().get("retry-after").unwrap().to_str().unwrap(),
            "2",
        );
    }
}
