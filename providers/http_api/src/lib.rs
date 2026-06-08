//! LatchGate HTTP API provider.
//!
//! This is a .wasm component that executes HTTP API calls on behalf of
//! the LatchGate kernel. It imports `latchgate:io/http` for host-mediated
//! outbound HTTP requests.
//!
//! # Request format (args_json)
//!
//! ```json
//! {
//!   "url": "https://api.example.com/endpoint",
//!   "method": "POST",
//!   "headers": { "Content-Type": "application/json" },
//!   "body": { "key": "value" },
//!   "timeout_ms": 30000
//! }
//! ```
//!
//! # Response format (returned JSON)
//!
//! ```json
//! {
//!   "ok": true,
//!   "data": {
//!     "status_code": 200,
//!     "headers": { "content-type": "application/json" },
//!     "body": "...",
//!     "url": "https://api.example.com/endpoint"
//!   }
//! }
//! ```
//!
//! # Security
//!
//! - URL is validated against allowed_sinks by the host before any request.
//! - Credentials (Authorization, API-Key) are injected by the host.
//! - This module never sees or handles credentials.
//! - Resource limits (fuel, memory, I/O budget) enforced by the host.

// Generate guest-side bindings from WIT definitions.
wit_bindgen::generate!({
    world: "provider",
    path: "../wit",
});

use serde::{Deserialize, Serialize};

use crate::latchgate::provider::io_http;
use crate::latchgate::provider::io_log;

/// Parsed action arguments from the pipeline.
#[derive(Deserialize)]
struct HttpApiRequest {
    /// Target URL (validated against allowed_sinks by the host).
    url: String,

    /// HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS).
    #[serde(default = "default_method")]
    method: String,

    /// Additional headers to send (credentials injected by host).
    #[serde(default)]
    headers: std::collections::HashMap<String, String>,

    /// Request body (serialised to JSON bytes if present).
    #[serde(default)]
    body: Option<serde_json::Value>,

    /// Request timeout in milliseconds (default: 30000).
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u32,
}

fn default_method() -> String {
    "GET".into()
}

fn default_timeout_ms() -> u32 {
    30_000
}

/// Structured response returned to the pipeline.
/// Follows the standard action contract: { ok, data?, error? }
#[derive(Serialize)]
struct HttpApiResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<HttpApiData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<HttpApiError>,
}

#[derive(Serialize)]
struct HttpApiData {
    status_code: u16,
    headers: std::collections::HashMap<String, String>,
    body: String,
    url: String,
}

#[derive(Serialize)]
struct HttpApiError {
    code: String,
    message: String,
}

/// Provider implementation.
struct HttpApiProvider;

impl Guest for HttpApiProvider {
    fn execute(task_json: String) -> Result<String, String> {
        io_log::log_info("http_api provider: parsing request");

        // Parse action arguments.
        let req: HttpApiRequest = serde_json::from_str(&task_json)
            .map_err(|e| format!("invalid request JSON: {e}"))?;

        io_log::log_info(&format!(
            "http_api provider: {} {}",
            req.method, req.url
        ));

        // Build WIT HTTP request.
        let headers: Vec<(String, String)> = req
            .headers
            .into_iter()
            .collect();

        let body = req.body
            .map(|b| serde_json::to_vec(&b).map_err(|e| format!("serialize request body: {e}")))
            .transpose()?;

        let http_req = io_http::HttpRequest {
            method: req.method,
            url: req.url,
            headers,
            body,
            timeout_ms: req.timeout_ms,
        };

        // Call host HTTP import. The host validates sinks and injects
        // credentials — this module never sees auth tokens.
        let http_resp = io_http::request(&http_req)?;

        io_log::log_info(&format!(
            "http_api provider: response status {}",
            http_resp.status
        ));

        // Build structured response.
        let resp_headers: std::collections::HashMap<String, String> = http_resp
            .headers
            .into_iter()
            .collect();

        let body_str = String::from_utf8(http_resp.body)
            .unwrap_or_else(|_| "<binary>".into());

        let response = HttpApiResponse {
            ok: true,
            data: Some(HttpApiData {
                status_code: http_resp.status,
                headers: resp_headers,
                body: body_str,
                url: http_req.url,
            }),
            error: None,
        };

        serde_json::to_string(&response)
            .map_err(|e| format!("failed to serialise response: {e}"))
    }
}

export!(HttpApiProvider);
