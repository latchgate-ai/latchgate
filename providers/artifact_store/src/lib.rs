//! LatchGate Artifact Store provider.
//!
//! Stores objects via the host-mediated storage import. The host manages
//! S3-compatible connections, TLS, and credential injection.
//!
//! # Request format
//!
//! ```json
//! {
//!   "bucket": "artifacts",
//!   "key": "reports/2025/q1.pdf",
//!   "content_base64": "...",
//!   "content_type": "application/pdf"
//! }
//! ```

wit_bindgen::generate!({
    world: "provider",
    path: "../wit",
});

use serde::{Deserialize, Serialize};

use crate::latchgate::provider::io_log;
use crate::latchgate::provider::io_storage;

#[derive(Deserialize)]
struct StoreRequest {
    bucket: String,
    key: String,
    /// Base64-encoded content.
    content_base64: String,
    #[serde(default)]
    content_type: Option<String>,
}

#[derive(Serialize)]
struct StoreResponse {
    artifact_id: String,
    content_hash: String,
    bytes_written: u64,
}

struct ArtifactStoreProvider;

impl Guest for ArtifactStoreProvider {
    fn execute(task_json: String) -> Result<String, String> {
        io_log::log_info("artifact_store provider: parsing request");

        let req: StoreRequest = serde_json::from_str(&task_json)
            .map_err(|e| format!("invalid request JSON: {e}"))?;

        // Decode base64 content.
        let content = base64_decode(&req.content_base64)
            .map_err(|e| format!("invalid base64: {e}"))?;

        let put_req = io_storage::PutRequest {
            bucket: req.bucket,
            key: req.key,
            content,
            content_type: req.content_type,
        };

        let receipt = io_storage::put_object(&put_req)?;

        let response = StoreResponse {
            artifact_id: receipt.artifact_id,
            content_hash: receipt.content_hash,
            bytes_written: receipt.bytes_written,
        };

        serde_json::to_string(&response)
            .map_err(|e| format!("failed to serialise response: {e}"))
    }
}

/// Base64 decoder supporting both standard (RFC 4648 §4) and URL-safe
/// (RFC 4648 §5) alphabets, with or without `=` padding.
///
/// Standard:  `+` and `/`, may include `=` padding.
/// URL-safe:  `-` and `_`, padding optional (common in JWTs, web APIs).
///
/// Normalises URL-safe input to standard before decoding so a single
/// lookup table handles both forms.
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    // Normalise URL-safe alphabet to standard alphabet before lookup.
    // This is a cheap allocation — artifact content is already base64-encoded
    // so an extra pass over the ASCII envelope is acceptable.
    let normalised: String = input
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();

    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(normalised.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for &b in normalised.as_bytes() {
        // Skip padding and whitespace (both are valid in encoded input).
        if b == b'=' || b == b'\n' || b == b'\r' || b == b' ' {
            continue;
        }
        let val = TABLE
            .iter()
            .position(|&c| c == b)
            .ok_or_else(|| format!("invalid base64 character: {:?}", b as char))? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Ok(out)
}

export!(ArtifactStoreProvider);
