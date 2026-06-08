//! LatchGate filesystem provider.
//!
//! A .wasm component that executes filesystem operations on behalf of the
//! LatchGate kernel. Imports `latchgate:io/fs` for host-mediated file I/O.
//!
//! The provider has zero ambient filesystem authority. Every operation
//! traverses the host's path-validation pipeline before any syscall.
//!
//! # Operations
//!
//! The `operation` field in the request JSON selects the action:
//!
//! - **read**  — read a file, return content + SHA-256 hash.
//! - **write** — decode `content_base64`, call host write (create or overwrite).
//! - **delete** — remove a regular file via the host unlink pipeline.
//!
//! # Security
//!
//! - Paths are validated by the host against allow/deny lists.
//! - Base64 decode happens here; the host receives raw bytes.
//! - `expected_before_hash` is parsed from `sha256:<hex>` and forwarded.
//! - This module never touches the filesystem directly.

wit_bindgen::generate!({
    world: "provider",
    path: "../wit",
});

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::latchgate::provider::io_fs;
use crate::latchgate::provider::io_log;

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

/// Parsed action arguments from the pipeline.
#[derive(Deserialize)]
struct FsRequest {
    /// Which operation to perform: "read", "write", or "delete".
    operation: String,

    /// Relative path (validated by the host against grant allowlists).
    path: String,

    /// Base64-encoded file content (write only).
    #[serde(default)]
    content_base64: Option<String>,

    /// Write mode: "create" or "overwrite" (write only, default: "overwrite").
    #[serde(default = "default_mode")]
    mode: String,

    /// Optimistic concurrency guard: `sha256:<64-hex>` (write-overwrite only).
    #[serde(default)]
    expected_before_hash: Option<String>,
}

fn default_mode() -> String {
    "overwrite".into()
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct FsResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<FsErrorResponse>,
}

#[derive(Serialize)]
struct FsErrorResponse {
    code: String,
    message: String,
}

impl FsResponse {
    fn success(data: serde_json::Value) -> Self {
        Self {
            ok: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(code: &str, message: String) -> Self {
        Self {
            ok: false,
            data: None,
            error: Some(FsErrorResponse {
                code: code.to_string(),
                message,
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

struct FsProvider;

impl Guest for FsProvider {
    fn execute(task_json: String) -> Result<String, String> {
        io_log::log_info("fs provider: parsing request");

        let req: FsRequest =
            serde_json::from_str(&task_json).map_err(|e| format!("invalid request JSON: {e}"))?;

        io_log::log_info(&format!("fs provider: {} {}", req.operation, req.path));

        let response = match req.operation.as_str() {
            "read" => execute_read(&req),
            "write" => execute_write(&req),
            "delete" => execute_delete(&req),
            other => FsResponse::error(
                "invalid_operation",
                format!("unknown operation: {other}"),
            ),
        };

        serde_json::to_string(&response).map_err(|e| format!("failed to serialise response: {e}"))
    }
}

export!(FsProvider);

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

fn execute_read(req: &FsRequest) -> FsResponse {
    let input = io_fs::FsReadInput {
        path: req.path.clone(),
    };

    match io_fs::read(&input) {
        Ok(output) => {
            let hash_hex = hex_encode(&output.hash);
            FsResponse::success(serde_json::json!({
                "path": req.path,
                "size_bytes": output.size_bytes,
                "hash": format!("sha256:{hash_hex}"),
                "content_base64": base64_encode(&output.content),
            }))
        }
        Err(e) => FsResponse::error(&fs_error_code(&e), fs_error_message(&e, &req.path)),
    }
}

fn execute_write(req: &FsRequest) -> FsResponse {
    // Decode base64 content.
    let content_b64 = match req.content_base64.as_deref() {
        Some(b64) => b64,
        None => {
            return FsResponse::error(
                "invalid_content",
                "write operation requires content_base64".into(),
            );
        }
    };

    let content = match base64::engine::general_purpose::STANDARD.decode(content_b64) {
        Ok(bytes) => bytes,
        Err(e) => {
            return FsResponse::error("invalid_content", format!("base64 decode failed: {e}"));
        }
    };

    // Parse write mode.
    let mode = match req.mode.as_str() {
        "create" => io_fs::FsWriteMode::Create,
        "overwrite" => io_fs::FsWriteMode::Overwrite,
        other => {
            return FsResponse::error(
                "invalid_operation",
                format!("unknown write mode: {other}"),
            );
        }
    };

    // Parse optional expected_before_hash from "sha256:<64hex>".
    let expected_hash = match req.expected_before_hash.as_deref() {
        Some(s) => match parse_sha256_prefixed(s) {
            Ok(bytes) => Some(bytes),
            Err(msg) => {
                return FsResponse::error("invalid_content", msg);
            }
        },
        None => None,
    };

    let input = io_fs::FsWriteInput {
        path: req.path.clone(),
        content,
        mode,
        expected_before_hash: expected_hash,
    };

    match io_fs::write(&input) {
        Ok(output) => {
            let after_hex = hex_encode(&output.after_hash);
            let mut data = serde_json::json!({
                "path": req.path,
                "after_hash": format!("sha256:{after_hex}"),
                "bytes_written": output.bytes_written,
            });

            if let Some(ref before) = output.before_hash {
                let before_hex = hex_encode(before);
                data["before_hash"] = serde_json::json!(format!("sha256:{before_hex}"));
                data["bytes_before"] = serde_json::json!(output.bytes_before);
            }

            FsResponse::success(data)
        }
        Err(e) => FsResponse::error(&fs_error_code(&e), fs_error_message(&e, &req.path)),
    }
}

fn execute_delete(req: &FsRequest) -> FsResponse {
    let input = io_fs::FsDeleteInput {
        path: req.path.clone(),
    };

    match io_fs::delete(&input) {
        Ok(_) => FsResponse::success(serde_json::json!({
            "path": req.path,
            "deleted": true,
        })),
        Err(e) => FsResponse::error(&fs_error_code(&e), fs_error_message(&e, &req.path)),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse `sha256:<64 hex chars>` into raw bytes.
fn parse_sha256_prefixed(s: &str) -> Result<Vec<u8>, String> {
    let hex_str = s
        .strip_prefix("sha256:")
        .ok_or_else(|| format!("expected_before_hash must start with 'sha256:': {s}"))?;

    if hex_str.len() != 64 {
        return Err(format!(
            "expected_before_hash hex must be 64 chars, got {}",
            hex_str.len()
        ));
    }

    hex_decode(hex_str).map_err(|e| format!("expected_before_hash hex decode failed: {e}"))
}

/// Encode bytes as lowercase hex.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_CHARS[(b >> 4) as usize]);
        s.push(HEX_CHARS[(b & 0x0f) as usize]);
    }
    s
}

const HEX_CHARS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

/// Decode a hex string into bytes.
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd-length hex string".into());
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    let chars = s.as_bytes();
    for i in (0..chars.len()).step_by(2) {
        let hi = hex_nibble(chars[i])?;
        let lo = hex_nibble(chars[i + 1])?;
        bytes.push((hi << 4) | lo);
    }
    Ok(bytes)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex character: {:?}", b as char)),
    }
}

/// Encode bytes to standard base64.
fn base64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Map `FsError` to a stable error code string.
fn fs_error_code(e: &io_fs::FsError) -> String {
    match e {
        io_fs::FsError::OperationNotAllowed => "operation_not_allowed",
        io_fs::FsError::PathNotAllowed => "path_not_allowed",
        io_fs::FsError::PathDenied => "path_denied",
        io_fs::FsError::PathNotFound => "path_not_found",
        io_fs::FsError::PathInvalid => "path_invalid",
        io_fs::FsError::AlreadyExists => "already_exists",
        io_fs::FsError::TooLarge => "too_large",
        io_fs::FsError::SymlinkEscape => "symlink_escape",
        io_fs::FsError::Traversal => "traversal",
        io_fs::FsError::SpecialFile => "special_file",
        io_fs::FsError::Conflict => "conflict",
        io_fs::FsError::InvalidContent => "invalid_content",
        io_fs::FsError::IoError => "io_error",
    }
    .into()
}

/// Human-readable error message for a given `FsError`.
fn fs_error_message(e: &io_fs::FsError, path: &str) -> String {
    match e {
        io_fs::FsError::OperationNotAllowed => {
            format!("operation not permitted by allowed_operations for: {path}")
        }
        io_fs::FsError::PathNotAllowed => {
            format!("path not covered by allowed_paths: {path}")
        }
        io_fs::FsError::PathDenied => format!("path matched denied_paths: {path}"),
        io_fs::FsError::PathNotFound => format!("file not found: {path}"),
        io_fs::FsError::PathInvalid => format!("invalid path: {path}"),
        io_fs::FsError::AlreadyExists => format!("file already exists: {path}"),
        io_fs::FsError::TooLarge => format!("content exceeds max_file_bytes: {path}"),
        io_fs::FsError::SymlinkEscape => {
            format!("symlink escape detected: {path}")
        }
        io_fs::FsError::Traversal => format!("path traversal rejected: {path}"),
        io_fs::FsError::SpecialFile => {
            format!("target is not a regular file: {path}")
        }
        io_fs::FsError::Conflict => {
            format!("expected_before_hash mismatch (concurrent modification): {path}")
        }
        io_fs::FsError::InvalidContent => "base64 decode failure".into(),
        io_fs::FsError::IoError => format!("I/O error: {path}"),
    }
}
