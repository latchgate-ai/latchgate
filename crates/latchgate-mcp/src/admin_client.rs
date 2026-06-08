//! Operator-authenticated client for the LatchGate admin API.
//!
//! # Security
//!
//! The operator private key is held only in this struct's `signing_key`
//! field. It is never serialized, logged, or exposed via MCP responses.
//! The operator token (`api_key`) is held in memory and used solely for
//! DPoP proof construction.
//!
//! `AdminError` is distinct from `GateError` — admin transport failures
//! do not affect agent transport state or reconnection logic.

use std::borrow::Cow;
use std::path::Path;

use latchgate_auth::dpop::{compute_ath, sign_dpop_proof, DPoPSigningKey};
use latchgate_client::Transport;
use serde_json::{json, Value};
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::protocol::{
    tool_error_codes, ContentBlock, JsonRpcResponse, McpTool, McpToolAnnotations, RequestId,
    StructuredToolError,
};

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors from operator-side admin operations.
///
/// Intentionally distinct from [`crate::gate_client::GateError`] so that
/// admin transport failures do not trigger agent reconnection logic.
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("admin API returned HTTP {status}: {body}")]
    Http { status: u16, body: String },

    #[error("admin transport error: {0}")]
    Transport(String),

    #[error("DPoP proof signing failed: {0}")]
    Signing(String),

    #[error("invalid response: {0}")]
    InvalidResponse(String),
}

// ── Input validation ──────────────────────────────────────────────────────────

/// UUID format: exactly 36 hex-lowercase chars with hyphens.
///
/// Pattern: `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`
///
/// Enforced as a character-class check + length check rather than a regex
/// dependency. Rejects uppercase to match the gate's canonical UUID format.
fn validate_approval_id(id: &str) -> Result<(), AdminError> {
    if id.len() != 36 {
        return Err(AdminError::InvalidInput(
            "approval_id must be a 36-character UUID".into(),
        ));
    }
    // Expected positions of hyphens: 8, 13, 18, 23.
    let valid = id.bytes().enumerate().all(|(i, b)| {
        if i == 8 || i == 13 || i == 18 || i == 23 {
            b == b'-'
        } else {
            b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
        }
    });
    if !valid {
        return Err(AdminError::InvalidInput(
            "approval_id must match UUID format (lowercase hex with hyphens)".into(),
        ));
    }
    Ok(())
}

/// Validate an action_id or agent_id: ASCII alphanumeric, underscore, hyphen.
/// Length 1..=128.
fn validate_resource_id(id: &str, label: &str) -> Result<(), AdminError> {
    if id.is_empty() || id.len() > 128 {
        return Err(AdminError::InvalidInput(format!(
            "{label} must be 1-128 characters"
        )));
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(AdminError::InvalidInput(format!(
            "{label} contains invalid characters (allowed: a-z A-Z 0-9 _ -)"
        )));
    }
    Ok(())
}

/// Byte-level cap for operator denial reasons.
///
/// The JSON Schema `maxLength: 500` (codepoints) constrains at the protocol
/// level; this byte cap is defense-in-depth at the sanitization boundary.
/// 2000 bytes accommodates 500 codepoints at maximum UTF-8 width (4 bytes
/// each) without silently truncating any conforming input.
const REASON_MAX_BYTES: usize = 2000;

// ── AdminClient ───────────────────────────────────────────────────────────────

/// Operator-authenticated client for the LatchGate admin API.
///
/// SECURITY: the operator private key is held only in this struct's
/// `signing_key`. It is never serialized, logged, or exposed via MCP.
pub struct AdminClient {
    transport: Transport,
    signing_key: DPoPSigningKey,
    operator_token: String,
    operator_id: String,
}

impl AdminClient {
    /// Construct from pre-loaded components.
    ///
    /// The signing key must already be loaded from the PEM file. The caller
    /// is responsible for dropping the file handle after loading.
    pub fn new(
        transport: Transport,
        signing_key: DPoPSigningKey,
        operator_token: String,
        operator_id: String,
    ) -> Self {
        Self {
            transport,
            signing_key,
            operator_token,
            operator_id,
        }
    }

    /// Load the operator signing key from a PEM file.
    ///
    /// Reads the file, parses the key, and immediately drops the file
    /// handle. The PEM content is wrapped in [`Zeroizing`] to ensure the
    /// raw key material is overwritten on drop (normal or panic).
    ///
    /// # Security
    ///
    /// - PEM content is zeroed before deallocation via `Zeroizing<String>`.
    /// - Warns on loose file permissions (mode > 0o600) on Unix.
    pub fn load_signing_key(path: &Path) -> Result<DPoPSigningKey, String> {
        let pem = Zeroizing::new(
            std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read operator key '{}': {e}", path.display()))?,
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if let Ok(meta) = std::fs::metadata(path) {
                let mode = meta.mode() & 0o777;
                if mode & 0o077 != 0 {
                    warn!(
                        path = %path.display(),
                        mode = format!("{mode:04o}"),
                        "operator key file has loose permissions; recommend 0600",
                    );
                }
            }
        }

        DPoPSigningKey::from_pem(&pem)
            .map_err(|e| format!("invalid operator key '{}': {e}", path.display()))
    }

    /// Operator principal name.
    pub fn operator_id(&self) -> &str {
        &self.operator_id
    }

    /// Verify the operator credential against the admin API at startup.
    ///
    /// Performs an authenticated `GET /v1/approvals` — the operator's
    /// read surface — exercising the exact DPoP signing path that
    /// [`approve`](Self::approve) and [`deny`](Self::deny) use. This makes a
    /// misconfigured operator credential (wrong key, wrong token, revoked
    /// access) fail fast at boot with a clear message, rather than surfacing
    /// a confusing runtime 401 on the first approval and wasting a turn.
    ///
    /// Idempotent and side-effect-free: listing pending approvals mutates
    /// nothing.
    pub async fn verify_credential(&self) -> Result<(), AdminError> {
        self.authenticated_request("GET", "/v1/approvals", &[])
            .await
            .map(|_| ())
    }

    // ── Approval operations ──────────────────────────────────────────────

    /// Approve a pending action execution request.
    pub async fn approve(&self, approval_id: &str) -> Result<Value, AdminError> {
        validate_approval_id(approval_id)?;
        let path = format!("/v1/approvals/{approval_id}/approve");
        self.authenticated_request("POST", &path, &[]).await
    }

    /// Deny a pending action execution request.
    pub async fn deny(&self, approval_id: &str, reason: Option<&str>) -> Result<Value, AdminError> {
        validate_approval_id(approval_id)?;
        let body = match reason {
            Some(r) => {
                let sanitized = latchgate_core::sanitize_for_log(r, REASON_MAX_BYTES);
                serde_json::to_vec(&json!({ "reason": &*sanitized }))
                    .map_err(|e| AdminError::InvalidInput(e.to_string()))?
            }
            None => Vec::new(),
        };
        let path = format!("/v1/approvals/{approval_id}/deny");
        self.authenticated_request("POST", &path, &body).await
    }

    /// List pending approvals visible to the operator.
    ///
    /// Returns the approval summaries from `GET /v1/approvals?status=pending`.
    /// Read-only — no state mutations.
    pub async fn list_pending(&self) -> Result<Value, AdminError> {
        self.authenticated_request("GET", "/v1/approvals?status=pending", &[])
            .await
    }

    /// Fetch the most recent audit ledger entries.
    ///
    /// Returns the last `limit` entries from `GET /v1/audit/recent?limit=N`.
    /// Read-only — no state mutations.
    pub async fn audit_recent(&self, limit: u32) -> Result<Value, AdminError> {
        let path = format!("/v1/audit/recent?limit={limit}");
        self.authenticated_request("GET", &path, &[]).await
    }

    /// Fetch audit ledger entries for a specific trace_id.
    ///
    /// Used by the `explain_denial` prompt to retrieve the policy chain,
    /// budget state, and egress rules that applied to a denied action.
    /// Read-only — no state mutations.
    pub async fn audit_by_trace_id(&self, trace_id: &str) -> Result<Value, AdminError> {
        validate_resource_id(trace_id, "trace_id")?;
        let path = format!("/v1/audit?trace_id={trace_id}");
        self.authenticated_request("GET", &path, &[]).await
    }

    /// Retrieve the full detail of a single approval for operator review.
    ///
    /// Returns the enriched approval detail from `GET /v1/approvals/{id}`,
    /// including plan review fields (targets, secrets names, risk level,
    /// budget snapshot, provider digest).
    pub async fn get_approval(&self, approval_id: &str) -> Result<Value, AdminError> {
        validate_approval_id(approval_id)?;
        let path = format!("/v1/approvals/{approval_id}");
        self.authenticated_request("GET", &path, &[]).await
    }

    /// Add a scoped allowlist entry (action + agent bypass approval gate).
    pub async fn allowlist(&self, action_id: &str, agent_id: &str) -> Result<Value, AdminError> {
        validate_resource_id(action_id, "action_id")?;
        validate_resource_id(agent_id, "agent_id")?;
        let body = serde_json::to_vec(&json!({
            "action_id": action_id,
            "agent_id": agent_id,
        }))
        .map_err(|e| AdminError::InvalidInput(e.to_string()))?;
        self.authenticated_request("POST", "/v1/admin/policy/allowlist", &body)
            .await
    }

    // ── Transport ────────────────────────────────────────────────────────

    async fn authenticated_request(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<Value, AdminError> {
        // Defense-in-depth: RFC 9449 §4.2 requires htu = scheme + authority
        // + path, no query or fragment. `sign_dpop_proof` normalizes internally
        // via `normalize_htu`, so this is not strictly necessary — but stripping
        // at the call site makes the invariant visible here and protects against
        // a future refactor that removes the internal normalization.
        let htu_path = path.split('?').next().unwrap_or(path);
        let htu = self.transport.full_url(htu_path);
        let ath = compute_ath(&self.operator_token);
        let jti = uuid::Uuid::now_v7().to_string();

        let proof = sign_dpop_proof(&self.signing_key, method, &htu, &ath, &jti)
            .map_err(|e| AdminError::Signing(e.to_string()))?;

        debug!(
            method,
            path,
            jti = %jti,
            operator_id = %self.operator_id,
            "admin request"
        );

        let authorization = format!("DPoP {}", self.operator_token);
        let headers = [
            ("authorization", authorization.as_str()),
            ("dpop", proof.as_str()),
        ];

        let (_, response_body) = self
            .transport
            .request(method, path, body, &headers)
            .await
            .map_err(|e| match e {
                latchgate_client::ClientError::Http { status, body } => {
                    AdminError::Http { status, body }
                }
                other => AdminError::Transport(other.to_string()),
            })?;

        serde_json::from_str(&response_body).map_err(|e| AdminError::InvalidResponse(e.to_string()))
    }
}

// SECURITY: Debug impl redacts key material and token.
impl std::fmt::Debug for AdminClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminClient")
            .field("operator_id", &self.operator_id)
            .field("signing_key", &"[redacted]")
            .field("operator_token", &"[redacted]")
            .finish()
    }
}

// ── Static tool definitions ───────────────────────────────────────────────────

/// Operator-only MCP tool annotations shared by all approval tools.
///
/// `destructiveHint: true` triggers IDE confirmation dialogs (Cursor,
/// Claude Desktop, Cline). This is the primary UX gate preventing
/// accidental approvals.
fn approval_annotations() -> McpToolAnnotations {
    McpToolAnnotations {
        read_only_hint: Some(false),
        destructive_hint: Some(true),
        idempotent_hint: Some(true),
        open_world_hint: Some(false),
    }
}

/// Operator-only annotations for read-only approval tools.
///
/// `readOnlyHint: true` signals that no side effects occur. IDEs may
/// skip confirmation dialogs for these tools.
fn approval_read_annotations() -> McpToolAnnotations {
    McpToolAnnotations {
        read_only_hint: Some(true),
        destructive_hint: Some(false),
        idempotent_hint: Some(true),
        open_world_hint: Some(false),
    }
}

/// Build the static `latchgate_list_pending` tool definition.
fn tool_list_pending() -> McpTool {
    McpTool {
        name: "latchgate_list_pending".into(),
        description: "List pending LatchGate approvals awaiting operator decision. \
                       Returns approval summaries with action, principal, risk level, \
                       and expiry. Use latchgate_get_approval for full review detail."
            .into(),
        input_schema: json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        }),
        annotations: Some(approval_read_annotations()),
    }
}

/// Build the static `latchgate_get_approval` tool definition.
fn tool_get_approval() -> McpTool {
    McpTool {
        name: "latchgate_get_approval".into(),
        description: "Get full detail of a pending approval for operator review. \
                       Includes the execution plan: approved targets, secret names \
                       (never values), risk level, provider digest, budget snapshot, \
                       and plan hash. Use this before approving to verify the scope."
            .into(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "approval_id": {
                    "type": "string",
                    "description": "The approval_id to inspect."
                }
            },
            "required": ["approval_id"],
            "additionalProperties": false
        }),
        annotations: Some(approval_read_annotations()),
    }
}

/// Build the static `latchgate_approve` tool definition.
fn tool_approve() -> McpTool {
    McpTool {
        name: "latchgate_approve".into(),
        description: "Approve a pending LatchGate action execution. \
                       This is an operator-only action that requires human confirmation."
            .into(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "approval_id": {
                    "type": "string",
                    "description": "The approval_id from the pending_approval response."
                }
            },
            "required": ["approval_id"],
            "additionalProperties": false
        }),
        annotations: Some(approval_annotations()),
    }
}

/// Build the static `latchgate_deny` tool definition.
fn tool_deny() -> McpTool {
    McpTool {
        name: "latchgate_deny".into(),
        description: "Deny a pending LatchGate action execution. \
                       This is an operator-only action that requires human confirmation."
            .into(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "approval_id": {
                    "type": "string",
                    "description": "The approval_id from the pending_approval response."
                },
                "reason": {
                    "type": "string",
                    "maxLength": 500,
                    "description": "Denial reason (recorded in audit trail)."
                }
            },
            "required": ["approval_id"],
            "additionalProperties": false
        }),
        annotations: Some(approval_annotations()),
    }
}

/// Build the static `latchgate_allowlist` tool definition.
fn tool_allowlist() -> McpTool {
    McpTool {
        name: "latchgate_allowlist".into(),
        description: "Permanently allow an action for an agent without requiring approval. \
                       This modifies security policy and requires explicit operator confirmation."
            .into(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "action_id": {
                    "type": "string",
                    "description": "Action to allowlist (e.g. 'github_read')."
                },
                "agent_id": {
                    "type": "string",
                    "description": "Agent principal. Defaults to the current agent."
                }
            },
            "required": ["action_id"],
            "additionalProperties": false
        }),
        annotations: Some(approval_annotations()),
    }
}

/// Return the set of approval tools that should be registered.
///
/// Only called when `AdminClient` is configured. The allowlist tool is
/// included only when `allowlist_enabled` is true (opt-in policy mutation).
pub fn approval_tools(allowlist_enabled: bool) -> Vec<McpTool> {
    let mut tools = vec![
        tool_list_pending(),
        tool_get_approval(),
        tool_approve(),
        tool_deny(),
    ];
    if allowlist_enabled {
        tools.push(tool_allowlist());
    }
    tools
}

/// Check whether a tool name is an approval tool.
pub fn is_approval_tool(name: &str) -> bool {
    matches!(
        name,
        "latchgate_approve"
            | "latchgate_deny"
            | "latchgate_list_pending"
            | "latchgate_get_approval"
            | "latchgate_allowlist"
    )
}

// ── MCP response builders ─────────────────────────────────────────────────────

/// Handle a `tools/call` for an approval tool, routing to the appropriate
/// `AdminClient` method and mapping the result to an MCP response.
pub async fn handle_approval_tool_call(
    admin: &AdminClient,
    allowlist_enabled: bool,
    default_agent_id: &str,
    id: Option<RequestId>,
    tool_name: &str,
    arguments: &Value,
    trace_id: &str,
) -> JsonRpcResponse {
    match tool_name {
        "latchgate_list_pending" => match admin.list_pending().await {
            Ok(resp) => admin_success(id, &resp),
            Err(e) => map_admin_error(id, e, tool_name, trace_id),
        },
        "latchgate_get_approval" => {
            let approval_id = match arguments["approval_id"].as_str() {
                Some(s) => s,
                None => {
                    return admin_input_error(
                        id,
                        "Missing required field 'approval_id'.",
                        tool_name,
                        trace_id,
                    );
                }
            };
            match admin.get_approval(approval_id).await {
                Ok(resp) => admin_success(id, &resp),
                Err(e) => map_admin_error(id, e, tool_name, trace_id),
            }
        }
        "latchgate_approve" => {
            let approval_id = match arguments["approval_id"].as_str() {
                Some(s) => s,
                None => {
                    return admin_input_error(
                        id,
                        "Missing required field 'approval_id'.",
                        tool_name,
                        trace_id,
                    );
                }
            };
            match admin.approve(approval_id).await {
                Ok(resp) => admin_success(id, &resp),
                Err(e) => map_admin_error(id, e, tool_name, trace_id),
            }
        }
        "latchgate_deny" => {
            let approval_id = match arguments["approval_id"].as_str() {
                Some(s) => s,
                None => {
                    return admin_input_error(
                        id,
                        "Missing required field 'approval_id'.",
                        tool_name,
                        trace_id,
                    );
                }
            };
            let reason = arguments["reason"].as_str();
            match admin.deny(approval_id, reason).await {
                Ok(resp) => admin_success(id, &resp),
                Err(e) => map_admin_error(id, e, tool_name, trace_id),
            }
        }
        "latchgate_allowlist" => {
            if !allowlist_enabled {
                return admin_tool_error(
                    id,
                    tool_error_codes::POLICY_DENIED,
                    "latchgate_allowlist is not enabled. \
                     Start the adapter with --enable-allowlist-tool.",
                    tool_name,
                    trace_id,
                );
            }
            let action_id = match arguments["action_id"].as_str() {
                Some(s) => s,
                None => {
                    return admin_input_error(
                        id,
                        "Missing required field 'action_id'.",
                        tool_name,
                        trace_id,
                    );
                }
            };
            let agent_id = arguments["agent_id"].as_str().unwrap_or(default_agent_id);
            match admin.allowlist(action_id, agent_id).await {
                Ok(resp) => admin_success(id, &resp),
                Err(e) => map_admin_error(id, e, tool_name, trace_id),
            }
        }
        _ => {
            // Unreachable when called via is_approval_tool guard.
            admin_tool_error(
                id,
                tool_error_codes::ACTION_NOT_FOUND,
                &format!("Unknown approval tool '{tool_name}'."),
                tool_name,
                trace_id,
            )
        }
    }
}

fn admin_success(id: Option<RequestId>, resp: &Value) -> JsonRpcResponse {
    let clean = strip_nulls(resp);
    let text = serde_json::to_string_pretty(&clean).unwrap_or_else(|_| resp.to_string());
    JsonRpcResponse::ok(
        id,
        json!({
            "content": [ContentBlock::text(text)],
            "isError": false,
        }),
    )
}

/// Recursively strip null values from a JSON value.
///
/// Defense-in-depth: even with `skip_serializing_if` on the API structs,
/// this ensures the MCP layer never surfaces noisy null fields to IDEs.
fn strip_nulls(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let cleaned: serde_json::Map<String, Value> = map
                .iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| (k.clone(), strip_nulls(v)))
                .collect();
            Value::Object(cleaned)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(strip_nulls).collect()),
        other => other.clone(),
    }
}

fn admin_input_error(
    id: Option<RequestId>,
    message: &str,
    tool_name: &str,
    trace_id: &str,
) -> JsonRpcResponse {
    admin_tool_error(
        id,
        tool_error_codes::SCHEMA_VALIDATION,
        message,
        tool_name,
        trace_id,
    )
}

fn admin_tool_error(
    id: Option<RequestId>,
    code: &'static str,
    message: &str,
    tool_name: &str,
    trace_id: &str,
) -> JsonRpcResponse {
    let error = StructuredToolError {
        code: Cow::Borrowed(code),
        message: message.to_string(),
        action_id: Some(tool_name.to_string()),
        trace_id: Some(trace_id.to_string()),
        approval_id: None,
        remediation: None,
    };
    JsonRpcResponse::ok(
        id,
        json!({
            "content": [ContentBlock::text(error.to_json())],
            "isError": true,
        }),
    )
}

fn map_admin_error(
    id: Option<RequestId>,
    err: AdminError,
    tool_name: &str,
    trace_id: &str,
) -> JsonRpcResponse {
    let (code, message) = match &err {
        AdminError::InvalidInput(msg) => (tool_error_codes::SCHEMA_VALIDATION, msg.clone()),
        AdminError::Http { status, body } => {
            let parsed = serde_json::from_str::<Value>(body).ok();
            let gate_code = parsed
                .as_ref()
                .and_then(|j| j["error"].as_str())
                .unwrap_or("");

            let code = match gate_code {
                "approval_not_found" | "not_found" => tool_error_codes::ACTION_NOT_FOUND,
                "auth_failed" | "dpop_invalid" => tool_error_codes::AUTH_FAILED,
                "action_not_found" => tool_error_codes::ACTION_NOT_FOUND,
                _ if *status == 401 || *status == 403 => tool_error_codes::AUTH_FAILED,
                _ if *status == 404 => tool_error_codes::ACTION_NOT_FOUND,
                _ => tool_error_codes::GATE_UNAVAILABLE,
            };
            let msg = parsed
                .as_ref()
                .and_then(|j| j["message"].as_str())
                .map(str::to_string)
                .unwrap_or_else(|| format!("Admin API error (HTTP {status})."));
            (code, msg)
        }
        AdminError::Transport(msg) => (
            tool_error_codes::GATE_UNAVAILABLE,
            format!("Admin socket unreachable: {msg}"),
        ),
        AdminError::Signing(msg) => (
            tool_error_codes::AUTH_FAILED,
            format!("Operator DPoP signing failed: {msg}"),
        ),
        AdminError::InvalidResponse(msg) => (
            tool_error_codes::GATE_UNAVAILABLE,
            format!("Unexpected admin API response: {msg}"),
        ),
    };

    // SECURITY: never expose signing details or token material in the
    // error message. The mapping above uses only gate-provided messages.
    admin_tool_error(id, code, &message, tool_name, trace_id)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_approval_id ─────────────────────────────────────────────

    #[test]
    fn valid_uuid_accepted() {
        assert!(validate_approval_id("019e6963-abcd-7def-8901-234567890abc").is_ok());
        assert!(validate_approval_id("00000000-0000-0000-0000-000000000000").is_ok());
    }

    #[test]
    fn uppercase_hex_rejected() {
        assert!(validate_approval_id("019E6963-ABCD-7DEF-8901-234567890ABC").is_err());
    }

    #[test]
    fn wrong_length_rejected() {
        assert!(validate_approval_id("too-short").is_err());
        assert!(validate_approval_id("019e6963-abcd-7def-8901-234567890abcX").is_err());
        assert!(validate_approval_id("").is_err());
    }

    #[test]
    fn path_traversal_rejected() {
        assert!(validate_approval_id("../leases/../../v1/admin/revoke").is_err());
    }

    #[test]
    fn missing_hyphens_rejected() {
        assert!(validate_approval_id("019e6963xabcdx7defx8901x234567890abc").is_err());
    }

    // ── validate_resource_id ─────────────────────────────────────────────

    #[test]
    fn valid_action_ids_accepted() {
        assert!(validate_resource_id("http_fetch", "action_id").is_ok());
        assert!(validate_resource_id("github-read", "action_id").is_ok());
        assert!(validate_resource_id("a", "action_id").is_ok());
        assert!(validate_resource_id(&"a".repeat(128), "action_id").is_ok());
    }

    #[test]
    fn empty_resource_id_rejected() {
        assert!(validate_resource_id("", "action_id").is_err());
    }

    #[test]
    fn overlength_resource_id_rejected() {
        assert!(validate_resource_id(&"a".repeat(129), "action_id").is_err());
    }

    #[test]
    fn resource_id_path_traversal_rejected() {
        assert!(validate_resource_id("../admin", "action_id").is_err());
        assert!(validate_resource_id("foo/bar", "action_id").is_err());
        assert!(validate_resource_id("foo\\bar", "action_id").is_err());
    }

    #[test]
    fn resource_id_special_chars_rejected() {
        assert!(validate_resource_id("foo bar", "action_id").is_err());
        assert!(validate_resource_id("foo?bar", "action_id").is_err());
        assert!(validate_resource_id("foo.bar", "action_id").is_err());
    }

    // ── reason sanitization (delegates to latchgate_core::sanitize_for_log) ─

    #[test]
    fn clean_reason_unchanged() {
        let out = latchgate_core::sanitize_for_log("Not authorized", REASON_MAX_BYTES);
        assert_eq!(&*out, "Not authorized");
    }

    #[test]
    fn control_chars_replaced_with_space() {
        let out = latchgate_core::sanitize_for_log("bad\x00\x01\x1frequest", REASON_MAX_BYTES);
        assert_eq!(&*out, "bad   request");
    }

    #[test]
    fn ansi_escape_neutralized() {
        let out = latchgate_core::sanitize_for_log("\x1b[31mred\x1b[0m", REASON_MAX_BYTES);
        assert_eq!(&*out, " [31mred [0m");
    }

    #[test]
    fn reason_truncated_at_byte_budget() {
        // 3000 ASCII bytes exceeds the 2000-byte budget.
        let long = "x".repeat(3000);
        let out = latchgate_core::sanitize_for_log(&long, REASON_MAX_BYTES);
        assert_eq!(out.len(), REASON_MAX_BYTES);
    }

    #[test]
    fn multibyte_reason_within_budget_preserved() {
        // 400 two-byte chars = 800 bytes, well within 2000.
        let input = "é".repeat(400);
        let out = latchgate_core::sanitize_for_log(&input, REASON_MAX_BYTES);
        assert_eq!(&*out, input);
    }

    #[test]
    fn truncation_respects_utf8_boundary() {
        // Fill just past the byte budget with multi-byte chars. The result
        // must be valid UTF-8 and within the byte budget.
        let input = "é".repeat(1200); // 2400 bytes
        let out = latchgate_core::sanitize_for_log(&input, REASON_MAX_BYTES);
        assert!(out.len() <= REASON_MAX_BYTES);
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
        // 2000 bytes / 2 bytes per 'é' = exactly 1000 chars.
        assert_eq!(out.chars().count(), 1000);
    }

    // ── approval_tools ───────────────────────────────────────────────────

    #[test]
    fn approval_tools_without_allowlist() {
        let tools = approval_tools(false);
        assert_eq!(tools.len(), 4);
        assert_eq!(tools[0].name, "latchgate_list_pending");
        assert_eq!(tools[1].name, "latchgate_get_approval");
        assert_eq!(tools[2].name, "latchgate_approve");
        assert_eq!(tools[3].name, "latchgate_deny");
    }

    #[test]
    fn approval_tools_with_allowlist() {
        let tools = approval_tools(true);
        assert_eq!(tools.len(), 5);
        assert_eq!(tools[4].name, "latchgate_allowlist");
    }

    #[test]
    fn all_approval_tools_have_correct_annotations() {
        for tool in approval_tools(true) {
            let ann = tool.annotations.as_ref().expect("annotations must be set");
            assert_eq!(ann.idempotent_hint, Some(true), "tool: {}", tool.name);
            assert_eq!(ann.open_world_hint, Some(false), "tool: {}", tool.name);

            let is_read = matches!(
                tool.name.as_str(),
                "latchgate_list_pending" | "latchgate_get_approval"
            );
            if is_read {
                assert_eq!(ann.read_only_hint, Some(true), "tool: {}", tool.name);
                assert_eq!(ann.destructive_hint, Some(false), "tool: {}", tool.name);
            } else {
                assert_eq!(ann.read_only_hint, Some(false), "tool: {}", tool.name);
                assert_eq!(ann.destructive_hint, Some(true), "tool: {}", tool.name);
            }
        }
    }

    #[test]
    fn is_approval_tool_matches() {
        assert!(is_approval_tool("latchgate_approve"));
        assert!(is_approval_tool("latchgate_deny"));
        assert!(is_approval_tool("latchgate_list_pending"));
        assert!(is_approval_tool("latchgate_get_approval"));
        assert!(is_approval_tool("latchgate_allowlist"));
        assert!(!is_approval_tool("http_fetch"));
        assert!(!is_approval_tool(""));
    }

    // ── tool schemas ─────────────────────────────────────────────────────

    #[test]
    fn list_pending_schema_requires_no_fields() {
        let tool = tool_list_pending();
        let props = tool.input_schema["properties"].as_object().unwrap();
        assert!(props.is_empty(), "list_pending must take no arguments");
    }

    #[test]
    fn get_approval_schema_requires_approval_id() {
        let tool = tool_get_approval();
        let required = tool.input_schema["required"]
            .as_array()
            .expect("required must be array");
        assert!(required.iter().any(|v| v == "approval_id"));
    }

    #[test]
    fn approve_schema_requires_approval_id() {
        let tool = tool_approve();
        let required = tool.input_schema["required"]
            .as_array()
            .expect("required must be array");
        assert!(required.iter().any(|v| v == "approval_id"));
    }

    #[test]
    fn deny_schema_approval_id_required_reason_optional() {
        let tool = tool_deny();
        let required = tool.input_schema["required"]
            .as_array()
            .expect("required must be array");
        assert!(required.iter().any(|v| v == "approval_id"));
        assert!(!required.iter().any(|v| v == "reason"));
    }

    #[test]
    fn allowlist_schema_requires_action_id() {
        let tool = tool_allowlist();
        let required = tool.input_schema["required"]
            .as_array()
            .expect("required must be array");
        assert!(required.iter().any(|v| v == "action_id"));
        assert!(!required.iter().any(|v| v == "agent_id"));
    }

    #[test]
    fn all_schemas_disallow_additional_properties() {
        for tool in approval_tools(true) {
            assert_eq!(
                tool.input_schema["additionalProperties"],
                json!(false),
                "tool {} must disallow additionalProperties",
                tool.name
            );
        }
    }
}
