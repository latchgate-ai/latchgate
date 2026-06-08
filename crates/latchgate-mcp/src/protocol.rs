//! MCP JSON-RPC 2.0 protocol types.
//!
//! Covers the subset of the Model Context Protocol (2024-11-05) used by the
//! LatchGate adapter: initialize, tools/list, tools/call, resources/list,
//! resources/read, prompts/list, prompts/get, and ping.
//!
//! Spec: <https://spec.modelcontextprotocol.io/specification/2024-11-05/>

use std::borrow::Cow;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PROTOCOL_VERSION: &str = "2024-11-05";

/// JSON-RPC 2.0 id — number, string, or null.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestId {
    Number(i64),
    String(String),
}

#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    /// Must be "2.0".
    pub jsonrpc: String,
    /// Present for requests, absent for notifications.
    pub id: Option<RequestId>,
    pub method: String,
    /// Parameters (object or absent).
    #[serde(default)]
    pub params: Value,
}

/// Outgoing JSON-RPC 2.0 response.
#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<RequestId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Serialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

/// Standard JSON-RPC 2.0 error codes.
pub mod error_codes {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;
}

impl JsonRpcResponse {
    pub fn ok(id: Option<RequestId>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: Option<RequestId>, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
            }),
        }
    }
}

/// Outgoing JSON-RPC 2.0 notification (no id, no response expected).
///
/// Used for MCP progress updates during approval polling and log messages.
#[derive(Debug, Serialize)]
pub struct JsonRpcNotification {
    pub jsonrpc: &'static str,
    pub method: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl JsonRpcNotification {
    /// Create an MCP progress notification (`notifications/progress`).
    pub fn progress(token: &Value, progress: u64, total: Option<u64>) -> Self {
        let mut params = serde_json::json!({
            "progressToken": token,
            "progress": progress,
        });
        if let Some(t) = total {
            params["total"] = serde_json::json!(t);
        }
        Self {
            jsonrpc: "2.0",
            method: "notifications/progress",
            params: Some(params),
        }
    }

    /// Create an MCP log notification (`notifications/message`).
    pub fn log_message(level: &str, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            method: "notifications/message",
            params: Some(serde_json::json!({
                "level": level,
                "logger": "latchgate-mcp",
                "data": message.into(),
            })),
        }
    }

    /// Notify the client that the tool list has changed.
    ///
    /// Per the MCP spec (2024-11-05), the server must advertise
    /// `"tools": { "listChanged": true }` in `initialize` capabilities
    /// for this notification to be honored. Clients that receive it
    /// re-issue `tools/list` to obtain the updated set.
    pub fn tools_list_changed() -> Self {
        Self {
            jsonrpc: "2.0",
            method: "notifications/tools/list_changed",
            params: None,
        }
    }
}

/// MCP tool definition (returned in tools/list).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpTool {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    /// Behavioral hints for IDEs (read-only, destructive, open-world).
    ///
    /// Derived from manifest metadata at discovery time. Omitted when
    /// insufficient metadata exists to determine the hint — missing is
    /// safer than wrong.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<McpToolAnnotations>,
}

/// MCP tool annotations — behavioral hints for IDEs.
///
/// IDEs that support annotations (Claude Desktop, Cursor) use these to
/// show users whether a tool is read-only, destructive, or contacts
/// external services.
///
/// Derivation rules (from manifest metadata):
///
/// | Condition                                       | Annotation                |
/// |-------------------------------------------------|---------------------------|
/// | `declared_side_effects: []`                      | `readOnlyHint: true`      |
/// | `risk_level: critical`                           | `destructiveHint: true`   |
/// | Destructive verb in `declared_side_effects`      | `destructiveHint: true`   |
/// | Destructive verb in `action_id` (high-risk only) | `destructiveHint: true`   |
/// | Approval / read-only admin tools                 | `idempotentHint: true`    |
/// | `egress.profile: none`                           | `openWorldHint: false`    |
/// | `egress.profile: proxy_allowlist`                | `openWorldHint: true`     |
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpToolAnnotations {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_only_hint: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destructive_hint: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotent_hint: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_world_hint: Option<bool>,
}

impl McpToolAnnotations {
    /// Returns `true` if no hints are set.
    pub fn is_empty(&self) -> bool {
        self.read_only_hint.is_none()
            && self.destructive_hint.is_none()
            && self.idempotent_hint.is_none()
            && self.open_world_hint.is_none()
    }
}

/// MCP content block — the unit of tool call output.
#[derive(Debug, Serialize)]
pub struct ContentBlock {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub text: String,
}

impl ContentBlock {
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            kind: "text",
            text: text.into(),
        }
    }
}

/// MCP resource definition (returned in `resources/list`).
///
/// Resources provide IDE sidebars (Cursor, Claude Desktop) with read-only
/// visibility into gate state without tool calls.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpResource {
    pub uri: String,
    pub name: String,
    pub description: String,
    pub mime_type: String,
}

/// MCP resource content (returned in `resources/read`).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpResourceContent {
    pub uri: String,
    pub mime_type: String,
    pub text: String,
}

/// MCP prompt definition (returned in `prompts/list`).
///
/// Prompt templates let IDEs offer structured analysis workflows.
/// Operator-only in LatchGate — the agent must not introspect its own
/// denial reasons (information leakage).
#[derive(Debug, Clone, Serialize)]
pub struct McpPrompt {
    pub name: String,
    pub description: String,
    /// Prompt arguments. Omitted from JSON when empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<McpPromptArgument>,
}

/// A single argument to an MCP prompt.
#[derive(Debug, Clone, Serialize)]
pub struct McpPromptArgument {
    pub name: String,
    pub description: String,
    pub required: bool,
}

/// MCP `initialize` request params.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeParams {
    pub protocol_version: String,
    #[serde(default)]
    pub client_info: Option<ClientInfo>,
}

/// MCP client info (informational).
#[derive(Debug, Deserialize)]
pub struct ClientInfo {
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
}

/// MCP `tools/call` request params.
#[derive(Debug, Deserialize)]
pub struct ToolCallParams {
    pub name: String,
    #[serde(default)]
    pub arguments: Value,
    /// MCP metadata — carries `progressToken` for progress notifications.
    #[serde(default, rename = "_meta")]
    pub meta: Option<Value>,
}

impl ToolCallParams {
    /// Extract the MCP progress token, if the client provided one.
    pub fn progress_token(&self) -> Option<&Value> {
        self.meta.as_ref().and_then(|m| m.get("progressToken"))
    }
}

/// Machine-readable error codes for MCP tool-level errors.
///
/// These are the exhaustive set of codes returned in the `code` field of
/// structured error JSON bodies. Orchestrators branch on these programmatically;
/// IDEs display the accompanying `message` to the user.
///
/// SECURITY: codes are intentionally coarse. Fine-grained failure reasons
/// (OPA rule names, manifest fields, dev-mode diagnostics) belong in the
/// operator-facing audit trail, not in agent-visible error content.
pub mod tool_error_codes {
    /// OPA policy rejected the call.
    pub const POLICY_DENIED: &str = "policy_denied";
    /// Waiting for operator approval.
    pub const PENDING_APPROVAL: &str = "pending_approval";
    /// Session or global budget exceeded.
    pub const BUDGET_EXHAUSTED: &str = "budget_exhausted";
    /// Action ID doesn't exist in registry.
    pub const ACTION_NOT_FOUND: &str = "action_not_found";
    /// Input doesn't match JSON Schema.
    pub const SCHEMA_VALIDATION: &str = "schema_validation";
    /// Target domain not in allowlist.
    pub const EGRESS_BLOCKED: &str = "egress_blocked";
    /// Execution grant timed out.
    pub const LEASE_EXPIRED: &str = "lease_expired";
    /// Revocation epoch advanced; all grants invalidated.
    pub const REVOKED: &str = "revoked";
    /// Cannot reach the gate.
    pub const GATE_UNAVAILABLE: &str = "gate_unavailable";
    /// WASM execution failed.
    pub const SANDBOX_ERROR: &str = "sandbox_error";
    /// DPoP or identity verification failed.
    pub const AUTH_FAILED: &str = "auth_failed";
}

/// Structured error body for MCP tool-level errors.
///
/// Serialized as JSON into the `text` field of an `isError: true` content
/// block. Machine-readable by orchestrators; human-readable by IDE users
/// via the `message` field.
///
/// SECURITY: never include receipt IDs, internal stack traces, or enforcement
/// metadata. `trace_id` is opaque and safe for operator correlation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StructuredToolError {
    /// One of the [`tool_error_codes`] constants.
    pub code: Cow<'static, str>,
    /// Human-readable description of the error with actionable guidance.
    pub message: String,
    /// The action that was invoked (if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_id: Option<String>,
    /// Opaque trace identifier for operator-side correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// Approval identifier (only for `pending_approval`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    /// Copy-pasteable CLI command to fix the denial (only for `policy_denied`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

impl StructuredToolError {
    /// Serialize to compact JSON.
    ///
    /// Falls back to a minimal JSON literal on serialization failure (should
    /// never happen, but we never panic on the stdio path).
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            format!(
                r#"{{"code":"{}","message":"serialization error"}}"#,
                self.code
            )
        })
    }
}

/// Map a gate-returned error string to the canonical tool error code.
///
/// The gate uses its own error identifiers in HTTP error response bodies.
/// This function normalizes them to the MCP adapter's exhaustive code set.
///
/// Unknown gate codes are mapped by HTTP status class:
/// - 4xx → `policy_denied` (authorization / client error)
/// - 5xx → `gate_unavailable` (server error)
pub fn map_gate_error_code(gate_code: &str, http_status: u16) -> &'static str {
    match gate_code {
        // Direct mappings — gate uses the same identifiers.
        "policy_denied" | "acl_denied" | "not_allowed" => tool_error_codes::POLICY_DENIED,
        "pending_approval" => tool_error_codes::PENDING_APPROVAL,
        "budget_exhausted" | "budget_exceeded" => tool_error_codes::BUDGET_EXHAUSTED,
        "action_not_found" | "not_found" => tool_error_codes::ACTION_NOT_FOUND,
        "schema_validation" | "validation_error" => tool_error_codes::SCHEMA_VALIDATION,
        "egress_blocked" | "domain_blocked" => tool_error_codes::EGRESS_BLOCKED,
        "lease_expired" | "grant_expired" => tool_error_codes::LEASE_EXPIRED,
        "revoked" | "epoch_advanced" => tool_error_codes::REVOKED,
        "sandbox_error" | "wasm_error" | "provider_error" => tool_error_codes::SANDBOX_ERROR,
        "auth_failed" | "dpop_invalid" | "lease_invalid" => tool_error_codes::AUTH_FAILED,
        // Fallback by HTTP status class.
        _ if http_status == 404 => tool_error_codes::ACTION_NOT_FOUND,
        _ if http_status == 401 || http_status == 403 => tool_error_codes::AUTH_FAILED,
        _ if http_status == 429 => tool_error_codes::BUDGET_EXHAUSTED,
        _ if (400..500).contains(&http_status) => tool_error_codes::POLICY_DENIED,
        _ => tool_error_codes::GATE_UNAVAILABLE,
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // RequestId

    #[test]
    fn request_id_number_roundtrips() {
        let id = RequestId::Number(42);
        let json = serde_json::to_value(&id).unwrap();
        assert_eq!(json, 42);

        let restored: RequestId = serde_json::from_value(json).unwrap();
        assert!(matches!(restored, RequestId::Number(42)));
    }

    #[test]
    fn request_id_string_roundtrips() {
        let id = RequestId::String("req-001".into());
        let json = serde_json::to_value(&id).unwrap();
        assert_eq!(json, "req-001");

        let restored: RequestId = serde_json::from_value(json).unwrap();
        assert!(matches!(restored, RequestId::String(ref s) if s == "req-001"));
    }

    // JsonRpcRequest parsing

    #[test]
    fn parse_request_with_number_id() {
        let raw = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
        let req: JsonRpcRequest = serde_json::from_value(raw).unwrap();
        assert_eq!(req.method, "tools/list");
        assert!(matches!(req.id, Some(RequestId::Number(1))));
        assert_eq!(req.params, Value::Null);
    }

    #[test]
    fn parse_request_with_string_id() {
        let raw = json!({"jsonrpc": "2.0", "id": "abc", "method": "ping"});
        let req: JsonRpcRequest = serde_json::from_value(raw).unwrap();
        assert!(matches!(req.id, Some(RequestId::String(ref s)) if s == "abc"));
    }

    #[test]
    fn parse_notification_has_no_id() {
        let raw = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        let req: JsonRpcRequest = serde_json::from_value(raw).unwrap();
        assert!(req.id.is_none());
    }

    #[test]
    fn parse_request_with_params() {
        let raw = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "http_fetch", "arguments": {"url": "https://example.com"}}
        });
        let req: JsonRpcRequest = serde_json::from_value(raw).unwrap();
        assert_eq!(req.method, "tools/call");
        assert_eq!(req.params["name"], "http_fetch");
    }

    #[test]
    fn parse_request_missing_method_fails() {
        let raw = json!({"jsonrpc": "2.0", "id": 1});
        assert!(serde_json::from_value::<JsonRpcRequest>(raw).is_err());
    }

    // JsonRpcResponse construction

    #[test]
    fn ok_response_has_result_no_error() {
        let resp = JsonRpcResponse::ok(Some(RequestId::Number(1)), json!({"tools": []}));
        let json = serde_json::to_value(&resp).unwrap();

        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["id"], 1);
        assert!(json["result"].is_object());
        assert!(json.get("error").is_none());
    }

    #[test]
    fn err_response_has_error_no_result() {
        let resp = JsonRpcResponse::err(
            Some(RequestId::Number(1)),
            error_codes::METHOD_NOT_FOUND,
            "Method not found",
        );
        let json = serde_json::to_value(&resp).unwrap();

        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["error"]["code"], error_codes::METHOD_NOT_FOUND);
        assert_eq!(json["error"]["message"], "Method not found");
        assert!(json.get("result").is_none());
    }

    #[test]
    fn ok_response_null_id_for_notification() {
        let resp = JsonRpcResponse::ok(None, json!("pong"));
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("id").is_none());
    }

    // Error codes

    #[test]
    fn standard_error_codes_in_spec_range() {
        assert_eq!(error_codes::PARSE_ERROR, -32700);
        assert_eq!(error_codes::INVALID_REQUEST, -32600);
        assert_eq!(error_codes::METHOD_NOT_FOUND, -32601);
        assert_eq!(error_codes::INVALID_PARAMS, -32602);
        assert_eq!(error_codes::INTERNAL_ERROR, -32603);
    }

    // MCP tool types

    #[test]
    fn mcp_tool_serializes_camel_case() {
        let tool = McpTool {
            name: "http_fetch".into(),
            description: "Fetch a URL".into(),
            input_schema: json!({"type": "object"}),
            annotations: None,
        };
        let json = serde_json::to_value(&tool).unwrap();
        assert!(json.get("inputSchema").is_some());
        assert!(json.get("input_schema").is_none());
        // annotations omitted when None
        assert!(json.get("annotations").is_none());
    }

    #[test]
    fn mcp_tool_with_annotations() {
        let tool = McpTool {
            name: "github_read".into(),
            description: "Read GitHub".into(),
            input_schema: json!({"type": "object"}),
            annotations: Some(McpToolAnnotations {
                read_only_hint: Some(true),
                destructive_hint: None,
                idempotent_hint: Some(true),
                open_world_hint: Some(false),
            }),
        };
        let json = serde_json::to_value(&tool).unwrap();
        let ann = &json["annotations"];
        assert_eq!(ann["readOnlyHint"], true);
        assert_eq!(ann["idempotentHint"], true);
        assert_eq!(ann["openWorldHint"], false);
        // destructiveHint omitted when None
        assert!(ann.get("destructiveHint").is_none());
    }

    #[test]
    fn annotations_empty_check() {
        let empty = McpToolAnnotations::default();
        assert!(empty.is_empty());

        let non_empty = McpToolAnnotations {
            read_only_hint: Some(true),
            ..Default::default()
        };
        assert!(!non_empty.is_empty());
    }

    #[test]
    fn content_block_text_has_type_text() {
        let block = ContentBlock::text("hello world");
        let json = serde_json::to_value(&block).unwrap();
        assert_eq!(json["type"], "text");
        assert_eq!(json["text"], "hello world");
    }

    // MCP resource types

    #[test]
    fn mcp_resource_serializes_camel_case() {
        let res = McpResource {
            uri: "latchgate://actions".into(),
            name: "Actions".into(),
            description: "test".into(),
            mime_type: "application/json".into(),
        };
        let json = serde_json::to_value(&res).unwrap();
        assert!(json.get("mimeType").is_some());
        assert!(json.get("mime_type").is_none());
        assert_eq!(json["uri"], "latchgate://actions");
    }

    #[test]
    fn mcp_resource_content_serializes_camel_case() {
        let content = McpResourceContent {
            uri: "latchgate://status".into(),
            mime_type: "application/json".into(),
            text: r#"{"ok":true}"#.into(),
        };
        let json = serde_json::to_value(&content).unwrap();
        assert!(json.get("mimeType").is_some());
        assert!(json.get("mime_type").is_none());
        assert_eq!(json["text"], r#"{"ok":true}"#);
    }

    // MCP prompt types

    #[test]
    fn mcp_prompt_serializes_with_arguments() {
        let prompt = McpPrompt {
            name: "explain_denial".into(),
            description: "Explain a denial.".into(),
            arguments: vec![McpPromptArgument {
                name: "trace_id".into(),
                description: "The trace_id.".into(),
                required: true,
            }],
        };
        let json = serde_json::to_value(&prompt).unwrap();
        assert_eq!(json["name"], "explain_denial");
        assert!(json["arguments"].is_array());
        assert_eq!(json["arguments"][0]["required"], true);
    }

    #[test]
    fn mcp_prompt_omits_empty_arguments() {
        let prompt = McpPrompt {
            name: "review_pending".into(),
            description: "Review pending.".into(),
            arguments: vec![],
        };
        let json = serde_json::to_value(&prompt).unwrap();
        assert!(json.get("arguments").is_none());
    }

    #[test]
    fn tool_call_params_parse() {
        let raw = json!({"name": "github_read", "arguments": {"repo": "org/repo"}});
        let params: ToolCallParams = serde_json::from_value(raw).unwrap();
        assert_eq!(params.name, "github_read");
        assert_eq!(params.arguments["repo"], "org/repo");
    }

    #[test]
    fn tool_call_params_default_arguments() {
        let raw = json!({"name": "ping"});
        let params: ToolCallParams = serde_json::from_value(raw).unwrap();
        assert_eq!(params.name, "ping");
        assert_eq!(params.arguments, Value::Null);
    }

    #[test]
    fn initialize_params_parse() {
        let raw = json!({
            "protocolVersion": "2024-11-05",
            "clientInfo": {"name": "claude-code", "version": "1.0.0"}
        });
        let params: InitializeParams = serde_json::from_value(raw).unwrap();
        assert_eq!(params.protocol_version, PROTOCOL_VERSION);
        assert_eq!(params.client_info.as_ref().unwrap().name, "claude-code");
    }

    #[test]
    fn initialize_params_without_client_info() {
        let raw = json!({"protocolVersion": "2024-11-05"});
        let params: InitializeParams = serde_json::from_value(raw).unwrap();
        assert!(params.client_info.is_none());
    }

    #[test]
    fn protocol_version_matches_spec() {
        assert_eq!(PROTOCOL_VERSION, "2024-11-05");
    }

    // Structured tool errors

    #[test]
    fn structured_error_serializes_all_fields() {
        let err = StructuredToolError {
            code: tool_error_codes::POLICY_DENIED.into(),
            message: "Action 'github_push' denied.".into(),
            action_id: Some("github_push".into()),
            trace_id: Some("tr_abc123".into()),
            approval_id: None,
            remediation: None,
        };
        let json: Value = serde_json::from_str(&err.to_json()).unwrap();
        assert_eq!(json["code"], "policy_denied");
        assert_eq!(json["action_id"], "github_push");
        assert_eq!(json["trace_id"], "tr_abc123");
        // approval_id omitted
        assert!(json.get("approval_id").is_none());
    }

    #[test]
    fn structured_error_pending_approval_includes_approval_id() {
        let err = StructuredToolError {
            code: tool_error_codes::PENDING_APPROVAL.into(),
            message: "Waiting for approval.".into(),
            action_id: Some("slack_post".into()),
            trace_id: Some("tr_xyz".into()),
            approval_id: Some("apr_456".into()),
            remediation: None,
        };
        let json: Value = serde_json::from_str(&err.to_json()).unwrap();
        assert_eq!(json["code"], "pending_approval");
        assert_eq!(json["approval_id"], "apr_456");
    }

    #[test]
    fn structured_error_omits_none_fields() {
        let err = StructuredToolError {
            code: tool_error_codes::GATE_UNAVAILABLE.into(),
            message: "Cannot reach gate.".into(),
            action_id: None,
            trace_id: None,
            approval_id: None,
            remediation: None,
        };
        let json: Value = serde_json::from_str(&err.to_json()).unwrap();
        assert!(json.get("action_id").is_none());
        assert!(json.get("trace_id").is_none());
        assert!(json.get("approval_id").is_none());
    }

    #[test]
    fn structured_error_roundtrips() {
        let err = StructuredToolError {
            code: tool_error_codes::SCHEMA_VALIDATION.into(),
            message: "field 'url': expected string".into(),
            action_id: Some("http_post".into()),
            trace_id: Some("tr_001".into()),
            approval_id: None,
            remediation: None,
        };
        let json_str = err.to_json();
        let restored: StructuredToolError = serde_json::from_str(&json_str).unwrap();
        assert_eq!(err, restored);
    }

    // Gate error code mapping

    #[test]
    fn map_gate_error_direct_codes() {
        assert_eq!(
            map_gate_error_code("policy_denied", 403),
            tool_error_codes::POLICY_DENIED
        );
        assert_eq!(
            map_gate_error_code("budget_exhausted", 429),
            tool_error_codes::BUDGET_EXHAUSTED
        );
        assert_eq!(
            map_gate_error_code("sandbox_error", 500),
            tool_error_codes::SANDBOX_ERROR
        );
        assert_eq!(
            map_gate_error_code("dpop_invalid", 401),
            tool_error_codes::AUTH_FAILED
        );
        assert_eq!(
            map_gate_error_code("egress_blocked", 403),
            tool_error_codes::EGRESS_BLOCKED
        );
    }

    #[test]
    fn map_gate_error_alias_codes() {
        assert_eq!(
            map_gate_error_code("acl_denied", 403),
            tool_error_codes::POLICY_DENIED
        );
        assert_eq!(
            map_gate_error_code("budget_exceeded", 429),
            tool_error_codes::BUDGET_EXHAUSTED
        );
        assert_eq!(
            map_gate_error_code("wasm_error", 500),
            tool_error_codes::SANDBOX_ERROR
        );
        assert_eq!(
            map_gate_error_code("epoch_advanced", 403),
            tool_error_codes::REVOKED
        );
    }

    #[test]
    fn map_gate_error_unknown_code_falls_back_to_status() {
        assert_eq!(
            map_gate_error_code("something_new", 404),
            tool_error_codes::ACTION_NOT_FOUND
        );
        assert_eq!(
            map_gate_error_code("something_new", 401),
            tool_error_codes::AUTH_FAILED
        );
        assert_eq!(
            map_gate_error_code("something_new", 403),
            tool_error_codes::AUTH_FAILED
        );
        assert_eq!(
            map_gate_error_code("something_new", 422),
            tool_error_codes::POLICY_DENIED
        );
        assert_eq!(
            map_gate_error_code("something_new", 500),
            tool_error_codes::GATE_UNAVAILABLE
        );
    }

    // JsonRpcNotification

    #[test]
    fn progress_notification_serializes() {
        let notif = JsonRpcNotification::progress(&json!("tok-1"), 3, Some(10));
        let json = serde_json::to_value(&notif).unwrap();
        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["method"], "notifications/progress");
        assert_eq!(json["params"]["progressToken"], "tok-1");
        assert_eq!(json["params"]["progress"], 3);
        assert_eq!(json["params"]["total"], 10);
        // No id field — this is a notification.
        assert!(json.get("id").is_none());
    }

    #[test]
    fn progress_notification_omits_total_when_none() {
        let notif = JsonRpcNotification::progress(&json!(42), 1, None);
        let json = serde_json::to_value(&notif).unwrap();
        assert!(json["params"].get("total").is_none());
    }

    #[test]
    fn log_message_notification_serializes() {
        let notif = JsonRpcNotification::log_message("info", "waiting for approval");
        let json = serde_json::to_value(&notif).unwrap();
        assert_eq!(json["method"], "notifications/message");
        assert_eq!(json["params"]["level"], "info");
        assert_eq!(json["params"]["logger"], "latchgate-mcp");
        assert_eq!(json["params"]["data"], "waiting for approval");
    }

    #[test]
    fn tools_list_changed_notification_serializes() {
        let notif = JsonRpcNotification::tools_list_changed();
        let json = serde_json::to_value(&notif).unwrap();
        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["method"], "notifications/tools/list_changed");
        // No params field — must be omitted, not null.
        assert!(json.get("params").is_none());
        // No id field — this is a notification.
        assert!(json.get("id").is_none());
    }

    // ToolCallParams with _meta

    #[test]
    fn tool_call_params_extracts_progress_token() {
        let raw = json!({
            "name": "slack_post",
            "arguments": {"channel": "general"},
            "_meta": {"progressToken": "pt-99"}
        });
        let params: ToolCallParams = serde_json::from_value(raw).unwrap();
        assert_eq!(params.progress_token(), Some(&json!("pt-99")));
    }

    #[test]
    fn tool_call_params_no_meta_returns_none() {
        let raw = json!({"name": "ping"});
        let params: ToolCallParams = serde_json::from_value(raw).unwrap();
        assert!(params.progress_token().is_none());
    }

    #[test]
    fn tool_call_params_meta_without_progress_token() {
        let raw = json!({"name": "test", "_meta": {"other": "field"}});
        let params: ToolCallParams = serde_json::from_value(raw).unwrap();
        assert!(params.progress_token().is_none());
    }
}
