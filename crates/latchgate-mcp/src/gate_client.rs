//! HTTP client for the LatchGate REST API.
//!
//! Supports two transports via [`latchgate_client::Transport`]:
//!
//! - **Unix domain socket** (default, secure): connects via the gate's UDS
//!   path. Only processes with filesystem access to the socket can reach it.
//!
//! - **TCP/HTTP**: connects to a base URL (e.g. `http://localhost:3000`).
//!   Requires `unsafe_expose_http = true` in latchgate.toml. Dev only.
//!
//! # Session binding
//!
//! Every action execution request carries an `X-LatchGate-Session-Id` header
//! so the gate can group calls from one adapter lifecycle in the audit trail.
//!
//! # Security
//!
//! Every action execution request carries a DPoP-bound Authorization header
//! produced by [`crate::auth::DPoPClient`]. The `DPoPClient` auto-renews
//! the Lease as needed.

use std::time::Duration;

use latchgate_client::Transport;
use serde_json::Value;
use tracing::{debug, instrument, warn};

use crate::auth::{DPoPClient, McpAuthError};
use crate::protocol::{McpTool, McpToolAnnotations};

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum GateError {
    #[error("authentication error: {0}")]
    Auth(#[from] McpAuthError),

    #[error("gate returned HTTP {status}: {body}")]
    GateHttp { status: u16, body: String },

    #[error("HTTP transport error: {0}")]
    Transport(String),

    #[error("JSON decode error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("unexpected gate response shape: {0}")]
    UnexpectedResponse(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),
}

impl From<latchgate_client::ClientError> for GateError {
    fn from(e: latchgate_client::ClientError) -> Self {
        match e {
            latchgate_client::ClientError::Http { status, body } => {
                GateError::GateHttp { status, body }
            }
            other => GateError::Transport(other.to_string()),
        }
    }
}

impl GateError {
    /// True if this error indicates the gate is unreachable.
    ///
    /// Used by the reconnection state machine to distinguish "gate is down"
    /// (transport/connection failure) from "gate is up but rejected the
    /// request" (HTTP 4xx/5xx with a body).
    pub fn is_transport_failure(&self) -> bool {
        match self {
            GateError::Transport(_) => true,
            // Lease renewal failed at the transport level (not an HTTP error
            // from the gate, but a socket/connection failure).
            GateError::Auth(McpAuthError::Http(_)) => true,
            _ => false,
        }
    }
}

// ── Approval polling ──────────────────────────────────────────────────────────

/// Outcome of polling an approval request.
#[derive(Debug)]
pub enum ApprovalOutcome {
    /// Still waiting for operator action.
    Pending,
    /// Approved — the response body contains the execution result.
    Approved(Value),
    /// Denied by the operator.
    Denied { reason: String },
    /// Approval window expired.
    Expired,
}

// ── Input validation ──────────────────────────────────────────────────────────

/// Validate that an identifier (action_id, receipt_id, etc.) is safe for URL
/// path interpolation.
///
/// Rejects empty strings, strings containing path separators or URL-special
/// characters, and strings exceeding a reasonable length. This is a defense-
/// in-depth measure: the gate also validates identifiers, but rejecting
/// malformed input at the adapter boundary prevents path traversal and
/// request smuggling before they reach the network.
fn validate_identifier(id: &str, label: &str) -> Result<(), GateError> {
    if id.is_empty() {
        return Err(GateError::InvalidInput(format!(
            "{label} must not be empty"
        )));
    }
    if id.len() > 256 {
        return Err(GateError::InvalidInput(format!(
            "{label} exceeds maximum length (256)"
        )));
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        return Err(GateError::InvalidInput(format!(
            "{label} contains invalid characters"
        )));
    }
    // Reject dot-only sequences (`.`, `..`, `...`) — they are never valid
    // identifiers and could cause path confusion in URL construction.
    if id.bytes().all(|b| b == b'.') {
        return Err(GateError::InvalidInput(format!(
            "{label} must not be a dot-only sequence"
        )));
    }
    Ok(())
}

// ── Annotation derivation ─────────────────────────────────────────────────────

/// Verbs that indicate destructive behavior.
///
/// Checked in two contexts:
/// 1. `declared_side_effects` — matched as substrings at any risk level.
///    e.g. `"http_delete"` matches on `"delete"`.
/// 2. `action_id` — matched as substrings only for `risk_level: high`.
///    Heuristic fallback for under-declared manifests.
const DESTRUCTIVE_VERBS: &[&str] = &[
    "delete",
    "destroy",
    "drop",
    "purge",
    "remove",
    "revoke",
    "terminate",
    "truncate",
    "wipe",
];

/// Derive MCP tool annotations from manifest metadata.
///
/// Returns `None` if no hints could be determined (insufficient metadata).
/// This is intentional: omitting an annotation is safer than guessing.
///
/// For `destructiveHint`, two sources are checked:
/// 1. `declared_side_effects` for destructive verbs (any risk level).
/// 2. `action_id` for destructive verbs (`risk_level: high` only — heuristic
///    fallback for under-declared manifests).
fn derive_annotations(
    action_id: &str,
    risk_level: &str,
    detail: Option<&Value>,
) -> Option<McpToolAnnotations> {
    let mut annotations = McpToolAnnotations::default();

    // ── readOnlyHint ─────────────────────────────────────────────────────
    // True when declared_side_effects is present and empty.
    if let Some(effects) = detail.and_then(|d| d["declared_side_effects"].as_array()) {
        annotations.read_only_hint = Some(effects.is_empty());
    }

    // ── destructiveHint ──────────────────────────────────────────────────
    // True when risk_level is "critical", OR declared_side_effects contains
    // a destructive verb, OR (high-risk only) the action_id itself contains
    // a destructive verb. The action_id heuristic is a safety net for
    // manifests that under-declare side effects.
    let is_critical = risk_level == "critical";

    let has_destructive_effect = detail
        .and_then(|d| d["declared_side_effects"].as_array())
        .map(|effects| {
            effects.iter().any(|e| {
                let s = e.as_str().unwrap_or("");
                DESTRUCTIVE_VERBS.iter().any(|verb| s.contains(verb))
            })
        })
        .unwrap_or(false);

    let has_destructive_name = risk_level == "high"
        && DESTRUCTIVE_VERBS
            .iter()
            .any(|verb| action_id.contains(verb));

    if is_critical || has_destructive_effect || has_destructive_name {
        annotations.destructive_hint = Some(true);
    } else if detail
        .and_then(|d| d["declared_side_effects"].as_array())
        .is_some()
    {
        // Side effects metadata is present but nothing destructive.
        annotations.destructive_hint = Some(false);
    }

    // ── openWorldHint ────────────────────────────────────────────────────
    // `none`            → false (no external access at all).
    // `proxy_allowlist` → true  (contacts external services through a
    //                            controlled proxy — users should be aware).
    //
    // The gate API may represent the egress profile in three ways:
    //   1. String:       `{"egress": "none"}`
    //   2. Flat object:  `{"egress": {"profile": "proxy_allowlist"}}`
    //   3. Tagged enum:  `{"egress": {"proxy_allowlist": {...}}}`
    // A top-level `egress_profile` string is also accepted as a fallback.
    //
    // All object paths use `Map::get()` instead of `Map[key]` — the latter
    // delegates to `BTreeMap::index`, which panics on missing keys.
    let egress_profile = detail
        .and_then(|d| {
            let egress = &d["egress"];
            egress.as_str().or_else(|| {
                egress.as_object().and_then(|m| {
                    m.get("profile")
                        .and_then(Value::as_str)
                        .or_else(|| m.keys().next().map(String::as_str))
                })
            })
        })
        .or_else(|| detail.and_then(|d| d["egress_profile"].as_str()));

    match egress_profile {
        Some("none") => annotations.open_world_hint = Some(false),
        Some("proxy_allowlist") => annotations.open_world_hint = Some(true),
        _ => {} // Unknown or absent — omit rather than guess.
    }

    if annotations.is_empty() {
        None
    } else {
        Some(annotations)
    }
}

// ── GateClient ────────────────────────────────────────────────────────────────

/// HTTP client for the LatchGate REST API with integrated DPoP authentication.
///
/// Handles both UDS and TCP transports. All action execution requests are
/// DPoP-authenticated via the embedded [`DPoPClient`] and carry the
/// `X-LatchGate-Session-Id` header for audit trail grouping.
#[derive(Clone)]
pub struct GateClient {
    transport: Transport,
    dpop: DPoPClient,
    /// Agent principal identifier (e.g. "claude-agent-01").
    ///
    /// Used for scoping `my_pending` queries to this agent's approvals.
    agent_id: String,
    /// Session identifier for audit trail grouping.
    ///
    /// Transmitted on every execute call via `X-LatchGate-Session-Id`.
    /// Generated once at adapter startup (UUID v7) or supplied externally
    /// via `--session-id` / `LATCHGATE_SESSION_ID`.
    session_id: String,
}

impl GateClient {
    /// Create a client using Unix domain socket transport.
    ///
    /// `base_url` is used only for URI construction in HTTP request headers.
    /// The actual connection goes to `socket_path`. Must match the server's
    /// `public_base_url` for DPoP htu verification to succeed.
    #[cfg(unix)]
    pub fn new_uds(
        socket_path: std::path::PathBuf,
        base_url: String,
        public_base_url: String,
        agent_id: String,
        session_id: String,
    ) -> Result<Self, McpAuthError> {
        let transport =
            Transport::uds(socket_path.to_string_lossy().into_owned(), base_url.clone());
        let dpop = DPoPClient::new(&base_url, &public_base_url, agent_id.clone())?;
        Ok(Self {
            transport,
            dpop,
            agent_id,
            session_id,
        })
    }

    /// Create a client using TCP/HTTP transport.
    ///
    /// `base_url` must be the full HTTP base URL (e.g. "http://localhost:3000").
    pub fn new_http(
        base_url: String,
        agent_id: String,
        session_id: String,
    ) -> Result<Self, McpAuthError> {
        let transport =
            Transport::http(base_url.clone()).map_err(|e| McpAuthError::Http(e.to_string()))?;
        let dpop = DPoPClient::new(&base_url, &base_url, agent_id.clone())?;
        Ok(Self {
            transport,
            dpop,
            agent_id,
            session_id,
        })
    }

    /// The session identifier for this adapter lifecycle.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// The agent principal identifier.
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    // ── Pending approvals (agent self-query) ────────────────────────────────

    /// Fetch this agent's own pending approvals.
    ///
    /// Scoped server-side to `agent_id` + `session_id` — the agent cannot
    /// see other agents' pending approvals. Read-only, no mutations.
    ///
    /// Used by `latchgate_my_pending` to let an agent recover its in-flight
    /// approvals after a crash or reconnect.
    #[instrument(
        name = "gate.my_pending",
        skip(self),
        fields(agent_id = %self.agent_id, session_id = %self.session_id),
    )]
    pub async fn my_pending(&self) -> Result<Value, GateError> {
        let path = format!(
            "/v1/approvals?status=pending&agent_id={}&session_id={}",
            self.agent_id, self.session_id,
        );
        let (status, body) = self.get_authenticated(&path).await?;
        if status >= 400 {
            Err(GateError::GateHttp {
                status,
                body: body.to_string(),
            })
        } else {
            Ok(body)
        }
    }

    // ── Lease management ─────────────────────────────────────────────────────

    /// Ensure a valid DPoP lease exists, renewing if expiring soon.
    ///
    /// Must be called once before the first `execute()` or `list_tools()`.
    /// Subsequent calls are idempotent when the lease is still valid.
    pub async fn ensure_connected(&self) -> Result<(), GateError> {
        let transport = self.transport.clone();

        self.dpop
            .ensure_lease(|url, body| {
                let transport = transport.clone();
                async move { post_unauthenticated(&transport, &url, body).await }
            })
            .await
            .map_err(GateError::Auth)
    }

    // ── Action discovery ─────────────────────────────────────────────────────

    /// Fetch all registered actions and their request schemas from LatchGate.
    ///
    /// Used to populate the MCP `tools/list` response. Schemas are fetched
    /// from `GET /v1/actions/{id}/schema/request`; if the endpoint returns
    /// 404 or an error, the tool is registered with a permissive
    /// `{"type": "object"}` input schema.
    ///
    /// For database actions (actions with a `database` block in their detail
    /// response), the description is enriched with the list of available
    /// predeclared statements and whether parameterized queries are allowed.
    ///
    /// Tool annotations (`readOnlyHint`, `destructiveHint`, `openWorldHint`)
    /// are derived from manifest metadata in the detail response.
    #[instrument(name = "gate.list_tools", skip(self))]
    pub async fn list_tools(&self) -> Result<Vec<McpTool>, GateError> {
        let resp = self.get_unauthenticated("/v1/actions").await?;

        let actions = resp["actions"]
            .as_array()
            .ok_or_else(|| GateError::UnexpectedResponse("missing 'actions' array".into()))?;

        let mut tools = Vec::with_capacity(actions.len());
        for action in actions {
            let action_id = action["action_id"]
                .as_str()
                .ok_or_else(|| GateError::UnexpectedResponse("action missing action_id".into()))?;
            let version = action["version"].as_str().unwrap_or("?");
            let risk_level = action["risk_level"].as_str().unwrap_or("unknown");

            // Fetch schema and detail concurrently — halves per-action latency.
            let (schema_result, detail_result) = tokio::join!(
                self.fetch_request_schema(action_id),
                self.fetch_action_detail(action_id),
            );

            let input_schema = schema_result.unwrap_or_else(|e| {
                warn!(action_id, error = %e, "could not fetch schema; using permissive fallback");
                serde_json::json!({"type": "object", "additionalProperties": true})
            });
            let detail = detail_result.ok();

            let description =
                build_tool_description(action_id, version, risk_level, detail.as_ref());

            let annotations = derive_annotations(action_id, risk_level, detail.as_ref());

            tools.push(McpTool {
                name: action_id.to_string(),
                description,
                input_schema,
                annotations,
            });
        }

        debug!(tools = tools.len(), "action list fetched");
        Ok(tools)
    }

    // ── Action execution ──────────────────────────────────────────────────────

    /// Execute a protected action through LatchGate.
    ///
    /// Returns the parsed JSON response body. The caller is responsible for
    /// interpreting `decision` ("allow", "pending_approval") and mapping it
    /// to the appropriate MCP content.
    ///
    /// Every request carries `X-LatchGate-Session-Id` for audit grouping.
    #[instrument(
        name = "gate.execute",
        skip(self, args),
        fields(action_id = %action_id),
    )]
    pub async fn execute(&self, action_id: &str, args: &Value) -> Result<Value, GateError> {
        validate_identifier(action_id, "action_id")?;

        let path = format!("/v1/actions/{action_id}/execute");

        // Ensure the lease is fresh before constructing the DPoP proof.
        let transport = self.transport.clone();
        self.dpop
            .ensure_lease(|url, body| {
                let transport = transport.clone();
                async move { post_unauthenticated(&transport, &url, body).await }
            })
            .await
            .map_err(GateError::Auth)?;

        // Produce a fresh DPoP proof bound to this request's method + URL.
        let (authorization, dpop_proof) = self
            .dpop
            .auth_headers("POST", &path)
            .await
            .map_err(GateError::Auth)?;

        let body_bytes = serde_json::to_vec(args)?;
        let headers = [
            ("authorization", authorization.as_str()),
            ("dpop", dpop_proof.as_str()),
            ("x-latchgate-session-id", self.session_id.as_str()),
        ];

        let (status, text) = self
            .transport
            .request("POST", &path, &body_bytes, &headers)
            .await
            .or_else(|e| match e {
                // Transport returns Err on 4xx/5xx, but we need the body.
                latchgate_client::ClientError::Http { status, body } => Ok((status, body)),
                other => Err(GateError::Transport(other.to_string())),
            })?;

        let body: Value = serde_json::from_str(&text).map_err(|e| {
            warn!(action_id, status, error = %e, "gate returned non-JSON response body");
            GateError::UnexpectedResponse(format!(
                "non-JSON response from execute (HTTP {status}): {e}"
            ))
        })?;

        // 202 = pending approval — not an error, surface as structured output.
        // 200 = success. Anything else = error.
        if status == 200 || status == 202 {
            Ok(body)
        } else {
            Err(GateError::GateHttp { status, body: text })
        }
    }

    // ── Health check ──────────────────────────────────────────────────────────

    /// Quick reachability check — hits `GET /v1/actions` (unauthenticated).
    ///
    /// Used by the reconnection state machine to verify the gate is back
    /// before resuming normal operation.
    pub async fn health_check(&self) -> Result<(), GateError> {
        self.get_unauthenticated("/v1/actions").await.map(|_| ())
    }

    // ── Approval polling ──────────────────────────────────────────────────────

    /// Poll the resolution status of a pending approval.
    ///
    /// Returns the outcome and an optional `Retry-After` hint from the gate.
    /// If the approval endpoint returns 404, the endpoint doesn't exist and
    /// the caller should fall back to the immediate `pending_approval` response.
    #[instrument(
        name = "gate.poll_approval",
        skip(self),
        fields(approval_id = %approval_id),
    )]
    pub async fn poll_approval(
        &self,
        approval_id: &str,
    ) -> Result<(ApprovalOutcome, Option<Duration>), GateError> {
        validate_identifier(approval_id, "approval_id")?;
        let path = format!("/v1/approvals/{approval_id}/poll");

        let (status, body) = self.get_authenticated(&path).await?;

        if status == 404 {
            return Err(GateError::UnexpectedResponse(
                "approval endpoint returned 404".into(),
            ));
        }

        let retry_after = body["retry_after_seconds"]
            .as_u64()
            .map(Duration::from_secs);

        let outcome = match body["status"].as_str() {
            Some("approved") | Some("executed") => ApprovalOutcome::Approved(body),
            Some("denied") => {
                let reason = body["reason"]
                    .as_str()
                    .unwrap_or("no reason provided")
                    .to_string();
                ApprovalOutcome::Denied { reason }
            }
            Some("expired") => ApprovalOutcome::Expired,
            Some(other) => {
                warn!(
                    approval_id,
                    status = other,
                    "unknown approval status; treating as pending"
                );
                ApprovalOutcome::Pending
            }
            None => {
                warn!(
                    approval_id,
                    "approval response missing 'status' field; \
                     body may be malformed or an error without status"
                );
                return Err(GateError::UnexpectedResponse(
                    "approval response missing 'status' field".into(),
                ));
            }
        };

        Ok((outcome, retry_after))
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    async fn get_unauthenticated(&self, path: &str) -> Result<Value, GateError> {
        let (_status, text) = self.transport.request("GET", path, &[], &[]).await?;
        serde_json::from_str(&text).map_err(GateError::Json)
    }

    /// Authenticated GET — uses DPoP proof and session header.
    async fn get_authenticated(&self, path: &str) -> Result<(u16, Value), GateError> {
        let transport = self.transport.clone();
        self.dpop
            .ensure_lease(|url, body| {
                let transport = transport.clone();
                async move { post_unauthenticated(&transport, &url, body).await }
            })
            .await
            .map_err(GateError::Auth)?;

        let (authorization, dpop_proof) = self
            .dpop
            .auth_headers("GET", path)
            .await
            .map_err(GateError::Auth)?;

        let headers = [
            ("authorization", authorization.as_str()),
            ("dpop", dpop_proof.as_str()),
            ("x-latchgate-session-id", self.session_id.as_str()),
        ];

        let (status, text) = self
            .transport
            .request("GET", path, &[], &headers)
            .await
            .or_else(|e| match e {
                latchgate_client::ClientError::Http { status, body } => Ok((status, body)),
                other => Err(GateError::Transport(other.to_string())),
            })?;

        let body: Value = serde_json::from_str(&text).map_err(|e| {
            warn!(path, status, error = %e, "gate returned non-JSON response body");
            GateError::UnexpectedResponse(format!(
                "non-JSON response from {path} (HTTP {status}): {e}"
            ))
        })?;
        Ok((status, body))
    }

    async fn fetch_request_schema(&self, action_id: &str) -> Result<Value, GateError> {
        validate_identifier(action_id, "action_id")?;
        let path = format!("/v1/actions/{action_id}/schema/request");
        self.get_unauthenticated(&path).await
    }

    /// Fetch the full action detail including database discovery metadata
    /// and fields needed for annotation derivation.
    async fn fetch_action_detail(&self, action_id: &str) -> Result<Value, GateError> {
        validate_identifier(action_id, "action_id")?;
        let path = format!("/v1/actions/{action_id}");
        self.get_unauthenticated(&path).await
    }
}

// ── Standalone transport helpers ───────────────────────────────────────────────

/// POST without auth headers — used for lease issuance bootstrapping.
///
/// `url` is the full endpoint URL (e.g. `http://localhost/v1/leases`).
async fn post_unauthenticated(
    transport: &Transport,
    url: &str,
    body: Value,
) -> Result<Value, McpAuthError> {
    let body_bytes = serde_json::to_vec(&body).map_err(|e| McpAuthError::Http(e.to_string()))?;

    // Transport::request takes a path, but lease issuance passes a full URL.
    // Extract the path component for the transport.
    let path = match url.find("://") {
        Some(scheme_end) => url[scheme_end + 3..]
            .find('/')
            .map(|i| &url[scheme_end + 3 + i..])
            .unwrap_or("/"),
        None => url,
    };

    let result = transport
        .request("POST", path, &body_bytes, &[])
        .await
        .or_else(|e| match e {
            latchgate_client::ClientError::Http { status, body } => Ok((status, body)),
            other => Err(other),
        })
        .map_err(|e| McpAuthError::Http(e.to_string()))?;

    let (status, text) = result;

    if status >= 400 {
        return Err(McpAuthError::LeaseIssuance { status, body: text });
    }

    serde_json::from_str(&text).map_err(|e| McpAuthError::Http(e.to_string()))
}

// ── Tool description builder ────────────────────────────────────────────────

/// Build a human-readable tool description for an MCP tool.
///
/// For non-database actions, returns a standard description. For database
/// actions (those with a `database` block in the detail response), returns
/// an enriched description listing available predeclared statements and
/// whether parameterized queries are allowed — giving LLMs enough context
/// to construct valid requests.
fn build_tool_description(
    _action_id: &str,
    version: &str,
    risk_level: &str,
    detail: Option<&Value>,
) -> String {
    let base = format!(
        "LatchGate protected action (version {version}, risk: {risk_level}). \
         Execution is authorized, audited, and verified by LatchGate.",
    );

    let db = match detail.and_then(|d| d.get("database")) {
        Some(db) if !db.is_null() => db,
        _ => return base,
    };

    let mode = db["mode"].as_str().unwrap_or("unknown");
    let allows_param = db["allows_parameterized_queries"]
        .as_bool()
        .unwrap_or(false);

    let mut desc = format!(
        "{base}\n\n\
         Database action (mode: {mode}). Use `statement_id` with `params` \
         to invoke a predeclared operation.",
    );

    // List available statements.
    if let Some(stmts) = db["statements"].as_array() {
        if !stmts.is_empty() {
            desc.push_str("\n\nAvailable statements:");
            for stmt in stmts {
                let id = stmt["id"].as_str().unwrap_or("?");
                let op = stmt["operation"].as_str().unwrap_or("?");
                let param_count = stmt["param_count"].as_u64().unwrap_or(0);
                let tables: Vec<&str> = stmt["tables"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
                    .unwrap_or_default();

                let tables_str = if tables.is_empty() {
                    String::new()
                } else {
                    format!(" on {}", tables.join(", "))
                };

                let params_str = if param_count == 0 {
                    String::new()
                } else {
                    let placeholders: Vec<String> =
                        (1..=param_count).map(|i| format!("${i}")).collect();
                    format!(" — params: [{}]", placeholders.join(", "))
                };

                desc.push_str(&format!("\n  - {id}: {op}{tables_str}{params_str}"));
            }
        }
    }

    // Parameterized query note.
    if allows_param {
        let param_ops: Vec<&str> = db["parameterized_operations"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        if !param_ops.is_empty() {
            desc.push_str(&format!(
                "\n\nYou can also send parameterized queries using the `query` field \
                 for {} operations.",
                param_ops.join(", "),
            ));
        }
    }

    desc
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Tool description ────────────────────────────────────────────────

    #[test]
    fn build_description_non_database_action() {
        let desc = build_tool_description("http_fetch", "1.0.0", "low", None);
        assert!(desc.contains("LatchGate protected action"));
        assert!(desc.contains("version 1.0.0"));
        assert!(!desc.contains("Database action"));
    }

    #[test]
    fn build_description_non_database_action_with_detail() {
        let detail = serde_json::json!({
            "action_id": "http_fetch",
            "version": "1.0.0",
        });
        let desc = build_tool_description("http_fetch", "1.0.0", "low", Some(&detail));
        assert!(!desc.contains("Database action"));
        assert!(!desc.contains("statement_id"));
    }

    #[test]
    fn build_description_database_action_lists_statements() {
        let detail = serde_json::json!({
            "action_id": "database_query",
            "database": {
                "mode": "hybrid",
                "allows_parameterized_queries": true,
                "parameterized_operations": ["select"],
                "statements": [
                    {"id": "get_order", "operation": "select", "tables": ["orders"], "param_count": 1},
                    {"id": "update_order_status", "operation": "update", "tables": ["orders"], "param_count": 2},
                    {"id": "insert_order", "operation": "insert", "tables": ["orders"], "param_count": 4},
                ],
            },
        });

        let desc = build_tool_description("database_query", "1.0.0", "high", Some(&detail));

        assert!(
            desc.contains("Database action (mode: hybrid)"),
            "desc: {desc}"
        );
        assert!(desc.contains("statement_id"), "desc: {desc}");
        assert!(desc.contains("Available statements:"), "desc: {desc}");
        assert!(
            desc.contains("get_order: select on orders — params: [$1]"),
            "desc: {desc}"
        );
        assert!(
            desc.contains("update_order_status: update on orders — params: [$1, $2]"),
            "desc: {desc}"
        );
        assert!(
            desc.contains("insert_order: insert on orders — params: [$1, $2, $3, $4]"),
            "desc: {desc}"
        );
        assert!(desc.contains("parameterized queries"), "desc: {desc}");
        assert!(desc.contains("select operations"), "desc: {desc}");
    }

    #[test]
    fn build_description_strict_mode_no_parameterized() {
        let detail = serde_json::json!({
            "database": {
                "mode": "strict",
                "allows_parameterized_queries": false,
                "parameterized_operations": [],
                "statements": [
                    {"id": "get_order", "operation": "select", "tables": ["orders"], "param_count": 1},
                ],
            },
        });

        let desc = build_tool_description("database_query", "1.0.0", "high", Some(&detail));

        assert!(desc.contains("mode: strict"), "desc: {desc}");
        assert!(desc.contains("get_order"), "desc: {desc}");
        assert!(
            !desc.contains("parameterized queries"),
            "strict should not mention parameterized: {desc}"
        );
    }

    #[test]
    fn build_description_statement_with_no_params() {
        let detail = serde_json::json!({
            "database": {
                "mode": "strict",
                "allows_parameterized_queries": false,
                "parameterized_operations": [],
                "statements": [
                    {"id": "count_all", "operation": "select", "tables": ["orders"], "param_count": 0},
                ],
            },
        });

        let desc = build_tool_description("database_query", "1.0.0", "low", Some(&detail));
        assert!(desc.contains("count_all: select on orders"));
        assert!(
            !desc.contains("params:"),
            "zero-param statement should not show params: {desc}"
        );
    }

    // ── validate_identifier ──────────────────────────────────────────────

    #[test]
    fn validate_identifier_accepts_simple_names() {
        assert!(validate_identifier("http_fetch", "action_id").is_ok());
        assert!(validate_identifier("http-fetch", "action_id").is_ok());
        assert!(validate_identifier("action.v2", "action_id").is_ok());
        assert!(validate_identifier("a", "action_id").is_ok());
    }

    #[test]
    fn validate_identifier_rejects_empty() {
        assert!(validate_identifier("", "action_id").is_err());
    }

    #[test]
    fn validate_identifier_rejects_path_traversal() {
        assert!(validate_identifier("../leases", "action_id").is_err());
        assert!(validate_identifier("../../v1/leases", "action_id").is_err());
        assert!(validate_identifier("foo/bar", "action_id").is_err());
        assert!(validate_identifier("foo\\bar", "action_id").is_err());
    }

    #[test]
    fn validate_identifier_rejects_url_special_chars() {
        assert!(validate_identifier("foo?bar", "action_id").is_err());
        assert!(validate_identifier("foo#bar", "action_id").is_err());
        assert!(validate_identifier("foo bar", "action_id").is_err());
        assert!(validate_identifier("foo%2Fbar", "action_id").is_err());
    }

    #[test]
    fn validate_identifier_rejects_excessive_length() {
        let long = "a".repeat(257);
        assert!(validate_identifier(&long, "action_id").is_err());
        let ok = "a".repeat(256);
        assert!(validate_identifier(&ok, "action_id").is_ok());
    }

    // ── Annotation derivation ────────────────────────────────────────────

    #[test]
    fn annotations_read_only_when_no_side_effects() {
        let detail = serde_json::json!({
            "declared_side_effects": [],
            "egress": {"profile": "proxy_allowlist"},
        });
        let ann = derive_annotations("http_fetch", "low", Some(&detail)).unwrap();
        assert_eq!(ann.read_only_hint, Some(true));
        assert_eq!(ann.destructive_hint, Some(false));
        assert_eq!(ann.idempotent_hint, None);
        assert_eq!(ann.open_world_hint, Some(true));
    }

    #[test]
    fn annotations_destructive_for_critical_risk() {
        let detail = serde_json::json!({
            "declared_side_effects": ["http_delete"],
            "egress": {"profile": "proxy_allowlist"},
        });
        let ann = derive_annotations("http_delete", "critical", Some(&detail)).unwrap();
        assert_eq!(ann.read_only_hint, Some(false));
        assert_eq!(ann.destructive_hint, Some(true));
        assert_eq!(ann.idempotent_hint, None);
        assert_eq!(ann.open_world_hint, Some(true));
    }

    #[test]
    fn annotations_destructive_for_destructive_side_effects() {
        let detail = serde_json::json!({
            "declared_side_effects": ["http_delete"],
        });
        let ann = derive_annotations("http_request", "high", Some(&detail)).unwrap();
        assert_eq!(ann.destructive_hint, Some(true));
    }

    #[test]
    fn annotations_non_destructive_write() {
        let detail = serde_json::json!({
            "declared_side_effects": ["http_write"],
            "egress": {"profile": "proxy_allowlist"},
        });
        let ann = derive_annotations("http_write", "medium", Some(&detail)).unwrap();
        assert_eq!(ann.read_only_hint, Some(false));
        assert_eq!(ann.destructive_hint, Some(false));
    }

    #[test]
    fn annotations_none_when_no_metadata() {
        let detail = serde_json::json!({"action_id": "test"});
        assert!(derive_annotations("test", "unknown", Some(&detail)).is_none());
    }

    #[test]
    fn annotations_none_when_no_detail() {
        assert!(derive_annotations("test", "low", None).is_none());
    }

    #[test]
    fn annotations_egress_none_means_not_open_world() {
        let detail = serde_json::json!({
            "declared_side_effects": ["compute"],
            "egress": {"profile": "none"},
        });
        let ann = derive_annotations("compute_task", "low", Some(&detail)).unwrap();
        assert_eq!(ann.open_world_hint, Some(false));
    }

    #[test]
    fn annotations_proxy_allowlist_is_open_world() {
        let detail = serde_json::json!({
            "declared_side_effects": ["http_read"],
            "egress": {"profile": "proxy_allowlist"},
        });
        let ann = derive_annotations("http_fetch", "low", Some(&detail)).unwrap();
        assert_eq!(ann.open_world_hint, Some(true));
    }

    #[test]
    fn annotations_egress_profile_at_top_level() {
        // Some gate versions may return egress_profile at the top level.
        let detail = serde_json::json!({
            "declared_side_effects": ["http_read"],
            "egress_profile": "proxy_allowlist",
        });
        let ann = derive_annotations("http_read", "low", Some(&detail)).unwrap();
        assert_eq!(ann.open_world_hint, Some(true));
    }

    #[test]
    fn annotations_unknown_egress_profile_omits_hint() {
        let detail = serde_json::json!({
            "declared_side_effects": ["http_read"],
            "egress": {"profile": "direct"},
        });
        let ann = derive_annotations("http_read", "low", Some(&detail)).unwrap();
        // open_world_hint omitted for unknown profile.
        assert_eq!(ann.open_world_hint, None);
        // But other hints are still derived.
        assert_eq!(ann.read_only_hint, Some(false));
    }

    #[test]
    fn annotations_all_destructive_verbs_in_side_effects() {
        for verb in &[
            "delete",
            "destroy",
            "drop",
            "purge",
            "remove",
            "revoke",
            "terminate",
            "truncate",
            "wipe",
        ] {
            let detail = serde_json::json!({
                "declared_side_effects": [format!("db_{verb}")],
            });
            let ann = derive_annotations("safe_action", "low", Some(&detail)).unwrap();
            assert_eq!(
                ann.destructive_hint,
                Some(true),
                "side-effect verb '{verb}' should trigger destructiveHint"
            );
        }
    }

    #[test]
    fn annotations_destructive_name_heuristic_high_risk() {
        // High-risk action with a destructive verb in action_id but only
        // benign declared side effects — the name heuristic fires as a
        // safety net for under-declared manifests.
        let detail = serde_json::json!({
            "declared_side_effects": ["api_call"],
            "egress": {"profile": "proxy_allowlist"},
        });
        let ann = derive_annotations("github_delete_repo", "high", Some(&detail)).unwrap();
        assert_eq!(ann.destructive_hint, Some(true));
    }

    #[test]
    fn annotations_destructive_name_heuristic_skipped_for_low_risk() {
        // Same destructive action_id, but low-risk — the name heuristic
        // must not fire. Only declared_side_effects matter at low risk.
        let detail = serde_json::json!({
            "declared_side_effects": ["api_call"],
        });
        let ann = derive_annotations("cache_delete", "low", Some(&detail)).unwrap();
        assert_eq!(ann.destructive_hint, Some(false));
    }

    #[test]
    fn annotations_destructive_name_heuristic_without_detail() {
        // High-risk action with a destructive name but no detail response
        // at all — the heuristic still fires from action_id alone.
        let ann = derive_annotations("github_delete_repo", "high", None).unwrap();
        assert_eq!(ann.destructive_hint, Some(true));
    }

    /// Gate-discovered tools never set `idempotent_hint` — it is only set
    /// by the static approval tool definitions in `admin_client.rs`. This
    /// test makes the contract explicit so a future manifest field addition
    /// is a deliberate choice, not an accidental omission.
    #[test]
    fn annotations_never_set_idempotent_hint() {
        let cases: &[(&str, &str, Value)] = &[
            (
                "read-only",
                "http_fetch",
                serde_json::json!({
                    "declared_side_effects": [],
                    "egress": {"profile": "proxy_allowlist"},
                }),
            ),
            (
                "destructive",
                "http_delete",
                serde_json::json!({
                    "declared_side_effects": ["http_delete"],
                    "egress": {"profile": "none"},
                }),
            ),
            (
                "critical",
                "db_truncate",
                serde_json::json!({
                    "declared_side_effects": ["db_truncate"],
                }),
            ),
        ];
        for (label, action_id, detail) in cases {
            let ann = derive_annotations(action_id, "high", Some(detail))
                .unwrap_or_else(|| panic!("{label}: expected Some"));
            assert_eq!(
                ann.idempotent_hint, None,
                "{label}: gate annotations must not set idempotent_hint"
            );
        }
    }

    // ── GateError classification ─────────────────────────────────────────

    #[test]
    fn transport_error_is_transport_failure() {
        let err = GateError::Transport("connection refused".into());
        assert!(err.is_transport_failure());
    }

    #[test]
    fn auth_http_error_is_transport_failure() {
        let err = GateError::Auth(crate::auth::McpAuthError::Http("timeout".into()));
        assert!(err.is_transport_failure());
    }

    #[test]
    fn gate_http_error_is_not_transport_failure() {
        let err = GateError::GateHttp {
            status: 403,
            body: "denied".into(),
        };
        assert!(!err.is_transport_failure());
    }

    #[test]
    fn json_error_is_not_transport_failure() {
        let err = GateError::UnexpectedResponse("bad shape".into());
        assert!(!err.is_transport_failure());
    }

    #[test]
    fn unexpected_response_from_non_json_is_not_transport_failure() {
        // The new strict-parse path in get_authenticated/execute returns
        // UnexpectedResponse for non-JSON bodies — verify it doesn't
        // trigger the reconnect state machine.
        let err = GateError::UnexpectedResponse(
            "non-JSON response from /v1/approvals/x (HTTP 500): expected value".into(),
        );
        assert!(
            !err.is_transport_failure(),
            "non-JSON parse errors should not trigger reconnect"
        );
    }

    #[test]
    fn unexpected_response_for_missing_status_is_not_transport_failure() {
        // The M2 fix: poll_approval returns UnexpectedResponse when
        // the status field is missing.
        let err = GateError::UnexpectedResponse("approval response missing 'status' field".into());
        assert!(
            !err.is_transport_failure(),
            "missing-status errors should not trigger reconnect"
        );
    }
}
