//! MCP stdio server — JSON-RPC 2.0 event loop.
//!
//! Reads newline-delimited JSON from stdin, dispatches to the appropriate
//! handler, and writes responses to stdout. Logs go to stderr so they do
//! not interfere with the MCP transport.
//!
//! # Tool execution semantics
//!
//! - **Success** => `isError: false`, output JSON formatted as text.
//! - **Pending approval** => adapter polls `GET /v1/approvals/{id}` with
//!   MCP progress notifications, resolving to the executed output,
//!   `policy_denied`, or `lease_expired`.
//! - **LatchGate error** => `isError: true`, structured JSON body with the
//!   appropriate error code, message, and trace_id.
//!
//! # Reconnection
//!
//! When the gate becomes unreachable, the adapter enters a reconnecting
//! state with exponential backoff (1s → 2s → 4s → … → 30s cap, ±25%
//! jitter). Tool calls during reconnection return `gate_unavailable`
//! immediately. On successful reconnect, the tool cache is invalidated
//! and actions are re-discovered. The stdio loop never terminates due to
//! gate errors.
//!
//! # Input validation
//!
//! Tool call arguments are validated against the cached JSON Schema before
//! the gate round-trip. Schema violations return `schema_validation` with
//! the specific field that failed.
//!
//! # Shutdown
//!
//! The server exits cleanly when stdin is closed (EOF).

use std::borrow::Cow;
use std::io::{BufWriter, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{json, Value};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, BufReader as AsyncBufReader};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::admin_client::{self, AdminClient};
use crate::gate_client::{ApprovalOutcome, GateClient, GateError};
use crate::protocol::{
    error_codes, map_gate_error_code, tool_error_codes, ContentBlock, InitializeParams,
    JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, McpPrompt, McpPromptArgument,
    McpResource, McpResourceContent, McpTool, McpToolAnnotations, RequestId, StructuredToolError,
    ToolCallParams, PROTOCOL_VERSION,
};

// ── Constants ─────────────────────────────────────────────────────────────────

const TOOL_CACHE_TTL: Duration = Duration::from_secs(300);

/// Background refresh interval for proactive tool-change detection.
///
/// Set to half the cache TTL so a gate restart is noticed even when the
/// adapter is idle and no `tools/list` request forces a TTL-based refresh.
const TOOL_REFRESH_INTERVAL: Duration = Duration::from_secs(150);

const BACKOFF_MAX: Duration = Duration::from_secs(30);

const APPROVAL_POLL_INTERVAL: Duration = Duration::from_secs(2);
const APPROVAL_POLL_TIMEOUT: Duration = Duration::from_secs(300);
/// Floor/ceiling for gate-suggested Retry-After.
const RETRY_AFTER_MIN: Duration = Duration::from_secs(1);
const RETRY_AFTER_MAX: Duration = Duration::from_secs(30);

/// Maximum stdin line length. Lines exceeding this are rejected with
/// PARSE_ERROR without further processing. Protects against OOM from a
/// malicious or buggy IDE sending unbounded input.
///
/// Enforced incrementally by `read_bounded_line`: bytes beyond this limit
/// are never allocated — the reader drains the oversized line directly from
/// the internal buffer and returns an error.
const MAX_LINE_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

// ── Reconnection state ────────────────────────────────────────────────────────

struct ReconnectState {
    healthy: bool,
    attempt: u32,
    next_retry_at: Instant,
}

impl ReconnectState {
    fn new_healthy() -> Self {
        Self {
            healthy: true,
            attempt: 0,
            next_retry_at: Instant::now(),
        }
    }

    fn enter_reconnecting(&mut self) {
        self.healthy = false;
        self.attempt = 1;
        self.next_retry_at = Instant::now() + backoff_duration(1);
    }

    fn advance_backoff(&mut self) {
        self.attempt = self.attempt.saturating_add(1);
        self.next_retry_at = Instant::now() + backoff_duration(self.attempt);
    }

    fn restore_healthy(&mut self) {
        self.healthy = true;
        self.attempt = 0;
    }

    fn can_retry_now(&self) -> bool {
        Instant::now() >= self.next_retry_at
    }

    fn secs_until_retry(&self) -> u64 {
        self.next_retry_at
            .saturating_duration_since(Instant::now())
            .as_secs()
    }
}

/// Exponential backoff with ±25% jitter.
///
/// Base: 1→1s, 2→2s, 3→4s, 4→8s, 5→16s, 6+→30s (cap).
/// Jitter prevents thundering herd when multiple adapters reconnect.
fn backoff_duration(attempt: u32) -> Duration {
    let base = 1u64
        .checked_shl(attempt.saturating_sub(1))
        .unwrap_or(u64::MAX)
        .min(BACKOFF_MAX.as_secs());

    // ±25% jitter using nanosecond clock entropy.
    let jitter_range = (base / 4).max(1);
    let entropy = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    let jitter = entropy % (2 * jitter_range + 1);
    let actual = base.saturating_sub(jitter_range).saturating_add(jitter);

    Duration::from_secs(actual.max(1))
}

// ── McpServer ─────────────────────────────────────────────────────────────────

pub struct McpServer {
    client: GateClient,
    /// Operator-authenticated client for approval tools. `None` when
    /// admin socket / operator key are not configured — approval tools
    /// are not registered and the polling behavior is unchanged.
    admin: Option<AdminClient>,
    /// The agent principal identifier (for allowlist default).
    agent_id: String,
    /// Whether `latchgate_allowlist` is registered. Requires explicit
    /// opt-in via `--enable-allowlist-tool`.
    allowlist_enabled: bool,
    /// Cached tool list. `Arc` avoids deep-cloning schemas on cache hits.
    tools: RwLock<Option<(Arc<Vec<McpTool>>, Instant)>>,
    reconnect: std::sync::Mutex<ReconnectState>,
    stdout: std::sync::Mutex<BufWriter<std::io::Stdout>>,
    /// Set after `initialize` handshake completes. Prevents emitting
    /// notifications before the client is ready to receive them.
    initialized: AtomicBool,
}

impl McpServer {
    /// Construct the **agent** server.
    ///
    /// The agent session exposes protected actions as MCP tools and resolves
    /// held actions by polling for an out-of-band operator approval. It holds
    /// no operator credential and never advertises or handles approval tools:
    /// `admin` is unconditionally `None`, so the requesting agent has no code
    /// path by which it could approve its own held action.
    pub fn agent(client: GateClient, agent_id: String) -> Arc<Self> {
        Arc::new(Self {
            client,
            admin: None,
            agent_id,
            allowlist_enabled: false,
            tools: RwLock::new(None),
            reconnect: std::sync::Mutex::new(ReconnectState::new_healthy()),
            stdout: std::sync::Mutex::new(BufWriter::new(std::io::stdout())),
            initialized: AtomicBool::new(false),
        })
    }

    /// Construct the **operator** server (approval session).
    ///
    /// The operator session advertises and handles the approval tools, routing
    /// them to the supplied [`AdminClient`]. It must run as a separate adapter
    /// instance from [`agent`](Self::agent) so a requesting agent can never
    /// reach these tools.
    pub fn operator(
        client: GateClient,
        admin: AdminClient,
        agent_id: String,
        allowlist_enabled: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            client,
            admin: Some(admin),
            agent_id,
            allowlist_enabled,
            tools: RwLock::new(None),
            reconnect: std::sync::Mutex::new(ReconnectState::new_healthy()),
            stdout: std::sync::Mutex::new(BufWriter::new(std::io::stdout())),
            initialized: AtomicBool::new(false),
        })
    }

    pub async fn run(self: Arc<Self>) {
        info!(
            session_id = %self.client.session_id(),
            "latchgate-mcp starting — waiting for MCP initialize",
        );

        if let Err(e) = self.client.ensure_connected().await {
            warn!(error = %e, "initial connection to LatchGate failed; will retry on first request");
        } else if let Err(e) = self.warm_tool_cache().await {
            warn!(error = %e, "initial tool cache warm-up failed; will retry on tools/list");
        }

        // Spawn a background task that periodically re-fetches the tool list.
        // Detects gate restarts that add/remove actions even when the adapter
        // is idle (no incoming `tools/list` to trigger a TTL-based refresh).
        // The task runs until the process exits (stdin EOF → run() returns →
        // tokio runtime shuts down → task is cancelled).
        {
            let this = Arc::clone(&self);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(TOOL_REFRESH_INTERVAL).await;
                    this.background_refresh_tick().await;
                }
            });
        }

        let stdin = tokio::io::stdin();
        let mut reader = AsyncBufReader::new(stdin);
        let mut line = String::with_capacity(4096);

        loop {
            match read_bounded_line(&mut reader, &mut line, MAX_LINE_BYTES).await {
                Ok(0) => break, // EOF
                Ok(_) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }

                    debug!(bytes = trimmed.len(), "stdin line received");

                    let response = self.handle_line(trimmed).await;
                    if let Some(resp) = response {
                        if let Err(e) = self.write_message(&resp) {
                            error!(error = %e, "stdout write error");
                            break;
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                    warn!(error = %e, "rejecting invalid stdin message");
                    let resp = JsonRpcResponse::err(None, error_codes::PARSE_ERROR, e.to_string());
                    if let Err(e) = self.write_message(&resp) {
                        error!(error = %e, "stdout write error");
                        break;
                    }
                }
                Err(e) => {
                    error!(error = %e, "stdin read error");
                    break;
                }
            }
        }

        info!("stdin closed — latchgate-mcp exiting");
    }

    // ── Stdout ────────────────────────────────────────────────────────────────

    fn write_message(&self, msg: &impl Serialize) -> Result<(), std::io::Error> {
        let json = serde_json::to_string(msg).map_err(std::io::Error::other)?;
        let mut out = self.stdout.lock().unwrap_or_else(|e| e.into_inner());
        writeln!(out, "{json}")?;
        out.flush()
    }

    fn send_notification(&self, notif: &JsonRpcNotification) {
        if let Err(e) = self.write_message(notif) {
            debug!(error = %e, "failed to send notification");
        }
    }

    // ── Dispatch ──────────────────────────────────────────────────────────────

    async fn handle_line(&self, line: &str) -> Option<JsonRpcResponse> {
        let req: JsonRpcRequest = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "failed to parse incoming JSON-RPC message");
                return Some(JsonRpcResponse::err(
                    None,
                    error_codes::PARSE_ERROR,
                    format!("parse error: {e}"),
                ));
            }
        };

        if req.jsonrpc != "2.0" {
            return Some(JsonRpcResponse::err(
                req.id,
                error_codes::INVALID_REQUEST,
                "jsonrpc must be \"2.0\"",
            ));
        }

        debug!(method = %req.method, "dispatching");

        match req.method.as_str() {
            "initialize" => Some(self.handle_initialize(req.id, req.params).await),
            "notifications/initialized" => {
                debug!("initialized notification received");
                None
            }
            "tools/list" => Some(self.handle_tools_list(req.id).await),
            "tools/call" => Some(self.handle_tools_call(req.id, req.params).await),
            "resources/list" => Some(self.handle_resources_list(req.id)),
            "resources/read" => Some(self.handle_resources_read(req.id, req.params).await),
            "prompts/list" => Some(self.handle_prompts_list(req.id)),
            "prompts/get" => Some(self.handle_prompts_get(req.id, req.params).await),
            "ping" => Some(JsonRpcResponse::ok(req.id, json!({}))),
            other => {
                warn!(method = other, "unknown MCP method");
                Some(JsonRpcResponse::err(
                    req.id,
                    error_codes::METHOD_NOT_FOUND,
                    format!("method not found: {other}"),
                ))
            }
        }
    }

    // ── initialize ────────────────────────────────────────────────────────────

    async fn handle_initialize(&self, id: Option<RequestId>, params: Value) -> JsonRpcResponse {
        let _parsed: Result<InitializeParams, _> = serde_json::from_value(params.clone());
        if let Ok(ref p) = _parsed {
            info!(
                client_protocol = %p.protocol_version,
                client_name = p.client_info.as_ref().map(|c| c.name.as_str()).unwrap_or("unknown"),
                "MCP initialize"
            );
            if p.protocol_version != PROTOCOL_VERSION {
                warn!(
                    requested = %p.protocol_version,
                    supported = PROTOCOL_VERSION,
                    "client requested different protocol version; proceeding with supported version"
                );
            }
        }

        self.initialized.store(true, Ordering::Release);

        let capabilities = if self.admin.is_some() {
            json!({
                "tools": { "listChanged": true },
                "resources": { "listChanged": true },
                "prompts": { "listChanged": false }
            })
        } else {
            json!({
                "tools": { "listChanged": true },
                "resources": { "listChanged": true }
            })
        };

        JsonRpcResponse::ok(
            id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": capabilities,
                "serverInfo": {
                    "name": "latchgate-mcp",
                    "version": env!("CARGO_PKG_VERSION"),
                    "description": "LatchGate MCP adapter — action authorization + effect verification"
                }
            }),
        )
    }

    // ── tools/list ────────────────────────────────────────────────────────────

    async fn handle_tools_list(&self, id: Option<RequestId>) -> JsonRpcResponse {
        if let Err(msg) = self.ensure_gate_reachable().await {
            return JsonRpcResponse::err(
                id,
                error_codes::INTERNAL_ERROR,
                format!("Cannot fetch action list: {msg}"),
            );
        }

        match self.get_or_fetch_tools().await {
            Ok(gate_tools) => {
                debug!(count = gate_tools.len(), "returning tool list");
                self.on_gate_success();

                // Append operator approval tools when admin is configured.
                if self.admin.is_some() {
                    let approval = admin_client::approval_tools(self.allowlist_enabled);
                    let mut combined = (*gate_tools).clone();
                    combined.extend(approval);
                    JsonRpcResponse::ok(id, json!({ "tools": combined }))
                } else {
                    let mut tools = (*gate_tools).clone();
                    tools.push(tool_my_pending());
                    JsonRpcResponse::ok(id, json!({ "tools": tools }))
                }
            }
            Err(e) => {
                if e.is_transport_failure() {
                    self.on_transport_failure();
                }
                error!(error = %e, "tools/list failed");
                JsonRpcResponse::err(
                    id,
                    error_codes::INTERNAL_ERROR,
                    format!("failed to fetch action list from LatchGate: {e}"),
                )
            }
        }
    }

    // ── tools/call ────────────────────────────────────────────────────────────

    async fn handle_tools_call(&self, id: Option<RequestId>, params: Value) -> JsonRpcResponse {
        let call: ToolCallParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                return JsonRpcResponse::err(
                    id,
                    error_codes::INVALID_PARAMS,
                    format!("invalid tools/call params: {e}"),
                );
            }
        };

        let trace_id = generate_trace_id();

        if let Some(resp) = self
            .dispatch_special_tool(id.clone(), &call, &trace_id)
            .await
        {
            return resp;
        }

        if let Err(resp) = self.validate_tool_call(id.clone(), &call, &trace_id).await {
            return resp;
        }

        let progress_token = call.progress_token().cloned();
        self.execute_gate_tool(id, &call, &trace_id, progress_token.as_ref())
            .await
    }

    /// Route approval tools (operator session) and agent read-only tools.
    ///
    /// Returns `Some(response)` if the tool was handled locally, `None` to
    /// continue to the gate execution path.
    async fn dispatch_special_tool(
        &self,
        id: Option<RequestId>,
        call: &ToolCallParams,
        trace_id: &str,
    ) -> Option<JsonRpcResponse> {
        // Approval tools — operator session only. The agent server has
        // `admin == None`, so this branch is unreachable for agents.
        if let Some(ref admin) = self.admin {
            if admin_client::is_approval_tool(&call.name) {
                return Some(
                    admin_client::handle_approval_tool_call(
                        admin,
                        self.allowlist_enabled,
                        &self.agent_id,
                        id,
                        &call.name,
                        &call.arguments,
                        trace_id,
                    )
                    .await,
                );
            }
        }

        // Agent read-only tool — agent session only. On the operator
        // session this name is never in tools/list and falls through
        // to the gate (action_not_found).
        if call.name == "latchgate_my_pending" && self.admin.is_none() {
            return Some(self.handle_my_pending(id, trace_id).await);
        }

        None
    }

    /// Ensure the gate is reachable, resolve the tool name from the cache,
    /// and validate the input against the tool's JSON Schema.
    ///
    /// Returns `Ok(())` on success, `Err(response)` with a ready-to-send
    /// JSON-RPC error when validation fails or the tool is unknown.
    async fn validate_tool_call(
        &self,
        id: Option<RequestId>,
        call: &ToolCallParams,
        trace_id: &str,
    ) -> Result<(), JsonRpcResponse> {
        // ── Reconnection gate ────────────────────────────────────────
        if let Err(msg) = self.ensure_gate_reachable().await {
            return Err(structured_tool_error(
                id,
                tool_error_codes::GATE_UNAVAILABLE,
                msg,
                Some(&call.name),
                trace_id,
                None,
            ));
        }

        // ── Single-pass tool lookup: name check + schema extraction ──
        //
        // One RwLock acquire in the happy path. The refresh (miss) path
        // uses the Arc returned by warm_tool_cache directly.
        enum CacheLookup {
            Hit(Value),
            Miss,
            Cold,
        }

        let lookup = {
            let guard = self.tools.read().await;
            match &*guard {
                Some((tools, _)) => match tools.iter().find(|t| t.name == call.name) {
                    Some(tool) => CacheLookup::Hit(tool.input_schema.clone()),
                    None => CacheLookup::Miss,
                },
                None => CacheLookup::Cold,
            }
        };

        match lookup {
            CacheLookup::Hit(ref schema) => {
                if let Err(detail) = validate_input_schema(schema, &call.arguments) {
                    warn!(action_id = %call.name, %trace_id, detail = %detail, "input schema validation failed");
                    return Err(structured_tool_error(
                        id,
                        tool_error_codes::SCHEMA_VALIDATION,
                        format!("Input validation failed for '{}': {detail}", call.name),
                        Some(&call.name),
                        trace_id,
                        None,
                    ));
                }
            }
            CacheLookup::Miss => {
                // Refresh cache — action may have been deployed since last fetch.
                match self.warm_tool_cache().await {
                    Ok(fresh) => match fresh.iter().find(|t| t.name == call.name) {
                        Some(tool) => {
                            if let Err(detail) =
                                validate_input_schema(&tool.input_schema, &call.arguments)
                            {
                                warn!(action_id = %call.name, %trace_id, detail = %detail, "input schema validation failed");
                                return Err(structured_tool_error(
                                    id,
                                    tool_error_codes::SCHEMA_VALIDATION,
                                    format!(
                                        "Input validation failed for '{}': {detail}",
                                        call.name,
                                    ),
                                    Some(&call.name),
                                    trace_id,
                                    None,
                                ));
                            }
                        }
                        None => {
                            warn!(action_id = %call.name, %trace_id, "unknown tool after cache refresh");
                            return Err(structured_tool_error(
                                id,
                                tool_error_codes::ACTION_NOT_FOUND,
                                format!("Action '{}' not found in registry.", call.name),
                                Some(&call.name),
                                trace_id,
                                None,
                            ));
                        }
                    },
                    Err(e) => {
                        if e.is_transport_failure() {
                            self.on_transport_failure();
                        }
                        warn!(action_id = %call.name, error = %e, %trace_id, "cache refresh failed");
                        return Err(structured_tool_error(
                            id,
                            tool_error_codes::ACTION_NOT_FOUND,
                            format!("Action '{}' not found in registry.", call.name),
                            Some(&call.name),
                            trace_id,
                            None,
                        ));
                    }
                }
            }
            CacheLookup::Cold => {
                // Cache not yet populated — skip client-side validation.
                // The gate is the authoritative validator.
            }
        }

        Ok(())
    }

    /// Execute an action through the gate and map the response.
    ///
    /// On success, delegates to [`map_execute_response`](Self::map_execute_response)
    /// for approval polling and output formatting. On error, updates the
    /// reconnection state and converts the [`GateError`] into a structured
    /// MCP tool error via [`map_gate_error`].
    async fn execute_gate_tool(
        &self,
        id: Option<RequestId>,
        call: &ToolCallParams,
        trace_id: &str,
        progress_token: Option<&Value>,
    ) -> JsonRpcResponse {
        debug!(action_id = %call.name, %trace_id, "executing action");

        match self.client.execute(&call.name, &call.arguments).await {
            Ok(resp) => {
                self.on_gate_success();
                self.map_execute_response(id, &call.name, trace_id, progress_token, resp)
                    .await
            }
            Err(e) => {
                if e.is_transport_failure() {
                    self.on_transport_failure();
                }
                map_gate_error(id, &call.name, trace_id, e)
            }
        }
    }

    /// Map a successful gate response (200 or 202) to MCP tool call content.
    async fn map_execute_response(
        &self,
        id: Option<RequestId>,
        action_id: &str,
        trace_id: &str,
        progress_token: Option<&Value>,
        resp: Value,
    ) -> JsonRpcResponse {
        match resp["decision"].as_str() {
            Some("executed") => {
                let receipt_id = resp["receipt_id"].as_str().unwrap_or("unknown");
                let output = &resp["output"];
                let is_fully_successful = resp["verification"]["is_fully_successful"]
                    .as_bool()
                    .unwrap_or(false);
                let verification_outcome = resp["verification"]["outcome"]
                    .as_str()
                    .unwrap_or("unknown");

                info!(
                    action_id,
                    receipt_id,
                    trace_id,
                    verification = verification_outcome,
                    "action executed"
                );

                let text = format_success_output(output, receipt_id, is_fully_successful);
                tool_success(id, text)
            }
            Some("pending_approval") => {
                let approval_id = resp["approval_id"].as_str();

                match approval_id {
                    Some(aid) => {
                        // Operator session: return immediately with the
                        // approval_id so the operator can invoke
                        // latchgate_approve / latchgate_deny on this same
                        // session. The stdio transport is sequential, so
                        // polling here would block the operator's own approve
                        // call. `admin` is only ever set on the operator
                        // server, so this branch never runs for an agent.
                        if self.admin.is_some() {
                            info!(
                                action_id,
                                approval_id = aid,
                                trace_id,
                                "action requires approval — returning immediately (operator session)"
                            );
                            return self.pending_approval_immediate(id, action_id, aid, trace_id);
                        }

                        // Agent session: wait for an out-of-band operator
                        // approval (TUI/CLI or a separate operator MCP
                        // session). The agent cannot approve its own action.
                        info!(
                            action_id,
                            approval_id = aid,
                            trace_id,
                            "action requires approval — starting poll loop"
                        );
                        self.poll_for_approval(id, action_id, aid, trace_id, progress_token)
                            .await
                    }
                    None => {
                        // Gate returned pending_approval without an ID — can't poll.
                        warn!(
                            action_id,
                            trace_id, "pending_approval response missing approval_id"
                        );
                        self.pending_approval_fallback(id, action_id, "unknown", trace_id)
                    }
                }
            }
            other => {
                let body_preview = serde_json::to_string(&resp)
                    .unwrap_or_default()
                    .chars()
                    .take(500)
                    .collect::<String>();
                warn!(
                    action_id,
                    trace_id,
                    decision = ?other,
                    body = %body_preview,
                    "unexpected gate response"
                );
                structured_tool_error(
                    id,
                    tool_error_codes::GATE_UNAVAILABLE,
                    format!("Unexpected gate response for action '{action_id}'."),
                    Some(action_id),
                    trace_id,
                    None,
                )
            }
        }
    }

    // ── Approval polling ──────────────────────────────────────────────────────

    async fn poll_for_approval(
        &self,
        id: Option<RequestId>,
        action_id: &str,
        approval_id: &str,
        trace_id: &str,
        progress_token: Option<&Value>,
    ) -> JsonRpcResponse {
        let status_msg = format!(
            "Action '{action_id}' is waiting for operator approval (ID: {approval_id}). \
             Approve via 'latchgate tui' or 'latchgate approvals approve {approval_id}'."
        );
        self.send_notification(&JsonRpcNotification::log_message("info", &status_msg));
        if let Some(token) = progress_token {
            self.send_notification(&JsonRpcNotification::progress(token, 0, None));
        }

        let deadline = Instant::now() + APPROVAL_POLL_TIMEOUT;
        let mut interval = APPROVAL_POLL_INTERVAL;
        let mut poll_count = 0u64;

        loop {
            poll_count += 1;

            if Instant::now() >= deadline {
                warn!(
                    action_id,
                    approval_id, trace_id, "approval polling timed out"
                );
                return self.pending_approval_fallback(id, action_id, approval_id, trace_id);
            }

            match self.client.poll_approval(approval_id).await {
                Ok((ApprovalOutcome::Pending, retry_after)) => {
                    if let Some(ra) = retry_after {
                        interval = ra.clamp(RETRY_AFTER_MIN, RETRY_AFTER_MAX);
                    }
                    if let Some(token) = progress_token {
                        self.send_notification(&JsonRpcNotification::progress(
                            token, poll_count, None,
                        ));
                    }
                    if poll_count.is_multiple_of(5) {
                        self.send_notification(&JsonRpcNotification::log_message(
                            "info",
                            format!(
                                "Still waiting for approval on '{action_id}' ({approval_id})..."
                            ),
                        ));
                    }
                }
                Ok((ApprovalOutcome::Approved(body), _)) => {
                    info!(action_id, approval_id, trace_id, "approval granted");
                    self.send_notification(&JsonRpcNotification::log_message(
                        "info",
                        format!("Action '{action_id}' approved."),
                    ));

                    let receipt_id = body["receipt_id"]
                        .as_str()
                        .or_else(|| body["execution"]["receipt_id"].as_str())
                        .unwrap_or("unknown");
                    let output = if !body["output"].is_null() {
                        &body["output"]
                    } else if !body["execution"]["output"].is_null() {
                        &body["execution"]["output"]
                    } else {
                        &Value::Null
                    };
                    let is_fully_successful = body["verification"]["is_fully_successful"]
                        .as_bool()
                        .or_else(|| {
                            body["execution"]["verification"]["is_fully_successful"].as_bool()
                        })
                        .unwrap_or(false);

                    let text = format_success_output(output, receipt_id, is_fully_successful);
                    return tool_success(id, text);
                }
                Ok((ApprovalOutcome::Denied { reason }, _)) => {
                    info!(action_id, approval_id, trace_id, reason = %reason, "approval denied");
                    self.send_notification(&JsonRpcNotification::log_message(
                        "warning",
                        format!("Action '{action_id}' denied: {reason}"),
                    ));
                    return structured_tool_error(
                        id,
                        tool_error_codes::POLICY_DENIED,
                        format!("Action '{action_id}' was denied: {reason}"),
                        Some(action_id),
                        trace_id,
                        None,
                    );
                }
                Ok((ApprovalOutcome::Expired, _)) => {
                    info!(action_id, approval_id, trace_id, "approval expired");
                    return structured_tool_error(
                        id,
                        tool_error_codes::LEASE_EXPIRED,
                        format!("Approval for '{action_id}' expired."),
                        Some(action_id),
                        trace_id,
                        None,
                    );
                }
                Err(e) => {
                    warn!(
                        action_id, approval_id, trace_id, error = %e,
                        "approval polling failed; returning pending_approval"
                    );
                    if e.is_transport_failure() {
                        self.on_transport_failure();
                    }
                    return self.pending_approval_fallback(id, action_id, approval_id, trace_id);
                }
            }

            // Sleep *after* polling so the first iteration is immediate and the
            // gate's retry_after hint (set above) takes effect on this same sleep.
            tokio::time::sleep(interval).await;
        }
    }

    fn pending_approval_fallback(
        &self,
        id: Option<RequestId>,
        action_id: &str,
        approval_id: &str,
        trace_id: &str,
    ) -> JsonRpcResponse {
        let error = StructuredToolError {
            code: Cow::Borrowed(tool_error_codes::PENDING_APPROVAL),
            message: format!(
                "Action '{action_id}' is waiting for operator approval. \
                 Approve via 'latchgate tui' or \
                 'latchgate approvals approve {approval_id}'."
            ),
            action_id: Some(action_id.to_string()),
            trace_id: Some(trace_id.to_string()),
            approval_id: Some(approval_id.to_string()),
            remediation: None,
        };
        tool_error_structured(id, &error)
    }

    /// Return an immediate pending_approval response when admin client is
    /// configured. Includes the approval_id and instructions for invoking
    /// `latchgate_approve` or `latchgate_deny` as a structured non-error
    /// result so orchestrators can parse the approval_id and trace_id
    /// programmatically.
    ///
    /// Returned with `isError: false` — many MCP clients surface
    /// `isError: true` as a hard failure and will not attempt remediation.
    /// A non-error structured result lets the agent parse the approval_id
    /// and invoke the approval tool automatically.
    ///
    /// This unblocks the stdio loop so the operator can invoke the approval
    /// tool on the same MCP connection.
    fn pending_approval_immediate(
        &self,
        id: Option<RequestId>,
        action_id: &str,
        approval_id: &str,
        trace_id: &str,
    ) -> JsonRpcResponse {
        let body = json!({
            "status": "pending_approval",
            "approval_id": approval_id,
            "action_id": action_id,
            "trace_id": trace_id,
            "message": format!(
                "Action '{action_id}' requires approval.\n\n\
                 Approve with: latchgate_approve {{\"approval_id\": \"{approval_id}\"}}\n\
                 Or deny with: latchgate_deny {{\"approval_id\": \"{approval_id}\"}}"
            ),
        });
        let text = serde_json::to_string_pretty(&body).unwrap_or_else(|_| body.to_string());
        tool_success(id, text)
    }

    // ── Agent pending approvals ──────────────────────────────────────────────

    /// Handle `latchgate_my_pending` — agent-scoped read-only query.
    ///
    /// Fetches only this agent's own pending approvals (scoped by agent_id
    /// and session_id server-side). No cross-agent visibility, no mutations.
    async fn handle_my_pending(&self, id: Option<RequestId>, trace_id: &str) -> JsonRpcResponse {
        if let Err(msg) = self.ensure_gate_reachable().await {
            return structured_tool_error(
                id,
                tool_error_codes::GATE_UNAVAILABLE,
                msg,
                Some("latchgate_my_pending"),
                trace_id,
                None,
            );
        }

        match self.client.my_pending().await {
            Ok(body) => {
                self.on_gate_success();
                let text = serde_json::to_string_pretty(&body).unwrap_or_else(|_| body.to_string());
                tool_success(id, text)
            }
            Err(ref e) if e.is_transport_failure() => {
                self.on_transport_failure();
                structured_tool_error(
                    id,
                    tool_error_codes::GATE_UNAVAILABLE,
                    format!("Cannot reach LatchGate for pending approvals: {e}"),
                    Some("latchgate_my_pending"),
                    trace_id,
                    None,
                )
            }
            Err(e) => {
                warn!(trace_id, error = %e, "latchgate_my_pending failed");
                structured_tool_error(
                    id,
                    tool_error_codes::GATE_UNAVAILABLE,
                    format!("Failed to fetch pending approvals: {e}"),
                    Some("latchgate_my_pending"),
                    trace_id,
                    None,
                )
            }
        }
    }

    // ── resources/list ───────────────────────────────────────────────────────

    /// Return available resource URIs.
    ///
    /// Agent session: actions + status.
    /// Operator session: actions + status + pending approvals + audit.
    fn handle_resources_list(&self, id: Option<RequestId>) -> JsonRpcResponse {
        let resources = if self.admin.is_some() {
            operator_resource_list()
        } else {
            agent_resource_list()
        };
        JsonRpcResponse::ok(id, json!({ "resources": resources }))
    }

    // ── resources/read ───────────────────────────────────────────────────────

    async fn handle_resources_read(&self, id: Option<RequestId>, params: Value) -> JsonRpcResponse {
        let uri = match params["uri"].as_str() {
            Some(u) => u,
            None => {
                return JsonRpcResponse::err(
                    id,
                    error_codes::INVALID_PARAMS,
                    "missing required field 'uri'",
                );
            }
        };

        let text = match uri {
            "latchgate://actions" => match self.read_resource_actions().await {
                Ok(t) => t,
                Err(msg) => return JsonRpcResponse::err(id, error_codes::INTERNAL_ERROR, msg),
            },
            "latchgate://status" => self.read_resource_status(),
            "latchgate://approvals/pending" if self.admin.is_some() => {
                match self.read_resource_pending().await {
                    Ok(t) => t,
                    Err(msg) => return JsonRpcResponse::err(id, error_codes::INTERNAL_ERROR, msg),
                }
            }
            "latchgate://audit/recent" if self.admin.is_some() => {
                match self.read_resource_audit().await {
                    Ok(t) => t,
                    Err(msg) => return JsonRpcResponse::err(id, error_codes::INTERNAL_ERROR, msg),
                }
            }
            _ => {
                return JsonRpcResponse::err(
                    id,
                    error_codes::INVALID_PARAMS,
                    format!("unknown resource: {uri}"),
                );
            }
        };

        JsonRpcResponse::ok(
            id,
            json!({
                "contents": [McpResourceContent {
                    uri: uri.to_string(),
                    mime_type: "application/json".into(),
                    text,
                }]
            }),
        )
    }

    /// Read `latchgate://actions` — full tool definitions from the cache.
    async fn read_resource_actions(&self) -> Result<String, String> {
        let tools = self
            .get_or_fetch_tools()
            .await
            .map_err(|e| format!("cannot fetch actions: {e}"))?;
        self.on_gate_success();
        serde_json::to_string_pretty(&*tools).map_err(|e| format!("serialization failed: {e}"))
    }

    /// Read `latchgate://status` — always available, no gate round-trip.
    fn read_resource_status(&self) -> String {
        let healthy = {
            let state = self.reconnect.lock().unwrap_or_else(|e| e.into_inner());
            state.healthy
        };
        let body = json!({
            "session_id": self.client.session_id(),
            "agent_id": self.agent_id,
            "gate_healthy": healthy,
            "adapter_version": env!("CARGO_PKG_VERSION"),
            "protocol_version": PROTOCOL_VERSION,
        });
        serde_json::to_string_pretty(&body).unwrap_or_else(|_| body.to_string())
    }

    /// Read `latchgate://approvals/pending` — operator only.
    async fn read_resource_pending(&self) -> Result<String, String> {
        let admin = self.admin.as_ref().ok_or("not an operator session")?;
        let body = admin
            .list_pending()
            .await
            .map_err(|e| format!("cannot fetch pending approvals: {e}"))?;
        serde_json::to_string_pretty(&body).map_err(|e| format!("serialization failed: {e}"))
    }

    /// Read `latchgate://audit/recent` — operator only.
    async fn read_resource_audit(&self) -> Result<String, String> {
        let admin = self.admin.as_ref().ok_or("not an operator session")?;
        let body = admin
            .audit_recent(25)
            .await
            .map_err(|e| format!("cannot fetch audit log: {e}"))?;
        serde_json::to_string_pretty(&body).map_err(|e| format!("serialization failed: {e}"))
    }

    // ── prompts/list ─────────────────────────────────────────────────────────

    /// Return available prompt templates.
    ///
    /// Agent session: empty (prompts are operator-only — agent must not
    /// introspect its own denial reasons).
    /// Operator session: explain_denial + review_pending.
    fn handle_prompts_list(&self, id: Option<RequestId>) -> JsonRpcResponse {
        let prompts = if self.admin.is_some() {
            operator_prompt_list()
        } else {
            vec![]
        };
        JsonRpcResponse::ok(id, json!({ "prompts": prompts }))
    }

    // ── prompts/get ──────────────────────────────────────────────────────────

    async fn handle_prompts_get(&self, id: Option<RequestId>, params: Value) -> JsonRpcResponse {
        let name = match params["name"].as_str() {
            Some(n) => n,
            None => {
                return JsonRpcResponse::err(
                    id,
                    error_codes::INVALID_PARAMS,
                    "missing required field 'name'",
                );
            }
        };

        // SECURITY: prompts are operator-only. The agent must not
        // introspect denial reasons — that would leak policy internals.
        let Some(admin) = self.admin.as_ref() else {
            return JsonRpcResponse::err(
                id,
                error_codes::INVALID_PARAMS,
                format!("unknown prompt: {name}"),
            );
        };

        match name {
            "explain_denial" => self.prompt_explain_denial(admin, id, &params).await,
            "review_pending" => self.prompt_review_pending(admin, id).await,
            _ => JsonRpcResponse::err(
                id,
                error_codes::INVALID_PARAMS,
                format!("unknown prompt: {name}"),
            ),
        }
    }

    /// Build the `explain_denial` prompt: fetch audit entry, format for LLM.
    async fn prompt_explain_denial(
        &self,
        admin: &AdminClient,
        id: Option<RequestId>,
        params: &Value,
    ) -> JsonRpcResponse {
        let trace_id = match params["arguments"]["trace_id"].as_str() {
            Some(t) if !t.is_empty() => t,
            _ => {
                return JsonRpcResponse::err(
                    id,
                    error_codes::INVALID_PARAMS,
                    "missing required argument 'trace_id'",
                );
            }
        };

        // Validate trace_id: alphanumeric + underscore + hyphen, bounded.
        if trace_id.len() > 128
            || !trace_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return JsonRpcResponse::err(
                id,
                error_codes::INVALID_PARAMS,
                "trace_id contains invalid characters",
            );
        }

        let audit_data = match admin.audit_by_trace_id(trace_id).await {
            Ok(data) => serde_json::to_string_pretty(&data).unwrap_or_else(|_| data.to_string()),
            Err(e) => json!({"error": format!("could not fetch audit entry: {e}")}).to_string(),
        };

        let text = format!(
            "You are reviewing a denied LatchGate action.\n\n\
             Trace ID: {trace_id}\n\n\
             Audit ledger entry:\n```json\n{audit_data}\n```\n\n\
             Explain why this action was denied. Consider:\n\
             - Which policy rule triggered the denial\n\
             - The risk level and budget state at the time\n\
             - Whether an egress rule blocked the request\n\
             - The revocation epoch at the time of the request\n\
             - What the agent could do differently to succeed"
        );

        JsonRpcResponse::ok(
            id,
            json!({
                "description": format!("Denial analysis for {trace_id}"),
                "messages": [{
                    "role": "user",
                    "content": { "type": "text", "text": text }
                }]
            }),
        )
    }

    /// Build the `review_pending` prompt: fetch queue, format for LLM.
    async fn prompt_review_pending(
        &self,
        admin: &AdminClient,
        id: Option<RequestId>,
    ) -> JsonRpcResponse {
        let pending_data = match admin.list_pending().await {
            Ok(data) => serde_json::to_string_pretty(&data).unwrap_or_else(|_| data.to_string()),
            Err(e) => {
                json!({"error": format!("could not fetch pending approvals: {e}")}).to_string()
            }
        };

        let text = format!(
            "You are an operator reviewing pending LatchGate approvals.\n\n\
             Pending approvals:\n```json\n{pending_data}\n```\n\n\
             For each pending approval:\n\
             1. Assess the risk level and action scope\n\
             2. Check time remaining before expiry\n\
             3. Review the targets and any secret names (never values)\n\
             4. Recommend approve or deny with reasoning\n\n\
             Prioritize by risk level (critical > high > medium) and time remaining."
        );

        JsonRpcResponse::ok(
            id,
            json!({
                "description": "Prioritized review of pending approvals",
                "messages": [{
                    "role": "user",
                    "content": { "type": "text", "text": text }
                }]
            }),
        )
    }

    // ── Reconnection ──────────────────────────────────────────────────────────

    async fn ensure_gate_reachable(&self) -> Result<(), String> {
        let (healthy, can_retry, secs) = {
            let state = self.reconnect.lock().unwrap_or_else(|e| e.into_inner());
            (
                state.healthy,
                state.can_retry_now(),
                state.secs_until_retry(),
            )
        };

        if healthy {
            return Ok(());
        }

        if !can_retry {
            return Err(format!(
                "Gate unavailable, next reconnection attempt in {secs}s."
            ));
        }

        debug!("attempting gate reconnection");
        match self.client.health_check().await {
            Ok(()) => {
                // Validate the authenticated path too — health_check is
                // unauthenticated, so a gate that's up-but-auth-broken
                // would otherwise flip to healthy and fail on the next
                // real execute call. ensure_connected re-issues the lease.
                if let Err(e) = self.client.ensure_connected().await {
                    let secs = {
                        let mut state = self.reconnect.lock().unwrap_or_else(|e| e.into_inner());
                        state.advance_backoff();
                        state.secs_until_retry()
                    };
                    warn!(
                        error = %e,
                        next_retry_secs = secs,
                        "gate reachable but auth failed on reconnect"
                    );
                    return Err(format!(
                        "Gate reachable but auth failed: {e}. Next retry in {secs}s."
                    ));
                }

                {
                    let mut state = self.reconnect.lock().unwrap_or_else(|e| e.into_inner());
                    state.restore_healthy();
                }
                info!("gate connection restored");
                if let Err(e) = self.warm_tool_cache().await {
                    warn!(error = %e, "tool cache refresh after reconnect failed");
                }
                Ok(())
            }
            Err(e) => {
                let secs = {
                    let mut state = self.reconnect.lock().unwrap_or_else(|e| e.into_inner());
                    state.advance_backoff();
                    state.secs_until_retry()
                };
                warn!(error = %e, next_retry_secs = secs, "gate reconnection failed");
                Err(format!("Gate unreachable: {e}. Next retry in {secs}s."))
            }
        }
    }

    fn on_transport_failure(&self) {
        let mut state = self.reconnect.lock().unwrap_or_else(|e| e.into_inner());
        if state.healthy {
            warn!("gate connection lost, reconnecting...");
            state.enter_reconnecting();
        }
    }

    fn on_gate_success(&self) {
        let mut state = self.reconnect.lock().unwrap_or_else(|e| e.into_inner());
        if !state.healthy {
            state.restore_healthy();
            info!("gate connection restored");
        }
    }

    // ── Tool cache ────────────────────────────────────────────────────────────

    async fn get_or_fetch_tools(&self) -> Result<Arc<Vec<McpTool>>, GateError> {
        {
            let guard = self.tools.read().await;
            if let Some((ref tools, fetched_at)) = *guard {
                if fetched_at.elapsed() < TOOL_CACHE_TTL {
                    return Ok(Arc::clone(tools));
                }
                debug!("tool cache expired; refreshing");
            }
        }

        self.warm_tool_cache().await
    }

    /// Fetch tools from the gate, update the cache, and emit
    /// `notifications/tools/list_changed` if the tool set differs from the
    /// previously cached snapshot.
    ///
    /// The notification is suppressed until the MCP `initialize` handshake
    /// completes (tracked by `self.initialized`), ensuring we never send
    /// notifications to a client that isn't ready.
    async fn warm_tool_cache(&self) -> Result<Arc<Vec<McpTool>>, GateError> {
        let tools = Arc::new(self.client.list_tools().await?);

        // Single write lock: compare against the previous snapshot and update
        // atomically. Eliminates the TOCTOU window that a separate read-then-
        // write pattern would introduce if a concurrent refresh races us.
        let changed = {
            let mut guard = self.tools.write().await;
            let changed = match &*guard {
                Some((prev, _)) => tool_names(prev) != tool_names(&tools),
                // Initial population — no notification before handshake.
                None => false,
            };
            *guard = Some((Arc::clone(&tools), Instant::now()));
            changed
        };

        if changed && self.initialized.load(Ordering::Acquire) {
            info!(tools = tools.len(), "tool set changed — notifying client");
            self.send_notification(&JsonRpcNotification::tools_list_changed());
        } else {
            debug!(tools = tools.len(), "tool cache refreshed");
        }

        Ok(tools)
    }

    /// Best-effort background refresh. Skips if the gate is already known
    /// to be unreachable (the reconnect path handles its own refresh).
    async fn background_refresh_tick(&self) {
        let healthy = {
            let state = self.reconnect.lock().unwrap_or_else(|e| e.into_inner());
            state.healthy
        };
        if !healthy {
            return;
        }

        match self.warm_tool_cache().await {
            Ok(_) => self.on_gate_success(),
            Err(ref e) if e.is_transport_failure() => {
                self.on_transport_failure();
                debug!(error = %e, "background tool refresh failed (transport)");
            }
            Err(e) => {
                debug!(error = %e, "background tool refresh failed");
            }
        }
    }
}

// ── Tool set comparison ──────────────────────────────────────────────────────

/// Extract sorted tool names for set-equality comparison.
///
/// Only names matter for `tools/list_changed` — schema or annotation
/// changes within a tool don't alter the tool *set*.
fn tool_names(tools: &[McpTool]) -> Vec<&str> {
    let mut names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    names.sort_unstable();
    names
}

// ── Agent-only tool definitions ──────────────────────────────────────────────

/// Agent-only tool for discovering own pending approvals after reconnect.
///
/// Registered on the agent session alongside gate-discovered tools. NOT
/// registered on the operator session (operator has `latchgate_list_pending`
/// which returns all agents' approvals).
fn tool_my_pending() -> McpTool {
    McpTool {
        name: "latchgate_my_pending".into(),
        description:
            "List your own pending approvals. Read-only — cannot approve or deny. \
                       Use after reconnect to discover in-flight approvals from a previous session."
                .into(),
        input_schema: json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        }),
        annotations: Some(McpToolAnnotations {
            read_only_hint: Some(true),
            destructive_hint: Some(false),
            idempotent_hint: Some(true),
            open_world_hint: Some(false),
        }),
    }
}

// ── Resource definitions ─────────────────────────────────────────────────────

/// Resources available on the agent session.
fn agent_resource_list() -> Vec<McpResource> {
    vec![
        McpResource {
            uri: "latchgate://actions".into(),
            name: "Registered Actions".into(),
            description: "All registered LatchGate actions with schemas, \
                           risk levels, and annotations."
                .into(),
            mime_type: "application/json".into(),
        },
        McpResource {
            uri: "latchgate://status".into(),
            name: "Gate Status".into(),
            description: "Gate health, session metadata, and adapter version.".into(),
            mime_type: "application/json".into(),
        },
    ]
}

/// Additional resources available on the operator session.
fn operator_resource_list() -> Vec<McpResource> {
    let mut resources = agent_resource_list();
    resources.push(McpResource {
        uri: "latchgate://approvals/pending".into(),
        name: "Pending Approvals".into(),
        description: "Current approval queue with risk levels and expiry.".into(),
        mime_type: "application/json".into(),
    });
    resources.push(McpResource {
        uri: "latchgate://audit/recent".into(),
        name: "Recent Audit".into(),
        description: "Last 25 audit ledger entries.".into(),
        mime_type: "application/json".into(),
    });
    resources
}

// ── Prompt definitions ───────────────────────────────────────────────────────

/// Prompts available on the operator session. Empty on agent session.
fn operator_prompt_list() -> Vec<McpPrompt> {
    vec![
        McpPrompt {
            name: "explain_denial".into(),
            description: "Fetch the audit ledger entry for a trace_id and produce a \
                           human-readable explanation of why the action was denied."
                .into(),
            arguments: vec![McpPromptArgument {
                name: "trace_id".into(),
                description: "The trace_id from the denial error (e.g. tr_019e...).".into(),
                required: true,
            }],
        },
        McpPrompt {
            name: "review_pending".into(),
            description: "Fetch all pending approvals and format as a prioritized \
                           review list with risk levels, time remaining, and context."
                .into(),
            arguments: vec![],
        },
    ]
}

// ── Response builders ─────────────────────────────────────────────────────────

fn tool_success(id: Option<RequestId>, text: String) -> JsonRpcResponse {
    JsonRpcResponse::ok(
        id,
        json!({
            "content": [ContentBlock::text(text)],
            "isError": false,
        }),
    )
}

fn tool_error_structured(id: Option<RequestId>, error: &StructuredToolError) -> JsonRpcResponse {
    JsonRpcResponse::ok(
        id,
        json!({
            "content": [ContentBlock::text(error.to_json())],
            "isError": true,
        }),
    )
}

/// Convert a [`GateError`] into a structured MCP tool error response.
///
/// Categorises the error, logs at the appropriate level, and returns a
/// ready-to-send JSON-RPC response. Transport failures must be signalled
/// to the reconnection state machine by the caller *before* invoking this
/// function — `map_gate_error` is a pure error-to-response conversion.
fn map_gate_error(
    id: Option<RequestId>,
    action_id: &str,
    trace_id: &str,
    err: GateError,
) -> JsonRpcResponse {
    match err {
        GateError::InvalidInput(msg) => {
            warn!(%action_id, %trace_id, msg = %msg, "invalid input");
            structured_tool_error(
                id,
                tool_error_codes::SCHEMA_VALIDATION,
                format!("Invalid input for '{action_id}': {msg}"),
                Some(action_id),
                trace_id,
                None,
            )
        }
        GateError::GateHttp { status, body } => {
            warn!(%action_id, %trace_id, status, body = %body, "gate returned error");

            let parsed = serde_json::from_str::<Value>(&body).ok();
            let gate_code = parsed
                .as_ref()
                .and_then(|j| j["error"].as_str())
                .unwrap_or("");
            let error_code = map_gate_error_code(gate_code, status);
            let message = parsed
                .as_ref()
                .and_then(|j| j["message"].as_str().or_else(|| j["deny_reason"].as_str()))
                .map(str::to_string)
                .unwrap_or_else(|| {
                    format!("Action '{action_id}' failed: {error_code} (HTTP {status}).")
                });
            let remediation = parsed
                .as_ref()
                .and_then(|j| j["remediation"].as_str())
                .map(str::to_string);

            structured_tool_error(
                id,
                error_code,
                message,
                Some(action_id),
                trace_id,
                remediation,
            )
        }
        GateError::Auth(ref e) => {
            error!(%action_id, %trace_id, error = %e, "auth error");
            structured_tool_error(
                id,
                tool_error_codes::AUTH_FAILED,
                format!("Authentication failed for '{action_id}'. Check DPoP configuration."),
                Some(action_id),
                trace_id,
                None,
            )
        }
        ref e if e.is_transport_failure() => {
            error!(%action_id, %trace_id, error = %e, "transport error");
            structured_tool_error(
                id,
                tool_error_codes::GATE_UNAVAILABLE,
                format!("Cannot reach LatchGate for '{action_id}'. Verify the gate is running."),
                Some(action_id),
                trace_id,
                None,
            )
        }
        ref e => {
            error!(%action_id, %trace_id, error = %e, "gate client error");
            structured_tool_error(
                id,
                tool_error_codes::GATE_UNAVAILABLE,
                format!("Unexpected error for '{action_id}'. Contact the operator with trace_id."),
                Some(action_id),
                trace_id,
                None,
            )
        }
    }
}

fn structured_tool_error(
    id: Option<RequestId>,
    code: &'static str,
    message: String,
    action_id: Option<&str>,
    trace_id: &str,
    remediation: Option<String>,
) -> JsonRpcResponse {
    let error = StructuredToolError {
        code: Cow::Borrowed(code),
        message,
        action_id: action_id.map(str::to_string),
        trace_id: Some(trace_id.to_string()),
        approval_id: None,
        remediation,
    };
    tool_error_structured(id, &error)
}

fn format_success_output(output: &Value, receipt_id: &str, is_fully_successful: bool) -> String {
    let output_str = match output {
        Value::String(s) => s.clone(),
        Value::Null => "(no output)".to_string(),
        other => serde_json::to_string_pretty(other).unwrap_or_else(|_| other.to_string()),
    };

    let verification_note = if is_fully_successful {
        ""
    } else {
        "\n⚠️  Note: action executed but outcome verification was inconclusive."
    };

    format!("{output_str}\n\n[receipt_id: {receipt_id}]{verification_note}")
}

// ── Bounded async line reader ────────────────────────────────────────────────

/// Read a single newline-delimited line from `reader` into `buf`, enforcing a
/// byte limit *before* allocation.
///
/// Returns the number of bytes read (0 on EOF). If a line exceeds `limit`
/// bytes, the remainder is drained from the reader's buffer (so the reader is
/// positioned at the start of the next line) and an `InvalidData` error is
/// returned — no allocation beyond the internal `BufReader` chunk size occurs.
///
/// UTF-8 validation is performed once over the complete line, so multi-byte
/// sequences that span `BufReader` chunk boundaries are handled correctly.
async fn read_bounded_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    buf: &mut String,
    limit: usize,
) -> std::io::Result<usize> {
    buf.clear();

    // Accumulate raw bytes; validate UTF-8 once at the end so multi-byte
    // sequences spanning BufReader chunk boundaries are handled correctly.
    let mut raw: Vec<u8> = Vec::with_capacity(4096.min(limit));

    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            break; // EOF
        }

        let (take, found_newline) = match memchr_newline(available) {
            Some(pos) => (pos + 1, true),
            None => (available.len(), false),
        };

        if raw.len() + take > limit {
            // Oversize: drain the rest of this line without growing the buffer.
            reader.consume(take);
            if !found_newline {
                drain_until_newline(reader).await?;
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "message exceeds maximum size",
            ));
        }

        raw.extend_from_slice(&available[..take]);
        reader.consume(take);

        if found_newline {
            break;
        }
    }

    let n = raw.len();
    if n == 0 {
        return Ok(0);
    }

    *buf = String::from_utf8(raw).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "stdin contained invalid UTF-8",
        )
    })?;
    Ok(n)
}

/// Drain bytes from `reader` until a newline byte or EOF, without allocating.
async fn drain_until_newline<R: AsyncBufRead + Unpin>(reader: &mut R) -> std::io::Result<()> {
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(());
        }
        let end = match memchr_newline(available) {
            Some(pos) => {
                reader.consume(pos + 1);
                return Ok(());
            }
            None => available.len(),
        };
        reader.consume(end);
    }
}

/// Find the first `b'\n'` in `haystack`. Equivalent to `memchr::memchr(b'\n', haystack)`
/// without pulling in the `memchr` crate as a direct dependency — it is already
/// a transitive dep via `tokio`, but this avoids coupling to that detail.
#[inline]
fn memchr_newline(haystack: &[u8]) -> Option<usize> {
    haystack.iter().position(|&b| b == b'\n')
}

// ── Trace ID ──────────────────────────────────────────────────────────────────

fn generate_trace_id() -> String {
    format!("tr_{}", uuid::Uuid::now_v7())
}

// ── Schema validation ─────────────────────────────────────────────────────────

fn validate_input_schema(schema: &Value, input: &Value) -> Result<(), String> {
    if schema == &json!({"type": "object"})
        || schema == &json!({"type": "object", "additionalProperties": true})
    {
        return Ok(());
    }

    let validator = match jsonschema::validator_for(schema) {
        Ok(v) => v,
        Err(e) => {
            debug!(error = %e, "cached schema failed to compile; skipping client-side validation");
            return Ok(());
        }
    };

    match validator.validate(input) {
        Ok(()) => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_success_output_string() {
        let out = format_success_output(&json!("hello"), "rcpt-001", true);
        assert!(out.contains("hello"));
        assert!(out.contains("rcpt-001"));
        assert!(!out.contains("⚠️"));
    }

    #[test]
    fn format_success_output_not_verified() {
        let out = format_success_output(&json!({"ok": true}), "rcpt-002", false);
        assert!(out.contains("⚠️"));
        assert!(out.contains("rcpt-002"));
    }

    #[test]
    fn format_success_output_null() {
        let out = format_success_output(&Value::Null, "rcpt-003", true);
        assert!(out.contains("(no output)"));
    }

    #[test]
    fn tool_success_response_shape() {
        let resp = tool_success(Some(RequestId::Number(1)), "output".into());
        let result = resp.result.unwrap();
        assert_eq!(result["isError"], json!(false));
        assert!(result["content"].is_array());
    }

    #[test]
    fn structured_tool_error_response_shape() {
        let resp = structured_tool_error(
            Some(RequestId::Number(2)),
            tool_error_codes::POLICY_DENIED,
            "denied".into(),
            Some("github_push"),
            "tr_test",
            None,
        );
        let result = resp.result.unwrap();
        assert_eq!(result["isError"], json!(true));

        let text = result["content"][0]["text"].as_str().unwrap();
        let parsed: StructuredToolError = serde_json::from_str(text).unwrap();
        assert_eq!(parsed.code, "policy_denied");
        assert_eq!(parsed.action_id.as_deref(), Some("github_push"));
        assert_eq!(parsed.trace_id.as_deref(), Some("tr_test"));
    }

    #[test]
    fn structured_tool_error_code_is_borrowed() {
        let error = StructuredToolError {
            code: Cow::Borrowed(tool_error_codes::POLICY_DENIED),
            message: "test".into(),
            action_id: None,
            trace_id: None,
            approval_id: None,
            remediation: None,
        };
        // Borrowed variant — no heap allocation for the code string.
        assert!(matches!(error.code, Cow::Borrowed(_)));
    }

    #[test]
    fn trace_id_format() {
        let id = generate_trace_id();
        assert!(id.starts_with("tr_"));
        assert_eq!(id.len(), 39);
    }

    // ── Backoff ──────────────────────────────────────────────────────────

    #[test]
    fn backoff_duration_within_bounds() {
        for attempt in 0..20 {
            let d = backoff_duration(attempt);
            assert!(d.as_secs() >= 1, "attempt {attempt}: too short: {d:?}");
            // With +25% jitter on a 30s cap, max is 37s. Allow some headroom.
            assert!(d.as_secs() <= 40, "attempt {attempt}: too long: {d:?}");
        }
    }

    #[test]
    fn backoff_duration_grows() {
        // With jitter, individual samples may not be strictly ordered.
        // But the base should grow: average of many samples at attempt=5
        // should be much larger than attempt=1.
        let avg_1: u64 = (0..100).map(|_| backoff_duration(1).as_secs()).sum::<u64>() / 100;
        let avg_5: u64 = (0..100).map(|_| backoff_duration(5).as_secs()).sum::<u64>() / 100;
        assert!(avg_5 > avg_1, "avg@5={avg_5} should exceed avg@1={avg_1}");
    }

    // ── Reconnection state ──────────────────────────────────────────────

    #[test]
    fn reconnect_starts_healthy() {
        let state = ReconnectState::new_healthy();
        assert!(state.healthy);
        assert_eq!(state.attempt, 0);
    }

    #[test]
    fn reconnect_enter_reconnecting() {
        let mut state = ReconnectState::new_healthy();
        state.enter_reconnecting();
        assert!(!state.healthy);
        assert_eq!(state.attempt, 1);
        assert!(!state.can_retry_now());
    }

    #[test]
    fn reconnect_advance_backoff() {
        let mut state = ReconnectState::new_healthy();
        state.enter_reconnecting();
        state.advance_backoff();
        assert_eq!(state.attempt, 2);
        state.advance_backoff();
        assert_eq!(state.attempt, 3);
    }

    #[test]
    fn reconnect_restore_healthy() {
        let mut state = ReconnectState::new_healthy();
        state.enter_reconnecting();
        state.restore_healthy();
        assert!(state.healthy);
        assert_eq!(state.attempt, 0);
    }

    #[test]
    fn reconnect_can_retry_after_delay() {
        let mut state = ReconnectState::new_healthy();
        state.healthy = false;
        state.attempt = 1;
        state.next_retry_at = Instant::now() - Duration::from_secs(1);
        assert!(state.can_retry_now());
    }

    // ── Schema validation ────────────────────────────────────────────────

    #[test]
    fn validate_schema_accepts_valid_input() {
        let schema = json!({
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "count": {"type": "integer", "minimum": 1}
            },
            "required": ["url"]
        });
        let input = json!({"url": "https://example.com", "count": 5});
        assert!(validate_input_schema(&schema, &input).is_ok());
    }

    #[test]
    fn validate_schema_rejects_missing_required_field() {
        let schema = json!({
            "type": "object",
            "properties": { "url": {"type": "string"} },
            "required": ["url"]
        });
        assert!(validate_input_schema(&schema, &json!({})).is_err());
    }

    #[test]
    fn validate_schema_rejects_wrong_type() {
        let schema = json!({
            "type": "object",
            "properties": { "count": {"type": "integer"} },
            "required": ["count"]
        });
        assert!(validate_input_schema(&schema, &json!({"count": "nope"})).is_err());
    }

    #[test]
    fn validate_schema_skips_permissive() {
        assert!(validate_input_schema(&json!({"type": "object"}), &json!({"x": 1})).is_ok());
    }

    #[test]
    fn validate_schema_skips_malformed() {
        assert!(validate_input_schema(&json!({"type": "not_real"}), &json!({"x": 1})).is_ok());
    }

    #[test]
    fn validate_schema_null_input() {
        let schema = json!({"type": "object", "required": ["path"]});
        assert!(validate_input_schema(&schema, &Value::Null).is_err());
    }

    // ── Tool-set change detection ───────────────────────────────────────

    #[test]
    fn tool_names_sorted_deterministically() {
        let tools = vec![
            McpTool {
                name: "zulu".into(),
                description: String::new(),
                input_schema: json!({}),
                annotations: None,
            },
            McpTool {
                name: "alpha".into(),
                description: String::new(),
                input_schema: json!({}),
                annotations: None,
            },
            McpTool {
                name: "mike".into(),
                description: String::new(),
                input_schema: json!({}),
                annotations: None,
            },
        ];
        assert_eq!(tool_names(&tools), vec!["alpha", "mike", "zulu"]);
    }

    #[test]
    fn tool_names_empty_vec() {
        let tools: Vec<McpTool> = vec![];
        assert!(tool_names(&tools).is_empty());
    }

    #[test]
    fn tool_names_detects_set_difference() {
        let a = vec![McpTool {
            name: "github_push".into(),
            description: String::new(),
            input_schema: json!({}),
            annotations: None,
        }];
        let b = vec![
            McpTool {
                name: "github_push".into(),
                description: String::new(),
                input_schema: json!({}),
                annotations: None,
            },
            McpTool {
                name: "slack_post".into(),
                description: String::new(),
                input_schema: json!({}),
                annotations: None,
            },
        ];
        assert_ne!(tool_names(&a), tool_names(&b));
    }

    #[test]
    fn tool_names_ignores_description_changes() {
        let a = vec![McpTool {
            name: "github_push".into(),
            description: "old".into(),
            input_schema: json!({"type": "object"}),
            annotations: None,
        }];
        let b = vec![McpTool {
            name: "github_push".into(),
            description: "new and improved".into(),
            input_schema: json!({"type": "object", "required": ["repo"]}),
            annotations: None,
        }];
        assert_eq!(tool_names(&a), tool_names(&b));
    }

    #[test]
    fn tool_refresh_interval_is_half_ttl() {
        assert_eq!(TOOL_REFRESH_INTERVAL, TOOL_CACHE_TTL / 2);
    }

    // ── latchgate_my_pending ────────────────────────────────────────────

    #[test]
    fn my_pending_tool_definition() {
        let tool = tool_my_pending();
        assert_eq!(tool.name, "latchgate_my_pending");
        let ann = tool.annotations.as_ref().expect("annotations must be set");
        assert_eq!(ann.read_only_hint, Some(true));
        assert_eq!(ann.destructive_hint, Some(false));
        assert_eq!(ann.idempotent_hint, Some(true));
        assert_eq!(ann.open_world_hint, Some(false));
    }

    #[test]
    fn my_pending_schema_takes_no_arguments() {
        let tool = tool_my_pending();
        let props = tool.input_schema["properties"].as_object().unwrap();
        assert!(
            props.is_empty(),
            "latchgate_my_pending must take no arguments"
        );
        assert_eq!(tool.input_schema["additionalProperties"], json!(false));
    }

    #[test]
    fn my_pending_not_in_approval_tool_set() {
        // Ensures latchgate_my_pending on the operator session is not
        // intercepted by the approval tool handler — it falls through
        // to the gate and gets action_not_found.
        assert!(!admin_client::is_approval_tool("latchgate_my_pending"));
    }

    // ── Resources ───────────────────────────────────────────────────────

    #[test]
    fn agent_resource_uris() {
        // Agent session advertises exactly 2 resources.
        let resources = agent_resource_list();
        assert_eq!(resources.len(), 2);
        assert_eq!(resources[0].uri, "latchgate://actions");
        assert_eq!(resources[1].uri, "latchgate://status");
        for r in &resources {
            assert_eq!(r.mime_type, "application/json");
        }
    }

    #[test]
    fn operator_resource_uris() {
        // Operator session advertises 4 resources (agent + 2 operator-only).
        let resources = operator_resource_list();
        assert_eq!(resources.len(), 4);
        let uris: Vec<&str> = resources.iter().map(|r| r.uri.as_str()).collect();
        assert!(uris.contains(&"latchgate://actions"));
        assert!(uris.contains(&"latchgate://status"));
        assert!(uris.contains(&"latchgate://approvals/pending"));
        assert!(uris.contains(&"latchgate://audit/recent"));
    }

    #[test]
    fn resource_content_serializes_correctly() {
        let content = McpResourceContent {
            uri: "latchgate://status".into(),
            mime_type: "application/json".into(),
            text: r#"{"healthy":true}"#.into(),
        };
        let json = serde_json::to_value(&content).unwrap();
        assert_eq!(json["uri"], "latchgate://status");
        assert_eq!(json["mimeType"], "application/json");
        assert_eq!(json["text"], r#"{"healthy":true}"#);
    }

    // ── Prompts ─────────────────────────────────────────────────────────

    #[test]
    fn operator_prompt_definitions() {
        let prompts = operator_prompt_list();
        assert_eq!(prompts.len(), 2);

        assert_eq!(prompts[0].name, "explain_denial");
        assert_eq!(prompts[0].arguments.len(), 1);
        assert_eq!(prompts[0].arguments[0].name, "trace_id");
        assert!(prompts[0].arguments[0].required);

        assert_eq!(prompts[1].name, "review_pending");
        assert!(prompts[1].arguments.is_empty());
    }

    #[test]
    fn explain_denial_prompt_omits_arguments_key_when_serialized_empty() {
        // review_pending has no arguments — verify skip_serializing_if works.
        let prompts = operator_prompt_list();
        let review = &prompts[1];
        let json = serde_json::to_value(review).unwrap();
        assert!(json.get("arguments").is_none());
    }

    // ── Bounded line reader ─────────────────────────────────────────────

    #[tokio::test]
    async fn bounded_read_normal_line() {
        let data = b"hello world\n";
        let mut reader = tokio::io::BufReader::new(&data[..]);
        let mut buf = String::new();
        let n = read_bounded_line(&mut reader, &mut buf, 1024)
            .await
            .unwrap();
        assert_eq!(n, 12);
        assert_eq!(buf, "hello world\n");
    }

    #[tokio::test]
    async fn bounded_read_eof_returns_zero() {
        let data = b"";
        let mut reader = tokio::io::BufReader::new(&data[..]);
        let mut buf = String::new();
        let n = read_bounded_line(&mut reader, &mut buf, 1024)
            .await
            .unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn bounded_read_eof_without_newline() {
        let data = b"partial";
        let mut reader = tokio::io::BufReader::new(&data[..]);
        let mut buf = String::new();
        let n = read_bounded_line(&mut reader, &mut buf, 1024)
            .await
            .unwrap();
        assert_eq!(n, 7);
        assert_eq!(buf, "partial");
    }

    #[tokio::test]
    async fn bounded_read_rejects_oversize_line() {
        let data = b"this line is way too long\n";
        let mut reader = tokio::io::BufReader::new(&data[..]);
        let mut buf = String::new();
        let err = read_bounded_line(&mut reader, &mut buf, 10)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("maximum size"));
    }

    #[tokio::test]
    async fn bounded_read_oversize_drains_to_next_line() {
        // After rejecting an oversize line, the reader must be positioned
        // at the start of the next line.
        let data = b"aaaaaaaaaa_oversize\nnext line\n";
        let mut reader = tokio::io::BufReader::new(&data[..]);
        let mut buf = String::new();

        // First read: oversize (limit=10, line is 19 bytes).
        let err = read_bounded_line(&mut reader, &mut buf, 10)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        // Second read: must get "next line\n", proving the reader was drained.
        let n = read_bounded_line(&mut reader, &mut buf, 1024)
            .await
            .unwrap();
        assert_eq!(n, 10);
        assert_eq!(buf, "next line\n");
    }

    #[tokio::test]
    async fn bounded_read_rejects_invalid_utf8() {
        let data: &[u8] = &[0x80, 0x81, 0x82, b'\n'];
        let mut reader = tokio::io::BufReader::new(data);
        let mut buf = String::new();
        let err = read_bounded_line(&mut reader, &mut buf, 1024)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("UTF-8"));
    }

    #[tokio::test]
    async fn bounded_read_exact_limit_succeeds() {
        // A line that is exactly at the limit should succeed.
        let data = b"abcde\n"; // 6 bytes
        let mut reader = tokio::io::BufReader::new(&data[..]);
        let mut buf = String::new();
        let n = read_bounded_line(&mut reader, &mut buf, 6).await.unwrap();
        assert_eq!(n, 6);
        assert_eq!(buf, "abcde\n");
    }

    #[tokio::test]
    async fn bounded_read_one_byte_over_limit_rejects() {
        let data = b"abcdefg\n"; // 8 bytes
        let mut reader = tokio::io::BufReader::new(&data[..]);
        let mut buf = String::new();
        let err = read_bounded_line(&mut reader, &mut buf, 7)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn bounded_read_clears_buf_before_read() {
        let data = b"new\n";
        let mut reader = tokio::io::BufReader::new(&data[..]);
        let mut buf = String::from("leftover from previous call");
        let n = read_bounded_line(&mut reader, &mut buf, 1024)
            .await
            .unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf, "new\n");
    }

    #[tokio::test]
    async fn bounded_read_multibyte_utf8() {
        // Emoji: 4-byte UTF-8 sequence.
        let data = "🔒secure\n".as_bytes();
        let mut reader = tokio::io::BufReader::new(data);
        let mut buf = String::new();
        let n = read_bounded_line(&mut reader, &mut buf, 1024)
            .await
            .unwrap();
        assert_eq!(n, data.len());
        assert_eq!(buf, "🔒secure\n");
    }

    // ── memchr_newline ──────────────────────────────────────────────────

    #[test]
    fn memchr_newline_finds_first() {
        assert_eq!(memchr_newline(b"abc\ndef\n"), Some(3));
    }

    #[test]
    fn memchr_newline_none_when_absent() {
        assert_eq!(memchr_newline(b"no newline here"), None);
    }

    #[test]
    fn memchr_newline_empty_slice() {
        assert_eq!(memchr_newline(b""), None);
    }

    // ── pending_approval_immediate response shape ────────────────────────

    #[test]
    fn pending_approval_immediate_is_not_error() {
        // Verify that the pending_approval_immediate response has
        // isError: false so MCP clients treat it as actionable data.
        //
        // This is a free-function test exercising `tool_success` with the
        // same JSON shape that `pending_approval_immediate` produces.
        let body = json!({
            "status": "pending_approval",
            "approval_id": "apr_test-123",
            "action_id": "http_fetch",
            "trace_id": "tr_test-456",
            "message": "Action 'http_fetch' requires approval.",
        });
        let text = serde_json::to_string_pretty(&body).unwrap();
        let resp = tool_success(Some(RequestId::Number(42)), text);
        let result = resp.result.unwrap();

        assert_eq!(result["isError"], json!(false), "must be non-error");
        assert!(result["content"].is_array());

        let content_text = result["content"][0]["text"].as_str().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(content_text).unwrap();
        assert_eq!(parsed["status"], "pending_approval");
        assert_eq!(parsed["approval_id"], "apr_test-123");
        assert_eq!(parsed["action_id"], "http_fetch");
        assert_eq!(parsed["trace_id"], "tr_test-456");
    }

    #[test]
    fn pending_approval_fallback_is_error() {
        // Verify that the fallback (timeout/error) still uses isError: true,
        // distinct from the immediate non-error response.
        let error = StructuredToolError {
            code: Cow::Borrowed(tool_error_codes::PENDING_APPROVAL),
            message: "timed out".into(),
            action_id: Some("http_fetch".into()),
            trace_id: Some("tr_test".into()),
            approval_id: Some("apr_test-789".into()),
            remediation: None,
        };
        let resp = tool_error_structured(Some(RequestId::Number(99)), &error);
        let result = resp.result.unwrap();

        assert_eq!(result["isError"], json!(true), "fallback must be error");
        let text = result["content"][0]["text"].as_str().unwrap();
        let parsed: StructuredToolError = serde_json::from_str(text).unwrap();
        assert_eq!(parsed.code, "pending_approval");
        assert_eq!(parsed.approval_id.as_deref(), Some("apr_test-789"));
    }
}
