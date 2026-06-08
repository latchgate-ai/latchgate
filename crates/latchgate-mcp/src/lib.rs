//! LatchGate MCP adapter.
//!
//! Bridges MCP-speaking agents (Claude Desktop, Cursor, etc.) to a running
//! LatchGate gate. The adapter:
//!
//! - Connects to LatchGate via Unix domain socket (default) or HTTP.
//! - Issues a DPoP-bound Lease and maintains it across the process lifetime.
//! - Exposes all registered LatchGate actions as MCP tools with JSON Schema
//!   `inputSchema` derived from the action's declared request schema.
//! - Forwards `tools/call` invocations to `POST /v1/actions/{id}/execute`
//!   with a fresh per-request DPoP proof.
//! - Maps LatchGate results (allow, pending_approval, error) to MCP content.
//! - Optionally exposes operator-only approval tools (`latchgate_approve`,
//!   `latchgate_deny`, `latchgate_allowlist`) when an admin socket and
//!   operator key are configured.
//!
//! Bridges MCP stdio JSON-RPC to the LatchGate REST API via
//! DPoP-authenticated UDS/HTTP.

pub mod admin_client;
pub mod auth;
pub mod config;
pub mod gate_client;
pub mod install;
pub mod protocol;
pub mod server;
