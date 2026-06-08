//! MCP adapter configuration — CLI args and environment variables.
//!
//! # Separation of duties
//!
//! The agent session (`serve`) and the operator session (`operator`) are
//! distinct subcommands that construct entirely different servers. The agent
//! server has no operator credential and no code path that advertises or
//! handles approval tools — the requesting agent therefore *cannot* approve
//! its own held actions. Operator approval over MCP is available only on the
//! separate `operator` session, which is expected to run as its own adapter
//! instance on its own stdio transport.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

// ── Top-level CLI ──────────────────────────────────────────────────────────

#[derive(Debug, Parser)]
#[command(
    name = "latchgate-mcp",
    about = "LatchGate MCP adapter — exposes protected actions as MCP tools",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the agent MCP stdio server.
    ///
    /// Exposes protected actions as MCP tools. Held actions are resolved by
    /// waiting for an out-of-band operator approval (TUI/CLI, or a separate
    /// `operator` MCP session). This server never advertises approval tools.
    Serve(ServeArgs),

    /// Run the operator MCP stdio server (approval session).
    ///
    /// Exposes the `latchgate_approve` / `latchgate_deny` (and optional
    /// `latchgate_allowlist`) tools, authenticated by an operator DPoP
    /// credential that is verified at startup. Must run as a separate adapter
    /// instance from `serve` so a requesting agent can never reach these
    /// tools.
    Operator(OperatorArgs),

    /// Write IDE configuration for this adapter.
    Install(InstallArgs),
}

// ── serve ──────────────────────────────────────────────────────────────────

/// Arguments for the agent MCP stdio server.
#[derive(Debug, Parser)]
pub struct ServeArgs {
    /// Path to the LatchGate Unix domain socket.
    ///
    /// Mutually exclusive with --gate-url. Preferred in production: UDS
    /// restricts access to processes with filesystem access to the socket.
    ///
    /// Default: `$XDG_RUNTIME_DIR/latchgate/gate.sock`, falling back to
    /// `/tmp/latchgate-{uid}/gate.sock`.
    #[arg(
        long,
        env = "LATCHGATE_SOCKET",
        default_value_os_t = latchgate_core::paths::default_uds_path(),
        conflicts_with = "gate_url"
    )]
    pub gate_socket: PathBuf,

    /// HTTP base URL of the LatchGate API (e.g. http://localhost:3000).
    ///
    /// Mutually exclusive with --gate-socket. Requires the LatchGate server
    /// to be configured with unsafe_expose_http = true. For development only.
    #[arg(long, env = "LATCHGATE_URL", conflicts_with = "gate_socket")]
    pub gate_url: Option<String>,

    /// Canonical URL used for DPoP htu construction.
    ///
    /// Must match the `public_base_url` field in latchgate.toml exactly.
    /// For TCP transport this defaults to --gate-url. For UDS this MUST be
    /// set explicitly (e.g. http://localhost:3000).
    #[arg(long, env = "LATCHGATE_PUBLIC_URL")]
    pub public_base_url: Option<String>,

    /// Agent identifier embedded in the Lease request.
    ///
    /// Appears in the audit trail. Use a stable, descriptive identifier such
    /// as the agent framework name or deployment name.
    #[arg(long, env = "LATCHGATE_AGENT_ID", default_value = "latchgate-mcp")]
    pub agent_id: String,

    /// Session identifier used for budget tracking and audit correlation.
    ///
    /// Defaults to a fresh UUID v7 per process invocation. Set this to a
    /// stable value when the adapter runs as a long-lived daemon.
    #[arg(long, env = "LATCHGATE_SESSION_ID")]
    pub session_id: Option<String>,

    /// Log level (error, warn, info, debug, trace).
    ///
    /// Logs are written to stderr so they do not interfere with the MCP
    /// stdio transport on stdout.
    #[arg(long, env = "RUST_LOG", default_value = "warn")]
    pub log_level: String,
}

impl ServeArgs {
    /// Whether to use Unix domain socket transport.
    pub fn use_uds(&self) -> bool {
        self.gate_url.is_none()
    }

    /// Effective Gate base URL.
    pub fn effective_base_url(&self) -> String {
        self.gate_url
            .clone()
            .unwrap_or_else(|| "http://localhost".to_string())
    }

    /// Effective public base URL for DPoP htu computation.
    pub fn effective_public_base_url(&self) -> Option<String> {
        self.public_base_url
            .clone()
            .or_else(|| self.gate_url.clone())
    }

    /// Effective session ID — provided value or a freshly generated UUID.
    pub fn effective_session_id(&self) -> String {
        self.session_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::now_v7().to_string())
    }
}

// ── operator ─────────────────────────────────────────────────────────────────

/// Arguments for the operator MCP stdio server (approval session).
///
/// All three credential inputs (admin socket, operator key, operator token)
/// are **required** — the operator session has no meaning without them, so
/// they are mandatory rather than optional. The credential is verified
/// against the admin API at startup; an invalid credential aborts the process
/// rather than surfacing a runtime 401.
#[derive(Debug, Parser)]
pub struct OperatorArgs {
    /// Path to the admin Unix domain socket.
    ///
    /// Operator approval requests are authenticated via DPoP
    /// proof-of-possession against this socket.
    #[arg(long, env = "LATCHGATE_ADMIN_SOCKET")]
    pub admin_socket: PathBuf,

    /// Path to the operator private key file (P-256 PEM: PKCS#8 or SEC1).
    ///
    /// The file is read at startup and the handle is immediately dropped.
    /// The key is held only in process memory — never logged, serialized,
    /// included in error messages, or exposed via any MCP response.
    #[arg(long, env = "LATCHGATE_OPERATOR_KEY")]
    pub operator_key: PathBuf,

    /// Operator API token for DPoP authentication.
    ///
    /// Must match an `api_key` in the gate's `operator_credentials`
    /// configuration. Combined with --operator-key for DPoP
    /// proof-of-possession.
    #[arg(long, env = "LATCHGATE_OPERATOR_TOKEN")]
    pub operator_token: String,

    /// Operator principal name.
    ///
    /// Used for audit attribution. Defaults to "operator" when not set.
    #[arg(long, env = "LATCHGATE_OPERATOR_ID", default_value = "operator")]
    pub operator_id: String,

    /// Canonical URL used for DPoP htu construction.
    ///
    /// Must match the `public_base_url` field in latchgate.toml exactly.
    #[arg(
        long,
        env = "LATCHGATE_PUBLIC_URL",
        default_value = "http://localhost:3000"
    )]
    pub public_base_url: String,

    /// Default agent principal applied to `latchgate_allowlist` when the
    /// tool call omits `agent_id`.
    #[arg(long, env = "LATCHGATE_AGENT_ID", default_value = "latchgate-mcp")]
    pub agent_id: String,

    /// Enable the `latchgate_allowlist` MCP tool (policy mutation).
    ///
    /// Off by default — the allowlist tool permanently modifies security
    /// policy. Operator must opt in explicitly per deployment.
    #[arg(long, env = "LATCHGATE_ENABLE_ALLOWLIST_TOOL")]
    pub enable_allowlist_tool: bool,

    /// Log level (error, warn, info, debug, trace).
    #[arg(long, env = "RUST_LOG", default_value = "warn")]
    pub log_level: String,
}

// ── install ────────────────────────────────────────────────────────────────

/// Arguments for IDE config installation.
#[derive(Debug, Parser)]
pub struct InstallArgs {
    /// Target IDE.
    #[arg(long, value_enum)]
    pub ide: Ide,

    /// Path to the LatchGate Unix domain socket.
    ///
    /// Mutually exclusive with --gate-url. When neither flag is given the
    /// transport is auto-detected from the active `up` session, falling back
    /// to the default UDS path.
    #[arg(long, conflicts_with = "gate_url")]
    pub gate_socket: Option<PathBuf>,

    /// HTTP base URL of the LatchGate API (e.g. http://localhost:3000).
    ///
    /// Mutually exclusive with --gate-socket. Requires the LatchGate gate to
    /// be started with `--expose-http`. For development only.
    #[arg(long, conflicts_with = "gate_socket")]
    pub gate_url: Option<String>,

    /// Canonical URL used for DPoP htu construction in UDS mode.
    ///
    /// Required when using --gate-socket without an active `up` session.
    /// Automatically resolved from `public_base_url` in the active session
    /// config when available. Ignored in HTTP mode (defaults to --gate-url).
    #[arg(long)]
    pub public_base_url: Option<String>,

    /// Path to the latchgate-mcp binary to embed in the config.
    ///
    /// Defaults to the path of the currently running executable.
    #[arg(long)]
    pub binary_path: Option<PathBuf>,

    /// Print the config to stdout without writing to disk.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum Ide {
    /// Claude Desktop (Anthropic)
    Claude,
    /// Claude Code (Anthropic)
    ClaudeCode,
    /// Cursor IDE
    Cursor,
    /// Cline (VS Code extension)
    Cline,
    /// Windsurf (Codeium)
    Windsurf,
    /// Codex CLI (OpenAI)
    Codex,
    /// OpenCode
    OpenCode,
    /// OpenClaw (via MCPorter)
    OpenClaw,
    /// GitHub Copilot (VS Code agent mode)
    Copilot,
    /// Hermes Agent (NousResearch)
    HermesAgent,
    /// Antigravity CLI (Google)
    Antigravity,
}
