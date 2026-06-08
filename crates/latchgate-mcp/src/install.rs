//! IDE configuration installer.
//!
//! Writes (or prints) the MCP server config block that connects an IDE to
//! a running LatchGate instance via `latchgate-mcp serve`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::config::{Ide, InstallArgs};

// Transport resolution

/// Default `public_base_url` for DPoP `htu` construction.
const DEFAULT_PUBLIC_BASE_URL: &str = "http://localhost:3000";

#[derive(Debug, Clone)]
pub(crate) enum ResolvedTransport {
    /// Unix domain socket (secure default).
    Uds {
        socket: PathBuf,
        public_base_url: String,
    },
    /// HTTP (dev/exposed mode).
    Http { url: String },
}

/// Resolve the transport from explicit flags, active session, or defaults.
///
/// Priority:
///   1. Explicit `--gate-url` → HTTP
///   2. Explicit `--gate-socket` → UDS
///   3. Auto-detect from active `up` session config
///   4. Auto-detect from project config
///   5. Default UDS path
fn resolve_transport(args: &InstallArgs) -> Result<ResolvedTransport, InstallError> {
    // 1. Explicit HTTP.
    if let Some(url) = &args.gate_url {
        return Ok(ResolvedTransport::Http { url: url.clone() });
    }

    // 2. Explicit UDS.
    if let Some(socket) = &args.gate_socket {
        let public_base_url = args
            .public_base_url
            .clone()
            .or_else(detect_public_base_url)
            .unwrap_or_else(|| DEFAULT_PUBLIC_BASE_URL.to_string());
        return Ok(ResolvedTransport::Uds {
            socket: socket.clone(),
            public_base_url,
        });
    }

    // 3-4. Auto-detect from active session or project config.
    if let Some(transport) = detect_transport_from_configs(args.public_base_url.as_deref()) {
        return Ok(transport);
    }

    // 5. Default: UDS at the standard socket path.
    let socket = latchgate_core::paths::default_uds_path();
    let public_base_url = args
        .public_base_url
        .clone()
        .or_else(detect_public_base_url)
        // UDS-only configs omit public_base_url; fall back to the same
        // default that ServeArgs::effective_base_url() uses for UDS.
        .unwrap_or_else(|| DEFAULT_PUBLIC_BASE_URL.to_string());
    Ok(ResolvedTransport::Uds {
        socket,
        public_base_url,
    })
}

/// Read transport settings from the active `up` session config or project config.
fn detect_transport_from_configs(explicit_public_url: Option<&str>) -> Option<ResolvedTransport> {
    // Active session config: {runtime_dir}/latchgate-up/latchgate-up.toml
    let runtime_dir = latchgate_core::paths::resolve_runtime_dir().ok()?;
    let session_config = runtime_dir.join("latchgate-up/latchgate-up.toml");
    if let Some(t) = read_transport_from_toml(&session_config, explicit_public_url) {
        return Some(t);
    }

    // Project config: .latchgate/latchgate.toml
    let project_config = std::env::current_dir()
        .ok()?
        .join(".latchgate/latchgate.toml");
    read_transport_from_toml(&project_config, explicit_public_url)
}

/// Parse a TOML config file and extract transport settings.
fn read_transport_from_toml(
    path: &Path,
    explicit_public_url: Option<&str>,
) -> Option<ResolvedTransport> {
    let content = fs::read_to_string(path).ok()?;
    let table: toml::Table = content.parse().ok()?;

    // If listen_http_addr is set, use HTTP.
    if let Some(addr) = table.get("listen_http_addr").and_then(|v| v.as_str()) {
        let url = if addr.starts_with("http") {
            addr.to_string()
        } else {
            format!("http://{addr}")
        };
        return Some(ResolvedTransport::Http { url });
    }

    // Otherwise use UDS.
    let socket = table
        .get("listen_uds_path")
        .and_then(|v| v.as_str())
        .map(PathBuf::from)?;

    let public_base_url = explicit_public_url.map(str::to_string).or_else(|| {
        table
            .get("public_base_url")
            .and_then(|v| v.as_str())
            .map(str::to_string)
    })?;

    Some(ResolvedTransport::Uds {
        socket,
        public_base_url,
    })
}

/// Try to read `public_base_url` from the active session or project config.
///
/// Each config source is tried independently — failure to read one does
/// not short-circuit the remaining sources.
fn detect_public_base_url() -> Option<String> {
    // 1. Active session config.
    if let Ok(runtime_dir) = latchgate_core::paths::resolve_runtime_dir() {
        let session_config = runtime_dir.join("latchgate-up/latchgate-up.toml");
        if let Some(url) = read_public_base_url_from_toml(&session_config) {
            return Some(url);
        }
    }

    // 2. Project config.
    if let Ok(cwd) = std::env::current_dir() {
        let project_config = cwd.join(".latchgate/latchgate.toml");
        if let Some(url) = read_public_base_url_from_toml(&project_config) {
            return Some(url);
        }
    }

    None
}

/// Extract `public_base_url` from a TOML config file, if present.
fn read_public_base_url_from_toml(path: &Path) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    let table: toml::Table = content.parse().ok()?;
    table
        .get("public_base_url")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// Check reachability and print a warning if the endpoint appears down.
fn probe_and_warn(transport: &ResolvedTransport) {
    match transport {
        ResolvedTransport::Uds { socket, .. } => {
            if !socket.exists() {
                eprintln!();
                eprintln!(
                    "⚠  MCP configured for UDS {}\n   \
                     but no socket exists there. Start the gate with `latchgate up`,\n   \
                     or pass --gate-url if your gate exposes HTTP.",
                    socket.display()
                );
            }
        }
        ResolvedTransport::Http { url } => {
            // Best-effort: parse host:port and attempt a TCP connect.
            if let Some(addr) = url
                .strip_prefix("http://")
                .or_else(|| url.strip_prefix("https://"))
            {
                use std::net::{TcpStream, ToSocketAddrs};
                let reachable = addr
                    .to_socket_addrs()
                    .ok()
                    .and_then(|mut addrs| addrs.next())
                    .map(|a| {
                        TcpStream::connect_timeout(&a, std::time::Duration::from_secs(2)).is_ok()
                    })
                    .unwrap_or(false);
                if !reachable {
                    eprintln!();
                    eprintln!(
                        "⚠  MCP configured for HTTP {url}\n   \
                         but no listener is reachable there. Start the gate with\n   \
                         `latchgate up --expose-http`, or omit --gate-url for UDS."
                    );
                }
            }
        }
    }
}

// Operator resolution (admin socket + key + token)

/// Resolved operator configuration for IDE-invoked approval tools.
///
/// All four fields must be present for the installer to write admin flags.
/// `--enable-allowlist-tool` is never auto-enabled.
#[derive(Debug, Clone)]
pub(crate) struct ResolvedOperator {
    pub admin_socket: PathBuf,
    pub key_path: PathBuf,
    pub token: String,
    pub operator_id: String,
}

/// Attempt to auto-detect operator configuration from project/session configs.
///
/// Resolution for admin socket:
///   1. `listen_admin_uds_path` from the active `up` session config.
///   2. `listen_admin_uds_path` from the project config.
///   3. Default admin UDS path.
///
/// Resolution for operator key + token:
///   1. First `operator_credentials` entry from the project config,
///      locate corresponding PEM in `.latchgate/operators/<name>.pem`.
///   2. Fall back to `.latchgate/<name>.pem` (legacy flat path).
///
/// Returns `None` if either side cannot be resolved.
fn resolve_operator() -> Option<ResolvedOperator> {
    let admin_socket = resolve_admin_socket()?;
    let (operator_id, token, key_path) = resolve_operator_credentials()?;

    Some(ResolvedOperator {
        admin_socket,
        key_path,
        token,
        operator_id,
    })
}

/// Resolve the admin UDS path from session config, project config, or default.
fn resolve_admin_socket() -> Option<PathBuf> {
    let runtime_dir = latchgate_core::paths::resolve_runtime_dir().ok()?;

    // 1. Active session config.
    let session_config = runtime_dir.join("latchgate-up/latchgate-up.toml");
    if let Some(path) = read_admin_socket_from_toml(&session_config) {
        return Some(path);
    }

    // 2. Project config.
    let project_config = std::env::current_dir()
        .ok()?
        .join(".latchgate/latchgate.toml");
    if let Some(path) = read_admin_socket_from_toml(&project_config) {
        return Some(path);
    }

    // 3. Default.
    Some(latchgate_core::paths::default_admin_uds_path())
}

fn read_admin_socket_from_toml(path: &Path) -> Option<PathBuf> {
    let content = fs::read_to_string(path).ok()?;
    let table: toml::Table = content.parse().ok()?;
    table
        .get("listen_admin_uds_path")
        .and_then(|v| v.as_str())
        .map(PathBuf::from)
}

/// Resolve operator credentials from the project config.
///
/// Reads the first `operator_credentials` entry, finds the PEM, extracts
/// the api_key. Returns `(operator_id, api_key, pem_path)`.
fn resolve_operator_credentials() -> Option<(String, String, PathBuf)> {
    let project_dir = std::env::current_dir().ok()?;
    let config_path = project_dir.join(".latchgate/latchgate.toml");
    let content = fs::read_to_string(&config_path).ok()?;
    let table: toml::Table = content.parse().ok()?;

    let creds_table = table.get("operator_credentials")?.as_table()?;

    // Use the first credential entry.
    let (operator_id, cred_value) = creds_table.iter().next()?;

    // Validate operator_id before using it in path construction.
    // Reject path traversal, slashes, and non-portable characters.
    if operator_id.is_empty()
        || operator_id.len() > 128
        || !operator_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        tracing::warn!(
            operator_id = %operator_id,
            "operator_credentials key contains invalid characters; \
             skipping auto-detection (allowed: a-z A-Z 0-9 _ -)"
        );
        return None;
    }

    let api_key = cred_value.get("api_key")?.as_str()?;

    let latchgate_dir = project_dir.join(".latchgate");

    // Convention paths (canonical first, then legacy flat).
    let candidates = [
        latchgate_dir
            .join("operators")
            .join(format!("{operator_id}.pem")),
        latchgate_dir.join(format!("{operator_id}.pem")),
    ];

    for pem_path in &candidates {
        if pem_path.is_file() {
            return Some((operator_id.clone(), api_key.to_string(), pem_path.clone()));
        }
    }

    // Also check session state dir.
    if let Ok(runtime_dir) = latchgate_core::paths::resolve_runtime_dir() {
        let session_pem = runtime_dir.join("latchgate-up/operator.pem");
        if session_pem.is_file() {
            return Some((operator_id.clone(), api_key.to_string(), session_pem));
        }
    }

    None
}

// Entry point

/// Entry point for `latchgate-mcp install`.
pub fn run(args: &InstallArgs) -> Result<(), InstallError> {
    let binary = resolve_binary_path(args)?;
    let config_path = ide_config_path(&args.ide)?;
    let ide_name = ide_agent_id(&args.ide);
    let transport = resolve_transport(args)?;

    // Auto-detect operator configuration (admin socket + key + token).
    // Only injected when all components resolve successfully.
    let operator = resolve_operator();
    if operator.is_none() {
        eprintln!(
            "  note: operator configuration not found — approval tools will not \
             be enabled.\n  \
             To enable, configure operator_credentials in latchgate.toml \
             and place the PEM in .latchgate/operators/."
        );
    }

    match args.ide {
        Ide::Codex => run_toml(
            args,
            &binary,
            &config_path,
            ide_name,
            &transport,
            operator.as_ref(),
        ),
        Ide::OpenCode => run_opencode_json(
            args,
            &binary,
            &config_path,
            ide_name,
            &transport,
            operator.as_ref(),
        ),
        Ide::ClaudeCode => run_claude_code(args, &binary, ide_name, &transport, operator.as_ref()),
        Ide::Copilot => run_copilot_json(
            args,
            &binary,
            &config_path,
            ide_name,
            &transport,
            operator.as_ref(),
        ),
        Ide::HermesAgent => run_hermes_yaml(
            args,
            &binary,
            &config_path,
            ide_name,
            &transport,
            operator.as_ref(),
        ),
        _ => run_json(
            args,
            &binary,
            &config_path,
            ide_name,
            &transport,
            operator.as_ref(),
        ),
    }?;

    if !args.dry_run {
        probe_and_warn(&transport);
    }

    Ok(())
}

// JSON path (Claude, Cursor, Cline, Windsurf, OpenClaw, Antigravity)

fn run_json(
    args: &InstallArgs,
    binary: &Path,
    config_path: &Path,
    ide_name: &str,
    transport: &ResolvedTransport,
    operator: Option<&ResolvedOperator>,
) -> Result<(), InstallError> {
    let entry = build_server_entry(binary, transport, ide_name);
    let operator_entry = operator.map(|op| build_operator_entry(binary, transport, op));

    let mut servers = serde_json::Map::new();
    servers.insert("latchgate".to_string(), entry.clone());
    if let Some(ref op_entry) = operator_entry {
        servers.insert("latchgate-operator".to_string(), op_entry.clone());
    }
    let snippet = serde_json::to_string_pretty(&json!({ "mcpServers": servers }))
        .expect("serialization of static structure cannot fail");

    if args.dry_run {
        eprintln!("# Config for {ide_name} (dry run — not written)");
        eprintln!("# Would write to: {}", config_path.display());
        println!("{snippet}");
        return Ok(());
    }

    write_config(config_path, entry, operator_entry)?;
    print_success(
        config_path,
        binary,
        transport,
        ide_name,
        &args.ide,
        operator,
    );
    Ok(())
}

// Claude Code path — delegate to `claude mcp add` CLI

/// Install via `claude mcp add` instead of writing JSON directly.
///
/// Claude Code's config location and format varies across versions.
/// Shelling out to the official CLI ensures the entry lands in the
/// correct file regardless of version.
fn run_claude_code(
    args: &InstallArgs,
    binary: &Path,
    agent_id: &str,
    transport: &ResolvedTransport,
    operator: Option<&ResolvedOperator>,
) -> Result<(), InstallError> {
    let claude_bin = which_claude()?;

    // -- Agent entry --
    let (serve_args, env_pairs) = claude_code_agent_args(binary, transport, agent_id);

    if args.dry_run {
        eprintln!("# Claude Code install (dry run — not executed)");
        print_claude_mcp_command(&claude_bin, "latchgate", &env_pairs, &serve_args);
        if let Some(op) = operator {
            let (op_args, op_env) = claude_code_operator_args(binary, transport, op);
            print_claude_mcp_command(&claude_bin, "latchgate-operator", &op_env, &op_args);
        }
        return Ok(());
    }

    // Remove existing entries first (ignore errors — may not exist).
    let _ = std::process::Command::new(&claude_bin)
        .args(["mcp", "remove", "latchgate", "-s", "user"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    run_claude_mcp_add(&claude_bin, "latchgate", &env_pairs, &serve_args)?;

    // -- Operator entry --
    if let Some(op) = operator {
        let (op_args, op_env) = claude_code_operator_args(binary, transport, op);

        let _ = std::process::Command::new(&claude_bin)
            .args(["mcp", "remove", "latchgate-operator", "-s", "user"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();

        run_claude_mcp_add(&claude_bin, "latchgate-operator", &op_env, &op_args)?;
    }

    // -- Summary --
    eprintln!("✓ Registered latchgate MCP server via `claude mcp add`");
    eprintln!("  Binary:    {}", binary.display());
    match transport {
        ResolvedTransport::Uds {
            socket,
            public_base_url,
        } => {
            eprintln!("  Transport: UDS {}", socket.display());
            eprintln!("  Public URL: {public_base_url}");
        }
        ResolvedTransport::Http { url } => {
            eprintln!("  Transport: HTTP {url}");
        }
    }
    eprintln!("  Agent ID:  {agent_id}");
    if let Some(op) = operator {
        eprintln!("  Operator session (separate entry 'latchgate-operator'):");
        eprintln!("    Admin UDS: {}", op.admin_socket.display());
        eprintln!(
            "    Operator:  {} (key: {})",
            op.operator_id,
            op.key_path.display()
        );
        eprintln!("    Approval tools: latchgate_approve, latchgate_deny");
    }
    eprintln!("  Restart Claude Code to pick up the new configuration.");

    Ok(())
}

/// Locate the `claude` binary.
fn which_claude() -> Result<PathBuf, InstallError> {
    // Check PATH first.
    if let Ok(output) = std::process::Command::new("which").arg("claude").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Ok(PathBuf::from(path));
            }
        }
    }
    // Common install locations.
    let home = home_dir().unwrap_or_default();
    for candidate in [
        home.join(".claude/local/claude"),
        home.join(".local/bin/claude"),
        PathBuf::from("/usr/local/bin/claude"),
    ] {
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(InstallError::ClaudeCliNotFound)
}

/// Build args and env pairs for the agent `serve` command.
fn claude_code_agent_args(
    binary: &Path,
    transport: &ResolvedTransport,
    agent_id: &str,
) -> (Vec<String>, Vec<(String, String)>) {
    let mut cmd_args = vec![binary.to_string_lossy().into_owned(), "serve".to_string()];
    match transport {
        ResolvedTransport::Uds {
            socket,
            public_base_url,
        } => {
            cmd_args.extend([
                "--gate-socket".to_string(),
                socket.to_string_lossy().into_owned(),
                "--public-base-url".to_string(),
                public_base_url.clone(),
            ]);
        }
        ResolvedTransport::Http { url } => {
            cmd_args.extend(["--gate-url".to_string(), url.clone()]);
        }
    }

    let env_pairs = vec![
        ("LATCHGATE_AGENT_ID".to_string(), agent_id.to_string()),
        ("RUST_LOG".to_string(), "warn".to_string()),
    ];

    (cmd_args, env_pairs)
}

/// Build args and env pairs for the operator `operator` command.
fn claude_code_operator_args(
    binary: &Path,
    transport: &ResolvedTransport,
    op: &ResolvedOperator,
) -> (Vec<String>, Vec<(String, String)>) {
    let public_base_url = match transport {
        ResolvedTransport::Uds {
            public_base_url, ..
        } => public_base_url.clone(),
        ResolvedTransport::Http { url } => url.clone(),
    };

    let cmd_args = vec![
        binary.to_string_lossy().into_owned(),
        "operator".to_string(),
        "--admin-socket".to_string(),
        op.admin_socket.to_string_lossy().into_owned(),
        "--operator-key".to_string(),
        op.key_path.to_string_lossy().into_owned(),
        "--operator-id".to_string(),
        op.operator_id.clone(),
        "--public-base-url".to_string(),
        public_base_url,
    ];

    let env_pairs = vec![
        ("LATCHGATE_AGENT_ID".to_string(), op.operator_id.clone()),
        ("RUST_LOG".to_string(), "warn".to_string()),
        ("LATCHGATE_OPERATOR_TOKEN".to_string(), op.token.clone()),
    ];

    (cmd_args, env_pairs)
}

/// Execute `claude mcp add <name> -s user -e K=V ... -- <command> <args...>`.
fn run_claude_mcp_add(
    claude_bin: &Path,
    name: &str,
    env_pairs: &[(String, String)],
    cmd_args: &[String],
) -> Result<(), InstallError> {
    let mut args: Vec<String> = vec![
        "mcp".to_string(),
        "add".to_string(),
        name.to_string(),
        "-s".to_string(),
        "user".to_string(),
    ];
    for (k, v) in env_pairs {
        args.push("-e".to_string());
        args.push(format!("{k}={v}"));
    }
    args.push("--".to_string());
    args.extend(cmd_args.iter().cloned());

    let output = std::process::Command::new(claude_bin)
        .args(&args)
        .output()
        .map_err(|e| InstallError::ClaudeCliExec(e.to_string()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(InstallError::ClaudeCliExec(format!(
            "`claude mcp add {name}` failed (exit {}): {stderr}",
            output.status.code().unwrap_or(-1),
        )));
    }

    Ok(())
}

/// Print the `claude mcp add` command for dry-run output.
fn print_claude_mcp_command(
    claude_bin: &Path,
    name: &str,
    env_pairs: &[(String, String)],
    cmd_args: &[String],
) {
    let mut parts = vec![
        claude_bin.to_string_lossy().into_owned(),
        "mcp".to_string(),
        "add".to_string(),
        name.to_string(),
        "-s".to_string(),
        "user".to_string(),
    ];
    for (k, v) in env_pairs {
        parts.push("-e".to_string());
        parts.push(format!("{k}={v}"));
    }
    parts.push("--".to_string());
    parts.extend(cmd_args.iter().cloned());
    println!("{}", parts.join(" \\\n  "));
    println!();
}

// TOML path (Codex)

fn run_toml(
    args: &InstallArgs,
    binary: &Path,
    config_path: &Path,
    ide_name: &str,
    transport: &ResolvedTransport,
    operator: Option<&ResolvedOperator>,
) -> Result<(), InstallError> {
    let toml_snippet = build_toml_snippet(binary, transport, ide_name, operator);

    if args.dry_run {
        eprintln!("# Config for {ide_name} (dry run — not written)");
        eprintln!("# Would write to: {}", config_path.display());
        println!("{toml_snippet}");
        return Ok(());
    }

    write_toml_config(config_path, binary, transport, ide_name, operator)?;
    print_success(
        config_path,
        binary,
        transport,
        ide_name,
        &args.ide,
        operator,
    );
    Ok(())
}

/// Build a human-readable TOML snippet for display (dry-run).
fn build_toml_snippet(
    binary: &Path,
    transport: &ResolvedTransport,
    agent_id: &str,
    operator: Option<&ResolvedOperator>,
) -> String {
    let args_parts = match transport {
        ResolvedTransport::Uds {
            socket,
            public_base_url,
        } => vec![
            format!(r#""serve""#),
            format!(r#""--gate-socket""#),
            format!(r#""{}""#, socket.display()),
            format!(r#""--public-base-url""#),
            format!(r#""{public_base_url}""#),
        ],
        ResolvedTransport::Http { url } => vec![
            format!(r#""serve""#),
            format!(r#""--gate-url""#),
            format!(r#""{url}""#),
        ],
    };

    let args_str = format!("args = [{}]", args_parts.join(", "));
    let env_lines = [
        format!(r#"LATCHGATE_AGENT_ID = "{agent_id}""#),
        r#"RUST_LOG = "warn""#.to_string(),
    ];

    let mut snippet = format!(
        "[mcp_servers.latchgate]\ncommand = \"{}\"\n{args_str}\n\n[mcp_servers.latchgate.env]\n{}\n",
        binary.to_string_lossy(),
        env_lines.join("\n"),
    );

    if let Some(op) = operator {
        snippet.push('\n');
        snippet.push_str(&build_operator_toml_snippet(binary, transport, op));
    }

    snippet
}

/// Build the operator-session TOML snippet (separate `latchgate-operator`
/// entry running the `operator` command under the operator's identity).
fn build_operator_toml_snippet(
    binary: &Path,
    transport: &ResolvedTransport,
    op: &ResolvedOperator,
) -> String {
    let public_base_url = match transport {
        ResolvedTransport::Uds {
            public_base_url, ..
        } => public_base_url.clone(),
        ResolvedTransport::Http { url } => url.clone(),
    };

    let args_parts = vec![
        format!(r#""operator""#),
        format!(r#""--admin-socket""#),
        format!(r#""{}""#, op.admin_socket.display()),
        format!(r#""--operator-key""#),
        format!(r#""{}""#, op.key_path.display()),
        format!(r#""--operator-id""#),
        format!(r#""{}""#, op.operator_id),
        format!(r#""--public-base-url""#),
        format!(r#""{public_base_url}""#),
    ];
    let args_str = format!("args = [{}]", args_parts.join(", "));

    // Token in env (not args) — avoids /proc/pid/cmdline exposure. The
    // operator session runs under the operator's own identity.
    let env_lines = [
        format!(r#"LATCHGATE_AGENT_ID = "{}""#, op.operator_id),
        r#"RUST_LOG = "warn""#.to_string(),
        format!(r#"LATCHGATE_OPERATOR_TOKEN = "{}""#, op.token),
    ];

    format!(
        "[mcp_servers.latchgate-operator]\ncommand = \"{}\"\n{args_str}\n\n\
         [mcp_servers.latchgate-operator.env]\n{}\n",
        binary.to_string_lossy(),
        env_lines.join("\n"),
    )
}

/// Build the structured operator-session TOML entry table.
fn build_operator_toml_entry(
    binary: &Path,
    transport: &ResolvedTransport,
    op: &ResolvedOperator,
) -> toml::Table {
    let public_base_url = match transport {
        ResolvedTransport::Uds {
            public_base_url, ..
        } => public_base_url.clone(),
        ResolvedTransport::Http { url } => url.clone(),
    };

    let args = toml::Value::Array(vec![
        toml::Value::String("operator".to_string()),
        toml::Value::String("--admin-socket".to_string()),
        toml::Value::String(op.admin_socket.to_string_lossy().into_owned()),
        toml::Value::String("--operator-key".to_string()),
        toml::Value::String(op.key_path.to_string_lossy().into_owned()),
        toml::Value::String("--operator-id".to_string()),
        toml::Value::String(op.operator_id.clone()),
        toml::Value::String("--public-base-url".to_string()),
        toml::Value::String(public_base_url),
    ]);

    // Token in env (not args) — avoids /proc/pid/cmdline exposure. The
    // operator session runs under the operator's own identity.
    let mut env_table = toml::Table::new();
    env_table.insert(
        "LATCHGATE_AGENT_ID".to_string(),
        toml::Value::String(op.operator_id.clone()),
    );
    env_table.insert(
        "RUST_LOG".to_string(),
        toml::Value::String("warn".to_string()),
    );
    env_table.insert(
        "LATCHGATE_OPERATOR_TOKEN".to_string(),
        toml::Value::String(op.token.clone()),
    );

    let mut entry = toml::Table::new();
    entry.insert(
        "command".to_string(),
        toml::Value::String(binary.to_string_lossy().into_owned()),
    );
    entry.insert("args".to_string(), args);
    entry.insert("env".to_string(), toml::Value::Table(env_table));
    entry
}

/// Read existing TOML config, merge the latchgate MCP server entry, write back.
fn write_toml_config(
    path: &Path,
    binary: &Path,
    transport: &ResolvedTransport,
    agent_id: &str,
    operator: Option<&ResolvedOperator>,
) -> Result<(), InstallError> {
    // Read existing config or start with empty table.
    let mut root: toml::Table = if path.exists() {
        let content = fs::read_to_string(path).map_err(|e| InstallError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;

        if content.trim().is_empty() {
            toml::Table::new()
        } else {
            content
                .parse::<toml::Table>()
                .map_err(|e| InstallError::InvalidToml {
                    path: path.to_path_buf(),
                    source: e,
                })?
        }
    } else {
        toml::Table::new()
    };

    // Get or create [mcp_servers].
    let servers = root
        .entry("mcp_servers")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()));

    let servers_table = servers
        .as_table_mut()
        .ok_or_else(|| InstallError::NotTomlTable(path.to_path_buf(), "mcp_servers".to_string()))?;

    // Warn if overwriting.
    if servers_table.contains_key("latchgate") {
        eprintln!(
            "⚠ Overwriting existing latchgate entry in {}",
            path.display()
        );
    }

    // Build the agent latchgate server entry.
    let mut env_table = toml::Table::new();
    env_table.insert(
        "LATCHGATE_AGENT_ID".to_string(),
        toml::Value::String(agent_id.to_string()),
    );
    env_table.insert(
        "RUST_LOG".to_string(),
        toml::Value::String("warn".to_string()),
    );

    let args = transport_to_serve_args(transport);

    let mut entry = toml::Table::new();
    entry.insert(
        "command".to_string(),
        toml::Value::String(binary.to_string_lossy().into_owned()),
    );
    entry.insert("args".to_string(), args);
    entry.insert("env".to_string(), toml::Value::Table(env_table));
    entry.insert("cwd".to_string(), toml::Value::String(".".to_string()));

    servers_table.insert("latchgate".to_string(), toml::Value::Table(entry));

    // Operator session: a separate entry running the `operator` command under
    // the operator's own identity and credential.
    if let Some(op) = operator {
        if servers_table.contains_key("latchgate-operator") {
            eprintln!(
                "⚠ Overwriting existing latchgate-operator entry in {}",
                path.display()
            );
        }
        servers_table.insert(
            "latchgate-operator".to_string(),
            toml::Value::Table(build_operator_toml_entry(binary, transport, op)),
        );
    }

    // Write back.
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| InstallError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }

    let output = toml::to_string_pretty(&root).expect("re-serialization cannot fail");
    fs::write(path, output.as_bytes()).map_err(|e| InstallError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    Ok(())
}

/// Convert a resolved transport into a TOML `args` array value.
fn transport_to_serve_args(transport: &ResolvedTransport) -> toml::Value {
    match transport {
        ResolvedTransport::Uds {
            socket,
            public_base_url,
        } => toml::Value::Array(vec![
            toml::Value::String("serve".to_string()),
            toml::Value::String("--gate-socket".to_string()),
            toml::Value::String(socket.to_string_lossy().into_owned()),
            toml::Value::String("--public-base-url".to_string()),
            toml::Value::String(public_base_url.clone()),
        ]),
        ResolvedTransport::Http { url } => toml::Value::Array(vec![
            toml::Value::String("serve".to_string()),
            toml::Value::String("--gate-url".to_string()),
            toml::Value::String(url.clone()),
        ]),
    }
}

// OpenCode JSON path (uses `mcp` key with `type: "local"`)

fn run_opencode_json(
    args: &InstallArgs,
    binary: &Path,
    config_path: &Path,
    ide_name: &str,
    transport: &ResolvedTransport,
    operator: Option<&ResolvedOperator>,
) -> Result<(), InstallError> {
    let entry = build_opencode_server_entry(binary, transport, ide_name);
    let operator_entry = operator.map(|op| build_opencode_operator_entry(binary, transport, op));

    let mut servers = serde_json::Map::new();
    servers.insert("latchgate".to_string(), entry.clone());
    if let Some(ref op_entry) = operator_entry {
        servers.insert("latchgate-operator".to_string(), op_entry.clone());
    }
    let snippet = serde_json::to_string_pretty(&json!({ "mcp": servers }))
        .expect("serialization of static structure cannot fail");

    if args.dry_run {
        eprintln!("# Config for {ide_name} (dry run — not written)");
        eprintln!("# Would write to: {}", config_path.display());
        println!("{snippet}");
        return Ok(());
    }

    write_opencode_config(config_path, entry, operator_entry)?;
    print_success(
        config_path,
        binary,
        transport,
        ide_name,
        &args.ide,
        operator,
    );
    Ok(())
}

/// Build the OpenCode MCP server entry.
///
/// OpenCode uses `"type": "local"` for stdio-spawned servers.
pub(crate) fn build_opencode_server_entry(
    binary: &Path,
    transport: &ResolvedTransport,
    agent_id: &str,
) -> Value {
    let mut entry = build_server_entry(binary, transport, agent_id);

    // OpenCode requires a `type` discriminator for its MCP entries.
    if let Some(obj) = entry.as_object_mut() {
        obj.insert("type".to_string(), json!("local"));
    }

    entry
}

/// Build the OpenCode operator MCP server entry.
pub(crate) fn build_opencode_operator_entry(
    binary: &Path,
    transport: &ResolvedTransport,
    operator: &ResolvedOperator,
) -> Value {
    let mut entry = build_operator_entry(binary, transport, operator);

    if let Some(obj) = entry.as_object_mut() {
        obj.insert("type".to_string(), json!("local"));
    }

    entry
}

/// Read existing OpenCode config, merge the latchgate entry under `mcp`,
/// write back.
///
/// OpenCode uses `"mcp"` as the wrapper key (not `"mcpServers"`).
pub(crate) fn write_opencode_config(
    path: &Path,
    entry: Value,
    operator_entry: Option<Value>,
) -> Result<(), InstallError> {
    let mut root = if path.exists() {
        let content = fs::read_to_string(path).map_err(|e| InstallError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;

        if content.trim().is_empty() {
            Value::Object(Map::new())
        } else {
            serde_json::from_str::<Value>(&content).map_err(|e| InstallError::InvalidJson {
                path: path.to_path_buf(),
                source: e,
            })?
        }
    } else {
        Value::Object(Map::new())
    };

    let root_obj = root
        .as_object_mut()
        .ok_or_else(|| InstallError::NotJsonObject(path.to_path_buf()))?;

    let servers = root_obj
        .entry("mcp")
        .or_insert_with(|| Value::Object(Map::new()));

    let servers_obj = servers
        .as_object_mut()
        .ok_or_else(|| InstallError::NotJsonObject(path.to_path_buf()))?;

    if servers_obj.contains_key("latchgate") {
        eprintln!(
            "⚠ Overwriting existing latchgate entry in {}",
            path.display()
        );
    }

    servers_obj.insert("latchgate".to_string(), entry);

    if let Some(op_entry) = operator_entry {
        if servers_obj.contains_key("latchgate-operator") {
            eprintln!(
                "⚠ Overwriting existing latchgate-operator entry in {}",
                path.display()
            );
        }
        servers_obj.insert("latchgate-operator".to_string(), op_entry);
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| InstallError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }

    let output = serde_json::to_string_pretty(&root).expect("re-serialization cannot fail");
    fs::write(path, output.as_bytes()).map_err(|e| InstallError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    Ok(())
}

// GitHub Copilot JSON path (VS Code mcp.json: servers)

fn run_copilot_json(
    args: &InstallArgs,
    binary: &Path,
    config_path: &Path,
    ide_name: &str,
    transport: &ResolvedTransport,
    operator: Option<&ResolvedOperator>,
) -> Result<(), InstallError> {
    let entry = build_server_entry(binary, transport, ide_name);
    let operator_entry = operator.map(|op| build_operator_entry(binary, transport, op));

    let mut servers = serde_json::Map::new();
    servers.insert("latchgate".to_string(), entry.clone());
    if let Some(ref op_entry) = operator_entry {
        servers.insert("latchgate-operator".to_string(), op_entry.clone());
    }
    let snippet = serde_json::to_string_pretty(&json!({ "servers": servers }))
        .expect("serialization of static structure cannot fail");

    if args.dry_run {
        eprintln!("# Config for {ide_name} (dry run — not written)");
        eprintln!("# Would write to: {}", config_path.display());
        println!("{snippet}");
        return Ok(());
    }

    write_copilot_config(config_path, entry, operator_entry)?;
    print_success(
        config_path,
        binary,
        transport,
        ide_name,
        &args.ide,
        operator,
    );
    Ok(())
}

/// Read existing VS Code `mcp.json`, merge the latchgate entry under
/// `servers`, write back.
///
/// VS Code's dedicated MCP config file uses `servers` at the top level:
///
/// ```json
/// { "servers": { "latchgate": { ... } } }
/// ```
///
/// This differs from `write_config` (flat `mcpServers`) and
/// `write_opencode_config` (flat `mcp`).
pub(crate) fn write_copilot_config(
    path: &Path,
    entry: Value,
    operator_entry: Option<Value>,
) -> Result<(), InstallError> {
    let mut root = if path.exists() {
        let content = fs::read_to_string(path).map_err(|e| InstallError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;

        if content.trim().is_empty() {
            Value::Object(Map::new())
        } else {
            serde_json::from_str::<Value>(&content).map_err(|e| InstallError::InvalidJson {
                path: path.to_path_buf(),
                source: e,
            })?
        }
    } else {
        Value::Object(Map::new())
    };

    let root_obj = root
        .as_object_mut()
        .ok_or_else(|| InstallError::NotJsonObject(path.to_path_buf()))?;

    // VS Code mcp.json: root["servers"]["latchgate"]
    let servers = root_obj
        .entry("servers")
        .or_insert_with(|| Value::Object(Map::new()));

    let servers_obj = servers
        .as_object_mut()
        .ok_or_else(|| InstallError::NotJsonObject(path.to_path_buf()))?;

    if servers_obj.contains_key("latchgate") {
        eprintln!(
            "⚠ Overwriting existing latchgate entry in {}",
            path.display()
        );
    }

    servers_obj.insert("latchgate".to_string(), entry);

    if let Some(op_entry) = operator_entry {
        if servers_obj.contains_key("latchgate-operator") {
            eprintln!(
                "⚠ Overwriting existing latchgate-operator entry in {}",
                path.display()
            );
        }
        servers_obj.insert("latchgate-operator".to_string(), op_entry);
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| InstallError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }

    let output = serde_json::to_string_pretty(&root).expect("re-serialization cannot fail");
    fs::write(path, output.as_bytes()).map_err(|e| InstallError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    Ok(())
}

// Hermes Agent YAML path (config.yaml: mcp_servers)

fn run_hermes_yaml(
    args: &InstallArgs,
    binary: &Path,
    config_path: &Path,
    ide_name: &str,
    transport: &ResolvedTransport,
    operator: Option<&ResolvedOperator>,
) -> Result<(), InstallError> {
    let entry = build_hermes_server_entry(binary, transport, ide_name);
    let operator_entry = operator.map(|op| build_hermes_operator_entry(binary, transport, op));

    if args.dry_run {
        eprintln!("# Config for {ide_name} (dry run — not written)");
        eprintln!("# Would write to: {}", config_path.display());
        let mut snippet = serde_yaml_ng::Mapping::new();
        snippet.insert(
            serde_yaml_ng::Value::String("latchgate".to_string()),
            entry.clone(),
        );
        if let Some(ref op_entry) = operator_entry {
            snippet.insert(
                serde_yaml_ng::Value::String("latchgate-operator".to_string()),
                op_entry.clone(),
            );
        }
        let wrapper = {
            let mut m = serde_yaml_ng::Mapping::new();
            m.insert(
                serde_yaml_ng::Value::String("mcp_servers".to_string()),
                serde_yaml_ng::Value::Mapping(snippet),
            );
            m
        };
        println!(
            "{}",
            serde_yaml_ng::to_string(&wrapper).expect("YAML serialization cannot fail")
        );
        return Ok(());
    }

    write_hermes_config(config_path, entry, operator_entry)?;
    print_success(
        config_path,
        binary,
        transport,
        ide_name,
        &args.ide,
        operator,
    );
    Ok(())
}

/// Build a Hermes-format YAML entry for the agent `serve` command.
fn build_hermes_server_entry(
    binary: &Path,
    transport: &ResolvedTransport,
    agent_id: &str,
) -> serde_yaml_ng::Value {
    let mut entry = serde_yaml_ng::Mapping::new();
    entry.insert(
        serde_yaml_ng::Value::String("command".to_string()),
        serde_yaml_ng::Value::String(binary.to_string_lossy().into_owned()),
    );

    let args: Vec<serde_yaml_ng::Value> = match transport {
        ResolvedTransport::Uds {
            socket,
            public_base_url,
        } => vec![
            "serve",
            "--gate-socket",
            &socket.to_string_lossy(),
            "--public-base-url",
            public_base_url,
        ]
        .into_iter()
        .map(|s| serde_yaml_ng::Value::String(s.to_string()))
        .collect(),
        ResolvedTransport::Http { url } => vec!["serve", "--gate-url", url]
            .into_iter()
            .map(|s| serde_yaml_ng::Value::String(s.to_string()))
            .collect(),
    };
    entry.insert(
        serde_yaml_ng::Value::String("args".to_string()),
        serde_yaml_ng::Value::Sequence(args),
    );

    let mut env = serde_yaml_ng::Mapping::new();
    env.insert(
        serde_yaml_ng::Value::String("LATCHGATE_AGENT_ID".to_string()),
        serde_yaml_ng::Value::String(agent_id.to_string()),
    );
    env.insert(
        serde_yaml_ng::Value::String("RUST_LOG".to_string()),
        serde_yaml_ng::Value::String("warn".to_string()),
    );
    entry.insert(
        serde_yaml_ng::Value::String("env".to_string()),
        serde_yaml_ng::Value::Mapping(env),
    );

    serde_yaml_ng::Value::Mapping(entry)
}

/// Build a Hermes-format YAML entry for the operator `operator` command.
fn build_hermes_operator_entry(
    binary: &Path,
    transport: &ResolvedTransport,
    op: &ResolvedOperator,
) -> serde_yaml_ng::Value {
    let public_base_url = match transport {
        ResolvedTransport::Uds {
            public_base_url, ..
        } => public_base_url.clone(),
        ResolvedTransport::Http { url } => url.clone(),
    };

    let mut entry = serde_yaml_ng::Mapping::new();
    entry.insert(
        serde_yaml_ng::Value::String("command".to_string()),
        serde_yaml_ng::Value::String(binary.to_string_lossy().into_owned()),
    );

    let args: Vec<serde_yaml_ng::Value> = vec![
        "operator",
        "--admin-socket",
        &op.admin_socket.to_string_lossy(),
        "--operator-key",
        &op.key_path.to_string_lossy(),
        "--operator-id",
        &op.operator_id,
        "--public-base-url",
        &public_base_url,
    ]
    .into_iter()
    .map(|s| serde_yaml_ng::Value::String(s.to_string()))
    .collect();
    entry.insert(
        serde_yaml_ng::Value::String("args".to_string()),
        serde_yaml_ng::Value::Sequence(args),
    );

    let mut env = serde_yaml_ng::Mapping::new();
    env.insert(
        serde_yaml_ng::Value::String("LATCHGATE_AGENT_ID".to_string()),
        serde_yaml_ng::Value::String(op.operator_id.clone()),
    );
    env.insert(
        serde_yaml_ng::Value::String("RUST_LOG".to_string()),
        serde_yaml_ng::Value::String("warn".to_string()),
    );
    // Token in env (not args) — avoids /proc/pid/cmdline exposure.
    env.insert(
        serde_yaml_ng::Value::String("LATCHGATE_OPERATOR_TOKEN".to_string()),
        serde_yaml_ng::Value::String(op.token.clone()),
    );
    entry.insert(
        serde_yaml_ng::Value::String("env".to_string()),
        serde_yaml_ng::Value::Mapping(env),
    );

    serde_yaml_ng::Value::Mapping(entry)
}

/// Read existing Hermes `config.yaml`, merge the latchgate entry under
/// `mcp_servers`, write back.
///
/// Hermes Agent uses YAML with underscored keys:
///
/// ```yaml
/// mcp_servers:
///   latchgate:
///     command: /path/to/latchgate-mcp
///     args: [serve, --gate-url, http://localhost:3000]
///     env:
///       LATCHGATE_AGENT_ID: hermes-agent
/// ```
pub(crate) fn write_hermes_config(
    path: &Path,
    entry: serde_yaml_ng::Value,
    operator_entry: Option<serde_yaml_ng::Value>,
) -> Result<(), InstallError> {
    let mut root: serde_yaml_ng::Value = if path.exists() {
        let content = fs::read_to_string(path).map_err(|e| InstallError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;

        if content.trim().is_empty() {
            serde_yaml_ng::Value::Mapping(serde_yaml_ng::Mapping::new())
        } else {
            serde_yaml_ng::from_str(&content).map_err(|e| InstallError::InvalidYaml {
                path: path.to_path_buf(),
                source: e,
            })?
        }
    } else {
        serde_yaml_ng::Value::Mapping(serde_yaml_ng::Mapping::new())
    };

    let root_map = root
        .as_mapping_mut()
        .ok_or_else(|| InstallError::NotYamlMapping(path.to_path_buf()))?;

    let servers_key = serde_yaml_ng::Value::String("mcp_servers".to_string());

    // Get or create the `mcp_servers` mapping.
    if !root_map.contains_key(&servers_key) {
        root_map.insert(
            servers_key.clone(),
            serde_yaml_ng::Value::Mapping(serde_yaml_ng::Mapping::new()),
        );
    }

    let servers = root_map
        .get_mut(&servers_key)
        .expect("just inserted if missing");

    let servers_map = servers
        .as_mapping_mut()
        .ok_or_else(|| InstallError::NotYamlMapping(path.to_path_buf()))?;

    let lg_key = serde_yaml_ng::Value::String("latchgate".to_string());
    if servers_map.contains_key(&lg_key) {
        eprintln!(
            "⚠ Overwriting existing latchgate entry in {}",
            path.display()
        );
    }
    servers_map.insert(lg_key, entry);

    if let Some(op_entry) = operator_entry {
        let op_key = serde_yaml_ng::Value::String("latchgate-operator".to_string());
        if servers_map.contains_key(&op_key) {
            eprintln!(
                "⚠ Overwriting existing latchgate-operator entry in {}",
                path.display()
            );
        }
        servers_map.insert(op_key, op_entry);
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| InstallError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }

    let output = serde_yaml_ng::to_string(&root).expect("YAML re-serialization cannot fail");
    fs::write(path, output.as_bytes()).map_err(|e| InstallError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    Ok(())
}

// Shared success output

fn print_success(
    config_path: &Path,
    binary: &Path,
    transport: &ResolvedTransport,
    ide_name: &str,
    ide: &Ide,
    operator: Option<&ResolvedOperator>,
) {
    eprintln!("✓ Wrote latchgate MCP config to {}", config_path.display());
    eprintln!();
    eprintln!("  Binary:    {}", binary.display());
    match transport {
        ResolvedTransport::Uds {
            socket,
            public_base_url,
        } => {
            eprintln!("  Transport: UDS {}", socket.display());
            eprintln!("  Public URL: {public_base_url}");
        }
        ResolvedTransport::Http { url } => {
            eprintln!("  Transport: HTTP {url}");
        }
    }
    eprintln!("  Agent ID:  {ide_name}");
    match operator {
        Some(op) => {
            eprintln!();
            eprintln!("  Operator session (separate entry 'latchgate-operator'):");
            eprintln!("    Admin UDS: {}", op.admin_socket.display());
            eprintln!(
                "    Operator:  {} (key: {})",
                op.operator_id,
                op.key_path.display()
            );
            eprintln!("    Approval tools: latchgate_approve, latchgate_deny");
        }
        None => {
            eprintln!("  Operator session: not configured (approve via TUI/CLI)");
        }
    }
    eprintln!();
    eprintln!(
        "  Restart {} to pick up the new configuration.",
        ide_display_name(ide)
    );
}

// Config path resolution

fn ide_config_path(ide: &Ide) -> Result<PathBuf, InstallError> {
    let home = home_dir()?;

    let path = match ide {
        Ide::Claude => {
            if cfg!(target_os = "macos") {
                home.join("Library/Application Support/Claude/claude_desktop_config.json")
            } else if cfg!(target_os = "windows") {
                // %APPDATA%/Claude/claude_desktop_config.json
                std::env::var("APPDATA")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| home.join("AppData/Roaming"))
                    .join("Claude/claude_desktop_config.json")
            } else {
                // Linux / XDG
                std::env::var("XDG_CONFIG_HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| home.join(".config"))
                    .join("Claude/claude_desktop_config.json")
            }
        }
        Ide::ClaudeCode => {
            // Claude Code stores user-scope MCP config in
            // ~/.claude/settings.json under the `mcpServers` key.
            home.join(".claude/settings.json")
        }
        Ide::Cursor => home.join(".cursor/mcp.json"),
        Ide::Cline => {
            if cfg!(target_os = "macos") {
                home.join("Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json")
            } else if cfg!(target_os = "windows") {
                std::env::var("APPDATA")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| home.join("AppData/Roaming"))
                    .join("Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json")
            } else {
                home.join(".config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json")
            }
        }
        Ide::Windsurf => home.join(".codeium/windsurf/mcp_config.json"),
        Ide::Codex => {
            // $CODEX_HOME/config.toml, defaulting to ~/.codex/config.toml.
            std::env::var("CODEX_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| home.join(".codex"))
                .join("config.toml")
        }
        Ide::OpenCode => {
            // OpenCode global config: $XDG_CONFIG_HOME/opencode/opencode.json
            // (project-scope is ./opencode.json but install targets global).
            std::env::var("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| home.join(".config"))
                .join("opencode/opencode.json")
        }
        Ide::OpenClaw => {
            // OpenClaw: MCPorter config in the default workspace.
            // The OpenClaw agent reads MCP server definitions from
            // ~/.openclaw/workspace/config/mcporter.json at session start.
            home.join(".openclaw/workspace/config/mcporter.json")
        }
        Ide::Copilot => {
            // GitHub Copilot agent mode: user-level MCP config at
            // Code/User/mcp.json under the "servers" key.
            if cfg!(target_os = "macos") {
                home.join("Library/Application Support/Code/User/mcp.json")
            } else if cfg!(target_os = "windows") {
                std::env::var("APPDATA")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| home.join("AppData/Roaming"))
                    .join("Code/User/mcp.json")
            } else {
                std::env::var("XDG_CONFIG_HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| home.join(".config"))
                    .join("Code/User/mcp.json")
            }
        }
        Ide::HermesAgent => {
            // Hermes Agent (NousResearch): YAML config at
            // ~/.hermes/config.yaml under the `mcp_servers` key.
            home.join(".hermes/config.yaml")
        }
        Ide::Antigravity => {
            // Antigravity CLI/IDE/2.0 (Google): shared MCP config at
            // ~/.gemini/config/mcp_config.json under `mcpServers`.
            // Successor to Gemini CLI; all Antigravity surfaces read
            // from this single file.
            home.join(".gemini/config/mcp_config.json")
        }
    };

    Ok(path)
}

fn ide_agent_id(ide: &Ide) -> &'static str {
    match ide {
        Ide::Claude => "claude-desktop",
        Ide::ClaudeCode => "claude-code",
        Ide::Cursor => "cursor",
        Ide::Cline => "cline",
        Ide::Windsurf => "windsurf",
        Ide::Codex => "codex",
        Ide::OpenCode => "opencode",
        Ide::OpenClaw => "openclaw",
        Ide::Copilot => "copilot",
        Ide::HermesAgent => "hermes-agent",
        Ide::Antigravity => "antigravity",
    }
}

fn ide_display_name(ide: &Ide) -> &'static str {
    match ide {
        Ide::Claude => "Claude Desktop",
        Ide::ClaudeCode => "Claude Code",
        Ide::Cursor => "Cursor",
        Ide::Cline => "Cline (VS Code)",
        Ide::Windsurf => "Windsurf",
        Ide::Codex => "Codex CLI",
        Ide::OpenCode => "OpenCode",
        Ide::OpenClaw => "OpenClaw",
        Ide::Copilot => "GitHub Copilot (VS Code)",
        Ide::HermesAgent => "Hermes Agent",
        Ide::Antigravity => "Antigravity CLI",
    }
}

// JSON config generation (unchanged)

/// Build the **agent** MCP server entry (`serve` command).
///
/// Carries no operator credential — the agent session never advertises
/// approval tools.
pub(crate) fn build_server_entry(
    binary: &Path,
    transport: &ResolvedTransport,
    agent_id: &str,
) -> Value {
    let mut env = BTreeMap::new();
    env.insert("LATCHGATE_AGENT_ID", agent_id);
    env.insert("RUST_LOG", "warn");

    let args_vec: Vec<Value> = match transport {
        ResolvedTransport::Uds {
            socket,
            public_base_url,
        } => vec![
            json!("serve"),
            json!("--gate-socket"),
            json!(socket.to_string_lossy()),
            json!("--public-base-url"),
            json!(public_base_url),
        ],
        ResolvedTransport::Http { url } => vec![json!("serve"), json!("--gate-url"), json!(url)],
    };

    json!({
        "command": binary.to_string_lossy(),
        "args": args_vec,
        "env": env,
        "cwd": "."
    })
}

/// Build the **operator** MCP server entry (`operator` command).
///
/// A distinct entry from [`build_server_entry`]: it runs under the operator's
/// own identity and DPoP credential and advertises the approval tools. The
/// operator token is passed via env (not args) to avoid `/proc/pid/cmdline`
/// exposure.
pub(crate) fn build_operator_entry(
    binary: &Path,
    transport: &ResolvedTransport,
    operator: &ResolvedOperator,
) -> Value {
    let public_base_url = match transport {
        ResolvedTransport::Uds {
            public_base_url, ..
        } => public_base_url.clone(),
        ResolvedTransport::Http { url } => url.clone(),
    };

    let mut env = BTreeMap::new();
    env.insert(
        "LATCHGATE_AGENT_ID".to_string(),
        operator.operator_id.clone(),
    );
    env.insert("RUST_LOG".to_string(), "warn".to_string());
    // Token in env (not args) to avoid /proc/pid/cmdline exposure.
    env.insert(
        "LATCHGATE_OPERATOR_TOKEN".to_string(),
        operator.token.clone(),
    );

    let args_vec: Vec<Value> = vec![
        json!("operator"),
        json!("--admin-socket"),
        json!(operator.admin_socket.to_string_lossy()),
        json!("--operator-key"),
        json!(operator.key_path.to_string_lossy()),
        json!("--operator-id"),
        json!(operator.operator_id),
        json!("--public-base-url"),
        json!(public_base_url),
    ];

    json!({
        "command": binary.to_string_lossy(),
        "args": args_vec,
        "env": env
    })
}

// JSON config file I/O (unchanged)

/// Read existing config, merge the latchgate entry, write back.
///
/// Preserves all other entries in `mcpServers`. Creates the file and parent
/// directories if they don't exist.
pub(crate) fn write_config(
    path: &Path,
    entry: Value,
    operator_entry: Option<Value>,
) -> Result<(), InstallError> {
    // Read existing config or start with empty object.
    let mut root = if path.exists() {
        let content = fs::read_to_string(path).map_err(|e| InstallError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;

        // Tolerate empty files.
        if content.trim().is_empty() {
            Value::Object(Map::new())
        } else {
            serde_json::from_str::<Value>(&content).map_err(|e| InstallError::InvalidJson {
                path: path.to_path_buf(),
                source: e,
            })?
        }
    } else {
        Value::Object(Map::new())
    };

    // Ensure root is an object.
    let root_obj = root
        .as_object_mut()
        .ok_or_else(|| InstallError::NotJsonObject(path.to_path_buf()))?;

    // Get or create mcpServers.
    let servers = root_obj
        .entry("mcpServers")
        .or_insert_with(|| Value::Object(Map::new()));

    let servers_obj = servers
        .as_object_mut()
        .ok_or_else(|| InstallError::NotJsonObject(path.to_path_buf()))?;

    // Warn if overwriting.
    if servers_obj.contains_key("latchgate") {
        eprintln!(
            "⚠ Overwriting existing latchgate entry in {}",
            path.display()
        );
    }

    servers_obj.insert("latchgate".to_string(), entry);

    if let Some(op_entry) = operator_entry {
        if servers_obj.contains_key("latchgate-operator") {
            eprintln!(
                "⚠ Overwriting existing latchgate-operator entry in {}",
                path.display()
            );
        }
        servers_obj.insert("latchgate-operator".to_string(), op_entry);
    }

    // Write back.
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| InstallError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }

    let output = serde_json::to_string_pretty(&root).expect("re-serialization cannot fail");
    fs::write(path, output.as_bytes()).map_err(|e| InstallError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    Ok(())
}

// Helpers

fn resolve_binary_path(args: &InstallArgs) -> Result<PathBuf, InstallError> {
    if let Some(ref p) = args.binary_path {
        return Ok(p.clone());
    }
    std::env::current_exe().map_err(|_| InstallError::BinaryNotFound)
}

fn home_dir() -> Result<PathBuf, InstallError> {
    // std::env::home_dir is deprecated but the alternatives require a dep.
    // HOME is set on all Unix; USERPROFILE on Windows.
    #[cfg(unix)]
    {
        std::env::var("HOME")
            .map(PathBuf::from)
            .map_err(|_| InstallError::HomeNotFound)
    }
    #[cfg(windows)]
    {
        std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .map(PathBuf::from)
            .map_err(|_| InstallError::HomeNotFound)
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(InstallError::HomeNotFound)
    }
}

// Errors

#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error("cannot determine home directory — set $HOME")]
    HomeNotFound,

    #[error("cannot determine latchgate-mcp binary path — use --binary-path")]
    BinaryNotFound,

    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid JSON in {path}: {source}")]
    InvalidJson {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("invalid TOML in {path}: {source}")]
    InvalidToml {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    #[error("expected JSON object at root or mcpServers in {0}")]
    NotJsonObject(PathBuf),

    #[error("expected TOML table at `{1}` in {0}")]
    NotTomlTable(PathBuf, String),

    #[error("invalid YAML in {path}: {source}")]
    InvalidYaml {
        path: PathBuf,
        #[source]
        source: serde_yaml_ng::Error,
    },

    #[error("expected YAML mapping at root or mcp_servers in {0}")]
    NotYamlMapping(PathBuf),

    #[error(
        "`claude` CLI not found in PATH or standard locations.\n\
         Install Claude Code first: https://claude.ai/install.sh"
    )]
    ClaudeCliNotFound,

    #[error("claude CLI execution failed: {0}")]
    ClaudeCliExec(String),
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn server_entry_http_has_correct_structure() {
        let transport = ResolvedTransport::Http {
            url: "http://localhost:3000".into(),
        };
        let entry = build_server_entry(
            Path::new("/usr/local/bin/latchgate-mcp"),
            &transport,
            "cursor",
        );

        assert_eq!(entry["command"], "/usr/local/bin/latchgate-mcp");
        assert_eq!(entry["args"][0], "serve");
        assert_eq!(entry["args"][1], "--gate-url");
        assert_eq!(entry["args"][2], "http://localhost:3000");
        assert_eq!(entry["env"]["LATCHGATE_AGENT_ID"], "cursor");
        assert_eq!(entry["env"]["RUST_LOG"], "warn");
        assert_eq!(
            entry["cwd"], ".",
            "cwd must be '.' so IDE resolves to workspace root"
        );
    }

    #[test]
    fn server_entry_uds_has_correct_structure() {
        let transport = ResolvedTransport::Uds {
            socket: PathBuf::from("/run/user/1000/latchgate/gate.sock"),
            public_base_url: "http://localhost:3000".into(),
        };
        let entry = build_server_entry(
            Path::new("/usr/local/bin/latchgate-mcp"),
            &transport,
            "cursor",
        );

        assert_eq!(entry["command"], "/usr/local/bin/latchgate-mcp");
        assert_eq!(entry["args"][0], "serve");
        assert_eq!(entry["args"][1], "--gate-socket");
        assert_eq!(entry["args"][2], "/run/user/1000/latchgate/gate.sock");
        assert_eq!(entry["args"][3], "--public-base-url");
        assert_eq!(entry["args"][4], "http://localhost:3000");
    }

    #[test]
    fn server_entry_does_not_leak_extra_fields() {
        let transport = ResolvedTransport::Http {
            url: "http://x:3000".into(),
        };
        let entry = build_server_entry(Path::new("/bin/lm"), &transport, "test");
        let obj = entry.as_object().unwrap();
        assert_eq!(obj.len(), 4, "expected only command, args, env, cwd");
    }

    #[test]
    fn write_config_creates_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subdir/mcp.json");

        let entry = json!({"command": "/bin/latchgate-mcp"});
        write_config(&path, entry, None).unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            content["mcpServers"]["latchgate"]["command"],
            "/bin/latchgate-mcp"
        );
    }

    #[test]
    fn write_config_creates_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a/b/c/config.json");

        write_config(&path, json!({}), None).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn write_config_preserves_other_mcp_servers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");

        let existing = json!({
            "mcpServers": {
                "other-tool": {"command": "/bin/other"}
            }
        });
        fs::write(&path, serde_json::to_string(&existing).unwrap()).unwrap();

        write_config(&path, json!({"command": "/bin/latchgate-mcp"}), None).unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(content["mcpServers"]["other-tool"]["command"], "/bin/other");
        assert_eq!(
            content["mcpServers"]["latchgate"]["command"],
            "/bin/latchgate-mcp"
        );
    }

    #[test]
    fn write_config_preserves_non_mcp_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");

        let existing = json!({"theme": "dark", "mcpServers": {}});
        fs::write(&path, serde_json::to_string(&existing).unwrap()).unwrap();

        write_config(&path, json!({"command": "x"}), None).unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(content["theme"], "dark");
    }

    #[test]
    fn write_config_overwrites_existing_latchgate_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");

        let existing = json!({
            "mcpServers": {
                "latchgate": {"command": "/old/path"}
            }
        });
        fs::write(&path, serde_json::to_string(&existing).unwrap()).unwrap();

        write_config(&path, json!({"command": "/new/path"}), None).unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(content["mcpServers"]["latchgate"]["command"], "/new/path");
    }

    #[test]
    fn write_config_handles_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, "  \n  ").unwrap();

        write_config(&path, json!({"command": "x"}), None).unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(content["mcpServers"]["latchgate"].is_object());
    }

    #[test]
    fn write_config_creates_mcp_servers_key_if_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, r#"{"theme": "dark"}"#).unwrap();

        write_config(&path, json!({"command": "x"}), None).unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(content["mcpServers"].is_object());
        assert_eq!(content["mcpServers"]["latchgate"]["command"], "x");
    }

    #[test]
    fn write_config_rejects_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, "not json at all {{{").unwrap();

        let err = write_config(&path, json!({}), None).unwrap_err();
        assert!(matches!(err, InstallError::InvalidJson { .. }));
    }

    #[test]
    fn write_config_rejects_non_object_root() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, r#"[1, 2, 3]"#).unwrap();

        let err = write_config(&path, json!({}), None).unwrap_err();
        assert!(matches!(err, InstallError::NotJsonObject(_)));
    }

    #[test]
    fn write_config_rejects_non_object_mcp_servers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, r#"{"mcpServers": "not an object"}"#).unwrap();

        let err = write_config(&path, json!({}), None).unwrap_err();
        assert!(matches!(err, InstallError::NotJsonObject(_)));
    }

    fn http_transport(url: &str) -> ResolvedTransport {
        ResolvedTransport::Http { url: url.into() }
    }

    fn uds_transport(socket: &str, public_url: &str) -> ResolvedTransport {
        ResolvedTransport::Uds {
            socket: PathBuf::from(socket),
            public_base_url: public_url.into(),
        }
    }

    #[test]
    fn write_toml_config_creates_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subdir/config.toml");
        let transport = http_transport("http://localhost:3000");

        write_toml_config(
            &path,
            Path::new("/bin/latchgate-mcp"),
            &transport,
            "codex",
            None,
        )
        .unwrap();

        let content: toml::Table = fs::read_to_string(&path).unwrap().parse().unwrap();
        let cmd = content["mcp_servers"]["latchgate"]["command"]
            .as_str()
            .unwrap();
        assert_eq!(cmd, "/bin/latchgate-mcp");
    }

    #[test]
    fn write_toml_config_creates_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a/b/c/config.toml");
        let transport = http_transport("http://x:3000");

        write_toml_config(&path, Path::new("/bin/lm"), &transport, "codex", None).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn write_toml_config_preserves_other_servers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        let existing = r#"
[mcp_servers.context7]
command = "npx"
args = ["-y", "@upstash/context7-mcp"]
"#;
        fs::write(&path, existing).unwrap();

        let transport = http_transport("http://localhost:3000");
        write_toml_config(
            &path,
            Path::new("/bin/latchgate-mcp"),
            &transport,
            "codex",
            None,
        )
        .unwrap();

        let content: toml::Table = fs::read_to_string(&path).unwrap().parse().unwrap();
        assert_eq!(
            content["mcp_servers"]["context7"]["command"]
                .as_str()
                .unwrap(),
            "npx"
        );
        assert_eq!(
            content["mcp_servers"]["latchgate"]["command"]
                .as_str()
                .unwrap(),
            "/bin/latchgate-mcp"
        );
    }

    #[test]
    fn write_toml_config_preserves_non_mcp_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        let existing = "model = \"gpt-5-codex\"\n";
        fs::write(&path, existing).unwrap();

        let transport = http_transport("http://x:3000");
        write_toml_config(&path, Path::new("/bin/lm"), &transport, "codex", None).unwrap();

        let content: toml::Table = fs::read_to_string(&path).unwrap().parse().unwrap();
        assert_eq!(content["model"].as_str().unwrap(), "gpt-5-codex");
    }

    #[test]
    fn write_toml_config_overwrites_existing_latchgate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        let existing = r#"
[mcp_servers.latchgate]
command = "/old/path"
"#;
        fs::write(&path, existing).unwrap();

        let transport = http_transport("http://x:3000");
        write_toml_config(&path, Path::new("/new/path"), &transport, "codex", None).unwrap();

        let content: toml::Table = fs::read_to_string(&path).unwrap().parse().unwrap();
        assert_eq!(
            content["mcp_servers"]["latchgate"]["command"]
                .as_str()
                .unwrap(),
            "/new/path"
        );
    }

    #[test]
    fn write_toml_config_handles_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "  \n  ").unwrap();

        let transport = http_transport("http://x:3000");
        write_toml_config(&path, Path::new("/bin/lm"), &transport, "codex", None).unwrap();

        let content: toml::Table = fs::read_to_string(&path).unwrap().parse().unwrap();
        assert!(content["mcp_servers"]["latchgate"].is_table());
    }

    #[test]
    fn write_toml_config_http_has_correct_entry_structure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let transport = http_transport("http://localhost:3000");

        write_toml_config(
            &path,
            Path::new("/usr/local/bin/latchgate-mcp"),
            &transport,
            "codex",
            None,
        )
        .unwrap();

        let content: toml::Table = fs::read_to_string(&path).unwrap().parse().unwrap();
        let entry = content["mcp_servers"]["latchgate"].as_table().unwrap();

        assert_eq!(
            entry["command"].as_str().unwrap(),
            "/usr/local/bin/latchgate-mcp"
        );

        let args: Vec<&str> = entry["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(args, vec!["serve", "--gate-url", "http://localhost:3000"]);

        let env = entry["env"].as_table().unwrap();
        assert_eq!(env["LATCHGATE_AGENT_ID"].as_str().unwrap(), "codex");
        assert_eq!(env["RUST_LOG"].as_str().unwrap(), "warn");
    }

    #[test]
    fn write_toml_config_uds_has_correct_entry_structure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let transport = uds_transport(
            "/run/user/1000/latchgate/gate.sock",
            "http://localhost:3000",
        );

        write_toml_config(
            &path,
            Path::new("/usr/local/bin/latchgate-mcp"),
            &transport,
            "codex",
            None,
        )
        .unwrap();

        let content: toml::Table = fs::read_to_string(&path).unwrap().parse().unwrap();
        let entry = content["mcp_servers"]["latchgate"].as_table().unwrap();

        let args: Vec<&str> = entry["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(
            args,
            vec![
                "serve",
                "--gate-socket",
                "/run/user/1000/latchgate/gate.sock",
                "--public-base-url",
                "http://localhost:3000",
            ]
        );
    }

    #[test]
    fn write_toml_config_rejects_invalid_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "not valid toml [[[").unwrap();

        let transport = http_transport("http://x:3000");
        let err =
            write_toml_config(&path, Path::new("/bin/lm"), &transport, "codex", None).unwrap_err();
        assert!(matches!(err, InstallError::InvalidToml { .. }));
    }

    #[test]
    fn write_toml_config_rejects_non_table_mcp_servers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "mcp_servers = \"not a table\"\n").unwrap();

        let transport = http_transport("http://x:3000");
        let err =
            write_toml_config(&path, Path::new("/bin/lm"), &transport, "codex", None).unwrap_err();
        assert!(matches!(err, InstallError::NotTomlTable(_, _)));
    }

    #[test]
    fn all_ides_have_agent_ids() {
        assert_eq!(ide_agent_id(&Ide::Claude), "claude-desktop");
        assert_eq!(ide_agent_id(&Ide::ClaudeCode), "claude-code");
        assert_eq!(ide_agent_id(&Ide::Cursor), "cursor");
        assert_eq!(ide_agent_id(&Ide::Cline), "cline");
        assert_eq!(ide_agent_id(&Ide::Windsurf), "windsurf");
        assert_eq!(ide_agent_id(&Ide::Codex), "codex");
        assert_eq!(ide_agent_id(&Ide::OpenCode), "opencode");
        assert_eq!(ide_agent_id(&Ide::OpenClaw), "openclaw");
        assert_eq!(ide_agent_id(&Ide::Copilot), "copilot");
        assert_eq!(ide_agent_id(&Ide::HermesAgent), "hermes-agent");
        assert_eq!(ide_agent_id(&Ide::Antigravity), "antigravity");
    }

    #[test]
    fn all_ides_have_display_names() {
        // Ensures no panic on any variant.
        for ide in [
            Ide::Claude,
            Ide::ClaudeCode,
            Ide::Cursor,
            Ide::Cline,
            Ide::Windsurf,
            Ide::Codex,
            Ide::OpenCode,
            Ide::OpenClaw,
            Ide::Copilot,
            Ide::HermesAgent,
            Ide::Antigravity,
        ] {
            assert!(!ide_display_name(&ide).is_empty());
        }
    }

    /// Mutex to serialize tests that mutate process-global environment
    /// variables. Rust runs tests in parallel within the same process —
    /// `set_var` / `remove_var` are process-wide and racy without this.
    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn cursor_config_path_ends_with_mcp_json() {
        let _lock = ENV_MUTEX.lock().unwrap();
        // ide_config_path reads HOME, which is set in test envs.
        if let Ok(path) = ide_config_path(&Ide::Cursor) {
            assert!(
                path.ends_with(".cursor/mcp.json"),
                "unexpected cursor path: {}",
                path.display()
            );
        }
    }

    #[test]
    fn codex_config_path_ends_with_config_toml() {
        let _lock = ENV_MUTEX.lock().unwrap();
        // Clear CODEX_HOME so the test uses the default ~/.codex/ path,
        // even if a parallel test (codex_config_path_respects_codex_home)
        // has set it.
        let _guard = TempEnvVar::clear("CODEX_HOME");
        if let Ok(path) = ide_config_path(&Ide::Codex) {
            assert!(
                path.ends_with(".codex/config.toml"),
                "unexpected codex path: {}",
                path.display()
            );
        }
    }

    #[test]
    fn codex_config_path_respects_codex_home() {
        let _lock = ENV_MUTEX.lock().unwrap();
        // Temporarily set CODEX_HOME.
        let _guard = TempEnvVar::set("CODEX_HOME", "/tmp/my-codex");
        let path = ide_config_path(&Ide::Codex).unwrap();
        assert_eq!(path, PathBuf::from("/tmp/my-codex/config.toml"));
    }

    #[test]
    fn write_config_output_is_valid_pretty_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");

        write_config(&path, json!({"command": "/bin/lm"}), None).unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        // Pretty-printed = contains newlines.
        assert!(raw.contains('\n'), "output should be pretty-printed");
        // Re-parse succeeds.
        serde_json::from_str::<Value>(&raw).unwrap();
    }

    #[test]
    fn build_toml_snippet_http_is_valid_toml() {
        let transport = http_transport("http://localhost:3000");
        let snippet = build_toml_snippet(
            Path::new("/usr/local/bin/latchgate-mcp"),
            &transport,
            "codex",
            None,
        );
        let table: toml::Table = snippet.parse().expect("snippet must be valid TOML");
        assert!(table["mcp_servers"]["latchgate"]["command"].is_str());
    }

    #[test]
    fn build_toml_snippet_uds_is_valid_toml() {
        let transport = uds_transport(
            "/run/user/1000/latchgate/gate.sock",
            "http://localhost:3000",
        );
        let snippet = build_toml_snippet(
            Path::new("/usr/local/bin/latchgate-mcp"),
            &transport,
            "codex",
            None,
        );
        let table: toml::Table = snippet.parse().expect("snippet must be valid TOML");
        let args = table["mcp_servers"]["latchgate"]["args"]
            .as_array()
            .unwrap();
        assert!(args.iter().any(|v| v.as_str() == Some("--gate-socket")));
    }

    #[test]
    fn read_transport_detects_http_from_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("latchgate-up.toml");
        fs::write(
            &path,
            "listen_http_addr = \"127.0.0.1:3000\"\nlisten_uds_path = \"/tmp/gate.sock\"\n",
        )
        .unwrap();

        let transport = read_transport_from_toml(&path, None).unwrap();
        assert!(
            matches!(transport, ResolvedTransport::Http { url } if url == "http://127.0.0.1:3000")
        );
    }

    #[test]
    fn read_transport_detects_uds_from_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("latchgate-up.toml");
        fs::write(
            &path,
            "listen_uds_path = \"/tmp/gate.sock\"\npublic_base_url = \"http://localhost:3000\"\n",
        )
        .unwrap();

        let transport = read_transport_from_toml(&path, None).unwrap();
        assert!(matches!(
            transport,
            ResolvedTransport::Uds { ref socket, ref public_base_url }
            if socket == Path::new("/tmp/gate.sock") && public_base_url == "http://localhost:3000"
        ));
    }

    #[test]
    fn read_transport_returns_none_without_public_url_for_uds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("latchgate-up.toml");
        // UDS path but no public_base_url → cannot resolve.
        fs::write(&path, "listen_uds_path = \"/tmp/gate.sock\"\n").unwrap();

        assert!(read_transport_from_toml(&path, None).is_none());
    }

    #[test]
    fn read_transport_explicit_public_url_overrides_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("latchgate-up.toml");
        fs::write(
            &path,
            "listen_uds_path = \"/tmp/gate.sock\"\npublic_base_url = \"http://from-config:3000\"\n",
        )
        .unwrap();

        let transport = read_transport_from_toml(&path, Some("http://explicit:3000")).unwrap();
        assert!(matches!(
            transport,
            ResolvedTransport::Uds { ref public_base_url, .. }
            if public_base_url == "http://explicit:3000"
        ));
    }

    #[test]
    fn claude_code_config_path_ends_with_settings_json() {
        let _lock = ENV_MUTEX.lock().unwrap();
        if let Ok(path) = ide_config_path(&Ide::ClaudeCode) {
            assert!(
                path.ends_with(".claude/settings.json"),
                "unexpected claude-code path: {}",
                path.display()
            );
        }
    }

    #[test]
    fn opencode_config_path_ends_with_opencode_json() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _guard = TempEnvVar::clear("XDG_CONFIG_HOME");
        if let Ok(path) = ide_config_path(&Ide::OpenCode) {
            assert!(
                path.ends_with(".config/opencode/opencode.json"),
                "unexpected opencode path: {}",
                path.display()
            );
        }
    }

    #[test]
    fn opencode_config_path_respects_xdg_config_home() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _guard = TempEnvVar::set("XDG_CONFIG_HOME", "/tmp/my-xdg");
        let path = ide_config_path(&Ide::OpenCode).unwrap();
        assert_eq!(path, PathBuf::from("/tmp/my-xdg/opencode/opencode.json"));
    }

    #[test]
    fn build_opencode_entry_includes_type_local() {
        let transport = http_transport("http://localhost:3000");
        let entry = build_opencode_server_entry(
            Path::new("/usr/local/bin/latchgate-mcp"),
            &transport,
            "opencode",
        );

        assert_eq!(entry["type"], "local");
        assert_eq!(entry["command"], "/usr/local/bin/latchgate-mcp");
        assert_eq!(entry["env"]["LATCHGATE_AGENT_ID"], "opencode");
    }

    #[test]
    fn write_opencode_config_creates_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subdir/opencode.json");

        let entry = json!({"type": "local", "command": "/bin/latchgate-mcp"});
        write_opencode_config(&path, entry, None).unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(content["mcp"]["latchgate"]["command"], "/bin/latchgate-mcp");
        assert_eq!(content["mcp"]["latchgate"]["type"], "local");
    }

    #[test]
    fn write_opencode_config_uses_mcp_key_not_mcp_servers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opencode.json");

        write_opencode_config(&path, json!({"command": "x"}), None).unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(content["mcp"]["latchgate"].is_object());
        assert!(
            content["mcpServers"].is_null(),
            "must not use mcpServers key"
        );
    }

    #[test]
    fn write_opencode_config_preserves_other_mcp_servers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opencode.json");

        let existing = json!({
            "model": "anthropic/claude-sonnet-4-5",
            "mcp": {
                "postgres": {"type": "local", "command": "npx"}
            }
        });
        fs::write(&path, serde_json::to_string(&existing).unwrap()).unwrap();

        write_opencode_config(
            &path,
            json!({"type": "local", "command": "/bin/latchgate-mcp"}),
            None,
        )
        .unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(content["model"], "anthropic/claude-sonnet-4-5");
        assert_eq!(content["mcp"]["postgres"]["command"], "npx");
        assert_eq!(content["mcp"]["latchgate"]["command"], "/bin/latchgate-mcp");
    }

    #[test]
    fn write_opencode_config_overwrites_existing_latchgate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opencode.json");

        let existing = json!({"mcp": {"latchgate": {"command": "/old/path"}}});
        fs::write(&path, serde_json::to_string(&existing).unwrap()).unwrap();

        write_opencode_config(&path, json!({"command": "/new/path"}), None).unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(content["mcp"]["latchgate"]["command"], "/new/path");
    }

    #[test]
    fn write_opencode_config_handles_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opencode.json");
        fs::write(&path, "  \n  ").unwrap();

        write_opencode_config(&path, json!({"command": "x"}), None).unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(content["mcp"]["latchgate"].is_object());
    }

    #[test]
    fn write_opencode_config_rejects_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opencode.json");
        fs::write(&path, "not json at all {{{").unwrap();

        let err = write_opencode_config(&path, json!({}), None).unwrap_err();
        assert!(matches!(err, InstallError::InvalidJson { .. }));
    }

    #[test]
    fn write_opencode_config_rejects_non_object_root() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opencode.json");
        fs::write(&path, r#"[1, 2, 3]"#).unwrap();

        let err = write_opencode_config(&path, json!({}), None).unwrap_err();
        assert!(matches!(err, InstallError::NotJsonObject(_)));
    }

    #[test]
    fn openclaw_config_path_ends_with_mcporter_json() {
        let _lock = ENV_MUTEX.lock().unwrap();
        if let Ok(path) = ide_config_path(&Ide::OpenClaw) {
            assert!(
                path.ends_with(".openclaw/workspace/config/mcporter.json"),
                "unexpected openclaw path: {}",
                path.display()
            );
        }
    }

    #[test]
    fn copilot_config_path_ends_with_mcp_json() {
        let _lock = ENV_MUTEX.lock().unwrap();
        if let Ok(path) = ide_config_path(&Ide::Copilot) {
            assert!(
                path.ends_with("Code/User/mcp.json"),
                "unexpected copilot path: {}",
                path.display()
            );
        }
    }

    #[test]
    fn write_copilot_config_creates_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subdir/mcp.json");

        let entry = json!({"command": "/bin/latchgate-mcp"});
        write_copilot_config(&path, entry, None).unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            content["servers"]["latchgate"]["command"],
            "/bin/latchgate-mcp"
        );
    }

    #[test]
    fn write_copilot_config_uses_servers_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");

        write_copilot_config(&path, json!({"command": "x"}), None).unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(content["servers"]["latchgate"].is_object());
        assert!(
            content["mcpServers"].is_null(),
            "must not use mcpServers key"
        );
    }

    #[test]
    fn write_copilot_config_preserves_other_servers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");

        let existing = json!({
            "servers": {
                "github": {"command": "npx"}
            }
        });
        fs::write(&path, serde_json::to_string(&existing).unwrap()).unwrap();

        write_copilot_config(&path, json!({"command": "/bin/latchgate-mcp"}), None).unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(content["servers"]["github"]["command"], "npx");
        assert_eq!(
            content["servers"]["latchgate"]["command"],
            "/bin/latchgate-mcp"
        );
    }

    #[test]
    fn write_copilot_config_overwrites_existing_latchgate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");

        let existing = json!({"servers": {"latchgate": {"command": "/old/path"}}});
        fs::write(&path, serde_json::to_string(&existing).unwrap()).unwrap();

        write_copilot_config(&path, json!({"command": "/new/path"}), None).unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(content["servers"]["latchgate"]["command"], "/new/path");
    }

    #[test]
    fn write_copilot_config_handles_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");
        fs::write(&path, "  \n  ").unwrap();

        write_copilot_config(&path, json!({"command": "x"}), None).unwrap();

        let content: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(content["servers"]["latchgate"].is_object());
    }

    #[test]
    fn write_copilot_config_rejects_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");
        fs::write(&path, "not json at all {{{").unwrap();

        let err = write_copilot_config(&path, json!({}), None).unwrap_err();
        assert!(matches!(err, InstallError::InvalidJson { .. }));
    }

    #[test]
    fn write_copilot_config_rejects_non_object_root() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");
        fs::write(&path, r#"[1, 2, 3]"#).unwrap();

        let err = write_copilot_config(&path, json!({}), None).unwrap_err();
        assert!(matches!(err, InstallError::NotJsonObject(_)));
    }

    #[test]
    fn hermes_agent_config_path_ends_with_config_yaml() {
        let _lock = ENV_MUTEX.lock().unwrap();
        if let Ok(path) = ide_config_path(&Ide::HermesAgent) {
            assert!(
                path.ends_with(".hermes/config.yaml"),
                "unexpected hermes path: {}",
                path.display()
            );
        }
    }

    #[test]
    fn write_hermes_config_creates_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subdir/config.yaml");

        let entry = build_hermes_server_entry(
            Path::new("/bin/latchgate-mcp"),
            &http_transport("http://localhost:3000"),
            "hermes-agent",
        );
        write_hermes_config(&path, entry, None).unwrap();

        let content: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let cmd = content["mcp_servers"]["latchgate"]["command"]
            .as_str()
            .unwrap();
        assert_eq!(cmd, "/bin/latchgate-mcp");
    }

    #[test]
    fn write_hermes_config_preserves_other_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");

        let existing = "model:\n  default: anthropic/claude-opus-4.6\nmcp_servers:\n  time:\n    command: uvx\n    args:\n      - mcp-server-time\n";
        fs::write(&path, existing).unwrap();

        let entry = build_hermes_server_entry(
            Path::new("/bin/latchgate-mcp"),
            &http_transport("http://localhost:3000"),
            "hermes-agent",
        );
        write_hermes_config(&path, entry, None).unwrap();

        let content: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            content["model"]["default"].as_str().unwrap(),
            "anthropic/claude-opus-4.6"
        );
        assert_eq!(
            content["mcp_servers"]["time"]["command"].as_str().unwrap(),
            "uvx"
        );
        assert_eq!(
            content["mcp_servers"]["latchgate"]["command"]
                .as_str()
                .unwrap(),
            "/bin/latchgate-mcp"
        );
    }

    #[test]
    fn write_hermes_config_overwrites_existing_latchgate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");

        let existing = "mcp_servers:\n  latchgate:\n    command: /old/path\n";
        fs::write(&path, existing).unwrap();

        let entry = build_hermes_server_entry(
            Path::new("/new/path"),
            &http_transport("http://x:3000"),
            "hermes-agent",
        );
        write_hermes_config(&path, entry, None).unwrap();

        let content: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            content["mcp_servers"]["latchgate"]["command"]
                .as_str()
                .unwrap(),
            "/new/path"
        );
    }

    #[test]
    fn write_hermes_config_handles_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        fs::write(&path, "  \n  ").unwrap();

        let entry = build_hermes_server_entry(
            Path::new("/bin/lm"),
            &http_transport("http://x:3000"),
            "hermes-agent",
        );
        write_hermes_config(&path, entry, None).unwrap();

        let content: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(content["mcp_servers"]["latchgate"].is_mapping());
    }

    #[test]
    fn write_hermes_config_rejects_invalid_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        fs::write(&path, ":\n  :\n    : [[[invalid").unwrap();

        let err = write_hermes_config(
            &path,
            serde_yaml_ng::Value::Mapping(serde_yaml_ng::Mapping::new()),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, InstallError::InvalidYaml { .. }));
    }

    #[test]
    fn build_hermes_server_entry_http_has_correct_structure() {
        let transport = http_transport("http://localhost:3000");
        let entry = build_hermes_server_entry(
            Path::new("/usr/local/bin/latchgate-mcp"),
            &transport,
            "hermes-agent",
        );
        let map = entry.as_mapping().unwrap();

        assert_eq!(
            map[&ystr("command")].as_str().unwrap(),
            "/usr/local/bin/latchgate-mcp"
        );
        let args: Vec<&str> = map[&ystr("args")]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(args, vec!["serve", "--gate-url", "http://localhost:3000"]);
        let env = map[&ystr("env")].as_mapping().unwrap();
        assert_eq!(
            env[&ystr("LATCHGATE_AGENT_ID")].as_str().unwrap(),
            "hermes-agent"
        );
        assert_eq!(env[&ystr("RUST_LOG")].as_str().unwrap(), "warn");
    }

    fn ystr(s: &str) -> serde_yaml_ng::Value {
        serde_yaml_ng::Value::String(s.to_string())
    }

    #[test]
    fn antigravity_config_path_ends_with_mcp_config_json() {
        let _lock = ENV_MUTEX.lock().unwrap();
        if let Ok(path) = ide_config_path(&Ide::Antigravity) {
            assert!(
                path.ends_with(".gemini/config/mcp_config.json"),
                "unexpected antigravity path: {}",
                path.display()
            );
        }
    }

    struct TempEnvVar {
        key: String,
        prev: Option<String>,
    }

    impl TempEnvVar {
        fn set(key: &str, val: &str) -> Self {
            let prev = std::env::var(key).ok();
            std::env::set_var(key, val);
            Self {
                key: key.to_string(),
                prev,
            }
        }

        fn clear(key: &str) -> Self {
            let prev = std::env::var(key).ok();
            std::env::remove_var(key);
            Self {
                key: key.to_string(),
                prev,
            }
        }
    }

    impl Drop for TempEnvVar {
        fn drop(&mut self) {
            match &self.prev {
                Some(val) => std::env::set_var(&self.key, val),
                None => std::env::remove_var(&self.key),
            }
        }
    }
}
