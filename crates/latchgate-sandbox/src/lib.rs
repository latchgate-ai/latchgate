#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
//! Linux namespace sandbox for agent process containment.
//!
//! Provides `latchgate sandbox` — a launcher that runs an agent process
//! (Claude Code, Cursor, custom agents) inside Linux
//! user/network/mount/PID/UTS/IPC/cgroup namespaces. The agent's only
//! paths to the outside world are:
//!
//! 1. The LatchGate gate UDS (for protected actions).
//! 2. An HTTPS CONNECT proxy (for LLM API traffic to allowed hosts only).
//! 3. A credential-injecting reverse proxy (for API traffic where the
//!    proxy injects credentials on behalf of the agent).
//!
//! # Launch strategy
//!
//! Single path: **bubblewrap**. The launch selects between two modes
//! based on effective uid:
//!
//! ```text
//! euid == 0 (root/sudo)  → parent-assisted netns (robust, any kernel)
//! euid != 0              → rootless bwrap (permissive kernels only)
//! bwrap not found        → refuse with actionable error
//! ```
//!
//! # Platform
//!
//! **Linux only.** On non-Linux platforms, [`platform::check()`] returns
//! an actionable error. The gate itself runs on any platform — only the
//! sandbox launcher is Linux-specific.

// Namespace syscalls require `unsafe`. Each block has a SAFETY comment.
#![deny(clippy::undocumented_unsafe_blocks)]

pub mod platform;

#[cfg(target_os = "linux")]
pub(crate) mod bwrap;
#[cfg(target_os = "linux")]
pub(crate) mod hardening;
#[cfg(target_os = "linux")]
pub(crate) mod landlock;
#[cfg(target_os = "linux")]
pub(crate) mod loopback_forward;
#[cfg(target_os = "linux")]
pub(crate) mod netns;
#[cfg(target_os = "linux")]
mod proxy;
#[cfg(target_os = "linux")]
pub(crate) mod seccomp;

pub use latchgate_config::AgentSandboxConfig;

// Errors

/// Errors from sandbox setup and operation.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// The current platform does not support Linux namespaces.
    #[error(
        "agent sandbox requires Linux with namespace support;\n\
         {0}\n\n\
         The gate itself runs on any platform — only `latchgate sandbox` is Linux-specific.\n\
         On macOS, use a Linux VM or Docker for sandbox mode."
    )]
    UnsupportedPlatform(String),

    /// Bubblewrap is not available (required for sandbox operation).
    #[error(
        "cannot create sandbox;\n\
         {reason}\n\n\
         Fix: install bubblewrap (`apt install bubblewrap` / `dnf install bubblewrap`)"
    )]
    UserNamespacesDisabled { reason: String },

    /// Configuration validation failed.
    #[error("sandbox configuration invalid:\n{}", problems.join("\n"))]
    InvalidConfig { problems: Vec<String> },

    /// No command specified to run inside the sandbox.
    #[error("no command specified — provide a command after `--`")]
    NoCommand,

    /// Namespace setup failed.
    #[error("namespace setup failed: {0}")]
    NamespaceSetup(String),

    /// The proxy socket could not be created or bound.
    #[error("proxy setup failed: {0}")]
    ProxySetup(String),

    /// The sandboxed child process could not be spawned.
    #[error("failed to spawn agent process: {0}")]
    Spawn(#[source] std::io::Error),

    /// A credential source could not be resolved.
    #[error("credential resolution failed: {0}")]
    CredentialResolution(String),

    /// A profile declared credential routes but none resolved.
    ///
    /// Fail-closed: an agent that expects credential injection must not
    /// launch silently without any credentials.
    #[error(
        "no credential resolved — set at least one of: {}\n\n\
         hint: the sandbox credential proxy requires a BYO API key.\n\
         Subscription/OAuth tokens are not supported in-sandbox.",
        vars.join(", ")
    )]
    NoCredentialResolved {
        /// Route names that were declared (e.g. `["anthropic", "openai"]`).
        routes: Vec<String>,
        /// Environment variable names that were tried (e.g. `["ANTHROPIC_API_KEY"]`).
        vars: Vec<String>,
    },

    /// An I/O error during sandbox lifecycle.
    #[error("sandbox I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// Launch result

/// Which sandbox launch strategy was used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchMode {
    /// Namespace isolation via bubblewrap. In the root-assisted path,
    /// bwrap joins a pre-configured network namespace; in the rootless
    /// path, bwrap creates its own.
    Bwrap,
}

impl std::fmt::Display for LaunchMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bwrap => f.write_str("bwrap"),
        }
    }
}

/// Result of a successful sandbox launch.
#[derive(Debug)]
pub struct LaunchResult {
    /// The agent process exit code.
    pub exit_code: i32,
    /// Which isolation strategy was applied.
    pub mode: LaunchMode,
}

// Public API

/// Resolved, validated sandbox launch parameters.
///
/// Constructed from [`AgentSandboxConfig`] + CLI command after all
/// merging and validation. Fully resolved — no optional fields.
#[derive(Debug)]
pub struct SandboxLaunchParams {
    /// Absolute path to the workspace directory (host side).
    pub workspace: std::path::PathBuf,

    /// Hostnames the proxy will allow CONNECT to.
    pub allow_hosts: Vec<String>,

    /// Additional read-only bind mounts (host paths, absolute).
    pub ro_mounts: Vec<std::path::PathBuf>,

    /// Environment variables to pass into the sandbox.
    pub pass_env: Vec<String>,

    /// Gate UDS path on the host.
    pub gate_socket: std::path::PathBuf,

    /// Command + args to exec inside the sandbox.
    pub command: Vec<String>,

    /// Credential routes for the reverse proxy.
    pub credentials: std::collections::HashMap<String, latchgate_config::CredentialRouteConfig>,

    /// Explicitly configured sandbox uid (overrides workspace-owner detection).
    pub sandbox_uid: Option<u32>,

    /// Explicitly configured sandbox gid (overrides workspace-owner detection).
    pub sandbox_gid: Option<u32>,
}

impl SandboxLaunchParams {
    /// Build launch parameters from config + CLI command.
    pub fn resolve(
        config: &AgentSandboxConfig,
        command: Vec<String>,
    ) -> Result<Self, SandboxError> {
        if command.is_empty() {
            return Err(SandboxError::NoCommand);
        }

        let problems = config.validate();
        if !problems.is_empty() {
            return Err(SandboxError::InvalidConfig { problems });
        }

        let workspace = config.effective_workspace().map_err(|e| {
            SandboxError::Io(std::io::Error::new(
                e.kind(),
                format!("cannot resolve workspace directory: {e}"),
            ))
        })?;

        // SECURITY: canonicalize to prevent TOCTOU between validation and mount.
        let workspace = workspace.canonicalize().map_err(|e| {
            SandboxError::Io(std::io::Error::new(
                e.kind(),
                format!(
                    "cannot canonicalize workspace \"{}\": {e}",
                    workspace.display()
                ),
            ))
        })?;

        // SECURITY: canonicalize ro_mounts to prevent TOCTOU symlink attacks.
        let ro_mounts: Vec<std::path::PathBuf> = config
            .ro_mounts
            .iter()
            .map(|p| {
                p.canonicalize().map_err(|e| {
                    SandboxError::Io(std::io::Error::new(
                        e.kind(),
                        format!("cannot canonicalize ro_mount \"{}\": {e}", p.display()),
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        // SECURITY: canonicalize gate socket to prevent TOCTOU symlink attacks.
        // Also serves as an existence check — if the gate isn't running, the
        // socket file won't exist and this surfaces a clear error before bwrap
        // would fail with a cryptic "Can't find source path".
        let gate_socket = config.gate_socket.canonicalize().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                SandboxError::InvalidConfig {
                    problems: vec![format!(
                        "gate socket \"{}\" not found — is the gate running?\n\
                         Start it first: latchgate up (or latchgate gate)",
                        config.gate_socket.display()
                    )],
                }
            } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                SandboxError::InvalidConfig {
                    problems: vec![format!(
                        "cannot access gate socket \"{}\": permission denied\n\
                         hint: when using sudo, run the gate as root too: sudo latchgate up",
                        config.gate_socket.display()
                    )],
                }
            } else {
                SandboxError::Io(std::io::Error::new(
                    e.kind(),
                    format!(
                        "cannot access gate socket \"{}\": {e}",
                        config.gate_socket.display()
                    ),
                ))
            }
        })?;

        Ok(Self {
            workspace,
            allow_hosts: config.allow_hosts.clone(),
            ro_mounts,
            pass_env: config.pass_env.clone(),
            gate_socket,
            command,
            credentials: config.credentials.clone(),
            sandbox_uid: config.sandbox_uid,
            sandbox_gid: config.sandbox_gid,
        })
    }
}

// Credential coverage check (pure, platform-independent, testable)

/// Verify that credential resolution is consistent with the profile's
/// declared routes.
///
/// If the profile declares ≥1 credential route but zero resolved (i.e. every
/// `env:VAR` source was unset), log a warning. The agent may still
/// authenticate via subscription/OAuth through the CONNECT tunnel — the
/// credential proxy is an optional optimization that keeps API keys out
/// of the sandbox, not a hard requirement.
///
/// If no routes are declared (e.g. a bare `sandbox -- cmd`), or at least one
/// route resolved, this is a no-op.
fn check_credential_coverage(
    declared: &std::collections::HashMap<String, latchgate_config::CredentialRouteConfig>,
    resolved_count: usize,
) {
    if declared.is_empty() || resolved_count > 0 {
        return;
    }

    let mut vars: Vec<&str> = declared
        .values()
        .filter_map(|c| c.key_source.strip_prefix("env:"))
        .collect();
    vars.sort_unstable();

    tracing::warn!(
        env_vars = ?vars,
        "no credential routes resolved — the agent will authenticate \
         through the CONNECT tunnel (subscription/OAuth) instead of \
         the credential-injecting proxy. Set {} to enable \
         credential isolation.",
        vars.join(" or ")
    );
}

// Public entry points

/// Launch an agent in a sandboxed Linux namespace.
///
/// Returns [`LaunchResult`] with the exit code and which isolation
/// strategy was used. Requires bubblewrap on PATH.
pub async fn launch(params: SandboxLaunchParams) -> Result<LaunchResult, SandboxError> {
    #[cfg(target_os = "linux")]
    {
        if !platform::is_bwrap_available() {
            return Err(SandboxError::UserNamespacesDisabled {
                reason: "bubblewrap (bwrap) not found on PATH — required for sandbox".into(),
            });
        }

        tracing::info!(
            workspace = %params.workspace.display(),
            allow_hosts = ?params.allow_hosts,
            command = ?params.command,
            credential_routes = params.credentials.len(),
            "launching agent in sandbox"
        );

        if params.allow_hosts.is_empty() {
            tracing::warn!("allow_hosts is empty — the agent will have no network access at all");
        }

        launch_bwrap(params).await
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = params;
        Err(SandboxError::UnsupportedPlatform(
            "compiled on non-Linux platform".to_string(),
        ))
    }
}

/// Public entry point for the `sandbox-init` shim subcommand.
///
/// Called by the CLI handler for `latchgate sandbox-init --config-fd <N>`.
/// Runs inside the bwrap sandbox; does not return on success.
#[cfg(target_os = "linux")]
pub fn run_sandbox_init(config_fd: std::os::fd::RawFd) -> Result<(), SandboxError> {
    bwrap::run_sandbox_init(config_fd)
}

// Credential resolution

#[cfg(target_os = "linux")]
fn resolve_credentials(
    config_routes: &std::collections::HashMap<String, latchgate_config::CredentialRouteConfig>,
) -> Result<(Vec<proxy::ResolvedCredentialRoute>, Vec<String>), SandboxError> {
    use zeroize::Zeroizing;

    let mut resolved = Vec::with_capacity(config_routes.len());
    let mut route_names = Vec::with_capacity(config_routes.len());

    for (name, config) in config_routes {
        let raw_value = if let Some(var_name) = config.key_source.strip_prefix("env:") {
            match std::env::var(var_name) {
                Ok(v) => Zeroizing::new(v),
                Err(_) => {
                    tracing::warn!(
                        route = %name,
                        var = %var_name,
                        "credential route skipped: env var not set on host"
                    );
                    continue;
                }
            }
        } else {
            return Err(SandboxError::CredentialResolution(format!(
                "route \"{name}\": unsupported key_source \"{}\" (only \"env:VAR\" is supported)",
                config.key_source
            )));
        };

        let formatted = Zeroizing::new(config.format.replace("{}", raw_value.as_str()));

        let upstream = config.upstream.trim_end_matches('/');
        let without_scheme = upstream.strip_prefix("https://").ok_or_else(|| {
            SandboxError::CredentialResolution(format!(
                "route \"{name}\": upstream must use https:// scheme"
            ))
        })?;

        let (host_port, base_path) = match without_scheme.find('/') {
            Some(pos) => (&without_scheme[..pos], &without_scheme[pos..]),
            None => (without_scheme, ""),
        };

        let (host, port) = if let Some((h, p)) = host_port.rsplit_once(':') {
            let port: u16 = p.parse().map_err(|_| {
                SandboxError::CredentialResolution(format!(
                    "route \"{name}\": invalid port in upstream"
                ))
            })?;
            (h.to_string(), port)
        } else {
            (host_port.to_string(), 443)
        };

        resolved.push(proxy::ResolvedCredentialRoute {
            name: name.clone(),
            host,
            port,
            base_path: base_path.to_string(),
            inject_header: config.header.clone(),
            inject_value: formatted,
        });
        route_names.push(name.clone());
    }

    // Advisory check: warn if the profile declared credentials but none
    // resolved. The agent can still authenticate via the CONNECT tunnel.
    check_credential_coverage(config_routes, resolved.len());

    Ok((resolved, route_names))
}

#[cfg(target_os = "linux")]
fn generate_session_token() -> [u8; 32] {
    use rand::RngCore;
    let mut token = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token);
    token
}

// Bwrap launch

#[cfg(target_os = "linux")]
async fn launch_bwrap(params: SandboxLaunchParams) -> Result<LaunchResult, SandboxError> {
    let (credential_routes, route_names) = resolve_credentials(&params.credentials)?;

    let session_token = if credential_routes.is_empty() {
        None
    } else {
        Some(generate_session_token())
    };
    let token_hex = session_token.map(hex::encode);

    let temp_dir = tempfile::Builder::new()
        .prefix("latchgate-sandbox-")
        .tempdir()
        .map_err(SandboxError::Io)?;
    let proxy_socket = temp_dir.path().join("proxy.sock");

    let proxy_handle = proxy::start(
        proxy_socket.clone(),
        params.allow_hosts.clone(),
        credential_routes,
        session_token,
    )
    .await?;

    // Spawn parent-assisted netns helper when running as real root.
    // SAFETY: geteuid() is a read-only syscall with no side effects.
    let is_root = unsafe { libc::geteuid() } == 0;
    let netns_helper = if is_root {
        match netns::spawn_helper() {
            Ok(h) => Some(h),
            Err(e) => {
                proxy_handle.shutdown();
                return Err(e);
            }
        }
    } else {
        None
    };

    let (sandbox_uid, sandbox_gid) =
        bwrap::resolve_sandbox_uid_gid(&params.workspace, params.sandbox_uid, params.sandbox_gid);
    let mode = bwrap::BwrapMode {
        netns_path: netns_helper.as_ref().map(|h| h.netns_path()),
        sandbox_uid,
        sandbox_gid,
    };

    tracing::info!(
        root_assisted = is_root,
        sandbox_uid,
        sandbox_gid,
        "bwrap launch mode"
    );

    // From here, proxy and netns helper must be shut down on all paths.
    let result = launch_bwrap_inner(&params, &proxy_socket, token_hex, &route_names, &mode).await;

    drop(netns_helper);
    proxy_handle.shutdown();
    drop(temp_dir);

    result
}

/// Inner implementation of the bwrap launch, separated so the caller can
/// guarantee proxy shutdown on all exit paths.
#[cfg(target_os = "linux")]
async fn launch_bwrap_inner(
    params: &SandboxLaunchParams,
    proxy_socket: &std::path::Path,
    token_hex: Option<String>,
    route_names: &[String],
    mode: &bwrap::BwrapMode,
) -> Result<LaunchResult, SandboxError> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    // Snapshot environment for passthrough BEFORE spawning.
    let env_snapshot: Vec<(String, String)> = params
        .pass_env
        .iter()
        .filter_map(|name| std::env::var(name).ok().map(|v| (name.clone(), v)))
        .collect();

    // Detect Landlock ABI for the shim config.
    let landlock_abi = landlock::detect_abi();

    // Build shim config. Proxy-dependent values (token, route names) are
    // carried into the shim, which materializes the loopback proxy URL and
    // sets the corresponding env vars after it knows the forwarder port.
    let config = bwrap::SandboxInitConfig {
        workspace: "/workspace".to_string(),
        ro_mounts: params
            .ro_mounts
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect(),
        command: params.command.clone(),
        landlock_abi,
        credential_routes: route_names.to_vec(),
        proxy_token: token_hex.clone(),
    };

    // Seal config into memfd. OwnedFd ensures close-on-drop for all
    // error paths — no fd leak if spawn or any later step fails.
    let config_fd_raw = bwrap::create_sealed_memfd(&config)?;
    // SAFETY: config_fd_raw is a valid fd from create_sealed_memfd.
    let config_fd = unsafe { OwnedFd::from_raw_fd(config_fd_raw) };

    // Resolve latchgate binary path for bind-mount into sandbox.
    let latchgate_bin = std::env::current_exe().map_err(|e| {
        SandboxError::NamespaceSetup(format!("cannot resolve latchgate binary: {e}"))
    })?;

    // Stage the binary in the sandbox temp directory. On AppArmor-enabled
    // systems (Ubuntu, WSL2), bwrap's profile restricts bind-mount source
    // paths — user home directories and build trees are typically blocked.
    // The temp directory lives under /tmp which is always permitted.
    let sandbox_dir = proxy_socket.parent().ok_or_else(|| {
        SandboxError::NamespaceSetup("proxy socket has no parent directory".into())
    })?;
    let staged_bin = sandbox_dir.join("latchgate");
    std::fs::copy(&latchgate_bin, &staged_bin).map_err(|e| {
        SandboxError::NamespaceSetup(format!(
            "cannot stage latchgate binary to {}: {e}",
            sandbox_dir.display()
        ))
    })?;

    // Build environment args. Proxy env is set by the shim, not here.
    let env_args = bwrap::build_env_args(params, &env_snapshot);

    // Build and spawn the bwrap command.
    let mut cmd = bwrap::build_bwrap_command(
        params,
        proxy_socket,
        config_fd.as_raw_fd(),
        &staged_bin,
        &env_args,
        mode,
    );

    let mut child = cmd.spawn().map_err(SandboxError::Spawn)?;

    // Capture PID for signal forwarding. child.id() is available immediately
    // after spawn — no AtomicI32 race as with the fork path.
    let bwrap_pid = child.id() as i32;

    let signal_task = tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => return,
        };

        tokio::select! {
            _ = sigterm.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }

        tracing::info!(pid = bwrap_pid, "forwarding SIGTERM to bwrap");
        // SAFETY: bwrap_pid is a valid child PID from Command::spawn.
        unsafe { libc::kill(bwrap_pid, libc::SIGTERM) };
    });

    // Wait for bwrap to exit (blocking).
    let status = tokio::task::spawn_blocking(move || child.wait())
        .await
        .map_err(|e| SandboxError::NamespaceSetup(format!("task join: {e}")))?
        .map_err(SandboxError::Io)?;

    signal_task.abort();

    // config_fd (OwnedFd) drops here — closes the parent's copy of the memfd.
    // bwrap inherited its own copy which the shim already read and closed.
    drop(config_fd);

    let exit_code = if let Some(code) = status.code() {
        code
    } else {
        // Killed by signal — encode as 128 + signal.
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            status.signal().map_or(1, |sig| 128 + sig)
        }
        #[cfg(not(unix))]
        {
            1
        }
    };

    Ok(LaunchResult {
        exit_code,
        mode: LaunchMode::Bwrap,
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests;

// Platform-independent unit tests for pure functions

#[cfg(test)]
mod credential_coverage_tests {
    use super::*;
    use latchgate_config::CredentialRouteConfig;
    use std::collections::HashMap;

    fn route(name: &str, var: &str) -> (String, CredentialRouteConfig) {
        (
            name.to_string(),
            CredentialRouteConfig {
                upstream: "https://api.example.com".to_string(),
                header: "Authorization".to_string(),
                format: "Bearer {}".to_string(),
                key_source: format!("env:{var}"),
            },
        )
    }

    /// No routes declared — the check is a no-op.
    #[test]
    fn no_routes_declared_is_noop() {
        let declared = HashMap::new();
        check_credential_coverage(&declared, 0); // must not panic
    }

    /// All routes resolved — no warning path taken.
    #[test]
    fn all_routes_resolved_is_silent() {
        let declared: HashMap<_, _> = [route("anthropic", "ANTHROPIC_API_KEY")].into();
        check_credential_coverage(&declared, 1);
    }

    /// Partial resolution — at least one route resolved, no warning.
    #[test]
    fn partial_resolution_is_silent() {
        let declared: HashMap<_, _> = [
            route("anthropic", "ANTHROPIC_API_KEY"),
            route("openai", "OPENAI_API_KEY"),
        ]
        .into();
        check_credential_coverage(&declared, 1);
    }

    /// Zero resolved — the advisory path runs (logs a warning) but does
    /// not panic or block launch. The agent authenticates via subscription
    /// through the CONNECT tunnel instead.
    #[test]
    fn zero_resolved_does_not_block_launch() {
        let declared: HashMap<_, _> = [
            route("anthropic", "ANTHROPIC_API_KEY"),
            route("openai", "OPENAI_API_KEY"),
        ]
        .into();
        check_credential_coverage(&declared, 0); // must not panic
    }

    #[test]
    fn single_route_unresolved_does_not_block_launch() {
        let declared: HashMap<_, _> = [route("anthropic", "ANTHROPIC_API_KEY")].into();
        check_credential_coverage(&declared, 0); // must not panic
    }
}
