//! Sandbox configuration.
//!
//! Two independent sandboxing layers:
//!
//! 1. **WASM provider sandbox** ([`SandboxMode`]): controls how the gate
//!    enforces wasmtime isolation for provider execution. Every provider
//!    runs in a WASM sandbox by default.
//!
//! 2. **Agent process sandbox** ([`AgentSandboxConfig`]): Linux namespace
//!    containment for the agent process itself. The agent runs in isolated
//!    user/network/mount/PID namespaces where the only paths to the outside
//!    world are the gate UDS and an HTTPS proxy for LLM API traffic.
//!    Activated via `latchgate sandbox`. Linux ≥ 5.8 only.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum SandboxMode {
    #[default]
    Strict,
    Degraded,
    #[serde(rename = "degraded_ok")]
    DegradedOk,
    Disabled,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SandboxConfig {
    #[serde(default)]
    pub mode: SandboxMode,
    #[serde(default = "default_true")]
    pub strict_for_actions: bool,

    /// Agent process containment configuration.
    ///
    /// When present, `latchgate sandbox` uses these as defaults for
    /// namespace setup. CLI flags override TOML values.
    ///
    /// Linux only. Ignored on other platforms.
    #[serde(default)]
    pub agent: Option<AgentSandboxConfig>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            mode: SandboxMode::Strict,
            strict_for_actions: true,
            agent: None,
        }
    }
}

fn default_true() -> bool {
    true
}

/// Default LLM API hosts allowed through the sandbox egress proxy.
pub const DEFAULT_AGENT_ALLOW_HOSTS: &[&str] = &[
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
];

/// Default environment variables passed into the sandbox.
///
/// Only terminal and locale settings are passed by default. API keys
/// are NOT included — credentials are injected by the reverse proxy
/// via credential routes, never as environment variables inside the
/// sandbox.
pub const DEFAULT_AGENT_PASS_ENV: &[&str] = &["TERM", "LANG"];

/// Environment variable names reserved by the sandbox runtime.
///
/// These are set unconditionally by the sandbox after clearing the
/// inherited environment. Allowing them in `pass_env` would silently
/// break connectivity (the sandbox overrides them) or, if ordering were
/// reversed, compromise containment.
///
/// Validated by [`AgentSandboxConfig::validate`].
pub const RESERVED_AGENT_ENV_NAMES: &[&str] = &[
    "HOME",
    "PATH",
    "LATCHGATE_URL",
    "LATCHGATE_PROXY_TOKEN",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
];

/// Configuration for a single credential-injecting reverse proxy route.
///
/// Each entry maps a route name (e.g. "openai") to an upstream API
/// endpoint. The proxy reads the credential from the host environment
/// (before fork, never passed to the child), injects it as an HTTP
/// header, and forwards requests over TLS.
///
/// The agent inside the sandbox sees only:
/// - `<ROUTE_NAME>_BASE_URL=http+unix://.../route_name` — the proxy endpoint
/// - `LATCHGATE_PROXY_TOKEN=<session-token>` — per-session auth token
///
/// No API key enters the sandbox environment.
///
/// # Example (TOML)
///
/// ```toml
/// [sandbox.agent.credentials.openai]
/// upstream = "https://api.openai.com/v1"
/// header = "Authorization"
/// format = "Bearer {}"
/// key_source = "env:OPENAI_API_KEY"
/// ```
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct CredentialRouteConfig {
    /// Upstream base URL including scheme and path prefix.
    /// Example: `"https://api.openai.com/v1"`
    pub upstream: String,

    /// HTTP header name for credential injection.
    /// Example: `"Authorization"` or `"x-api-key"`
    pub header: String,

    /// Format string for the header value. `{}` is replaced with the
    /// raw credential. Example: `"Bearer {}"` produces `"Bearer sk-..."`.
    #[serde(default = "default_credential_format")]
    pub format: String,

    /// Where to read the credential value.
    /// Currently supported: `"env:VAR_NAME"` — read from host environment
    /// variable `VAR_NAME` before fork.
    pub key_source: String,
}

fn default_credential_format() -> String {
    "{}".to_string()
}

impl CredentialRouteConfig {
    /// Validate this credential route configuration.
    ///
    /// Returns a list of problems. Empty list means valid.
    pub fn validate(&self, name: &str) -> Vec<String> {
        let mut problems = Vec::new();

        if self.upstream.is_empty() {
            problems.push(format!("credentials.{name}.upstream is empty"));
        } else if !self.upstream.starts_with("https://") {
            problems.push(format!(
                "credentials.{name}.upstream = \"{}\" must use https:// scheme",
                self.upstream
            ));
        }

        if self.header.is_empty() {
            problems.push(format!("credentials.{name}.header is empty"));
        }

        if !self.format.contains("{}") {
            problems.push(format!(
                "credentials.{name}.format = \"{}\" must contain {{}} placeholder",
                self.format
            ));
        }

        if self.key_source.is_empty() {
            problems.push(format!("credentials.{name}.key_source is empty"));
        } else if !self.key_source.starts_with("env:") {
            problems.push(format!(
                "credentials.{name}.key_source = \"{}\" must start with \"env:\"",
                self.key_source
            ));
        } else {
            let var_name = &self.key_source[4..];
            if var_name.is_empty() {
                problems.push(format!(
                    "credentials.{name}.key_source = \"env:\" is missing the variable name"
                ));
            }
        }

        problems
    }
}

/// Pre-configured sandbox parameters for a known agent.
pub struct BuiltinProfile {
    /// Executable name to auto-discover on the host `PATH`.
    ///
    /// When the profile is selected, the launcher resolves this name on the
    /// host, follows symlinks to the real binary, and bind-mounts the
    /// smallest enclosing directory read-only so the agent is reachable
    /// inside the sandbox PATH. Used both as the discovery target and as the
    /// default command when none is given after `--`.
    pub binary: &'static str,
    pub allow_hosts: &'static [&'static str],
    pub pass_env: &'static [&'static str],
    pub credentials: &'static [BuiltinCredentialRoute],
}

/// Static credential route definition for a built-in profile.
pub struct BuiltinCredentialRoute {
    pub name: &'static str,
    pub upstream: &'static str,
    pub header: &'static str,
    pub format: &'static str,
    pub key_source: &'static str,
}

const PROFILE_CLAUDE_CODE: BuiltinProfile = BuiltinProfile {
    binary: "claude",
    allow_hosts: &[
        "api.anthropic.com",
        "platform.claude.com",
        "statsig.anthropic.com",
        "sentry.io",
    ],
    pass_env: &["TERM", "LANG", "SHELL", "EDITOR"],
    credentials: &[BuiltinCredentialRoute {
        name: "anthropic",
        upstream: "https://api.anthropic.com",
        header: "x-api-key",
        format: "{}",
        key_source: "env:ANTHROPIC_API_KEY",
    }],
};

const PROFILE_CODEX: BuiltinProfile = BuiltinProfile {
    binary: "codex",
    allow_hosts: &["api.openai.com"],
    pass_env: &["TERM", "LANG"],
    credentials: &[BuiltinCredentialRoute {
        name: "openai",
        upstream: "https://api.openai.com/v1",
        header: "Authorization",
        format: "Bearer {}",
        key_source: "env:OPENAI_API_KEY",
    }],
};

const PROFILE_CURSOR: BuiltinProfile = BuiltinProfile {
    binary: "cursor",
    allow_hosts: &[
        "api.anthropic.com",
        "api.openai.com",
        "api2.cursor.sh",
        "authenticate.cursor.sh",
        "generativelanguage.googleapis.com",
    ],
    pass_env: &["TERM", "LANG"],
    credentials: &[
        BuiltinCredentialRoute {
            name: "anthropic",
            upstream: "https://api.anthropic.com",
            header: "x-api-key",
            format: "{}",
            key_source: "env:ANTHROPIC_API_KEY",
        },
        BuiltinCredentialRoute {
            name: "openai",
            upstream: "https://api.openai.com/v1",
            header: "Authorization",
            format: "Bearer {}",
            key_source: "env:OPENAI_API_KEY",
        },
    ],
};

const PROFILE_OPENCODE: BuiltinProfile = BuiltinProfile {
    binary: "opencode",
    allow_hosts: &[
        "api.anthropic.com",
        "api.deepseek.com",
        "api.groq.com",
        "api.mistral.ai",
        "api.openai.com",
        "generativelanguage.googleapis.com",
        "openrouter.ai",
    ],
    pass_env: &["TERM", "LANG"],
    credentials: &[
        BuiltinCredentialRoute {
            name: "anthropic",
            upstream: "https://api.anthropic.com",
            header: "x-api-key",
            format: "{}",
            key_source: "env:ANTHROPIC_API_KEY",
        },
        BuiltinCredentialRoute {
            name: "openai",
            upstream: "https://api.openai.com/v1",
            header: "Authorization",
            format: "Bearer {}",
            key_source: "env:OPENAI_API_KEY",
        },
    ],
};

const PROFILE_AIDER: BuiltinProfile = BuiltinProfile {
    binary: "aider",
    allow_hosts: &[
        "api.anthropic.com",
        "api.deepseek.com",
        "api.groq.com",
        "api.mistral.ai",
        "api.openai.com",
        "generativelanguage.googleapis.com",
        "openrouter.ai",
    ],
    pass_env: &["TERM", "LANG"],
    credentials: &[
        BuiltinCredentialRoute {
            name: "anthropic",
            upstream: "https://api.anthropic.com",
            header: "x-api-key",
            format: "{}",
            key_source: "env:ANTHROPIC_API_KEY",
        },
        BuiltinCredentialRoute {
            name: "openai",
            upstream: "https://api.openai.com/v1",
            header: "Authorization",
            format: "Bearer {}",
            key_source: "env:OPENAI_API_KEY",
        },
    ],
};

/// Look up a built-in agent profile by name.
///
/// Returns `None` for unknown names — callers should report the error
/// with a list of known profiles.
pub fn builtin_profile(name: &str) -> Option<&'static BuiltinProfile> {
    match name {
        "claude-code" | "claude" => Some(&PROFILE_CLAUDE_CODE),
        "codex" | "openai-codex" => Some(&PROFILE_CODEX),
        "cursor" => Some(&PROFILE_CURSOR),
        "opencode" => Some(&PROFILE_OPENCODE),
        "aider" => Some(&PROFILE_AIDER),
        _ => None,
    }
}

/// All known built-in profile names (for help text and error messages).
pub const BUILTIN_PROFILE_NAMES: &[&str] = &["claude-code", "codex", "cursor", "opencode", "aider"];

/// Agent process sandbox configuration.
///
/// Loaded from `[sandbox.agent]` in `latchgate.toml`, from a standalone
/// `sandbox.toml`, or constructed from CLI flags. CLI flags override TOML.
///
/// # Security model
///
/// The agent runs in Linux user/network/mount/PID namespaces. The ONLY
/// paths to the outside world are:
///
/// 1. The gate UDS ([`gate_socket`](Self::gate_socket)) — for protected
///    actions through the full gate pipeline.
/// 2. The HTTPS CONNECT proxy — for non-credential traffic to
///    [`allow_hosts`](Self::allow_hosts) only (port 443, TLS passthrough).
/// 3. Credential reverse proxy routes — for API traffic where the proxy
///    injects credentials on behalf of the agent. The agent never sees
///    the raw API key.
///
/// Everything else — host filesystem, network, credentials, other
/// processes — is absent from the namespace.
///
/// # Platform
///
/// Requires Linux ≥ 5.8 with `CLONE_NEWUSER` support (unprivileged user
/// namespaces). On other platforms, `latchgate sandbox` exits with an
/// actionable error message.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AgentSandboxConfig {
    /// Host directory mounted as `/workspace` (read-write) inside the sandbox.
    ///
    /// This is the ONLY writable mount. The agent can modify files here;
    /// everything else is read-only or absent.
    ///
    /// Default: current working directory at launch time.
    #[serde(default)]
    pub workspace: Option<PathBuf>,

    /// Hostnames the agent may reach via the HTTPS CONNECT proxy.
    ///
    /// The proxy accepts only `CONNECT` on port 443 to these hosts.
    /// All other destinations receive TCP RST. Denied attempts are logged.
    ///
    /// Default: `["api.anthropic.com", "api.openai.com",
    /// "generativelanguage.googleapis.com"]`
    #[serde(default = "default_allow_hosts")]
    pub allow_hosts: Vec<String>,

    /// Additional read-only bind mounts from host into the sandbox.
    ///
    /// For agent-specific runtime dependencies (e.g. `/opt/cursor`, custom
    /// toolchains). Each path is bind-mounted read-only with
    /// `MS_NOSUID | MS_NODEV`.
    ///
    /// If a mount contains `bin/` or `sbin/` subdirectories, those are
    /// automatically added to the sandbox PATH and command search.
    #[serde(default)]
    pub ro_mounts: Vec<PathBuf>,

    /// Environment variables passed from host into the sandbox.
    ///
    /// Only explicitly listed variables are passed. No blanket inheritance.
    /// Variables not set on the host are silently skipped.
    ///
    /// **API keys should NOT be listed here.** Use [`credentials`] to
    /// configure credential injection via the reverse proxy instead.
    ///
    /// Default: `["TERM", "LANG"]`
    #[serde(default = "default_pass_env")]
    pub pass_env: Vec<String>,

    /// Path to the LatchGate gate UDS on the host.
    ///
    /// Bind-mounted into the sandbox at `/run/latchgate/gate.sock`.
    ///
    /// Default: same runtime directory the gate server uses
    /// (`$XDG_RUNTIME_DIR/latchgate/gate.sock`, falling back to
    /// `/tmp/latchgate/gate.sock`).
    #[serde(default = "default_gate_socket")]
    pub gate_socket: PathBuf,

    /// Credential routes for the reverse proxy.
    ///
    /// Each entry maps a route name (e.g. `"openai"`) to an upstream API
    /// and a credential source. The proxy reads the credential on the host,
    /// injects it into requests, and forwards over TLS. The agent receives
    /// only `<ROUTE>_BASE_URL` pointing at the proxy — no API key material
    /// enters the sandbox.
    ///
    /// Default: empty (no credential injection).
    #[serde(default)]
    pub credentials: HashMap<String, CredentialRouteConfig>,

    /// Explicit uid for the agent process inside the sandbox.
    ///
    /// When set, overrides workspace-owner detection (but not `$SUDO_UID`).
    /// Must not be 0 — the agent must never run as root inside the
    /// namespace, even a user namespace, to limit the blast radius of a
    /// namespace escape.
    ///
    /// Resolution order: `$SUDO_UID` → `sandbox_uid` → workspace owner → 65534.
    ///
    /// Default: `None` (auto-detect from workspace owner).
    #[serde(default)]
    pub sandbox_uid: Option<u32>,

    /// Explicit gid for the agent process inside the sandbox.
    ///
    /// Mirrors [`sandbox_uid`](Self::sandbox_uid). Must not be 0.
    /// When `sandbox_uid` is set but `sandbox_gid` is not, the gid
    /// defaults to the same value as `sandbox_uid`.
    ///
    /// Default: `None` (auto-detect).
    #[serde(default)]
    pub sandbox_gid: Option<u32>,
}

impl Default for AgentSandboxConfig {
    fn default() -> Self {
        Self {
            workspace: None,
            allow_hosts: default_allow_hosts(),
            ro_mounts: Vec::new(),
            pass_env: default_pass_env(),
            gate_socket: default_gate_socket(),
            credentials: HashMap::new(),
            sandbox_uid: None,
            sandbox_gid: None,
        }
    }
}

fn default_allow_hosts() -> Vec<String> {
    DEFAULT_AGENT_ALLOW_HOSTS
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

fn default_pass_env() -> Vec<String> {
    DEFAULT_AGENT_PASS_ENV
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

/// Resolve the default gate socket path using the same logic as the gate
/// server, so `latchgate sandbox` discovers the running gate automatically.
fn default_gate_socket() -> PathBuf {
    latchgate_core::paths::default_uds_path()
}

/// Resolve a profile's agent binary on the host `PATH` and return the
/// directory to bind-mount read-only so the binary is reachable inside the
/// sandbox.
///
/// The sandbox seeds its `PATH` with the `bin`/`sbin` subdirectory of each
/// read-only mount (see `latchgate-sandbox`), so the returned path is chosen
/// to satisfy that contract:
///
/// 1. Find `bin_name` in a `PATH` entry on the host.
/// 2. Canonicalize it, following symlinks to the real executable. Launchers
///    commonly symlink across trees — e.g. `~/.local/bin/claude` →
///    `~/.local/share/claude/versions/<v>` — so both the launcher directory
///    and the real target must end up under one mount.
/// 3. Return the deepest common ancestor of the launcher's `bin` directory
///    and the real executable. That ancestor contains a `bin/<name>` entry
///    (giving auto-PATH) and encloses the resolved target (so the symlink
///    resolves inside the namespace).
///
/// Returns `None` when the binary is not on `PATH` or cannot be resolved; the
/// caller falls through to the standard "command not found in sandbox PATH"
/// error, which remains correct and actionable.
///
/// # Security
///
/// Only the single resolved subtree is exposed — never the host `PATH` itself.
/// The mount is applied read-only with `MS_NOSUID | MS_NODEV` and canonicalized
/// again at launch (TOCTOU-safe) by the sandbox crate. Discovery is opt-in: it
/// runs only for an explicitly named profile, never for a bare `sandbox -- cmd`.
fn discover_agent_mount(bin_name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    let dirs: Vec<PathBuf> = std::env::split_paths(&path_var)
        .filter(|dir| !dir.as_os_str().is_empty())
        .collect();
    discover_agent_mount_in(bin_name, &dirs)
}

/// Pure core of [`discover_agent_mount`]: search `search_dirs` (in order) for
/// `bin_name` and compute the read-only mount that exposes it to the sandbox.
///
/// Separated from environment access so it is deterministic and testable
/// without mutating the process-wide `PATH`.
fn discover_agent_mount_in(bin_name: &str, search_dirs: &[PathBuf]) -> Option<PathBuf> {
    // A profile binary is a bare name, never a path. Reject anything with a
    // separator so a crafted profile can never widen the mount surface.
    if bin_name.is_empty() || bin_name.contains('/') {
        return None;
    }

    let launcher = search_dirs
        .iter()
        .map(|dir| dir.join(bin_name))
        .find(|candidate| candidate.is_file())?;

    // Follow symlinks to the real executable. If canonicalization fails the
    // launcher is unusable; bail rather than mount a tree that won't run.
    let real = std::fs::canonicalize(&launcher).ok()?;

    // Canonicalize the launcher's directory too, so the common-ancestor
    // computation operates on physical paths — matching the canonicalization
    // the sandbox applies at launch and keeping the `bin/<name>` entry inside
    // the returned mount even when the `PATH` entry traverses symlinks.
    let launcher_dir = launcher.parent()?.canonicalize().ok()?;

    // Widen the mount only as far as needed to enclose both the launcher
    // directory and the real binary, so a relocated target (versions/<v>/…)
    // still resolves. When the target already lives beside the launcher, the
    // launcher directory alone suffices and stays minimal.
    Some(common_ancestor(&launcher_dir, &real).unwrap_or(launcher_dir))
}

/// Deepest directory that is an ancestor of both `a` and `b`.
///
/// Returns `None` when the paths share no common prefix (distinct roots),
/// in which case the caller keeps the narrower mount.
fn common_ancestor(a: &Path, b: &Path) -> Option<PathBuf> {
    let mut shared = PathBuf::new();
    for (ca, cb) in a.components().zip(b.components()) {
        if ca != cb {
            break;
        }
        shared.push(ca);
    }
    // A single matching root component (`/`) is not a meaningful mount.
    if shared.components().count() <= 1 {
        None
    } else {
        Some(shared)
    }
}

impl AgentSandboxConfig {
    /// Create a config from a built-in agent profile.
    ///
    /// The profile provides `allow_hosts`, `pass_env`, and `credentials` tuned
    /// for the agent, and auto-discovers the agent binary on the host `PATH`,
    /// adding a read-only mount so it is reachable inside the sandbox. All
    /// other fields use defaults. CLI flags merge additively on top via
    /// [`merge_cli_overrides`].
    pub fn from_profile(name: &str) -> Result<Self, String> {
        let profile = builtin_profile(name).ok_or_else(|| {
            format!(
                "unknown profile \"{name}\" — available profiles: {}",
                BUILTIN_PROFILE_NAMES.join(", ")
            )
        })?;

        let credentials = profile
            .credentials
            .iter()
            .map(|cr| {
                (
                    cr.name.to_string(),
                    CredentialRouteConfig {
                        upstream: cr.upstream.to_string(),
                        header: cr.header.to_string(),
                        format: cr.format.to_string(),
                        key_source: cr.key_source.to_string(),
                    },
                )
            })
            .collect();

        let ro_mounts = discover_agent_mount(profile.binary).into_iter().collect();

        Ok(Self {
            allow_hosts: profile
                .allow_hosts
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            pass_env: profile.pass_env.iter().map(|s| (*s).to_string()).collect(),
            ro_mounts,
            credentials,
            ..Default::default()
        })
    }

    /// Default command for a built-in profile: the profile's agent binary.
    ///
    /// Lets `latchgate sandbox --profile <name>` run with no explicit command
    /// after `--`. Returns `None` for unknown profiles.
    pub fn profile_default_command(name: &str) -> Option<Vec<String>> {
        builtin_profile(name).map(|p| vec![p.binary.to_string()])
    }

    /// Resolve the effective workspace path.
    ///
    /// Returns the configured workspace or falls back to the current
    /// working directory. Fails if neither is available.
    pub fn effective_workspace(&self) -> std::io::Result<PathBuf> {
        match &self.workspace {
            Some(p) => Ok(p.clone()),
            None => std::env::current_dir(),
        }
    }

    /// Merge CLI overrides into this config.
    ///
    /// Non-`None` / non-empty CLI values replace or extend TOML values.
    /// `None` and empty slices are treated as "not specified on CLI" and
    /// leave the TOML value intact.
    pub fn merge_cli_overrides(
        &mut self,
        workspace: Option<PathBuf>,
        allow_hosts: &[String],
        ro_mounts: &[PathBuf],
        pass_env: &[String],
        gate_socket: Option<PathBuf>,
    ) {
        if let Some(ws) = workspace {
            self.workspace = Some(ws);
        }
        if !allow_hosts.is_empty() {
            for host in allow_hosts {
                if !self.allow_hosts.iter().any(|h| h == host) {
                    self.allow_hosts.push(host.clone());
                }
            }
        }
        if !ro_mounts.is_empty() {
            for mount in ro_mounts {
                if !self.ro_mounts.contains(mount) {
                    self.ro_mounts.push(mount.clone());
                }
            }
        }
        if !pass_env.is_empty() {
            for var in pass_env {
                if !self.pass_env.iter().any(|v| v == var) {
                    self.pass_env.push(var.clone());
                }
            }
        }
        if let Some(gs) = gate_socket {
            self.gate_socket = gs;
        }
    }

    /// Validate the configuration for obvious misconfigurations.
    ///
    /// Returns a list of problems. Empty list means valid.
    pub fn validate(&self) -> Vec<String> {
        let mut problems = Vec::new();

        for (i, host) in self.allow_hosts.iter().enumerate() {
            if host.is_empty() {
                problems.push(format!("allow_hosts[{i}] is empty"));
            } else if host.contains("://") {
                problems.push(format!(
                    "allow_hosts[{i}] = \"{host}\" contains a scheme — \
                     use bare hostnames (e.g. \"api.anthropic.com\")"
                ));
            } else if host.contains('/') {
                problems.push(format!(
                    "allow_hosts[{i}] = \"{host}\" contains a path — \
                     use bare hostnames (e.g. \"api.anthropic.com\")"
                ));
            } else if host.contains(':') {
                problems.push(format!(
                    "allow_hosts[{i}] = \"{host}\" contains a port — \
                     the proxy enforces port 443 only; use bare hostnames"
                ));
            }
        }

        for (i, mount) in self.ro_mounts.iter().enumerate() {
            if !mount.is_absolute() {
                problems.push(format!(
                    "ro_mounts[{i}] = \"{}\" is not an absolute path",
                    mount.display()
                ));
            }
        }

        if !self.gate_socket.is_absolute() {
            problems.push(format!(
                "gate_socket = \"{}\" is not an absolute path",
                self.gate_socket.display()
            ));
        }

        for (i, var) in self.pass_env.iter().enumerate() {
            if var.is_empty() {
                problems.push(format!("pass_env[{i}] is empty"));
            }
            if var.contains('=') {
                problems.push(format!(
                    "pass_env[{i}] = \"{var}\" contains '=' — \
                     pass variable names only, not assignments"
                ));
            }
            if RESERVED_AGENT_ENV_NAMES.contains(&var.as_str()) {
                problems.push(format!(
                    "pass_env[{i}] = \"{var}\" is reserved by the sandbox — \
                     the sandbox sets this variable unconditionally and it cannot be overridden"
                ));
            }
        }

        if let Some(ws) = &self.workspace {
            if !ws.is_absolute() {
                problems.push(format!(
                    "workspace = \"{}\" is not an absolute path",
                    ws.display()
                ));
            }
        }

        if self.sandbox_uid == Some(0) {
            problems.push(
                "sandbox_uid = 0 is rejected — the agent must never run as root \
                 inside the namespace (limits blast radius of namespace escape)"
                    .to_string(),
            );
        }
        if self.sandbox_gid == Some(0) {
            problems.push(
                "sandbox_gid = 0 is rejected — the agent must not run in the root group"
                    .to_string(),
            );
        }

        for (name, route) in &self.credentials {
            problems.extend(route.validate(name));
        }

        problems
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_config_default_has_no_agent() {
        let cfg = SandboxConfig::default();
        assert_eq!(cfg.mode, SandboxMode::Strict);
        assert!(cfg.strict_for_actions);
        assert!(cfg.agent.is_none());
    }

    #[test]
    fn agent_config_defaults() {
        let cfg = AgentSandboxConfig::default();
        assert!(cfg.workspace.is_none());
        assert_eq!(cfg.allow_hosts.len(), 3);
        assert!(cfg.allow_hosts.contains(&"api.anthropic.com".to_string()));
        assert!(cfg.ro_mounts.is_empty());
        assert_eq!(cfg.pass_env.len(), 2);
        assert!(cfg.pass_env.contains(&"TERM".to_string()));
        assert!(
            !cfg.pass_env.contains(&"ANTHROPIC_API_KEY".to_string()),
            "API keys must not be in default pass_env"
        );
        assert!(cfg.credentials.is_empty());
        // gate_socket resolved from runtime directory — verify structure.
        assert!(
            cfg.gate_socket.is_absolute(),
            "gate_socket default must be absolute: {}",
            cfg.gate_socket.display()
        );
        assert!(
            cfg.gate_socket.to_string_lossy().ends_with("gate.sock"),
            "gate_socket must end with gate.sock: {}",
            cfg.gate_socket.display()
        );
    }

    #[test]
    fn agent_config_validates_clean() {
        let cfg = AgentSandboxConfig::default();
        assert!(cfg.validate().is_empty());
    }

    #[test]
    fn agent_config_validates_bad_hosts() {
        let cfg = AgentSandboxConfig {
            allow_hosts: vec![
                "https://api.anthropic.com".to_string(),
                "api.openai.com/v1".to_string(),
                "evil.com:8080".to_string(),
                String::new(),
            ],
            ..Default::default()
        };
        let problems = cfg.validate();
        assert_eq!(problems.len(), 4);
        assert!(problems[0].contains("scheme"));
        assert!(problems[1].contains("path"));
        assert!(problems[2].contains("port"));
        assert!(problems[3].contains("empty"));
    }

    #[test]
    fn agent_config_validates_relative_paths() {
        let cfg = AgentSandboxConfig {
            workspace: Some(PathBuf::from("relative/path")),
            ro_mounts: vec![PathBuf::from("also/relative")],
            gate_socket: PathBuf::from("gate.sock"),
            ..Default::default()
        };
        let problems = cfg.validate();
        assert_eq!(problems.len(), 3);
        assert!(problems.iter().all(|p| p.contains("absolute")));
    }

    #[test]
    fn agent_config_validates_bad_env() {
        let cfg = AgentSandboxConfig {
            pass_env: vec!["GOOD".into(), String::new(), "BAD=value".into()],
            ..Default::default()
        };
        let problems = cfg.validate();
        assert_eq!(problems.len(), 2);
        assert!(problems[0].contains("empty"));
        assert!(problems[1].contains("'='"));
    }

    #[test]
    fn agent_config_rejects_reserved_env() {
        let cfg = AgentSandboxConfig {
            pass_env: vec![
                "ANTHROPIC_API_KEY".into(),     // not reserved — fine
                "HTTPS_PROXY".into(),           // reserved
                "HOME".into(),                  // reserved
                "https_proxy".into(),           // reserved (lowercase variant)
                "LATCHGATE_PROXY_TOKEN".into(), // reserved
            ],
            ..Default::default()
        };
        let problems = cfg.validate();
        assert_eq!(problems.len(), 4);
        assert!(problems.iter().all(|p| p.contains("reserved")));
    }

    #[test]
    fn merge_cli_overrides_additive() {
        let mut cfg = AgentSandboxConfig::default();
        let default_gate = cfg.gate_socket.clone();
        cfg.merge_cli_overrides(
            Some(PathBuf::from("/my/project")),
            &["api.deepseek.com".to_string()],
            &[PathBuf::from("/opt/node")],
            &["GITHUB_TOKEN".to_string()],
            None,
        );
        assert_eq!(cfg.workspace, Some(PathBuf::from("/my/project")));
        assert_eq!(cfg.allow_hosts.len(), 4);
        assert!(cfg.allow_hosts.contains(&"api.deepseek.com".to_string()));
        assert_eq!(cfg.ro_mounts, vec![PathBuf::from("/opt/node")]);
        assert_eq!(cfg.pass_env.len(), 3);
        assert!(cfg.pass_env.contains(&"GITHUB_TOKEN".to_string()));
        assert_eq!(cfg.gate_socket, default_gate);
    }

    #[test]
    fn merge_cli_overrides_no_duplicates() {
        let mut cfg = AgentSandboxConfig::default();
        cfg.merge_cli_overrides(
            None,
            &["api.anthropic.com".to_string()],
            &[],
            &["TERM".to_string()],
            None,
        );
        assert_eq!(cfg.allow_hosts.len(), 3);
        assert_eq!(cfg.pass_env.len(), 2);
    }

    #[test]
    fn merge_cli_overrides_empty_is_noop() {
        let original = AgentSandboxConfig::default();
        let mut cfg = original.clone();
        cfg.merge_cli_overrides(None, &[], &[], &[], None);
        assert_eq!(cfg, original);
    }

    #[test]
    fn deserialize_toml_with_agent() {
        let toml_str = r#"
mode = "strict"
strict_for_actions = true

[agent]
workspace = "/home/dev/myproject"
allow_hosts = ["api.anthropic.com", "api.custom.ai"]
gate_socket = "/run/latchgate/gate.sock"
"#;
        let cfg: SandboxConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.mode, SandboxMode::Strict);
        let agent = cfg.agent.unwrap();
        assert_eq!(agent.workspace, Some(PathBuf::from("/home/dev/myproject")));
        assert_eq!(agent.allow_hosts.len(), 2);
    }

    #[test]
    fn deserialize_toml_without_agent() {
        let toml_str = r#"
mode = "strict"
strict_for_actions = true
"#;
        let cfg: SandboxConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.agent.is_none());
    }

    #[test]
    fn effective_workspace_uses_configured() {
        let cfg = AgentSandboxConfig {
            workspace: Some(PathBuf::from("/explicit")),
            ..Default::default()
        };
        assert_eq!(
            cfg.effective_workspace().unwrap(),
            PathBuf::from("/explicit")
        );
    }

    #[test]
    fn effective_workspace_falls_back_to_cwd() {
        let cfg = AgentSandboxConfig::default();
        let ws = cfg.effective_workspace().unwrap();
        assert!(ws.is_absolute());
    }

    #[test]
    fn gate_socket_matches_gate_server_default() {
        let sandbox_default = AgentSandboxConfig::default().gate_socket;
        let gate_default = latchgate_core::paths::default_uds_path();
        assert_eq!(
            sandbox_default, gate_default,
            "sandbox gate_socket default must match gate server default"
        );
    }

    #[test]
    fn profile_claude_code() {
        let cfg = AgentSandboxConfig::from_profile("claude-code").unwrap();
        assert!(cfg.allow_hosts.contains(&"api.anthropic.com".to_string()));
        assert!(cfg.pass_env.contains(&"TERM".to_string()));
        assert!(cfg.pass_env.contains(&"SHELL".to_string()));
        assert!(
            !cfg.pass_env.contains(&"ANTHROPIC_API_KEY".to_string()),
            "API keys must not be in pass_env — use credential routes"
        );
        assert!(cfg.credentials.contains_key("anthropic"));
        let route = &cfg.credentials["anthropic"];
        assert_eq!(route.upstream, "https://api.anthropic.com");
        assert_eq!(route.header, "x-api-key");
        assert_eq!(route.key_source, "env:ANTHROPIC_API_KEY");
    }

    #[test]
    fn profile_claude_alias() {
        let cfg = AgentSandboxConfig::from_profile("claude").unwrap();
        assert!(cfg.allow_hosts.contains(&"api.anthropic.com".to_string()));
        assert!(cfg.credentials.contains_key("anthropic"));
    }

    #[test]
    fn profile_codex() {
        let cfg = AgentSandboxConfig::from_profile("codex").unwrap();
        assert!(cfg.allow_hosts.contains(&"api.openai.com".to_string()));
        assert!(
            !cfg.pass_env.contains(&"OPENAI_API_KEY".to_string()),
            "API keys must not be in pass_env — use credential routes"
        );
        assert!(cfg.credentials.contains_key("openai"));
        let route = &cfg.credentials["openai"];
        assert_eq!(route.upstream, "https://api.openai.com/v1");
        assert_eq!(route.header, "Authorization");
        assert_eq!(route.format, "Bearer {}");
        assert_eq!(route.key_source, "env:OPENAI_API_KEY");
    }

    #[test]
    fn profile_cursor() {
        let cfg = AgentSandboxConfig::from_profile("cursor").unwrap();
        assert!(cfg.allow_hosts.contains(&"api.anthropic.com".to_string()));
        assert!(cfg.allow_hosts.contains(&"api.openai.com".to_string()));
        assert!(
            cfg.allow_hosts
                .contains(&"generativelanguage.googleapis.com".to_string()),
            "cursor profile must allow Google Generative Language API"
        );
        assert!(cfg.credentials.contains_key("anthropic"));
        assert!(cfg.credentials.contains_key("openai"));
        let anthropic = &cfg.credentials["anthropic"];
        assert_eq!(anthropic.upstream, "https://api.anthropic.com");
        assert_eq!(anthropic.header, "x-api-key");
        assert_eq!(anthropic.key_source, "env:ANTHROPIC_API_KEY");
        let openai = &cfg.credentials["openai"];
        assert_eq!(openai.upstream, "https://api.openai.com/v1");
        assert_eq!(openai.header, "Authorization");
        assert_eq!(openai.format, "Bearer {}");
        assert_eq!(openai.key_source, "env:OPENAI_API_KEY");
    }

    #[test]
    fn profile_opencode() {
        let cfg = AgentSandboxConfig::from_profile("opencode").unwrap();
        assert!(cfg.allow_hosts.contains(&"api.anthropic.com".to_string()));
        assert!(cfg.allow_hosts.contains(&"api.openai.com".to_string()));
        assert!(cfg.credentials.contains_key("anthropic"));
        assert!(cfg.credentials.contains_key("openai"));
        let anthropic = &cfg.credentials["anthropic"];
        assert_eq!(anthropic.upstream, "https://api.anthropic.com");
        assert_eq!(anthropic.header, "x-api-key");
        assert_eq!(anthropic.key_source, "env:ANTHROPIC_API_KEY");
        let openai = &cfg.credentials["openai"];
        assert_eq!(openai.upstream, "https://api.openai.com/v1");
        assert_eq!(openai.header, "Authorization");
        assert_eq!(openai.format, "Bearer {}");
        assert_eq!(openai.key_source, "env:OPENAI_API_KEY");
    }

    #[test]
    fn profile_aider() {
        let cfg = AgentSandboxConfig::from_profile("aider").unwrap();
        assert!(cfg.allow_hosts.contains(&"api.anthropic.com".to_string()));
        assert!(cfg.allow_hosts.contains(&"api.openai.com".to_string()));
        assert!(cfg.credentials.contains_key("anthropic"));
        assert!(cfg.credentials.contains_key("openai"));
        let anthropic = &cfg.credentials["anthropic"];
        assert_eq!(anthropic.upstream, "https://api.anthropic.com");
        assert_eq!(anthropic.header, "x-api-key");
        assert_eq!(anthropic.key_source, "env:ANTHROPIC_API_KEY");
        let openai = &cfg.credentials["openai"];
        assert_eq!(openai.upstream, "https://api.openai.com/v1");
        assert_eq!(openai.header, "Authorization");
        assert_eq!(openai.format, "Bearer {}");
        assert_eq!(openai.key_source, "env:OPENAI_API_KEY");
    }

    #[test]
    fn profile_unknown_returns_error() {
        let err = AgentSandboxConfig::from_profile("nonexistent").unwrap_err();
        assert!(err.contains("unknown profile"));
        assert!(err.contains("claude-code"));
        assert!(err.contains("opencode"));
        assert!(err.contains("aider"));
    }

    #[test]
    fn profile_default_command_known() {
        assert_eq!(
            AgentSandboxConfig::profile_default_command("claude-code"),
            Some(vec!["claude".to_string()])
        );
        assert_eq!(
            AgentSandboxConfig::profile_default_command("claude"),
            Some(vec!["claude".to_string()])
        );
        assert_eq!(
            AgentSandboxConfig::profile_default_command("codex"),
            Some(vec!["codex".to_string()])
        );
        assert_eq!(
            AgentSandboxConfig::profile_default_command("cursor"),
            Some(vec!["cursor".to_string()])
        );
        assert_eq!(
            AgentSandboxConfig::profile_default_command("opencode"),
            Some(vec!["opencode".to_string()])
        );
        assert_eq!(
            AgentSandboxConfig::profile_default_command("aider"),
            Some(vec!["aider".to_string()])
        );
    }

    #[test]
    fn profile_default_command_unknown() {
        assert_eq!(AgentSandboxConfig::profile_default_command("nope"), None);
    }

    #[test]
    fn common_ancestor_shared_subtree() {
        // Sibling directories under a shared root → the shared root.
        let a = PathBuf::from("/home/u/.local/bin");
        let b = PathBuf::from("/home/u/.local/share/claude/versions/1");
        assert_eq!(
            common_ancestor(&a, &b),
            Some(PathBuf::from("/home/u/.local"))
        );
    }

    #[test]
    fn common_ancestor_identical() {
        let a = PathBuf::from("/opt/agent/bin");
        assert_eq!(common_ancestor(&a, &a), Some(a));
    }

    #[test]
    fn common_ancestor_only_root_is_none() {
        // Sharing only `/` is not a meaningful mount.
        let a = PathBuf::from("/usr/bin");
        let b = PathBuf::from("/opt/tool/bin");
        assert_eq!(common_ancestor(&a, &b), None);
    }

    #[test]
    fn discover_agent_mount_rejects_path_like_names() {
        let dirs = [PathBuf::from("/usr/bin")];
        assert_eq!(discover_agent_mount_in("", &dirs), None);
        assert_eq!(discover_agent_mount_in("../escape", &dirs), None);
        assert_eq!(discover_agent_mount_in("/usr/bin/claude", &dirs), None);
        assert_eq!(discover_agent_mount_in("sub/dir", &dirs), None);
    }

    #[test]
    fn discover_agent_mount_missing_binary() {
        let dirs = [PathBuf::from("/usr/bin"), PathBuf::from("/bin")];
        assert_eq!(
            discover_agent_mount_in("latchgate-nonexistent-agent-xyz", &dirs),
            None
        );
    }

    #[test]
    fn discover_agent_mount_resolves_symlinked_launcher() {
        use std::fs;

        // Mirror a real Claude Code install:
        //   <root>/bin/claude  ->  <root>/share/claude/versions/<v>
        let root = tempfile::tempdir().unwrap();
        let root_path = fs::canonicalize(root.path()).unwrap();

        let bin_dir = root_path.join("bin");
        let versions = root_path.join("share/claude/versions");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::create_dir_all(&versions).unwrap();

        let real_bin = versions.join("2.1.158");
        fs::write(&real_bin, b"#!/bin/true\n").unwrap();
        std::os::unix::fs::symlink(&real_bin, bin_dir.join("claude")).unwrap();

        let mount = discover_agent_mount_in("claude", &[bin_dir])
            .expect("claude must be discovered in the provided dir");

        // The mount must enclose both the launcher symlink and its real target,
        // so the symlink resolves inside the sandbox namespace.
        assert_eq!(mount, root_path, "mount must be the shared root");
        assert!(
            mount.join("bin").join("claude").exists(),
            "mount must expose bin/claude for sandbox auto-PATH"
        );
        assert!(
            real_bin.starts_with(&mount),
            "mount must enclose the real binary target"
        );
    }

    #[test]
    fn discover_agent_mount_colocated_target() {
        use std::fs;

        // Binary directly in bin/ with no cross-tree symlink → mount the
        // smallest enclosing directory (the bin dir itself).
        let root = tempfile::tempdir().unwrap();
        let root_path = fs::canonicalize(root.path()).unwrap();
        let bin_dir = root_path.join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let real_bin = bin_dir.join("codex");
        fs::write(&real_bin, b"#!/bin/true\n").unwrap();

        let mount =
            discover_agent_mount_in("codex", std::slice::from_ref(&bin_dir)).expect("codex must be discovered");
        assert_eq!(mount, bin_dir);
        assert!(mount.join("codex").exists());
    }

    #[test]
    fn discover_agent_mount_first_match_wins() {
        use std::fs;

        // Earlier PATH dirs take precedence, matching shell resolution.
        let root = tempfile::tempdir().unwrap();
        let root_path = fs::canonicalize(root.path()).unwrap();
        let first = root_path.join("first/bin");
        let second = root_path.join("second/bin");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        fs::write(first.join("cursor"), b"#!/bin/true\n").unwrap();
        fs::write(second.join("cursor"), b"#!/bin/true\n").unwrap();

        let mount = discover_agent_mount_in("cursor", &[first.clone(), second])
            .expect("cursor must be discovered");
        assert_eq!(mount, first, "first PATH match must win");
    }

    #[test]
    fn profile_merges_with_cli_overrides() {
        let mut cfg = AgentSandboxConfig::from_profile("claude-code").unwrap();
        cfg.merge_cli_overrides(
            Some(PathBuf::from("/my/project")),
            &["api.custom.ai".to_string()],
            &[],
            &["CUSTOM_VAR".to_string()],
            None,
        );
        assert_eq!(cfg.workspace, Some(PathBuf::from("/my/project")));
        assert!(cfg.allow_hosts.contains(&"api.anthropic.com".to_string()));
        assert!(cfg.allow_hosts.contains(&"api.custom.ai".to_string()));
        assert!(cfg.pass_env.contains(&"CUSTOM_VAR".to_string()));
        assert!(cfg.credentials.contains_key("anthropic"));
    }

    #[test]
    fn deserialize_toml_with_credentials() {
        let toml_str = r#"
mode = "strict"

[agent]
allow_hosts = ["api.openai.com"]

[agent.credentials.openai]
upstream = "https://api.openai.com/v1"
header = "Authorization"
format = "Bearer {}"
key_source = "env:OPENAI_API_KEY"
"#;
        let cfg: SandboxConfig = toml::from_str(toml_str).unwrap();
        let agent = cfg.agent.unwrap();
        assert!(agent.credentials.contains_key("openai"));
        let route = &agent.credentials["openai"];
        assert_eq!(route.upstream, "https://api.openai.com/v1");
        assert_eq!(route.header, "Authorization");
        assert_eq!(route.format, "Bearer {}");
        assert_eq!(route.key_source, "env:OPENAI_API_KEY");
    }

    #[test]
    fn validate_credential_route_valid() {
        let route = CredentialRouteConfig {
            upstream: "https://api.openai.com/v1".to_string(),
            header: "Authorization".to_string(),
            format: "Bearer {}".to_string(),
            key_source: "env:OPENAI_API_KEY".to_string(),
        };
        assert!(route.validate("openai").is_empty());
    }

    #[test]
    fn validate_credential_route_bad_upstream() {
        let route = CredentialRouteConfig {
            upstream: "http://api.openai.com".to_string(),
            header: "Authorization".to_string(),
            format: "Bearer {}".to_string(),
            key_source: "env:OPENAI_API_KEY".to_string(),
        };
        let problems = route.validate("openai");
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("https://"));
    }

    #[test]
    fn validate_credential_route_bad_format() {
        let route = CredentialRouteConfig {
            upstream: "https://api.openai.com".to_string(),
            header: "Authorization".to_string(),
            format: "Bearer".to_string(), // missing {}
            key_source: "env:OPENAI_API_KEY".to_string(),
        };
        let problems = route.validate("openai");
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("{}"));
    }

    #[test]
    fn validate_credential_route_bad_key_source() {
        let route = CredentialRouteConfig {
            upstream: "https://api.openai.com".to_string(),
            header: "Authorization".to_string(),
            format: "Bearer {}".to_string(),
            key_source: "keyring:openai".to_string(), // not supported yet
        };
        let problems = route.validate("openai");
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("env:"));
    }

    #[test]
    fn builtin_profile_names_all_resolve() {
        for name in BUILTIN_PROFILE_NAMES {
            assert!(
                builtin_profile(name).is_some(),
                "BUILTIN_PROFILE_NAMES entry \"{name}\" has no builtin_profile() match"
            );
        }
    }

    #[test]
    fn no_profile_leaks_api_keys_in_pass_env() {
        for name in BUILTIN_PROFILE_NAMES {
            let cfg = AgentSandboxConfig::from_profile(name).unwrap();
            for var in &cfg.pass_env {
                let upper = var.to_ascii_uppercase();
                assert!(
                    !upper.contains("KEY") && !upper.contains("SECRET") && !upper.contains("TOKEN"),
                    "profile \"{name}\" leaks sensitive var \"{var}\" in pass_env — \
                     use credential routes instead"
                );
            }
        }
    }

    #[test]
    fn all_profile_credential_routes_validate() {
        for name in BUILTIN_PROFILE_NAMES {
            let cfg = AgentSandboxConfig::from_profile(name).unwrap();
            let problems = cfg.validate();
            assert!(
                problems.is_empty(),
                "profile \"{name}\" has validation errors: {problems:?}"
            );
        }
    }

    #[test]
    fn validate_sandbox_uid_zero_rejected() {
        let cfg = AgentSandboxConfig {
            sandbox_uid: Some(0),
            ..Default::default()
        };
        let problems = cfg.validate();
        assert!(
            problems.iter().any(|p| p.contains("sandbox_uid = 0")),
            "uid 0 must be rejected: {problems:?}"
        );
    }

    #[test]
    fn validate_sandbox_gid_zero_rejected() {
        let cfg = AgentSandboxConfig {
            sandbox_gid: Some(0),
            ..Default::default()
        };
        let problems = cfg.validate();
        assert!(
            problems.iter().any(|p| p.contains("sandbox_gid = 0")),
            "gid 0 must be rejected: {problems:?}"
        );
    }

    #[test]
    fn validate_sandbox_uid_nonzero_accepted() {
        let cfg = AgentSandboxConfig {
            sandbox_uid: Some(1000),
            sandbox_gid: Some(1000),
            ..Default::default()
        };
        let problems = cfg.validate();
        assert!(
            !problems
                .iter()
                .any(|p| p.contains("sandbox_uid") || p.contains("sandbox_gid")),
            "non-zero uid/gid must be accepted: {problems:?}"
        );
    }

    #[test]
    fn validate_sandbox_uid_none_accepted() {
        let cfg = AgentSandboxConfig::default();
        let problems = cfg.validate();
        assert!(
            !problems.iter().any(|p| p.contains("sandbox_uid")),
            "None uid must be accepted"
        );
    }
}
