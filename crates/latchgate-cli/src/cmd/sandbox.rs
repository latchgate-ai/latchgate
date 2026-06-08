//! `latchgate sandbox` — launch an agent in a Linux namespace sandbox.

use std::path::{Path, PathBuf};

use latchgate_config::{AgentSandboxConfig, Config};
use latchgate_sandbox::{SandboxError, SandboxLaunchParams};

use crate::output::Printer;

pub struct SandboxArgs {
    pub config: Option<Config>,
    pub sandbox_config: Option<PathBuf>,
    pub profile: Option<String>,
    pub workspace: Option<PathBuf>,
    pub allow_hosts: Vec<String>,
    pub ro_mounts: Vec<PathBuf>,
    pub pass_env: Vec<String>,
    pub gate_socket: Option<PathBuf>,
    pub command: Vec<String>,
}

pub async fn run(args: SandboxArgs, pr: &Printer) -> i32 {
    let mut agent_config = if let Some(ref profile_name) = args.profile {
        match AgentSandboxConfig::from_profile(profile_name) {
            Ok(cfg) => cfg,
            Err(e) => {
                pr.error(&e);
                return 1;
            }
        }
    } else {
        match resolve_base_config(args.config.as_ref(), args.sandbox_config.as_deref()) {
            Ok(cfg) => cfg,
            Err(e) => {
                pr.error(&e.to_string());
                return 1;
            }
        }
    };

    agent_config.merge_cli_overrides(
        args.workspace,
        &args.allow_hosts,
        &args.ro_mounts,
        &args.pass_env,
        args.gate_socket,
    );

    // With a profile, an empty command defaults to the profile's agent binary.
    let command = match (args.command.is_empty(), args.profile.as_deref()) {
        (true, Some(profile_name)) => {
            AgentSandboxConfig::profile_default_command(profile_name).unwrap_or_default()
        }
        _ => args.command,
    };

    let params = match SandboxLaunchParams::resolve(&agent_config, command) {
        Ok(p) => p,
        Err(SandboxError::NoCommand) => {
            pr.error("no command specified — provide a command after `--`");
            pr.info("  example: latchgate sandbox -- claude");
            pr.info("  or:      latchgate sandbox --profile claude-code");
            return 1;
        }
        Err(SandboxError::InvalidConfig { problems }) => {
            pr.error("sandbox configuration invalid:");
            for problem in &problems {
                pr.error(&format!("  • {problem}"));
            }
            return 1;
        }
        Err(e) => {
            pr.error(&format!("{e}"));
            return 1;
        }
    };

    match latchgate_sandbox::launch(params).await {
        Ok(result) => {
            emit_usage_signal(args.profile.as_deref(), &agent_config);
            result.exit_code
        }
        Err(SandboxError::UnsupportedPlatform(msg)) => {
            pr.error("agent sandbox is not supported on this platform:");
            pr.error(&format!("  {msg}"));
            1
        }
        Err(SandboxError::UserNamespacesDisabled { reason }) => {
            pr.error("cannot create sandbox — bubblewrap not available:");
            pr.error(&format!("  {reason}"));
            pr.info("  fix: apt install bubblewrap (or dnf install bubblewrap)");
            pr.info("  alt: re-run with sudo for parent-assisted sandbox on hardened kernels");
            1
        }
        Err(SandboxError::NoCredentialResolved { vars, .. }) => {
            pr.error(&format!(
                "no credential resolved — set at least one of: {}",
                vars.join(", ")
            ));
            pr.info("  hint: the sandbox credential proxy requires a BYO API key.");
            pr.info("  Subscription/OAuth tokens are not supported in-sandbox.");
            1
        }
        Err(e) => {
            pr.error(&format!("sandbox failed: {e}"));
            1
        }
    }
}

fn resolve_base_config(
    gate_config: Option<&Config>,
    standalone_config: Option<&Path>,
) -> Result<AgentSandboxConfig, String> {
    if let Some(path) = standalone_config {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read sandbox config \"{}\": {e}", path.display()))?;
        let cfg: AgentSandboxConfig = toml::from_str(&contents)
            .map_err(|e| format!("cannot parse sandbox config \"{}\": {e}", path.display()))?;
        return Ok(cfg);
    }

    if let Some(config) = gate_config {
        if let Some(agent) = &config.sandbox.agent {
            return Ok(agent.clone());
        }
    }

    Ok(AgentSandboxConfig::default())
}

/// Emit a single structured usage event for profile adoption tracking.
///
/// Gated behind `LATCHGATE_USAGE_SIGNAL=1`. Emits one JSON line to stderr
/// containing only the profile name and whether a credential resolved.
///
/// # Privacy
///
/// No PII, no command args, no paths, no workspace contents, no secret
/// values. Only the profile name (from a fixed set) and a boolean.
///
/// # Credential semantics
///
/// On the success path, the fail-closed check guarantees that if the profile
/// declared credential routes, at least one resolved. An empty credentials
/// map means the launch had no credential injection configured (bare
/// `sandbox -- cmd` or profile with no routes).
fn emit_usage_signal(profile: Option<&str>, config: &AgentSandboxConfig) {
    if std::env::var_os("LATCHGATE_USAGE_SIGNAL").is_none() {
        return;
    }

    let profile = profile.unwrap_or("none");
    let credential_resolved = !config.credentials.is_empty();

    // Single-line JSON, machine-parseable, no allocations beyond the format.
    eprintln!(
        r#"{{"event":"sandbox.launch","profile":"{profile}","credential_resolved":{credential_resolved}}}"#,
    );
}
