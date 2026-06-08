//! Security posture checks (ledger, SOPS, egress, webhooks, etc.).

use std::path::Path;
use std::time::Duration;

use latchgate_config::{Config, SandboxMode};
use latchgate_registry::manifest::ActionSpec;

use super::Check;

pub(super) fn check_sops(config: &Config) -> Check {
    if config.secrets.sops_secrets_file.is_none() {
        // Scan manifests to determine whether any actions actually need secrets.
        // Without this context the bare "not configured" verdict contradicts
        // check_secrets_coverage when secrets ARE required.
        let (required, optional) = count_secret_actions(config);
        if required > 0 {
            return Check::warn(
                "sops",
                format!(
                    "not configured — required by {required} action(s). \
                     Run: latchgate secrets init"
                ),
            );
        }
        if optional > 0 {
            return Check::warn(
                "sops",
                format!("not configured — {optional} action(s) declare optional secrets"),
            );
        }
        return Check::ok("sops", "not configured (no actions need secrets)");
    }
    match which_sops(latchgate_core::security_constants::SOPS_BIN) {
        true => Check::ok(
            "sops",
            format!(
                "binary found ({})",
                latchgate_core::security_constants::SOPS_BIN
            ),
        ),
        false => Check::error(
            "sops",
            format!(
                "binary '{}' not found on PATH — required by sops_secrets_file",
                latchgate_core::security_constants::SOPS_BIN
            ),
        ),
    }
}

/// Count actions that declare required and optional secrets.
///
/// Returns `(required_count, optional_only_count)`.
fn count_secret_actions(config: &Config) -> (usize, usize) {
    let manifests_dir = Path::new(&config.manifests_dir);
    let entries = match std::fs::read_dir(manifests_dir) {
        Ok(e) => e,
        Err(_) => return (0, 0),
    };

    let mut required = 0usize;
    let mut optional = 0usize;

    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "yaml" && ext != "yml" {
            continue;
        }
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(spec) = ActionSpec::from_yaml(&contents) else {
            continue;
        };
        if spec.secrets.iter().any(|s| s.required) {
            required += 1;
        } else if !spec.secrets.is_empty() {
            optional += 1;
        }
    }

    (required, optional)
}

/// Verify that actions requiring secrets have SOPS configured.
///
/// Scans manifests for `secrets` with `required: true`. If any exist and
/// `sops_secrets_file` is not set, the gate will start but those actions
/// will fail at runtime when the provider can't find the credential.
pub(super) fn check_secrets_coverage(config: &Config) -> Check {
    if config.dev_mode() {
        return Check::skip("secrets_coverage", "skipped (dev) — secrets not enforced");
    }

    let manifests_dir = Path::new(&config.manifests_dir);
    if !manifests_dir.exists() {
        return Check::ok("secrets_coverage", "no manifests — skipped");
    }

    let entries = match std::fs::read_dir(manifests_dir) {
        Ok(e) => e,
        Err(_) => return Check::ok("secrets_coverage", "cannot read manifests — skipped"),
    };

    let mut required_count: usize = 0;
    let mut action_count: usize = 0;

    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "yaml" && ext != "yml" {
            continue;
        }

        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let spec = match ActionSpec::from_yaml(&contents) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let has_required = spec.secrets.iter().any(|s| s.required);
        if has_required {
            required_count += 1;
            action_count += 1;
        } else if !spec.secrets.is_empty() {
            // Has optional secrets — still counts as an action that benefits.
            action_count += 1;
        }
    }

    if action_count == 0 {
        return Check::ok("secrets_coverage", "no actions declare secrets");
    }

    match &config.secrets.sops_secrets_file {
        Some(_) => Check::ok(
            "secrets_coverage",
            format!("{action_count} action(s) use secrets — sops_secrets_file configured"),
        ),
        None => {
            if required_count > 0 {
                Check::error(
                    "secrets_coverage",
                    format!(
                        "{required_count} action(s) require secrets but sops_secrets_file not configured — \
                         run: latchgate secrets init"
                    ),
                )
            } else {
                Check::warn(
                    "secrets_coverage",
                    format!(
                        "{action_count} action(s) declare optional secrets but sops_secrets_file not configured"
                    ),
                )
            }
        }
    }
}

pub(super) fn check_webhooks(config: &Config) -> Vec<Check> {
    if config.webhooks.is_empty() {
        return vec![Check::ok("webhooks", "none configured (optional)")];
    }

    let mut configs: Vec<latchgate_webhooks::WebhookEndpointConfig> = Vec::new();
    let mut checks = Vec::new();

    for (i, raw) in config.webhooks.iter().enumerate() {
        match raw
            .clone()
            .try_into::<latchgate_webhooks::WebhookEndpointConfig>()
        {
            Ok(cfg) => configs.push(cfg),
            Err(e) => {
                checks.push(Check::error(
                    "webhooks",
                    format!("webhooks[{i}]: TOML parse error — {e}"),
                ));
            }
        }
    }

    if !checks.is_empty() {
        return checks;
    }

    match latchgate_webhooks::validate_webhook_configs(configs, config.dev_mode()) {
        Ok(validated) => {
            checks.push(Check::ok(
                "webhooks",
                format!(
                    "{} endpoint(s) valid{}",
                    validated.len(),
                    if validated.iter().any(|c| c.disable) {
                        " (some disabled)"
                    } else {
                        ""
                    },
                ),
            ));
        }
        Err(e) => {
            checks.push(Check::error("webhooks", format!("validation failed — {e}")));
        }
    }

    checks
}

#[cfg(target_os = "linux")]
pub(super) fn check_seccomp(mode: SandboxMode) -> Check {
    match std::fs::read_to_string("/proc/sys/kernel/seccomp/enabled") {
        Ok(v) if v.trim() == "2" || v.trim() == "1" => Check::ok("seccomp", "enabled"),
        Ok(v) => {
            let msg = format!(
                "/proc/sys/kernel/seccomp/enabled = {} (expected 1 or 2)",
                v.trim()
            );
            // Without degraded mode, seccomp is always required for sandbox.
            match mode {
                SandboxMode::Disabled => Check::warn("seccomp", msg),
                _ => Check::error("seccomp", msg),
            }
        }
        Err(_) => {
            let msg = "cannot read /proc/sys/kernel/seccomp/enabled";
            match mode {
                SandboxMode::Disabled => Check::warn("seccomp", msg),
                _ => Check::warn("seccomp", msg),
            }
        }
    }
}

/// Check ledger database: existence, schema version, integrity.
pub(super) fn check_ledger(config: &Config) -> Vec<Check> {
    let db_path = Path::new(&config.storage.ledger_db_path);

    if !db_path.exists() {
        return vec![Check::ok(
            "ledger",
            "database does not exist yet (will be created on first start)",
        )];
    }

    let conn = match rusqlite::Connection::open_with_flags(
        db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        Ok(c) => {
            if let Err(e) = c.busy_timeout(Duration::from_secs(2)) {
                return vec![Check::warn(
                    "ledger",
                    format!("opened but cannot set busy_timeout: {e}"),
                )];
            }
            c
        }
        Err(e) => {
            return vec![Check::error(
                "ledger",
                format!("cannot open {}: {e}", db_path.display()),
            )]
        }
    };

    let mut checks = Vec::new();

    match check_ledger_schema(&conn) {
        Ok(c) => checks.push(c),
        Err(c) => checks.push(c),
    }

    checks.push(check_ledger_integrity(&conn));

    checks
}

pub(super) fn check_ledger_schema(conn: &rusqlite::Connection) -> Result<Check, Check> {
    let required = latchgate_ledger::REQUIRED_TABLES;
    let mut missing = Vec::new();

    for table in required {
        let exists: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name=?1",
                [table],
                |row| row.get(0),
            )
            .map_err(|e| Check::error("ledger_schema", format!("query failed: {e}")))?;

        if !exists {
            missing.push(*table);
        }
    }

    if missing.is_empty() {
        Ok(Check::ok(
            "ledger_schema",
            format!("all {} tables present", required.len()),
        ))
    } else {
        Err(Check::error(
            "ledger_schema",
            format!(
                "missing tables: {} — the gate will create them on next start",
                missing.join(", ")
            ),
        ))
    }
}

pub(super) fn check_ledger_integrity(conn: &rusqlite::Connection) -> Check {
    match conn.pragma_query_value(None, "quick_check", |row| row.get::<_, String>(0)) {
        Ok(result) if result == "ok" => Check::ok("ledger_integrity", "quick_check passed"),
        Ok(result) => Check::error("ledger_integrity", format!("quick_check failed: {result}")),
        Err(e) => Check::error("ledger_integrity", format!("quick_check error: {e}")),
    }
}

pub(super) fn which_sops(bin: &str) -> bool {
    std::process::Command::new("which")
        .arg(bin)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check whether the agent sandbox can be used on this host.
///
/// Reports the sandbox tier based on effective uid and bwrap availability,
/// plus Landlock defense-in-depth status.
pub(super) fn check_agent_sandbox(config: &Config) -> Vec<Check> {
    if config.sandbox.agent.is_none() {
        return vec![Check::skip(
            "agent_sandbox",
            "[sandbox.agent] not configured — agent sandbox checks skipped",
        )];
    }

    let mut checks = Vec::new();

    // Validate config regardless of platform.
    let agent = config.sandbox.agent.as_ref().unwrap();
    let problems = agent.validate();
    if !problems.is_empty() {
        checks.push(Check::warn(
            "agent_sandbox_config",
            format!("config issues: {}", problems.join("; ")),
        ));
    }

    // Report sandbox tier.
    #[cfg(target_os = "linux")]
    {
        use latchgate_sandbox::platform::{detect_tier, SandboxTier};

        match detect_tier() {
            SandboxTier::RootAssisted => {
                checks.push(Check::ok(
                    "agent_sandbox",
                    "running as root — parent-assisted network namespace (robust, any kernel)",
                ));
            }
            SandboxTier::RootlessBwrap => {
                checks.push(Check::ok(
                    "agent_sandbox",
                    "bubblewrap available — rootless sandbox \
                     (permissive kernels only; use sudo for hardened kernels like Ubuntu 24.04)",
                ));
            }
            SandboxTier::Unavailable => {
                checks.push(Check::error(
                    "agent_sandbox",
                    "bubblewrap (bwrap) not found — required for sandbox.\n\
                     Fix: apt install bubblewrap (or dnf install bubblewrap)",
                ));
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        checks.push(Check::warn(
            "agent_sandbox",
            "not available on this platform — Linux required",
        ));
    }

    // Landlock defense-in-depth status.
    #[cfg(target_os = "linux")]
    {
        if latchgate_sandbox::platform::is_landlock_available() {
            checks.push(Check::ok("landlock", "available — defense-in-depth active"));
        } else {
            checks.push(Check::warn(
                "landlock",
                "not available (kernel < 5.13) — namespace + seccomp only",
            ));
        }
    }

    checks
}
