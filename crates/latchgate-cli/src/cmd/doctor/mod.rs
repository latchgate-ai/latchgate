//! `latchgate doctor` — pre-flight host capability check.
//!
//! Verifies all runtime dependencies before starting the gate:
//! config, policy files, ACL, manifests, provider modules, Redis, OPA,
//! SOPS secrets coverage, webhooks, and host features (seccomp).
//!
//! Output is grouped into logical sections for scannability:
//! Config, Policy, Registry, Dependencies, Security.
//!
//! Exit 0 = all required checks pass; non-zero = fix errors before deploying.

mod checks;
mod config_checks;
mod dependency_checks;
mod policy_checks;
mod registry_checks;
mod security_checks;

use latchgate_config::{Config, SandboxMode};
use serde_json::json;

use crate::output::{print_json, Printer};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Ok,
    Skip,
    Warn,
    Error,
}

impl Severity {
    fn label(&self) -> &'static str {
        match self {
            Severity::Ok => "ok",
            Severity::Skip => "skip",
            Severity::Warn => "warn",
            Severity::Error => "error",
        }
    }
}

#[derive(Debug)]
pub struct Check {
    pub name: &'static str,
    pub severity: Severity,
    pub message: String,
}

impl Check {
    pub(super) fn ok(name: &'static str, msg: impl Into<String>) -> Self {
        Self {
            name,
            severity: Severity::Ok,
            message: msg.into(),
        }
    }
    pub(super) fn skip(name: &'static str, msg: impl Into<String>) -> Self {
        Self {
            name,
            severity: Severity::Skip,
            message: msg.into(),
        }
    }
    pub(super) fn warn(name: &'static str, msg: impl Into<String>) -> Self {
        Self {
            name,
            severity: Severity::Warn,
            message: msg.into(),
        }
    }
    pub(super) fn error(name: &'static str, msg: impl Into<String>) -> Self {
        Self {
            name,
            severity: Severity::Error,
            message: msg.into(),
        }
    }
}

/// A named group of checks for structured output.
struct Section {
    name: &'static str,
    checks: Vec<Check>,
}

/// Run all pre-flight checks.
///
/// Exit codes:
///   0 — all checks pass (ok or skip)
///   1 — errors found
///   2 — warnings only (no errors) — for CI scripts that distinguish
pub async fn run(config: &Config, pr: &Printer) -> i32 {
    let sections = collect_sections(config).await;

    let total_checks: usize = sections.iter().map(|s| s.checks.len()).sum();
    let total_errors: usize = sections
        .iter()
        .flat_map(|s| &s.checks)
        .filter(|c| c.severity == Severity::Error)
        .count();
    let total_warns: usize = sections
        .iter()
        .flat_map(|s| &s.checks)
        .filter(|c| c.severity == Severity::Warn)
        .count();

    if pr.json {
        let items: Vec<_> = sections
            .iter()
            .flat_map(|s| {
                s.checks.iter().map(move |c| {
                    json!({
                        "section": s.name,
                        "check": c.name,
                        "severity": c.severity.label(),
                        "message": c.message,
                    })
                })
            })
            .collect();
        print_json(&json!({
            "checks":   items,
            "errors":   total_errors,
            "warnings": total_warns,
            "healthy":  total_errors == 0,
        }));
    } else {
        pr.banner(crate::VERSION);
        pr.blank();
        pr.section("Pre-flight check");

        let name_width = sections
            .iter()
            .flat_map(|s| &s.checks)
            .map(|c| c.name.len())
            .max()
            .unwrap_or(0);

        for section in &sections {
            pr.blank();
            pr.line(&format!("  {}", pr.bold(section.name)));

            for c in &section.checks {
                let sym = match c.severity {
                    Severity::Ok => pr.ok_sym(),
                    Severity::Skip => pr.info_sym(),
                    Severity::Warn => pr.warn_sym(),
                    Severity::Error => pr.err_sym(),
                };
                pr.timed(&sym, c.name, &c.message, name_width);
            }
        }

        pr.blank();
        let passed = total_checks - total_errors;
        if total_errors == 0 && total_warns == 0 {
            pr.success(&format!(
                "{passed}/{total_checks} passed. Gate is ready to start."
            ));
        } else if total_errors == 0 {
            pr.warn(&format!(
                "{passed}/{total_checks} passed, {total_warns} warning(s)"
            ));
        } else {
            pr.error(&format!(
                "{passed}/{total_checks} passed, {total_errors} error(s). Fix before starting the gate."
            ));
            if config.sandbox.mode == SandboxMode::Strict {
                pr.blank();
                pr.hint("Tip: sandbox mode is 'strict'. For dev hosts, set:");
                pr.hint("     [sandbox]");
                pr.hint("     mode = \"degraded_ok\"");
            }
        }
        pr.blank();
    }

    if total_errors > 0 {
        1
    } else if total_warns > 0 {
        2
    } else {
        0
    }
}

/// Run startup-critical checks only. Returns errors for compact display.
///
/// Unlike `run()`, this produces no output — the caller decides how to
/// present failures. Checks: config, manifests, providers, principal
/// reachability, redis, opa.
/// Skips: signing keys, secrets, webhooks, seccomp, ledger, egress proxy.
pub async fn run_preflight(config: &Config) -> Vec<Check> {
    use config_checks::*;
    use dependency_checks::*;
    use policy_checks::*;
    use registry_checks::*;

    let mut checks = vec![
        check_config_file(config),
        check_manifests_dir(config),
        check_providers_dir(config),
        check_provider_modules(config),
        check_principal_reachability(config),
        await_check_redis(config).await,
        await_check_opa(config).await,
    ];
    checks.extend(check_manifest_digests(config));

    checks
        .into_iter()
        .filter(|c| c.severity == Severity::Error)
        .collect()
}

/// Run all doctor checks and return them as a flat list with section labels.
///
/// Unlike [`run`] this produces no output — the caller (TUI config screen)
/// decides how to present results.
pub async fn collect_all_checks(config: &Config) -> Vec<(String, Check)> {
    let sections = collect_sections(config).await;
    sections
        .into_iter()
        .flat_map(|s| {
            let name = s.name.to_string();
            s.checks.into_iter().map(move |c| (name.clone(), c))
        })
        .collect()
}
/// Report the resolved gate log path so users can find it.
///
/// The gate writes its log to `{state_dir}/logs/gate.log` which is inside the
/// runtime directory, not `.latchgate/`. This check surfaces the path.
fn check_gate_log_path() -> Check {
    let state = crate::cmd::up::state_dir();
    let log_path = state.join("logs").join("gate.log");
    if log_path.exists() {
        Check::ok("gate_log", format!("{}", log_path.display()))
    } else {
        Check::skip(
            "gate_log",
            format!(
                "not found (created on `latchgate up`): {}",
                log_path.display()
            ),
        )
    }
}

// ---------------------------------------------------------------------------
// Section collection
// ---------------------------------------------------------------------------

async fn collect_sections(config: &Config) -> Vec<Section> {
    use config_checks::*;
    use dependency_checks::*;
    use policy_checks::*;
    use registry_checks::*;
    use security_checks::*;

    let mut sections = Vec::new();

    // -- Config ---------------------------------------------------------------
    sections.push(Section {
        name: "Config",
        checks: {
            let mut c = vec![check_config_file(config)];
            c.push(check_operator_credentials(config));
            c.push(check_signing_keys(config));
            c.push(check_gate_log_path());
            c
        },
    });

    // -- Policy ---------------------------------------------------------------
    sections.push(Section {
        name: "Policy",
        checks: vec![
            check_policy_files(),
            check_policy_acl(config),
            check_wildcard_acl(config),
            check_principal_reachability(config),
        ],
    });

    // -- Registry -------------------------------------------------------------
    sections.push(Section {
        name: "Registry",
        checks: {
            let mut c = vec![
                check_manifests_dir(config),
                check_manifests_dir_consistency(config),
                check_manifest_overrides(config),
                check_providers_dir(config),
                check_provider_modules(config),
            ];
            c.extend(check_manifest_digests(config));
            c
        },
    });

    // -- Dependencies ---------------------------------------------------------
    sections.push(Section {
        name: "Dependencies",
        checks: vec![
            await_check_redis(config).await,
            await_check_opa(config).await,
            await_check_egress_proxy(config).await,
        ],
    });

    // -- Security -------------------------------------------------------------
    {
        let mut sec = vec![check_sops(config)];
        sec.push(check_secrets_coverage(config));
        sec.extend(check_webhooks(config));
        #[cfg(target_os = "linux")]
        sec.push(check_seccomp(config.sandbox.mode));
        sec.extend(check_agent_sandbox(config));
        sec.extend(check_ledger(config));
        sections.push(Section {
            name: "Security",
            checks: sec,
        });
    }

    sections
}
