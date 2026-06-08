//! Policy and ACL checks.

use std::path::Path;

use latchgate_config::Config;

use super::Check;

/// Resolve the policy directory by searching known layouts.
///
/// Search order:
///   1. `.latchgate/policies/`   — project-local init output
///   2. `policies/`              — flat layout (init without .latchgate wrapper)
///   3. `policies/opa/`          — repo-root layout (source checkout)
fn resolve_policy_dir() -> Option<&'static Path> {
    let candidates: &[&'static Path] = &[
        Path::new(".latchgate/policies"),
        Path::new("policies"),
        Path::new("policies/opa"),
    ];

    candidates.iter().copied().find(|dir| dir.is_dir())
}

/// Verify that `latchgate.rego` exists in a known policy directory.
///
/// Without the Rego policy file, OPA has no rules to evaluate and every
/// request will be denied (or worse, OPA returns an undefined decision
/// that the gate interprets as deny). This is the #1 init=>up failure mode.
pub(super) fn check_policy_files() -> Check {
    if let Some(dir) = resolve_policy_dir() {
        let rego = dir.join("latchgate.rego");
        if rego.is_file() {
            return Check::ok("policy_files", format!("{} present", rego.display()));
        }
    }

    Check::error(
        "policy_files",
        "latchgate.rego not found — run 'latchgate init' or copy from source",
    )
}

/// Verify that `data.json` has at least one ACL entry.
///
/// An empty ACL means no principal can execute any action. In production
/// this is almost certainly a misconfiguration. In dev mode it's unusual
/// but not fatal (the wildcard ACL should be present).
pub(super) fn check_policy_acl(config: &Config) -> Check {
    let data_path = resolve_policy_dir().map(|d| d.join("data.json"));

    let data_path = match data_path {
        Some(p) if p.is_file() => p,
        _ => {
            return Check::error(
                "policy_acl",
                "data.json not found — run 'latchgate init' or 'latchgate policy grant'",
            );
        }
    };

    let content = match std::fs::read_to_string(&data_path) {
        Ok(c) => c,
        Err(e) => {
            return Check::error(
                "policy_acl",
                format!("cannot read {}: {e}", data_path.display()),
            );
        }
    };

    let parsed: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            return Check::error(
                "policy_acl",
                format!("{} is not valid JSON: {e}", data_path.display()),
            );
        }
    };

    let acl = match parsed.get("acl").and_then(|v| v.as_object()) {
        Some(obj) => obj,
        None => {
            return Check::error(
                "policy_acl",
                format!(
                    "{} missing 'acl' object — file may be corrupt",
                    data_path.display()
                ),
            );
        }
    };

    if acl.is_empty() {
        if config.dev_mode() {
            Check::warn(
                "policy_acl",
                "ACL is empty — no principals can execute actions. Run: latchgate policy grant '*' <actions>",
            )
        } else {
            Check::error(
                "policy_acl",
                "ACL is empty — no principals can execute actions. Run: latchgate policy grant <principal> <actions>",
            )
        }
    } else {
        Check::ok(
            "policy_acl",
            format!("{} principal(s) configured", acl.len()),
        )
    }
}

/// Warn or reject a wildcard `*` ACL entry in production.
///
/// The wildcard principal grants every unauthenticated or unmapped caller
/// the listed actions. This is appropriate during development but dangerous
/// in production: a misconfigured proxy, a leaked lease, or a missing
/// principal mapping would grant the full wildcard action set.
///
/// - `dev_mode`: warn if `*` has write/delete actions.
/// - Production: error if `*` has any `allowed_actions`.
pub(super) fn check_wildcard_acl(config: &Config) -> Check {
    let data_path = resolve_policy_dir().map(|d| d.join("data.json"));

    let data_path = match data_path {
        Some(p) if p.is_file() => p,
        _ => {
            // No data.json — check_policy_acl already reports this.
            return Check::skip("wildcard_acl", "data.json not found (see policy_acl)");
        }
    };

    let content = match std::fs::read_to_string(&data_path) {
        Ok(c) => c,
        Err(_) => return Check::skip("wildcard_acl", "cannot read data.json"),
    };

    let parsed: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Check::skip("wildcard_acl", "data.json parse error (see policy_acl)"),
    };

    let wildcard = parsed
        .get("acl")
        .and_then(|a| a.get("*"))
        .and_then(|w| w.as_object());

    let Some(wildcard) = wildcard else {
        return Check::ok("wildcard_acl", "no wildcard (*) principal in ACL");
    };

    let actions = wildcard
        .get("allowed_actions")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);

    let sinks = wildcard
        .get("allowed_sinks")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);

    if actions == 0 && sinks == 0 {
        return Check::ok(
            "wildcard_acl",
            "wildcard (*) principal has empty permissions",
        );
    }

    if config.dev_mode() {
        Check::warn(
            "wildcard_acl",
            format!(
                "wildcard (*) grants {actions} action(s) and {sinks} sink(s) — \
                 acceptable in dev_mode, but remove before production"
            ),
        )
    } else {
        Check::error(
            "wildcard_acl",
            format!(
                "wildcard (*) grants {actions} action(s) and {sinks} sink(s) in production — \
                 use named principals instead. \
                 Run: latchgate policy revoke '*' --all"
            ),
        )
    }
}

/// Verify that every configured peercred principal can reach at least one
/// action through the ACL.
///
/// This is the highest-leverage pre-flight check for the peercred/wildcard
/// mismatch: if a named principal exists in the identity config but has no
/// ACL entry (and no `inherits_wildcard`), every call from that principal
/// will be denied at the ACL stage — silently, with no remediation hint.
///
/// The check cross-references `config.identity.peercred.principals` against
/// the `acl` section of `data.json`.
pub(super) fn check_principal_reachability(config: &Config) -> Check {
    use latchgate_config::IdentityProviderKind;

    // Only relevant when peercred identity is active.
    if config.identity.provider != IdentityProviderKind::Peercred {
        return Check::skip(
            "principal_reachability",
            "identity provider is not peercred — check not applicable",
        );
    }

    if config.identity.peercred.principals.is_empty() {
        return Check::skip(
            "principal_reachability",
            "no peercred principals configured",
        );
    }

    let data_path = resolve_policy_dir().map(|d| d.join("data.json"));

    let data_path = match data_path {
        Some(p) if p.is_file() => p,
        _ => {
            return Check::skip(
                "principal_reachability",
                "data.json not found (see policy_acl)",
            );
        }
    };

    let content = match std::fs::read_to_string(&data_path) {
        Ok(c) => c,
        Err(_) => {
            return Check::skip("principal_reachability", "cannot read data.json");
        }
    };

    let parsed: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => {
            return Check::skip(
                "principal_reachability",
                "data.json parse error (see policy_acl)",
            );
        }
    };

    let acl = match parsed.get("acl").and_then(|v| v.as_object()) {
        Some(obj) => obj,
        None => {
            return Check::skip("principal_reachability", "no ACL in data.json");
        }
    };

    let wildcard_has_actions = acl
        .get("*")
        .and_then(|v| v.get("allowed_actions"))
        .and_then(|v| v.as_array())
        .is_some_and(|a| !a.is_empty());

    let mut unreachable = Vec::new();

    for entry in config.identity.peercred.principals.values() {
        let name = &entry.principal;

        // Check whether this principal has a usable ACL path.
        let has_own_entry = acl.get(name.as_str()).is_some();
        let has_own_actions = acl
            .get(name.as_str())
            .and_then(|v| v.get("allowed_actions"))
            .and_then(|v| v.as_array())
            .is_some_and(|a| !a.is_empty());
        let inherits_wildcard = acl
            .get(name.as_str())
            .and_then(|v| v.get("inherits_wildcard"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Reachable if:
        //   (a) principal has its own non-empty actions, OR
        //   (b) principal has inherits_wildcard and wildcard has actions, OR
        //   (c) principal has NO ACL entry (Rego falls back to wildcard).
        let reachable = has_own_actions
            || (inherits_wildcard && wildcard_has_actions)
            || (!has_own_entry && wildcard_has_actions);

        if !reachable {
            unreachable.push(name.clone());
        }
    }

    if unreachable.is_empty() {
        Check::ok(
            "principal_reachability",
            format!(
                "all {} peercred principal(s) can reach actions through the ACL",
                config.identity.peercred.principals.len()
            ),
        )
    } else {
        unreachable.sort();
        Check::error(
            "principal_reachability",
            format!(
                "principal(s) will be denied all actions (no ACL grant, no inherits_wildcard): {}. \
                 Fix: run `latchgate policy grant <principal> <actions>` or re-run `latchgate init --dev`",
                unreachable.join(", ")
            ),
        )
    }
}
