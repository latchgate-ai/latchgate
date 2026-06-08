//! `latchgate policy` — manage OPA ACL without editing JSON by hand.
//!
//! Operates on `policies/data.json` (init output) or `policies/opa/data.json`
//! (repo root). Validates action IDs against manifests and auto-derives
//! `allowed_sinks` from `declared_side_effects` — sinks are a security
//! invariant and must not be set manually.
//!
//! All writes are atomic (tmp => fsync => rename). `policy_version` is
//! auto-incremented on every mutation.

pub(crate) mod data_io;
pub(crate) mod manifest_index;

use data_io::{
    ensure_acl_object, increment_version, read_data_json, resolve_data_json, resolve_manifests_dir,
    write_data_json,
};
use manifest_index::{build_manifest_index, derive_sinks, suggest_action, ManifestIndex};

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use crate::cmd::output;
use crate::output::{print_json, Printer};
use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum PolicyCommand {
    /// Grant actions to a principal in the OPA ACL.
    ///
    /// Validates every action ID against manifests on disk. Computes
    /// `allowed_sinks` automatically from `declared_side_effects`.
    ///
    /// Examples:
    ///   latchgate policy grant agent-ops http_fetch,github_read,http_post
    ///   latchgate policy grant '*' http_fetch
    Grant {
        /// Principal name (e.g. `agent-ops`). Use `*` for wildcard.
        #[arg(value_name = "PRINCIPAL")]
        principal: String,
        /// Comma-separated action IDs to grant.
        #[arg(value_name = "ACTIONS")]
        actions: String,
    },

    /// Revoke actions from a principal.
    ///
    /// Removes specified actions and recomputes `allowed_sinks` from the
    /// remaining set. If no actions remain, the principal entry is removed
    /// entirely.
    Revoke {
        /// Principal name.
        #[arg(value_name = "PRINCIPAL")]
        principal: String,
        /// Comma-separated action IDs to revoke.
        #[arg(value_name = "ACTIONS")]
        actions: String,
    },

    /// Show ACL details for one or all principals.
    ///
    /// Displays granted actions, derived sinks, and risk breakdown
    /// (when manifests are available). Shows all principals if no name
    /// is given.
    Show {
        /// Principal name. Shows all if omitted.
        #[arg(value_name = "PRINCIPAL")]
        principal: Option<String>,
    },

    /// List principals with action counts (compact view).
    List,
}

pub fn run(manifests_dir_config: &str, sub: &PolicyCommand, pr: &Printer, json_mode: bool) -> i32 {
    match sub {
        PolicyCommand::Grant { principal, actions } => {
            run_grant(manifests_dir_config, principal, actions, pr, json_mode)
        }
        PolicyCommand::Revoke { principal, actions } => {
            run_revoke(manifests_dir_config, principal, actions, pr, json_mode)
        }
        PolicyCommand::Show { principal } => {
            run_show(manifests_dir_config, principal.as_deref(), pr, json_mode)
        }
        PolicyCommand::List => run_list(pr, json_mode),
    }
}

fn run_grant(
    manifests_dir_config: &str,
    principal: &str,
    actions_csv: &str,
    pr: &Printer,
    json_mode: bool,
) -> i32 {
    let action_ids = parse_action_ids(actions_csv);
    if action_ids.is_empty() {
        return output::emit_error(pr, "no action IDs provided");
    }

    let manifests_dir = match resolve_manifests_dir(manifests_dir_config) {
        Some(d) => d,
        None => {
            return output::emit_error(
                pr,
                "cannot find manifests directory — run latchgate init first",
            )
        }
    };

    let data_path = match resolve_data_json() {
        Some(p) => p,
        None => {
            return output::emit_error(
                pr,
                "cannot find policies/data.json — run latchgate init first",
            )
        }
    };

    let manifest_index = match build_manifest_index(&manifests_dir) {
        Ok(idx) => idx,
        Err(e) => return output::emit_error(pr, &e),
    };

    for aid in &action_ids {
        if !manifest_index.contains_key(aid.as_str()) {
            let suggestion = suggest_action(aid, &manifest_index);
            let msg = match suggestion {
                Some(s) => format!("unknown action '{aid}' — did you mean '{s}'?"),
                None => format!("unknown action '{aid}' — not found in manifests"),
            };
            return output::emit_error(pr, &msg);
        }
    }

    let mut doc = match read_data_json(&data_path) {
        Ok(d) => d,
        Err(e) => return output::emit_error(pr, &e),
    };

    let acl = match ensure_acl_object(&mut doc) {
        Ok(a) => a,
        Err(e) => return output::emit_error(pr, &e.to_string()),
    };

    let entry = acl
        .entry(principal.to_string())
        .or_insert_with(|| json!({ "allowed_actions": [], "allowed_sinks": [] }));

    let entry_obj = match entry.as_object_mut() {
        Some(o) => o,
        None => return output::emit_error(pr, "ACL entry is not an object"),
    };

    let mut current_actions: BTreeSet<String> = entry_obj
        .get("allowed_actions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    for aid in &action_ids {
        current_actions.insert(aid.clone());
    }

    let sinks = derive_sinks(&current_actions, &manifest_index);

    entry_obj.insert(
        "allowed_actions".into(),
        json!(current_actions.iter().collect::<Vec<_>>()),
    );
    entry_obj.insert(
        "allowed_sinks".into(),
        json!(sinks.iter().collect::<Vec<_>>()),
    );

    if let Err(e) = increment_version(&mut doc) {
        return output::emit_error(pr, &e.to_string());
    }

    if let Err(e) = write_data_json(&data_path, &doc) {
        return output::emit_error(pr, &e);
    }

    if json_mode {
        print_json(&json!({
            "ok": true,
            "principal": principal,
            "granted": action_ids,
            "total_actions": current_actions.len(),
            "allowed_sinks": sinks.iter().collect::<Vec<_>>(),
        }));
        return 0;
    }

    pr.blank();
    pr.success(&format!(
        "{}: {} action(s) granted",
        principal,
        action_ids.len()
    ));
    pr.blank();
    pr.field(
        "  Actions",
        &current_actions
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", "),
    );
    pr.field(
        "  Sinks  ",
        &format!(
            "{} (auto-derived)",
            sinks.iter().cloned().collect::<Vec<_>>().join(", ")
        ),
    );
    pr.blank();

    0
}

fn run_revoke(
    manifests_dir_config: &str,
    principal: &str,
    actions_csv: &str,
    pr: &Printer,
    json_mode: bool,
) -> i32 {
    let action_ids = parse_action_ids(actions_csv);
    if action_ids.is_empty() {
        return output::emit_error(pr, "no action IDs provided");
    }

    let manifests_dir = match resolve_manifests_dir(manifests_dir_config) {
        Some(d) => d,
        None => {
            return output::emit_error(
                pr,
                "cannot find manifests directory — run latchgate init first",
            )
        }
    };

    let data_path = match resolve_data_json() {
        Some(p) => p,
        None => {
            return output::emit_error(
                pr,
                "cannot find policies/data.json — run latchgate init first",
            )
        }
    };

    let manifest_index = match build_manifest_index(&manifests_dir) {
        Ok(idx) => idx,
        Err(e) => return output::emit_error(pr, &e),
    };

    let mut doc = match read_data_json(&data_path) {
        Ok(d) => d,
        Err(e) => return output::emit_error(pr, &e),
    };

    let acl = match ensure_acl_object(&mut doc) {
        Ok(a) => a,
        Err(e) => return output::emit_error(pr, &e.to_string()),
    };

    let entry = match acl.get_mut(principal) {
        Some(e) => e,
        None => {
            return output::emit_error(pr, &format!("principal '{principal}' not found in ACL"))
        }
    };

    let entry_obj = match entry.as_object_mut() {
        Some(o) => o,
        None => return output::emit_error(pr, "ACL entry is not an object"),
    };

    let mut current_actions: BTreeSet<String> = entry_obj
        .get("allowed_actions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    for aid in &action_ids {
        current_actions.remove(aid);
    }

    if current_actions.is_empty() {
        acl.remove(principal);
    } else {
        let sinks = derive_sinks(&current_actions, &manifest_index);
        entry_obj.insert(
            "allowed_actions".into(),
            json!(current_actions.iter().collect::<Vec<_>>()),
        );
        entry_obj.insert(
            "allowed_sinks".into(),
            json!(sinks.iter().collect::<Vec<_>>()),
        );
    }

    if let Err(e) = increment_version(&mut doc) {
        return output::emit_error(pr, &e.to_string());
    }

    if let Err(e) = write_data_json(&data_path, &doc) {
        return output::emit_error(pr, &e);
    }

    if json_mode {
        print_json(&json!({
            "ok": true,
            "principal": principal,
            "revoked": action_ids,
            "remaining": current_actions.len(),
        }));
        return 0;
    }

    pr.blank();
    if current_actions.is_empty() {
        pr.success(&format!(
            "{principal}: all actions revoked — principal removed from ACL"
        ));
    } else {
        pr.success(&format!(
            "{}: {} action(s) revoked, {} remaining",
            principal,
            action_ids.len(),
            current_actions.len(),
        ));
        pr.blank();
        pr.field(
            "  Actions",
            &current_actions
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    pr.blank();

    0
}

fn run_show(
    manifests_dir_config: &str,
    principal: Option<&str>,
    pr: &Printer,
    json_mode: bool,
) -> i32 {
    let data_path = match resolve_data_json() {
        Some(p) => p,
        None => {
            return output::emit_error(
                pr,
                "cannot find policies/data.json — run latchgate init first",
            )
        }
    };

    let doc = match read_data_json(&data_path) {
        Ok(d) => d,
        Err(e) => return output::emit_error(pr, &e),
    };

    let acl = match doc.get("acl").and_then(|v| v.as_object()) {
        Some(a) => a,
        None => {
            if json_mode {
                print_json(&json!({ "ok": true, "principals": {} }));
            } else {
                pr.blank();
                pr.info("No ACL entries configured.");
                pr.blank();
            }
            return 0;
        }
    };

    let manifests_dir = resolve_manifests_dir(manifests_dir_config);
    let manifest_index = manifests_dir
        .as_ref()
        .and_then(|d| build_manifest_index(d).ok());

    if let Some(name) = principal {
        let entry = match acl.get(name) {
            Some(e) => e,
            None => return output::emit_error(pr, &format!("principal '{name}' not found in ACL")),
        };

        if json_mode {
            print_json(&json!({ "ok": true, "principal": name, "acl": entry }));
            return 0;
        }

        show_principal_detail(name, entry, manifest_index.as_ref(), pr);
    } else {
        if json_mode {
            print_json(&json!({ "ok": true, "acl": acl }));
            return 0;
        }

        if acl.is_empty() {
            pr.blank();
            pr.info("No ACL entries configured.");
            pr.blank();
            return 0;
        }

        pr.blank();
        for (name, entry) in acl {
            show_principal_detail(name, entry, manifest_index.as_ref(), pr);
        }
    }

    0
}

fn show_principal_detail(
    name: &str,
    entry: &Value,
    manifest_index: Option<&ManifestIndex>,
    pr: &Printer,
) {
    let actions: Vec<&str> = entry
        .get("allowed_actions")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    let sinks: Vec<&str> = entry
        .get("allowed_sinks")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    pr.section(name);
    pr.field(
        &format!("  Actions ({})", actions.len()),
        &actions.join(", "),
    );
    pr.field(&format!("  Sinks ({})", sinks.len()), &sinks.join(", "));

    if let Some(idx) = manifest_index {
        let mut risk_counts: BTreeMap<&str, usize> = BTreeMap::new();
        for aid in &actions {
            if let Some(info) = idx.get(*aid) {
                *risk_counts.entry(info.risk_label).or_default() += 1;
            }
        }
        if !risk_counts.is_empty() {
            let breakdown: Vec<String> = risk_counts
                .iter()
                .map(|(level, count)| format!("{level}:{count}"))
                .collect();
            pr.field("  Risk levels", &breakdown.join("  "));
        }
    }

    pr.blank();
}

fn run_list(pr: &Printer, json_mode: bool) -> i32 {
    let data_path = match resolve_data_json() {
        Some(p) => p,
        None => {
            return output::emit_error(
                pr,
                "cannot find policies/data.json — run latchgate init first",
            )
        }
    };

    let doc = match read_data_json(&data_path) {
        Ok(d) => d,
        Err(e) => return output::emit_error(pr, &e),
    };

    let acl = match doc.get("acl").and_then(|v| v.as_object()) {
        Some(a) => a,
        None => {
            if json_mode {
                print_json(&json!({ "ok": true, "principals": [] }));
            } else {
                pr.blank();
                pr.info("No ACL entries configured.");
                pr.blank();
            }
            return 0;
        }
    };

    if json_mode {
        let entries: Vec<Value> = acl
            .iter()
            .map(|(name, entry)| {
                let count = entry
                    .get("allowed_actions")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                json!({ "principal": name, "actions": count })
            })
            .collect();
        print_json(&json!({ "ok": true, "principals": entries }));
        return 0;
    }

    if acl.is_empty() {
        pr.blank();
        pr.info("No ACL entries configured.");
        pr.blank();
        return 0;
    }

    pr.blank();
    pr.line(&format!(
        "  {:<24} {}",
        pr.bold("Principal"),
        pr.bold("Actions")
    ));
    pr.rule();
    for (name, entry) in acl {
        let count = entry
            .get("allowed_actions")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        pr.kv(name, &count.to_string(), 24);
    }
    pr.blank();

    0
}

fn parse_action_ids(csv: &str) -> Vec<String> {
    csv.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::manifest_index::edit_distance;
    use super::*;
    use std::path::PathBuf;

    struct TestEnv {
        _dir: tempfile::TempDir,
        manifests_dir: PathBuf,
        data_json_path: PathBuf,
    }

    fn setup() -> TestEnv {
        let dir = tempfile::tempdir().unwrap();
        let manifests_dir = dir.path().join("manifests");
        let policies_dir = dir.path().join("policies");
        std::fs::create_dir_all(&policies_dir).unwrap();

        crate::embedded_manifests::extract_manifests(
            crate::embedded_manifests::ManifestFilter::All,
            &manifests_dir,
        )
        .unwrap();

        let data = json!({
            "policy_version": "test-0",
            "acl": {}
        });
        let data_path = policies_dir.join("data.json");
        std::fs::write(&data_path, serde_json::to_string_pretty(&data).unwrap()).unwrap();

        TestEnv {
            _dir: dir,
            manifests_dir,
            data_json_path: data_path,
        }
    }

    fn read_acl(env: &TestEnv) -> Value {
        let content = std::fs::read_to_string(&env.data_json_path).unwrap();
        serde_json::from_str(&content).unwrap()
    }

    #[test]
    fn grant_adds_actions_and_computes_sinks() {
        let env = setup();
        let idx = build_manifest_index(&env.manifests_dir).unwrap();

        let mut doc = read_data_json(&env.data_json_path).unwrap();
        let acl = ensure_acl_object(&mut doc).unwrap();

        let entry = acl
            .entry("agent-ops".to_string())
            .or_insert_with(|| json!({ "allowed_actions": [], "allowed_sinks": [] }));
        let entry_obj = entry.as_object_mut().unwrap();

        let mut actions: BTreeSet<String> = BTreeSet::new();
        actions.insert("http_fetch".into());

        let sinks = derive_sinks(&actions, &idx);

        entry_obj.insert(
            "allowed_actions".into(),
            json!(actions.iter().collect::<Vec<_>>()),
        );
        entry_obj.insert(
            "allowed_sinks".into(),
            json!(sinks.iter().collect::<Vec<_>>()),
        );

        increment_version(&mut doc).unwrap();
        write_data_json(&env.data_json_path, &doc).unwrap();

        let result = read_acl(&env);
        let agent_ops = &result["acl"]["agent-ops"];
        let granted: Vec<&str> = agent_ops["allowed_actions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(granted.contains(&"http_fetch"));

        let result_sinks: Vec<&str> = agent_ops["allowed_sinks"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(
            result_sinks.contains(&"http_read"),
            "http_fetch must produce http_read sink, got: {result_sinks:?}"
        );
    }

    #[test]
    fn grant_is_idempotent() {
        let env = setup();
        let idx = build_manifest_index(&env.manifests_dir).unwrap();

        for _ in 0..2 {
            let mut doc = read_data_json(&env.data_json_path).unwrap();
            let acl = ensure_acl_object(&mut doc).unwrap();
            let entry = acl
                .entry("test".to_string())
                .or_insert_with(|| json!({ "allowed_actions": [], "allowed_sinks": [] }));
            let entry_obj = entry.as_object_mut().unwrap();

            let mut current: BTreeSet<String> = entry_obj
                .get("allowed_actions")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            current.insert("http_fetch".into());

            let sinks = derive_sinks(&current, &idx);
            entry_obj.insert(
                "allowed_actions".into(),
                json!(current.iter().collect::<Vec<_>>()),
            );
            entry_obj.insert(
                "allowed_sinks".into(),
                json!(sinks.iter().collect::<Vec<_>>()),
            );

            increment_version(&mut doc).unwrap();
            write_data_json(&env.data_json_path, &doc).unwrap();
        }

        let result = read_acl(&env);
        let actions_arr = result["acl"]["test"]["allowed_actions"].as_array().unwrap();
        assert_eq!(actions_arr.len(), 1, "duplicate grant must not add twice");
    }

    #[test]
    fn grant_unknown_action_is_detected() {
        let env = setup();
        let idx = build_manifest_index(&env.manifests_dir).unwrap();
        assert!(
            !idx.contains_key("__nonexistent_action__"),
            "test prerequisite"
        );
    }

    #[test]
    fn revoke_removes_actions_and_recomputes_sinks() {
        let env = setup();
        let idx = build_manifest_index(&env.manifests_dir).unwrap();

        let mut doc = read_data_json(&env.data_json_path).unwrap();
        let acl = ensure_acl_object(&mut doc).unwrap();
        let mut actions = BTreeSet::new();
        actions.insert("http_fetch".into());
        actions.insert("http_post".into());
        let sinks = derive_sinks(&actions, &idx);
        acl.insert(
            "agent".into(),
            json!({
                "allowed_actions": actions.iter().collect::<Vec<_>>(),
                "allowed_sinks": sinks.iter().collect::<Vec<_>>(),
            }),
        );
        write_data_json(&env.data_json_path, &doc).unwrap();

        let mut doc = read_data_json(&env.data_json_path).unwrap();
        let acl = ensure_acl_object(&mut doc).unwrap();
        let entry = acl.get_mut("agent").unwrap().as_object_mut().unwrap();
        let mut current: BTreeSet<String> = entry["allowed_actions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        current.remove("http_post");
        let new_sinks = derive_sinks(&current, &idx);
        entry.insert(
            "allowed_actions".into(),
            json!(current.iter().collect::<Vec<_>>()),
        );
        entry.insert(
            "allowed_sinks".into(),
            json!(new_sinks.iter().collect::<Vec<_>>()),
        );
        write_data_json(&env.data_json_path, &doc).unwrap();

        let result = read_acl(&env);
        let remaining: Vec<&str> = result["acl"]["agent"]["allowed_actions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(remaining, vec!["http_fetch"]);
        assert!(!remaining.contains(&"http_post"));
    }

    #[test]
    fn revoke_all_removes_principal_entry() {
        let env = setup();
        let idx = build_manifest_index(&env.manifests_dir).unwrap();

        let mut doc = read_data_json(&env.data_json_path).unwrap();
        let acl = ensure_acl_object(&mut doc).unwrap();
        let actions: BTreeSet<String> = ["http_fetch".into()].into();
        let sinks = derive_sinks(&actions, &idx);
        acl.insert(
            "temp".into(),
            json!({
                "allowed_actions": actions.iter().collect::<Vec<_>>(),
                "allowed_sinks": sinks.iter().collect::<Vec<_>>(),
            }),
        );
        write_data_json(&env.data_json_path, &doc).unwrap();

        let mut doc = read_data_json(&env.data_json_path).unwrap();
        let acl = ensure_acl_object(&mut doc).unwrap();
        let entry = acl.get_mut("temp").unwrap().as_object_mut().unwrap();
        let mut current: BTreeSet<String> = entry["allowed_actions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        current.remove("http_fetch");
        assert!(current.is_empty());
        acl.remove("temp");
        write_data_json(&env.data_json_path, &doc).unwrap();

        let result = read_acl(&env);
        assert!(
            result["acl"].get("temp").is_none(),
            "principal with no actions must be removed"
        );
    }

    #[test]
    fn wildcard_principal_works() {
        let env = setup();
        let idx = build_manifest_index(&env.manifests_dir).unwrap();

        let mut doc = read_data_json(&env.data_json_path).unwrap();
        let acl = ensure_acl_object(&mut doc).unwrap();
        let actions: BTreeSet<String> = ["http_fetch".into()].into();
        let sinks = derive_sinks(&actions, &idx);
        acl.insert(
            "*".into(),
            json!({
                "allowed_actions": actions.iter().collect::<Vec<_>>(),
                "allowed_sinks": sinks.iter().collect::<Vec<_>>(),
            }),
        );
        write_data_json(&env.data_json_path, &doc).unwrap();

        let result = read_acl(&env);
        assert!(result["acl"]["*"].is_object());
    }

    #[test]
    fn sink_derivation_known_actions() {
        let env = setup();
        let idx = build_manifest_index(&env.manifests_dir).unwrap();

        let sinks = derive_sinks(&["http_fetch".into()].into(), &idx);
        assert!(
            sinks.contains("http_read"),
            "http_fetch => http_read: {sinks:?}"
        );

        let sinks = derive_sinks(&["http_post".into()].into(), &idx);
        assert!(
            sinks.contains("http_write"),
            "http_post => http_write: {sinks:?}"
        );

        let sinks = derive_sinks(&["http_delete".into()].into(), &idx);
        assert!(
            sinks.contains("http_write"),
            "http_delete => http_write: {sinks:?}"
        );
    }

    #[test]
    fn sink_derivation_is_union() {
        let env = setup();
        let idx = build_manifest_index(&env.manifests_dir).unwrap();

        let sinks = derive_sinks(&["http_fetch".into(), "http_post".into()].into(), &idx);
        assert!(sinks.contains("http_read"));
        assert!(sinks.contains("http_write"));
    }

    #[test]
    fn version_increment() {
        let mut doc = json!({ "policy_version": "test-0", "acl": {} });
        increment_version(&mut doc).unwrap();
        assert_eq!(doc["policy_version"].as_str().unwrap(), "test-1");

        increment_version(&mut doc).unwrap();
        assert_eq!(doc["policy_version"].as_str().unwrap(), "test-2");
    }

    #[test]
    fn version_increment_no_trailing_number() {
        let mut doc = json!({ "policy_version": "dev-init", "acl": {} });
        increment_version(&mut doc).unwrap();
        assert_eq!(doc["policy_version"].as_str().unwrap(), "dev-init-1");
    }

    #[test]
    fn version_increment_empty() {
        let mut doc = json!({ "acl": {} });
        increment_version(&mut doc).unwrap();
        assert_eq!(doc["policy_version"].as_str().unwrap(), "v1");
    }

    #[test]
    fn extra_keys_preserved_on_write() {
        let env = setup();

        let mut doc = read_data_json(&env.data_json_path).unwrap();
        doc.as_object_mut().unwrap().insert(
            "database_sensitive_tables".into(),
            json!({"users": ["ssn", "email"]}),
        );
        write_data_json(&env.data_json_path, &doc).unwrap();

        let mut doc = read_data_json(&env.data_json_path).unwrap();
        let acl = ensure_acl_object(&mut doc).unwrap();
        acl.insert(
            "test".into(),
            json!({"allowed_actions": [], "allowed_sinks": []}),
        );
        increment_version(&mut doc).unwrap();
        write_data_json(&env.data_json_path, &doc).unwrap();

        let result = read_acl(&env);
        assert!(
            result.get("database_sensitive_tables").is_some(),
            "extra keys must survive ACL mutations"
        );
    }

    #[test]
    fn edit_distance_basic() {
        assert_eq!(edit_distance("http_fetch", "http_fetch"), 0);
        assert_eq!(edit_distance("http_fech", "http_fetch"), 1);
        assert_eq!(edit_distance("", "abc"), 3);
    }
}
