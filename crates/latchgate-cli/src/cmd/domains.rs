//! `latchgate domains` — manage learned egress domains.
//!
//! Reads/writes the SQLite ledger directly. Does not require the gate
//! to be running — learned domains are persisted in the same database
//! as audit events and receipts.
//!

use std::path::Path;
use std::sync::Arc;

use serde_json::json;

use latchgate_config::Config;
use latchgate_core::EgressProfile;
use latchgate_ledger::{EntrySource, LedgerStore};
use latchgate_registry::manifest::ActionSpec;

use crate::output::{print_json, Printer};

use super::{output, text};
use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum DomainsCommand {
    /// List learned domains.
    ///
    /// Shows all operator-approved domains with audit metadata (who added it,
    /// when, and how). Use --action to filter by a specific action.
    /// Manifest domains are shown with source "manifest" and cannot be removed.
    List {
        /// Filter by action ID.
        #[arg(long, value_name = "ACTION_ID")]
        action: Option<String>,
    },

    /// Add a learned domain for an action.
    ///
    /// The domain becomes part of the effective allowlist immediately. Future
    /// requests from this action to the domain will be allowed without
    /// re-approval.
    ///
    /// Per-action isolation: a domain added for `slack_post` is not available
    /// to `web_read`.
    Add {
        /// Action ID to associate the domain with.
        #[arg(value_name = "ACTION_ID")]
        action: String,

        /// Domain to allow (e.g. "hooks.slack.com").
        #[arg(value_name = "DOMAIN")]
        domain: String,

        /// Accept broad wildcard suffixes (fewer than 3 labels).
        ///
        /// Required for wildcards like `*.example.com` where the suffix has
        /// only 2 labels. Wildcards with 3+ label suffixes (e.g.
        /// `*.s3.amazonaws.com`) do not need this flag.
        #[arg(long)]
        force: bool,
    },

    /// Remove a learned domain for an action.
    ///
    /// Only learned domains can be removed. Manifest domains require a
    /// manifest change and restart.
    Remove {
        /// Action ID the domain belongs to.
        #[arg(value_name = "ACTION_ID")]
        action: String,

        /// Domain to remove.
        #[arg(value_name = "DOMAIN")]
        domain: String,
    },

    /// Remove all learned domains for an action.
    ///
    /// Manifest domains are unaffected. Prompts for confirmation unless
    /// --yes is given.
    Clear {
        /// Action ID to clear domains for.
        #[arg(value_name = "ACTION_ID")]
        action: String,

        /// Skip the confirmation prompt.
        #[arg(long, short)]
        yes: bool,
    },

    /// Dry-run: check whether a domain is in the effective allowlist.
    ///
    /// Evaluates a domain against the combined manifest + learned allowlist
    /// for an action. Uses the same matching logic as the runtime gate
    /// (exact match or subdomain boundary match).
    Check {
        /// Action ID to check against.
        #[arg(value_name = "ACTION_ID")]
        action: String,

        /// Domain to check (e.g. "api.github.com").
        #[arg(value_name = "DOMAIN")]
        domain: String,
    },
}

/// Run a domains subcommand. Returns exit code.
pub fn run(config: &Config, command: &DomainsCommand, pr: &Printer) -> i32 {
    match command {
        DomainsCommand::List { action } => run_list(config, action.as_deref(), pr),
        DomainsCommand::Add {
            action,
            domain,
            force,
        } => run_add(config, action, domain, *force, pr),
        DomainsCommand::Remove { action, domain } => run_remove(config, action, domain, pr),
        DomainsCommand::Clear { action, yes } => run_clear(config, action, *yes, pr),
        DomainsCommand::Check { action, domain } => run_check(config, action, domain, pr),
    }
}

fn open_ledger(db_path: &Path, pr: &Printer) -> Option<LedgerStore> {
    if !db_path.exists() {
        output::emit_error_coded(
            pr,
            "ledger_not_found",
            &format!("ledger file not found: {}", db_path.display()),
        );
        return None;
    }

    match LedgerStore::open(db_path, None) {
        Ok(l) => Some(l),
        Err(e) => {
            output::emit_error_coded(pr, "ledger_open_failed", &e.to_string());
            None
        }
    }
}
/// Resolve the operator identity for the `added_by` audit field.
///
/// Uses: LATCHGATE_OPERATOR_NAME env => USER env => "cli".
fn operator_name() -> String {
    std::env::var("LATCHGATE_OPERATOR_NAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "cli".into())
}

fn run_list(config: &Config, action: Option<&str>, pr: &Printer) -> i32 {
    let db_path = Path::new(&config.storage.ledger_db_path);
    let ledger = match open_ledger(db_path, pr) {
        Some(l) => l,
        None => return 1,
    };

    let domains = match ledger.list_learned_domains(action) {
        Ok(d) => d,
        Err(e) => {
            output::emit_error_coded(pr, "query_failed", &e.to_string());
            return 1;
        }
    };

    if pr.json {
        let entries: Vec<serde_json::Value> = domains
            .iter()
            .map(|d| {
                json!({
                    "action_id": d.action_id,
                    "domain": d.domain,
                    "source": d.source,
                    "added_by": d.added_by,
                    "added_at": d.added_at,
                    "approval_id": d.approval_id,
                })
            })
            .collect();
        print_json(&json!({ "ok": true, "domains": entries }));
        return 0;
    }

    pr.blank();

    if domains.is_empty() {
        let msg = match action {
            Some(a) => format!("No learned domains for action '{a}'."),
            None => "No learned domains.".to_string(),
        };
        pr.info(&msg);
        pr.blank();
        return 0;
    }

    // Column widths.
    let act_w = domains
        .iter()
        .map(|d| d.action_id.len())
        .max()
        .unwrap_or(6)
        .max(6);
    let dom_w = domains
        .iter()
        .map(|d| d.domain.len())
        .max()
        .unwrap_or(6)
        .max(6);

    // Header.
    println!(
        "  {action:<act_w$}  {domain:<dom_w$}  {source:<9}  {added_by:<12}  {when}",
        action = pr.dim("Action"),
        domain = pr.dim("Domain"),
        source = pr.dim("Source"),
        added_by = pr.dim("Added by"),
        when = pr.dim("When"),
    );
    println!(
        "  {}  {}  {}  {}  {}",
        pr.dim(&"─".repeat(act_w)),
        pr.dim(&"─".repeat(dom_w)),
        pr.dim(&"─".repeat(9)),
        pr.dim(&"─".repeat(12)),
        pr.dim(&"─".repeat(19)),
    );

    for d in &domains {
        let when = format_relative_time(&d.added_at);
        println!(
            "  {action:<act_w$}  {domain:<dom_w$}  {source:<9}  {added_by:<12}  {when}",
            action = d.action_id,
            domain = d.domain,
            source = d.source,
            added_by = text::truncate(&d.added_by, 12),
            when = pr.dim(&when),
        );
    }

    println!("\n  {} learned domain(s)", domains.len());
    pr.blank();
    0
}

fn run_add(config: &Config, action: &str, domain: &str, force: bool, pr: &Printer) -> i32 {
    // Pre-validate for clear CLI error messages. The ledger also validates
    // (defense in depth), but the error would be wrapped in a generic
    // LedgerError::Io — this gives the operator a direct, actionable message.
    let normalized = match latchgate_core::net::validate_domain_entry(domain, force) {
        Ok(n) => n,
        Err(e) => {
            if pr.json {
                print_json(&json!({
                    "ok": false,
                    "error": "invalid_domain",
                    "domain": domain,
                    "message": e.to_string(),
                }));
            } else {
                pr.blank();
                pr.error(&format!("Invalid domain: {e}"));
                pr.blank();
            }
            return 1;
        }
    };

    let db_path = Path::new(&config.storage.ledger_db_path);
    let ledger = match open_ledger(db_path, pr) {
        Some(l) => l,
        None => return 1,
    };

    let added_by = operator_name();

    match ledger.add_learned_domain(
        action,
        &normalized,
        &added_by,
        EntrySource::Cli,
        None,
        force,
    ) {
        Ok(true) => {
            if pr.json {
                print_json(&json!({
                    "ok": true,
                    "action": "added",
                    "action_id": action,
                    "domain": normalized,
                    "added_by": added_by,
                }));
            } else {
                pr.blank();
                pr.success(&format!(
                    "Learned domain '{normalized}' added for action '{action}'."
                ));
                if normalized != domain {
                    pr.info(&format!("  (normalized from '{domain}')"));
                }
                pr.blank();
            }
            sync_live_allowlist(config, &ledger, pr);
            0
        }
        Ok(false) => {
            if pr.json {
                print_json(&json!({
                    "ok": true,
                    "action": "already_exists",
                    "action_id": action,
                    "domain": normalized,
                }));
            } else {
                pr.blank();
                pr.info(&format!(
                    "Domain '{normalized}' is already learned for action '{action}'."
                ));
                pr.blank();
            }
            0
        }
        Err(e) => {
            output::emit_error_coded(pr, "add_failed", &e.to_string());
            1
        }
    }
}

fn run_remove(config: &Config, action: &str, domain: &str, pr: &Printer) -> i32 {
    let db_path = Path::new(&config.storage.ledger_db_path);
    let ledger = match open_ledger(db_path, pr) {
        Some(l) => l,
        None => return 1,
    };

    match ledger.remove_learned_domain(action, domain) {
        Ok(true) => {
            if pr.json {
                print_json(&json!({
                    "ok": true,
                    "action": "removed",
                    "action_id": action,
                    "domain": domain,
                }));
            } else {
                pr.blank();
                pr.success(&format!(
                    "Learned domain '{domain}' removed for action '{action}'."
                ));
                pr.blank();
            }
            sync_live_allowlist(config, &ledger, pr);
            0
        }
        Ok(false) => {
            if pr.json {
                print_json(&json!({
                    "ok": true,
                    "action": "not_found",
                    "action_id": action,
                    "domain": domain,
                }));
            } else {
                pr.blank();
                pr.warn(&format!(
                    "Domain '{domain}' is not a learned domain for action '{action}'."
                ));
                pr.info("Manifest domains cannot be removed via CLI — edit the manifest YAML.");
                pr.blank();
            }
            0
        }
        Err(e) => {
            output::emit_error_coded(pr, "remove_failed", &e.to_string());
            1
        }
    }
}

fn run_clear(config: &Config, action: &str, yes: bool, pr: &Printer) -> i32 {
    let db_path = Path::new(&config.storage.ledger_db_path);
    let ledger = match open_ledger(db_path, pr) {
        Some(l) => l,
        None => return 1,
    };

    // Show what will be cleared.
    let domains = match ledger.list_learned_domains(Some(action)) {
        Ok(d) => d,
        Err(e) => {
            output::emit_error_coded(pr, "query_failed", &e.to_string());
            return 1;
        }
    };

    if domains.is_empty() {
        if pr.json {
            print_json(&json!({
                "ok": true,
                "action": "nothing_to_clear",
                "action_id": action,
            }));
        } else {
            pr.blank();
            pr.info(&format!("No learned domains for action '{action}'."));
            pr.blank();
        }
        return 0;
    }

    // Confirmation gate.
    if !yes && !pr.json {
        pr.blank();
        eprintln!(
            "  {}  About to remove {} learned domain(s) for action '{action}':",
            pr.warn_sym(),
            domains.len(),
        );
        for d in &domains {
            eprintln!("       · {}", d.domain);
        }
        pr.blank();
        eprint!(
            "  Type {} to confirm, anything else to cancel: ",
            pr.bold("yes")
        );

        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() || line.trim() != "yes" {
            pr.blank();
            pr.info("Clear cancelled.");
            pr.blank();
            return 0;
        }
    }

    match ledger.clear_learned_domains_for_action(action) {
        Ok(count) => {
            if pr.json {
                print_json(&json!({
                    "ok": true,
                    "action": "cleared",
                    "action_id": action,
                    "domains_removed": count,
                }));
            } else {
                pr.blank();
                pr.success(&format!(
                    "Removed {count} learned domain(s) for action '{action}'."
                ));
                pr.blank();
            }
            sync_live_allowlist(config, &ledger, pr);
            0
        }
        Err(e) => {
            output::emit_error_coded(pr, "clear_failed", &e.to_string());
            1
        }
    }
}

fn run_check(config: &Config, action: &str, domain: &str, pr: &Printer) -> i32 {
    let spec = match load_manifest(config, action) {
        Ok(s) => s,
        Err(msg) => {
            output::emit_error_coded(pr, "manifest_not_found", &msg);
            return 1;
        }
    };

    #[allow(unreachable_patterns)]
    let manifest_domains = match spec.egress_profile() {
        Ok(EgressProfile::ProxyAllowlist { allowed_domains }) => allowed_domains,
        Ok(EgressProfile::None) => {
            let msg =
                format!("action '{action}' has egress profile 'none' — no domains are allowed");
            if pr.json {
                print_json(&json!({
                    "ok": true,
                    "action_id": action,
                    "domain": domain,
                    "verdict": "denied",
                    "reason": "egress_profile_none",
                    "effective_allowlist_count": 0,
                }));
                return 0;
            }
            pr.blank();
            pr.error(&format!("DENIED — {msg}"));
            pr.blank();
            return 0;
        }
        Ok(_) => {
            output::emit_error_coded(
                pr,
                "unsupported_egress_profile",
                &format!("action '{action}' has an unrecognized egress profile"),
            );
            return 1;
        }
        Err(e) => {
            output::emit_error_coded(
                pr,
                "egress_profile_error",
                &format!("cannot resolve egress profile for '{action}': {e}"),
            );
            return 1;
        }
    };

    // Build the effective allowlist: manifest + learned.
    let mut effective: Vec<Arc<str>> = manifest_domains.clone();

    let db_path = Path::new(&config.storage.ledger_db_path);
    if db_path.exists() {
        if let Some(ledger) = open_ledger(db_path, pr) {
            match ledger.list_learned_domains(Some(action)) {
                Ok(learned) => {
                    for d in &learned {
                        let lower = d.domain.to_ascii_lowercase();
                        if !effective.iter().any(|e| e.to_ascii_lowercase() == lower) {
                            effective.push(Arc::from(d.domain.as_str()));
                        }
                    }
                }
                Err(e) => {
                    // Non-fatal — evaluate with manifest-only domains.
                    pr.warn(&format!("could not read learned domains: {e}"));
                }
            }
        }
    }

    // Evaluate using the same matcher as the runtime gate.
    let lowered = latchgate_core::net::lowercase_allowlist(&effective);
    let allowed = latchgate_core::net::host_matches_allowlist_lower(domain, &lowered);

    // Find which pattern matched (for diagnostics).
    let matched_entry = if allowed {
        latchgate_core::net::find_matching_entry(domain, &lowered)
    } else {
        None
    };

    if pr.json {
        print_json(&json!({
            "ok": true,
            "action_id": action,
            "domain": domain,
            "verdict": if allowed { "allowed" } else { "not_matched" },
            "matched_entry": matched_entry,
            "effective_allowlist_count": effective.len(),
            "manifest_domains_count": manifest_domains.len(),
        }));
        return 0;
    }

    pr.blank();
    if allowed {
        let entry_display = matched_entry
            .map(|e| format!(" (matches '{e}')"))
            .unwrap_or_default();
        pr.success(&format!(
            "ALLOWED — '{domain}' is in the effective allowlist for '{action}'{entry_display}"
        ));
    } else {
        pr.warn(&format!(
            "NOT MATCHED — '{domain}' is not in the effective allowlist for '{action}'"
        ));
        if !effective.is_empty() {
            pr.info("  Effective allowlist:");
            for d in &effective {
                pr.info(&format!("    · {d}"));
            }
        }
    }
    pr.blank();
    0
}

/// Load a manifest by action_id from `manifests_dir`.
fn load_manifest(config: &Config, action: &str) -> Result<ActionSpec, String> {
    let as_path = Path::new(action);
    if as_path.is_file() {
        return ActionSpec::from_file(as_path)
            .map_err(|e| format!("failed to parse {action}: {e}"));
    }

    let dir = Path::new(&config.manifests_dir);
    if !dir.is_dir() {
        return Err(format!(
            "manifests directory not found: {}\n  \
             Set manifests_dir in latchgate.toml or pass a file path.",
            dir.display()
        ));
    }

    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("directory read error: {e}"))?;
        let path = entry.path();
        let is_yaml = path
            .extension()
            .map(|ext| ext == "yaml" || ext == "yml")
            .unwrap_or(false);
        if !is_yaml {
            continue;
        }

        let contents = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        if !contents.contains(action) {
            continue;
        }

        match ActionSpec::from_yaml(&contents) {
            Ok(spec) if spec.action_id == action => return Ok(spec),
            _ => continue,
        }
    }

    Err(format!(
        "action '{action}' not found in {}\n  \
         Pass a file path or check manifests_dir in latchgate.toml.",
        dir.display()
    ))
}

fn format_relative_time(iso_timestamp: &str) -> String {
    let Ok(dt) = chrono::DateTime::parse_from_rfc3339(iso_timestamp) else {
        return iso_timestamp.to_string();
    };
    let now = chrono::Utc::now();
    let delta = now.signed_duration_since(dt);

    if delta.num_seconds() < 60 {
        "just now".to_string()
    } else if delta.num_minutes() < 60 {
        format!("{}m ago", delta.num_minutes())
    } else if delta.num_hours() < 24 {
        format!("{}h ago", delta.num_hours())
    } else if delta.num_days() < 30 {
        format!("{}d ago", delta.num_days())
    } else {
        // Fall back to date.
        dt.format("%Y-%m-%d").to_string()
    }
}

/// Best-effort sync of the live egress allowlist after a domain mutation.
///
/// Logs a warning on failure but never affects the CLI exit code — the
/// ledger mutation already succeeded and the gate will pick up the change
/// at next restart even if the live sync fails here.
fn sync_live_allowlist(config: &Config, ledger: &LedgerStore, pr: &Printer) {
    match latchgate_embed::egress_sync::sync_from_disk(config, ledger) {
        Ok(latchgate_embed::egress_sync::SyncOutcome::Written { domain_count, path }) => {
            if !pr.json {
                pr.info(&format!(
                    "Live egress allowlist updated ({domain_count} domain(s)) => {path}"
                ));
            }
        }
        Ok(latchgate_embed::egress_sync::SyncOutcome::Disabled) => {}
        Err(e) => {
            pr.warn(&format!("Failed to update live egress allowlist: {e}"));
            pr.hint("The domain was added to the ledger. The gate will sync at next startup.");
        }
    }
}
