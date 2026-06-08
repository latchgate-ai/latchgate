//! `latchgate revoke` — emergency revocation kill-switch.
//!
//! Advances the revocation epoch by 1. Every `ExecutionGrant` issued before
//! this call carries the old epoch value and will fail `is_valid()` checks.
//! New grants issued after this call carry the new epoch and remain valid.
//!
//! The operation is O(1) and takes effect immediately — no need to restart
//! the gate or drain existing connections.

use serde_json::json;

use latchgate_config::Config;

use crate::client::{GateClient, OperatorAuth};
use crate::output::{print_json, Printer};

/// Run the `revoke` command. Returns exit code.
pub async fn run(config: &Config, auth: &OperatorAuth, yes: bool, pr: &Printer) -> i32 {
    // Confirmation gate — skip in --json mode (scripting) or if --yes given.
    if !yes && !pr.json && !confirm(pr) {
        pr.blank();
        pr.info("Revocation cancelled.");
        pr.blank();
        return 0;
    }

    let client = match GateClient::from_config(config) {
        Ok(c) => c,
        Err(e) => {
            pr.error(&e.to_string());
            return 1;
        }
    };

    match client.revoke_all(auth).await {
        Ok(resp) => {
            let old_epoch = resp["previous_epoch"].as_u64().unwrap_or(0);
            let new_epoch = resp["current_epoch"].as_u64().unwrap_or(0);

            if pr.json {
                print_json(&json!({
                    "ok": true,
                    "previous_epoch": old_epoch,
                    "current_epoch":  new_epoch,
                }));
                return 0;
            }

            pr.blank();
            pr.success("Revocation epoch advanced.");
            pr.blank();
            pr.table(&[
                ("previous_epoch", &old_epoch.to_string()),
                ("current_epoch", &new_epoch.to_string()),
            ]);
            pr.blank();
            println!("  All ExecutionGrants issued before this call are now invalid.");
            println!(
                "  New grants will carry epoch {} and remain valid.",
                pr.bold(&new_epoch.to_string()),
            );
            pr.blank();
            0
        }
        Err(e) => {
            if pr.json {
                print_json(&json!({ "ok": false, "error": e.to_string() }));
            } else {
                pr.blank();
                pr.error(&format!("Revocation failed: {e}"));
                pr.blank();
                eprintln!("  Is the gate running?  latchgate status");
                pr.blank();
            }
            1
        }
    }
}

fn confirm(pr: &Printer) -> bool {
    pr.blank();
    eprintln!(
        "  {}  This will immediately invalidate {}.",
        pr.warn_sym(),
        pr.bold("all outstanding ExecutionGrants"),
    );
    eprintln!("     In-flight action calls may fail.");
    pr.blank();
    eprint!(
        "  Type {} to confirm, anything else to cancel: ",
        pr.bold("yes")
    );

    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    line.trim() == "yes"
}
