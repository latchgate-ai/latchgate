//! `latchgate verify` — verify ledger hash-chain integrity.

use serde_json::json;

use latchgate_config::Config;

use crate::client::GateClient;
use crate::output::{print_json, Printer};

/// Run the `verify` command. Returns exit code.
pub async fn run(config: &Config, auth: &crate::OperatorAuth, pr: &Printer) -> i32 {
    let client = match GateClient::from_config(config) {
        Ok(c) => c,
        Err(e) => {
            pr.error(&e.to_string());
            return 1;
        }
    };

    let result = match client.verify_chain(auth).await {
        Ok(v) => v,
        Err(e) => {
            if pr.json {
                print_json(&json!({ "ok": false, "error": e.to_string() }));
            } else {
                pr.blank();
                pr.error(&format!("Cannot reach gate: {e}"));
                pr.blank();
            }
            return 1;
        }
    };

    if pr.json {
        print_json(&result);
        return if result["intact"].as_bool() == Some(true) {
            0
        } else {
            2
        };
    }

    pr.blank();

    let intact = result["intact"].as_bool() == Some(true);
    let total = result["total_events"].as_u64().unwrap_or(0);
    let verified = result["verified_links"].as_u64().unwrap_or(0);

    if intact {
        pr.success(&format!(
            "Ledger integrity verified: {total} events, {verified} links intact."
        ));
    } else {
        let broken_at = result["broken_at"].as_str().unwrap_or("unknown");
        pr.error(&format!("Ledger integrity BROKEN at trace_id={broken_at}"));
        pr.info(&format!(
            "  {verified} of {total} links verified before break."
        ));
    }

    pr.blank();
    if intact {
        0
    } else {
        2
    }
}
