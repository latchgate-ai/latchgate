//! `latchgate actions [ACTION_ID]` — list or inspect registered actions.

use serde_json::json;

use latchgate_config::Config;

use crate::client::GateClient;
use crate::output::{print_json, Printer};

/// Run the `actions` command. Returns exit code.
pub async fn run(config: &Config, action: Option<&str>, pr: &Printer) -> i32 {
    let client = match GateClient::from_config(config) {
        Ok(c) => c,
        Err(e) => {
            pr.error(&e.to_string());
            return 1;
        }
    };

    if let Some(action_id) = action {
        show_one(&client, action_id, pr).await
    } else {
        list_all(&client, pr).await
    }
}

async fn list_all(client: &GateClient, pr: &Printer) -> i32 {
    let actions = match client.list_actions().await {
        Ok(a) => a,
        Err(e) => {
            if pr.json {
                print_json(&json!({ "ok": false, "error": e.to_string() }));
            } else {
                pr.blank();
                pr.error(&format!("Cannot reach gate: {e}"));
                pr.blank();
                eprintln!("  Is the gate running?  latchgate serve");
                pr.blank();
            }
            return 1;
        }
    };

    if pr.json {
        print_json(&json!({ "actions": actions }));
        return 0;
    }

    pr.blank();

    if actions.is_empty() {
        pr.warn("No actions registered.");
        pr.blank();
        eprintln!("  Add manifests to your manifests_dir and restart the gate.");
        pr.blank();
        return 0;
    }

    // Column widths
    let id_w = actions
        .iter()
        .filter_map(|a| a["action_id"].as_str())
        .map(|s| s.len())
        .max()
        .unwrap_or(9)
        .max(9); // min "action_id"
    let ver_w = 7usize; // "version"

    println!(
        "  {id:<id_w$}  {ver:<ver_w$}  risk",
        id = pr.dim("action_id"),
        ver = pr.dim("version"),
    );
    println!(
        "  {}  {}  {}",
        pr.dim(&"─".repeat(id_w)),
        pr.dim(&"─".repeat(ver_w)),
        pr.dim("──────"),
    );

    for action in &actions {
        let id = action["action_id"].as_str().unwrap_or("?");
        let version = action["version"].as_str().unwrap_or("?");
        let risk = action["risk_level"].as_str().unwrap_or("unknown");

        let risk_col = match risk {
            "high" => pr.red(risk),
            "medium" => pr.yellow(risk),
            _ => pr.green(risk),
        };

        println!(
            "  {id:<id_w$}  {ver:<ver_w$}  {risk}",
            ver = pr.dim(version),
            risk = risk_col,
        );
    }

    println!(
        "\n  {} action(s)  ·  {}",
        actions.len(),
        pr.dim("latchgate actions <id> for detail"),
    );
    pr.blank();
    0
}

async fn show_one(client: &GateClient, action_id: &str, pr: &Printer) -> i32 {
    let detail = match client.get_action(action_id).await {
        Ok(v) => v,
        Err(crate::client::ClientError::Http { status: 404, .. }) => {
            if pr.json {
                print_json(
                    &json!({ "ok": false, "error": format!("action '{action_id}' not found") }),
                );
            } else {
                pr.blank();
                pr.error(&format!("Action '{action_id}' not found."));
                pr.blank();
                eprintln!("  Available actions:  latchgate actions");
                pr.blank();
            }
            return 1;
        }
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
        print_json(&detail);
        return 0;
    }

    pr.blank();
    pr.section(&format!(
        "Action: {}",
        detail["action_id"].as_str().unwrap_or(action_id)
    ));
    pr.blank();

    pr.table(&[
        ("version", detail["version"].as_str().unwrap_or("?")),
        ("risk_level", detail["risk_level"].as_str().unwrap_or("?")),
    ]);

    pr.blank();
    println!("  {}", pr.bold("Runtime limits"));
    if let Some(rt) = detail["resource_limits"].as_object() {
        let rows: Vec<(&str, String)> = vec![
            (
                "timeout",
                format!(
                    "{}s",
                    rt.get("timeout_seconds")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                ),
            ),
            (
                "memory",
                format!(
                    "{}MB",
                    rt.get("memory_mb").and_then(|v| v.as_u64()).unwrap_or(0)
                ),
            ),
            (
                "fuel",
                rt.get("fuel")
                    .and_then(|v| v.as_u64())
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "?".into()),
            ),
            (
                "max_io",
                rt.get("max_io_calls")
                    .and_then(|v| v.as_u64())
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "?".into()),
            ),
        ];
        for (k, v) in &rows {
            pr.field(k, v);
        }
    }

    let io = &detail["io"];
    pr.blank();
    println!("  {}", pr.bold("I/O schema"));
    pr.field(
        "request_schema",
        if io["has_request_schema"].as_bool().unwrap_or(false) {
            "yes"
        } else {
            "none"
        },
    );
    pr.field(
        "response_schema",
        if io["has_response_schema"].as_bool().unwrap_or(false) {
            "yes"
        } else {
            "none"
        },
    );
    pr.field(
        "max_request",
        &format!("{} bytes", io["max_request_bytes"].as_u64().unwrap_or(0)),
    );
    pr.field(
        "max_response",
        &format!("{} bytes", io["max_response_bytes"].as_u64().unwrap_or(0)),
    );

    if let Some(egress) = detail["egress"].as_object() {
        pr.blank();
        println!("  {}", pr.bold("Egress"));
        if let Some(allowlist) = egress.get("hosts").and_then(|v| v.as_array()) {
            for h in allowlist {
                pr.field("allowed_host", h.as_str().unwrap_or("?"));
            }
        }
    }

    if let Some(sinks) = detail["declared_side_effects"].as_array() {
        if !sinks.is_empty() {
            pr.blank();
            println!("  {}", pr.bold("Declared side effects"));
            for s in sinks {
                pr.field("sink", s.as_str().unwrap_or("?"));
            }
        }
    }

    pr.blank();
    0
}
