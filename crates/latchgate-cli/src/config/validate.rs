//! `config validate` — production security checks.

use latchgate_config::Config;
use serde_json::json;

use crate::output::{print_json, Printer};

/// Validate the current configuration, reporting each check individually.
pub fn run_validate(config: &Config, pr: &Printer, json_mode: bool) -> i32 {
    let checks: Vec<(&str, Result<(), String>)> = vec![
        (
            "listen/transport",
            config.validate_listen().map_err(|e| e.to_string()),
        ),
        (
            "operator_credentials",
            config.validate_operator_auth().map_err(|e| e.to_string()),
        ),
        (
            "identity",
            config.validate_identity_config().map_err(|e| e.to_string()),
        ),
        (
            "signing_material",
            config
                .validate_signing_material()
                .map_err(|e| e.to_string()),
        ),
        (
            "response_schema_enforcement",
            config
                .validate_response_schema_enforcement()
                .map_err(|e| e.to_string()),
        ),
    ];

    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut results_json = Vec::new();

    let mode_label = if config.dev_mode() {
        "dev mode"
    } else {
        "production"
    };

    if !json_mode {
        pr.blank();
        pr.section(&format!("Config validation ({mode_label})"));
    }

    for (name, result) in &checks {
        match result {
            Ok(()) => {
                pass += 1;
                if !json_mode {
                    println!("  {} {:<32} ok", pr.ok_sym(), name);
                }
                results_json.push(json!({
                    "check": name,
                    "status": "pass",
                }));
            }
            Err(msg) => {
                fail += 1;
                if !json_mode {
                    println!("  {} {:<32} {}", pr.err_sym(), name, msg);
                }
                results_json.push(json!({
                    "check": name,
                    "status": "fail",
                    "error": msg,
                }));
            }
        }
    }

    if json_mode {
        print_json(&json!({
            "ok": fail == 0,
            "mode": mode_label,
            "passed": pass,
            "failed": fail,
            "checks": results_json,
        }));
    } else {
        pr.blank();
        if fail == 0 {
            pr.success(&format!(
                "Config valid ({mode_label}) — {pass}/{pass} passed"
            ));
        } else {
            pr.error(&format!(
                "{fail} check(s) failed ({pass}/{} passed)",
                pass + fail
            ));
        }
        pr.blank();
    }

    if fail > 0 {
        1
    } else {
        0
    }
}
