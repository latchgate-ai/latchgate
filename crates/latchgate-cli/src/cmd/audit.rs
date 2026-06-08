//! `latchgate audit` — query the audit trail.

use serde_json::json;

use latchgate_config::Config;

use crate::client::{AuditParams, GateClient};
use crate::cmd::text::truncate;
use crate::output::{print_json, Printer};

use crate::AuditOutputFormat;

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn jsonl_output(events: &[serde_json::Value]) -> String {
    events
        .iter()
        .map(|e| serde_json::to_string(e).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

fn json_output(events: &[serde_json::Value]) -> serde_json::Value {
    json!({ "events": events })
}

fn validate_output_mode(
    _json: bool,
    _format: &Option<AuditOutputFormat>,
) -> Result<(), &'static str> {
    Ok(())
}

/// Run the `audit` command. Returns exit code.
pub async fn run(
    config: &Config,
    auth: &crate::OperatorAuth,
    params: AuditParams,
    pr: &Printer,
    format: &Option<AuditOutputFormat>,
) -> i32 {
    let client = match GateClient::from_config(config) {
        Ok(c) => c,
        Err(e) => {
            pr.error(&e.to_string());
            return 1;
        }
    };
    let limit = params.limit.unwrap_or(20);

    if let Err(msg) = validate_output_mode(pr.json, format) {
        pr.error(msg);
        return 1;
    }

    let events = match client.audit_events(auth, &params).await {
        Ok(e) => e,
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

    let output_format = match format {
        Some(fmt) => fmt.clone(),
        None if pr.json => AuditOutputFormat::Json,
        None => AuditOutputFormat::Table,
    };

    match output_format {
        AuditOutputFormat::Json => {
            print_json(&json_output(&events));
            return 0;
        }

        AuditOutputFormat::Jsonl => {
            println!("{}", jsonl_output(&events));
            return 0;
        }

        AuditOutputFormat::Csv => {
            println!(
        "trace_id,timestamp,event_type,action_id,principal,decision,reason,session_id,dev_mode"
    );

            for ev in &events {
                println!(
                    "{},{},{},{},{},{},{},{},{}",
                    csv_escape(ev["trace_id"].as_str().unwrap_or("")),
                    csv_escape(ev["timestamp"].as_str().unwrap_or("")),
                    csv_escape(ev["event_type"].as_str().unwrap_or("")),
                    csv_escape(ev["action_id"].as_str().unwrap_or("")),
                    csv_escape(ev["principal"].as_str().unwrap_or("")),
                    csv_escape(ev["decision"].as_str().unwrap_or("")),
                    csv_escape(ev["reason"].as_str().unwrap_or("")),
                    csv_escape(ev["session_id"].as_str().unwrap_or("")),
                    csv_escape(
                        &ev["dev_mode"]
                            .as_bool()
                            .map(|b| b.to_string())
                            .unwrap_or_default(),
                    ),
                );
            }

            return 0;
        }

        AuditOutputFormat::Table => {}
    }

    pr.blank();

    if events.is_empty() {
        pr.info("No audit events match the filter.");
        pr.blank();
        return 0;
    }

    // Header
    let act_w = events
        .iter()
        .filter_map(|e| e["action_id"].as_str())
        .map(|s| s.len())
        .max()
        .unwrap_or(9)
        .max(9);

    println!(
        "  {ts:<19}  {dec:<7}  {act:<act_w$}  {principal}",
        ts = pr.dim("timestamp"),
        dec = pr.dim("decision"),
        act = pr.dim("action"),
        principal = pr.dim("principal"),
    );
    println!(
        "  {}  {}  {}  {}",
        pr.dim(&"─".repeat(19)),
        pr.dim(&"─".repeat(7)),
        pr.dim(&"─".repeat(act_w)),
        pr.dim(&"─".repeat(20)),
    );

    for ev in &events {
        let ts = ev["timestamp"].as_str().unwrap_or("?");
        let ts_short = &ts[..ts.len().min(19)]; // "2025-01-01T12:00:00"
        let dec = ev["decision"].as_str().unwrap_or("?");
        let action_id = ev["action_id"].as_str().unwrap_or("-");
        let principal = ev["principal"].as_str().unwrap_or("-");

        let dec_col = match dec {
            "allow" => pr.green(dec),
            "allow_unverified" => pr.yellow("allow⚠"),
            "deny" => pr.red(dec),
            "pending_approval" => pr.yellow("pending"),
            "error" => pr.yellow(dec),
            other => pr.dim(other),
        };

        println!(
            "  {ts:<19}  {dec:<7}  {act:<act_w$}  {principal}",
            ts = pr.dim(ts_short),
            dec = dec_col,
            act = action_id,
            principal = pr.dim(&truncate(principal, 32)),
        );

        // Surface the deny/error reason inline if present
        if dec != "allow" {
            if let Some(reason) = ev["reason"].as_str().filter(|s| !s.is_empty()) {
                println!("  {}", pr.dim(&format!("  └─ {reason}")),);
            }
        }
    }

    println!(
        "\n  {} event(s){}",
        events.len(),
        if events.len() == limit {
            format!(
                "  ·  {}",
                pr.dim(&format!("showing latest {limit}; use --limit to see more"))
            )
        } else {
            String::new()
        },
    );
    pr.blank();
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_escape_plain_text() {
        assert_eq!(csv_escape("hello"), "hello");
    }

    #[test]
    fn csv_escape_quotes_commas_and_quotes() {
        let input = r#"hello,"world""#;
        let output = csv_escape(input);

        assert_eq!(output, "\"hello,\"\"world\"\"\"");
    }

    #[test]
    fn csv_escape_newline() {
        let input = "hello\nworld";
        let output = csv_escape(input);

        assert_eq!(output, "\"hello\nworld\"");
    }

    #[test]
    fn jsonl_lines_are_valid_json() {
        let events = vec![
            serde_json::json!({
                "trace_id": "t1",
                "decision": "allow"
            }),
            serde_json::json!({
                "trace_id": "t2",
                "decision": "deny"
            }),
        ];

        let output = jsonl_output(&events);

        for line in output.lines() {
            serde_json::from_str::<serde_json::Value>(line).unwrap();
        }
    }

    #[test]
    fn json_and_jsonl_round_trip_match() {
        let events = vec![
            serde_json::json!({
                "trace_id": "t1",
                "decision": "allow"
            }),
            serde_json::json!({
                "trace_id": "t2",
                "decision": "deny"
            }),
        ];

        let json = json_output(&events);

        let parsed: Vec<serde_json::Value> = jsonl_output(&events)
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();

        assert_eq!(json["events"], serde_json::json!(parsed));
    }

    #[test]
    fn jsonl_contains_no_ansi_escape_codes() {
        let events = vec![serde_json::json!({
            "trace_id": "t1",
            "decision": "allow"
        })];

        let output = jsonl_output(&events);

        assert!(!output.contains("\x1b["));
    }

    #[test]
    fn format_takes_precedence_over_json() {
        let format = Some(AuditOutputFormat::Csv);

        let output_format = match &format {
            Some(fmt) => fmt.clone(),
            None => AuditOutputFormat::Json,
        };

        assert!(matches!(output_format, AuditOutputFormat::Csv));
    }
}
