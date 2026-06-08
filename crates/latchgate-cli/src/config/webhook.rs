//! `config add/remove/list webhook` — notification endpoint management.

use latchgate_config::Config;
use serde_json::json;
use toml_edit;

use crate::cmd::output;
use crate::output::{print_json, Printer};

use super::edit_config_doc;

/// Known webhook event types, derived from [`latchgate_core::EventKind::ALL`].
fn known_event_types() -> Vec<&'static str> {
    latchgate_core::EventKind::ALL
        .iter()
        .map(|k| k.as_str())
        .collect()
}

/// Arguments for `run_add_webhook`.
pub struct AddWebhookArgs<'a> {
    pub config_path: Option<&'a str>,
    pub name: &'a str,
    pub url: &'a str,
    pub secret: Option<&'a str>,
    pub events_csv: &'a str,
    pub headers_csv: Option<&'a str>,
    pub timeout: u64,
    pub format: &'a str,
}

pub fn run_add_webhook(args: &AddWebhookArgs<'_>, pr: &Printer, json_mode: bool) -> i32 {
    // ── Validate inputs ───────────────────────────────────────────────

    if args.name.is_empty() {
        return output::emit_error(pr, "webhook name must not be empty");
    }

    // URL: basic check. Full validation done by validate_webhook_configs.
    if !args.url.starts_with("https://") && !args.url.starts_with("http://") {
        return output::emit_error(
            pr,
            &format!(
                "invalid URL: {0:?} — must start with https:// (or http:// in dev)",
                args.url
            ),
        );
    }

    // Auto-generate secret if not provided.
    let secret = match args.secret {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => crate::cmd::credential::generate_webhook_secret(),
    };
    let secret_generated = args.secret.is_none();

    let events: Vec<String> = args
        .events_csv
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if events.is_empty() {
        return output::emit_error(pr, "at least one event type is required");
    }

    let valid_types = known_event_types();
    for event in &events {
        if !valid_types.contains(&event.as_str()) {
            return output::emit_error(
                pr,
                &format!(
                    "unknown event type: '{event}' — valid types: {}",
                    valid_types.join(", ")
                ),
            );
        }
    }

    // Validate format.
    let valid_formats: Vec<&str> = latchgate_webhooks::WebhookFormat::ALL
        .iter()
        .map(|f| f.as_str())
        .collect();
    if !valid_formats.contains(&args.format) {
        return output::emit_error(
            pr,
            &format!(
                "unknown format: '{}' — valid formats: {}",
                args.format,
                valid_formats.join(", ")
            ),
        );
    }

    // Parse optional headers.
    let headers: Vec<(String, String)> = match args.headers_csv {
        Some(csv) if !csv.is_empty() => {
            let mut result = Vec::new();
            for pair in csv.split(',') {
                let pair = pair.trim();
                if let Some((k, v)) = pair.split_once('=') {
                    result.push((k.trim().to_string(), v.trim().to_string()));
                } else {
                    return output::emit_error(
                        pr,
                        &format!("invalid header: '{pair}' — expected K=V format"),
                    );
                }
            }
            result
        }
        _ => vec![],
    };

    // ── Load, mutate, validate, and write config ───────────────────────

    let result = edit_config_doc(pr, args.config_path, |doc| {
        // ── Check for duplicate name ──────────────────────────────────────

        if let Some(existing) = doc.get("webhooks").and_then(|v| v.as_array_of_tables()) {
            for entry in existing.iter() {
                if entry.get("name").and_then(|v| v.as_str()) == Some(args.name) {
                    return Err(format!("webhook '{}' already exists", args.name));
                }
            }
        }

        // ── Build TOML entry ──────────────────────────────────────────────

        let mut entry = toml_edit::Table::new();
        entry.insert("name", toml_edit::value(args.name));
        entry.insert("url", toml_edit::value(args.url));
        entry.insert("secret", toml_edit::value(&secret));

        let mut events_array = toml_edit::Array::new();
        for event in &events {
            events_array.push(event.as_str());
        }
        entry.insert("events", toml_edit::value(events_array));

        if !headers.is_empty() {
            let mut headers_table = toml_edit::InlineTable::new();
            for (k, v) in &headers {
                headers_table.insert(k, v.as_str().into());
            }
            entry.insert("headers", toml_edit::value(headers_table));
        }

        entry.insert("timeout_seconds", toml_edit::value(args.timeout as i64));

        // Only write format if non-default — keeps config tidy for generic endpoints.
        if args.format != "generic" {
            entry.insert("format", toml_edit::value(args.format));
        }

        // Append to [[webhooks]] array-of-tables.
        let webhooks = doc
            .entry("webhooks")
            .or_insert(toml_edit::Item::ArrayOfTables(
                toml_edit::ArrayOfTables::new(),
            ));
        match webhooks.as_array_of_tables_mut() {
            Some(arr) => arr.push(entry),
            None => {
                return Err("existing 'webhooks' key is not an array of tables".into());
            }
        }

        Ok(())
    });

    if let Err(code) = result {
        return code;
    }

    if json_mode {
        print_json(&json!({
            "ok": true,
            "webhook": args.name,
            "url": args.url,
            "events": events,
            "timeout_seconds": args.timeout,
            "format": args.format,
            "secret": &secret,
            "secret_generated": secret_generated,
        }));
    } else {
        pr.blank();
        pr.success(&format!("Webhook '{}' added", args.name));
        pr.blank();
        pr.field("  url    ", args.url);
        pr.field("  events ", &events.join(", "));
        pr.field("  format ", args.format);
        pr.field("  timeout", &format!("{}s", args.timeout));
        if secret_generated {
            pr.field("  secret ", &secret);
            pr.info("  (auto-generated — save it if your receiver needs to verify signatures)");
        }
        pr.blank();
    }
    0
}

pub fn run_remove_webhook(
    config_path: Option<&str>,
    name: &str,
    pr: &Printer,
    json_mode: bool,
) -> i32 {
    let result = edit_config_doc(pr, config_path, |doc| {
        let removed = match doc
            .get_mut("webhooks")
            .and_then(|v| v.as_array_of_tables_mut())
        {
            Some(arr) => {
                let idx = arr
                    .iter()
                    .position(|e| e.get("name").and_then(|v| v.as_str()) == Some(name));
                match idx {
                    Some(i) => {
                        arr.remove(i);
                        true
                    }
                    None => false,
                }
            }
            None => false,
        };

        if !removed {
            return Err(format!("webhook '{name}' not found in config"));
        }

        Ok(())
    });

    if let Err(code) = result {
        return code;
    }

    if json_mode {
        print_json(&json!({ "ok": true, "webhook": name, "removed": true }));
    } else {
        pr.blank();
        pr.success(&format!("Webhook '{name}' removed"));
        pr.blank();
    }
    0
}

pub fn run_list_webhooks(config: &Config, pr: &Printer, json_mode: bool) -> i32 {
    let webhooks = &config.webhooks;

    if json_mode {
        print_json(&json!({ "ok": true, "webhooks": webhooks }));
        return 0;
    }

    if webhooks.is_empty() {
        pr.blank();
        pr.info("No webhooks configured.");
        pr.blank();
        return 0;
    }

    pr.blank();
    println!(
        "  {:<16} {:<36} {:<10} {}",
        pr.bold("Name"),
        pr.bold("URL"),
        pr.bold("Format"),
        pr.bold("Events"),
    );
    println!("  {}", "─".repeat(80));

    for wh in webhooks {
        let name = wh.get("name").and_then(|v| v.as_str()).unwrap_or("?");
        let url = wh.get("url").and_then(|v| v.as_str()).unwrap_or("?");
        let format = wh
            .get("format")
            .and_then(|v| v.as_str())
            .unwrap_or("generic");
        let events: Vec<&str> = wh
            .get("events")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();

        let url_display = if url.len() > 34 {
            format!("{}...", &url[..31])
        } else {
            url.to_string()
        };
        println!(
            "  {:<16} {:<36} {:<10} {}",
            name,
            url_display,
            format,
            events.join(", ")
        );
    }
    pr.blank();

    0
}

/// Send a test event to one or all webhook endpoints and report results.
///
/// This is an async function — the caller must run it inside a tokio runtime.
pub async fn run_test_webhook(
    config: &Config,
    name: Option<&str>,
    pr: &Printer,
    json_mode: bool,
) -> i32 {
    let dev_mode = config.dev_mode();
    let gate_version = env!("CARGO_PKG_VERSION");

    // Parse webhook configs from the raw TOML values.
    let mut endpoints: Vec<latchgate_webhooks::WebhookEndpointConfig> = Vec::new();
    for (i, raw) in config.webhooks.iter().enumerate() {
        match raw
            .clone()
            .try_into::<latchgate_webhooks::WebhookEndpointConfig>()
        {
            Ok(cfg) => endpoints.push(cfg),
            Err(e) => {
                return output::emit_error(pr, &format!("webhooks[{i}]: invalid config — {e}"));
            }
        }
    }

    if endpoints.is_empty() {
        if json_mode {
            print_json(&json!({ "ok": false, "error": "no webhooks configured" }));
        } else {
            pr.blank();
            pr.info("No webhooks configured. Add one with `latchgate config add-webhook`.");
            pr.blank();
        }
        return 1;
    }

    // Filter to a single endpoint if --name is provided.
    let targets: Vec<&latchgate_webhooks::WebhookEndpointConfig> = match name {
        Some(n) => match endpoints.iter().find(|ep| ep.name == n) {
            Some(ep) => vec![ep],
            None => {
                let known: Vec<&str> = endpoints.iter().map(|ep| ep.name.as_str()).collect();
                return output::emit_error(
                    pr,
                    &format!("webhook '{n}' not found — configured: {}", known.join(", ")),
                );
            }
        },
        None => endpoints.iter().collect(),
    };

    if !json_mode {
        pr.blank();
        pr.info(&format!(
            "Testing {} webhook endpoint{}…",
            targets.len(),
            if targets.len() == 1 { "" } else { "s" }
        ));
        pr.blank();
    }

    let mut results = Vec::new();
    let mut any_failed = false;

    for ep in &targets {
        let result = latchgate_webhooks::test_deliver(ep, gate_version, dev_mode).await;

        if !result.is_ok() {
            any_failed = true;
        }

        if !json_mode {
            if result.is_ok() {
                pr.success(&format!(
                    "  ✓ {} — HTTP {} in {}ms",
                    result.endpoint_name,
                    result.status_code,
                    result.elapsed.as_millis(),
                ));
            } else {
                pr.error(&format!(
                    "  ✗ {} — {}",
                    result.endpoint_name,
                    result.error.as_deref().unwrap_or("unknown error"),
                ));
            }
        }

        results.push(result);
    }

    if json_mode {
        let json_results: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                json!({
                    "name": r.endpoint_name,
                    "ok": r.is_ok(),
                    "status_code": r.status_code,
                    "elapsed_ms": r.elapsed.as_millis() as u64,
                    "error": r.error,
                })
            })
            .collect();
        print_json(&json!({
            "ok": !any_failed,
            "results": json_results,
        }));
    } else {
        pr.blank();
    }

    if any_failed {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_fixtures::*;

    // -- add/remove/list webhook ---------------------------------------------

    #[test]
    fn add_webhook_creates_valid_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), PROD_TOML);
        let pr = Printer::new(false);

        let code = run_add_webhook(
            &AddWebhookArgs {
                config_path: Some(path.to_str().unwrap()),
                name: "slack-alerts",
                url: "https://hooks.slack.com/services/T/B/xxx",
                secret: Some("whsec_test123"),
                events_csv: "approval.pending,approval.expired",
                headers_csv: None,
                timeout: 10,
                format: "generic",
            },
            &pr,
            false,
        );
        assert_eq!(code, 0, "add_webhook failed");

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("[[webhooks]]"));
        assert!(content.contains("slack-alerts"));
        assert!(content.contains("hooks.slack.com"));

        // Must still parse as valid config.
        let _config: latchgate_config::Config = toml::from_str(&content)
            .unwrap_or_else(|e| panic!("TOML invalid after add_webhook: {e}"));
    }

    #[test]
    fn add_webhook_rejects_duplicate_name() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), PROD_TOML);
        let pr = Printer::new(false);

        run_add_webhook(
            &AddWebhookArgs {
                config_path: Some(path.to_str().unwrap()),
                name: "dup",
                url: "https://example.com/wh",
                secret: Some("whsec_x"),
                events_csv: "approval.pending",
                headers_csv: None,
                timeout: 10,
                format: "generic",
            },
            &pr,
            false,
        );
        let code = run_add_webhook(
            &AddWebhookArgs {
                config_path: Some(path.to_str().unwrap()),
                name: "dup",
                url: "https://example.com/wh2",
                secret: Some("whsec_y"),
                events_csv: "approval.pending",
                headers_csv: None,
                timeout: 10,
                format: "generic",
            },
            &pr,
            false,
        );
        assert_ne!(code, 0, "duplicate webhook name must be rejected");
    }

    #[test]
    fn add_webhook_rejects_unknown_event_type() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), PROD_TOML);
        let pr = Printer::new(false);

        let code = run_add_webhook(
            &AddWebhookArgs {
                config_path: Some(path.to_str().unwrap()),
                name: "test",
                url: "https://example.com/wh",
                secret: Some("whsec_x"),
                events_csv: "approval.pending,not.a.real.event",
                headers_csv: None,
                timeout: 10,
                format: "generic",
            },
            &pr,
            false,
        );
        assert_ne!(code, 0, "unknown event type must be rejected");
    }

    #[test]
    fn remove_webhook_by_name() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), PROD_TOML);
        let pr = Printer::new(false);

        run_add_webhook(
            &AddWebhookArgs {
                config_path: Some(path.to_str().unwrap()),
                name: "removeme",
                url: "https://example.com/wh",
                secret: Some("whsec_x"),
                events_csv: "approval.pending",
                headers_csv: None,
                timeout: 10,
                format: "generic",
            },
            &pr,
            false,
        );

        let code = run_remove_webhook(Some(path.to_str().unwrap()), "removeme", &pr, false);
        assert_eq!(code, 0);

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            !content.contains("removeme"),
            "removed webhook must be gone"
        );
    }

    #[test]
    fn remove_nonexistent_webhook_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), PROD_TOML);
        let pr = Printer::new(false);

        let code = run_remove_webhook(Some(path.to_str().unwrap()), "ghost", &pr, false);
        assert_ne!(code, 0);
    }

    #[test]
    fn webhook_round_trip_preserves_events_as_array() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), PROD_TOML);
        let pr = Printer::new(false);

        run_add_webhook(
            &AddWebhookArgs {
                config_path: Some(path.to_str().unwrap()),
                name: "multi",
                url: "https://example.com/wh",
                secret: Some("whsec_x"),
                events_csv: "approval.pending,action.denied,revocation",
                headers_csv: None,
                timeout: 15,
                format: "generic",
            },
            &pr,
            false,
        );

        let content = std::fs::read_to_string(&path).unwrap();
        let config: latchgate_config::Config = toml::from_str(&content).unwrap();

        assert_eq!(config.webhooks.len(), 1);
        let events = config.webhooks[0]
            .get("events")
            .and_then(|v| v.as_array())
            .expect("events must be an array");
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn known_event_types_match_event_kind() {
        // Verify known_event_types() produces valid EventKind values.
        // If EventKind gets a new variant, EventKind::ALL forces the update.
        for kind in latchgate_core::EventKind::ALL {
            let json_str = format!("\"{}\"", kind.as_str());
            let result: Result<latchgate_core::EventKind, _> = serde_json::from_str(&json_str);
            assert!(
                result.is_ok(),
                "EventKind::ALL contains '{}' which doesn't round-trip through serde",
                kind.as_str()
            );
        }
    }
}
