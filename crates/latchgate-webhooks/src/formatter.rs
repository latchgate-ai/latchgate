//! Convert [`DomainEvent`] variants into the standard JSON envelope.
//!
//! The envelope format is consistent across all event types:
//!
//! ```json
//! {
//!   "id": "evt_01JA...",
//!   "type": "approval.pending",
//!   "timestamp": "2025-03-28T14:30:00Z",
//!   "gate_version": "0.1.0",
//!   "data": { ... }
//! }
//! ```
//!
//! `data` varies by event type. For `ApprovalPending`, the formatter redacts
//! sensitive values from the raw request body before including a summary in
//! the payload. All other variants are passed through as-is.

use latchgate_core::DomainEvent;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::borrow::Cow;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    pub id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub timestamp: String,
    pub gate_version: String,
    pub data: serde_json::Value,
}

/// Convert a [`DomainEvent`] into the standard JSON envelope.
///
/// `gate_version` is stamped into every payload for receiver-side version
/// gating. Typically `env!("CARGO_PKG_VERSION")` from the workspace root,
/// passed in by the dispatcher at startup.
///
/// For `ApprovalPending`, the raw `request_body` is redacted using the
/// declared `secret_names` before inclusion as `request_summary`. This is
/// the single point where secret redaction occurs for webhook payloads.
pub fn format_event(event: &DomainEvent, gate_version: &str) -> WebhookPayload {
    let event_id = format!("evt_{}", uuid::Uuid::now_v7());
    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let data = event_data(event);

    WebhookPayload {
        id: event_id,
        event_type: event.kind().as_str().into(),
        timestamp,
        gate_version: gate_version.into(),
        data,
    }
}

/// Extract the data object from a [`DomainEvent`].
fn event_data(event: &DomainEvent) -> serde_json::Value {
    match event {
        DomainEvent::ApprovalPending(ev) => {
            let request_summary = redact_summary(&ev.request_body, &ev.secret_names);
            let mut data = json!({
                "approval_id": ev.approval_id,
                "action_id": ev.action_id,
                "principal": ev.principal,
                "owner": ev.owner,
                "risk_level": ev.risk_level,
                "request_hash": ev.request_hash,
                "expires_at": ev.expires_at,
                "request_summary": request_summary,
                "trace_id": ev.trace_id,
            });
            // Only include when non-empty — matches the GET API contract.
            if !ev.unresolved_domains.is_empty() {
                data["unresolved_domains"] = json!(ev.unresolved_domains);
            }
            if !ev.unresolved_paths.is_empty() {
                data["unresolved_paths"] = json!(ev.unresolved_paths);
            }
            data
        }

        DomainEvent::ApprovalGranted {
            approval_id,
            action_id,
            approved_by,
            receipt_id,
            trace_id,
        } => json!({
            "approval_id": approval_id,
            "action_id": action_id,
            "approved_by": approved_by,
            "receipt_id": receipt_id,
            "trace_id": trace_id,
        }),

        DomainEvent::ApprovalDenied {
            approval_id,
            action_id,
            denied_by,
            reason,
            trace_id,
        } => json!({
            "approval_id": approval_id,
            "action_id": action_id,
            "denied_by": denied_by,
            "reason": reason,
            "trace_id": trace_id,
        }),

        DomainEvent::ApprovalExpired {
            approval_id,
            action_id,
            principal,
            owner,
            created_at,
            expired_at,
        } => json!({
            "approval_id": approval_id,
            "action_id": action_id,
            "principal": principal,
            "owner": owner,
            "created_at": created_at,
            "expired_at": expired_at,
        }),

        DomainEvent::ActionDenied {
            action_id,
            principal,
            owner,
            deny_reason,
            trace_id,
        } => json!({
            "action_id": action_id,
            "principal": principal,
            "owner": owner,
            "deny_reason": deny_reason,
            "trace_id": trace_id,
        }),

        DomainEvent::ActionExecuted {
            action_id,
            principal,
            owner,
            receipt_id,
            verification_outcome,
            trace_id,
        } => json!({
            "action_id": action_id,
            "principal": principal,
            "owner": owner,
            "receipt_id": receipt_id,
            "verification_outcome": verification_outcome,
            "trace_id": trace_id,
        }),

        DomainEvent::ActionFailed {
            action_id,
            principal,
            owner,
            error_class,
            trace_id,
        } => json!({
            "action_id": action_id,
            "principal": principal,
            "owner": owner,
            "error_class": error_class,
            "trace_id": trace_id,
        }),

        DomainEvent::Revocation {
            old_epoch,
            new_epoch,
            operator_id,
        } => json!({
            "old_epoch": old_epoch,
            "new_epoch": new_epoch,
            "operator_id": operator_id,
        }),

        DomainEvent::BudgetExhausted {
            action_id,
            principal,
            owner,
            session_id,
        } => json!({
            "action_id": action_id,
            "principal": principal,
            "owner": owner,
            "session_id": session_id,
        }),

        DomainEvent::BudgetRollbackFailed {
            session_id,
            error,
            trace_id,
            label,
        } => json!({
            "session_id": session_id,
            "error": error,
            "trace_id": trace_id,
            "label": label,
        }),

        // Future DomainEvent variants — format_webhook_payload will
        // produce an empty data object until a formatter arm is added.
        _ => json!({}),
    }
}

use crate::config::{WebhookEndpointConfig, WebhookFormat};

/// Transform a generic [`WebhookPayload`] into the final JSON body for
/// a specific endpoint format.  Called after `format_event` and before
/// `sign_payload` — the HMAC covers the formatted bytes, not the generic
/// envelope.
///
/// Accepts the full endpoint config so platform formatters can read
/// auxiliary fields (e.g. PagerDuty reads the routing key from headers).
pub fn format_for_endpoint(
    payload: &WebhookPayload,
    endpoint: &WebhookEndpointConfig,
) -> serde_json::Value {
    match endpoint.format {
        WebhookFormat::Generic => serde_json::to_value(payload).unwrap_or(json!({})),
        WebhookFormat::Slack => format_slack(payload),
        WebhookFormat::Discord => format_discord(payload),
        WebhookFormat::PagerDuty => format_pagerduty(payload, endpoint),
    }
}

/// Produce a Slack Block Kit message from a webhook payload.
///
/// Every message includes a `text` fallback (required by Slack for
/// notifications and accessibility) and a `blocks` array for rich
/// rendering.  A context block at the bottom carries the event ID
/// and gate version for traceability.
fn format_slack(payload: &WebhookPayload) -> serde_json::Value {
    let (emoji, title, fields) = event_display_parts(&payload.event_type, &payload.data);
    let headline = format!("{emoji} {title}");

    let mut blocks = Vec::with_capacity(3);
    blocks.push(json!({
        "type": "header",
        "text": { "type": "plain_text", "text": &headline, "emoji": true }
    }));

    if !fields.is_empty() {
        let field_elements: Vec<serde_json::Value> = fields
            .iter()
            .map(|(k, v)| json!({ "type": "mrkdwn", "text": format!("*{k}:*\n{v}") }))
            .collect();
        blocks.push(json!({ "type": "section", "fields": field_elements }));
    }

    blocks.push(json!({
        "type": "context",
        "elements": [{ "type": "mrkdwn", "text": format!("{} · LatchGate {}", payload.id, payload.gate_version) }]
    }));

    json!({ "text": headline, "blocks": blocks })
}

/// Extract emoji, title, and key-value fields for a Slack message from
/// the event type and data object.
fn event_display_parts<'a>(
    event_type: &str,
    data: &'a serde_json::Value,
) -> (&'static str, String, Vec<(&'static str, Cow<'a, str>)>) {
    use Cow::{Borrowed, Owned};

    match event_type {
        "approval.pending" => {
            let action = str_field(data, "action_id");
            let principal = str_field(data, "principal");
            let risk = str_field(data, "risk_level");
            let expires = str_field(data, "expires_at");
            let mut fields = Vec::with_capacity(5);
            fields.push(("Action", Borrowed(action)));
            fields.push(("Principal", Borrowed(principal)));
            fields.push(("Risk", Borrowed(risk)));
            if !expires.is_empty() {
                fields.push(("Expires", Borrowed(expires)));
            }
            if let Some(owner) = data.get("owner").and_then(|v| v.as_str()) {
                fields.push(("Owner", Borrowed(owner)));
            }
            (
                "⏳",
                format!("Approval Required — {action} by {principal}"),
                fields,
            )
        }
        "approval.granted" => {
            let action = str_field(data, "action_id");
            let by = str_field(data, "approved_by");
            (
                "✅",
                format!("Approved — {action}"),
                vec![
                    ("Action", Borrowed(action)),
                    ("Approved by", Borrowed(by)),
                    ("Receipt", Borrowed(str_field(data, "receipt_id"))),
                ],
            )
        }
        "approval.denied" => {
            let action = str_field(data, "action_id");
            let by = str_field(data, "denied_by");
            let reason = str_field(data, "reason");
            (
                "❌",
                format!("Denied — {action}"),
                vec![
                    ("Action", Borrowed(action)),
                    ("Denied by", Borrowed(by)),
                    ("Reason", Borrowed(reason)),
                ],
            )
        }
        "approval.expired" => {
            let action = str_field(data, "action_id");
            (
                "⏰",
                format!("Approval Expired — {action}"),
                vec![
                    ("Action", Borrowed(action)),
                    ("Principal", Borrowed(str_field(data, "principal"))),
                    ("Created", Borrowed(str_field(data, "created_at"))),
                    ("Expired", Borrowed(str_field(data, "expired_at"))),
                ],
            )
        }
        "action.denied" => {
            let action = str_field(data, "action_id");
            let reason = str_field(data, "deny_reason");
            (
                "🚫",
                format!("Action Denied — {action}"),
                vec![
                    ("Action", Borrowed(action)),
                    ("Principal", Borrowed(str_field(data, "principal"))),
                    ("Reason", Borrowed(reason)),
                ],
            )
        }
        "action.executed" => {
            let action = str_field(data, "action_id");
            (
                "✅",
                format!("Action Executed — {action}"),
                vec![
                    ("Action", Borrowed(action)),
                    ("Principal", Borrowed(str_field(data, "principal"))),
                    (
                        "Verification",
                        Borrowed(str_field(data, "verification_outcome")),
                    ),
                    ("Receipt", Borrowed(str_field(data, "receipt_id"))),
                ],
            )
        }
        "action.failed" => {
            let action = str_field(data, "action_id");
            let error = str_field(data, "error_class");
            (
                "💥",
                format!("Action Failed — {action}"),
                vec![
                    ("Action", Borrowed(action)),
                    ("Principal", Borrowed(str_field(data, "principal"))),
                    ("Error", Borrowed(error)),
                ],
            )
        }
        "revocation" => {
            let old = data.get("old_epoch").and_then(|v| v.as_u64()).unwrap_or(0);
            let new = data.get("new_epoch").and_then(|v| v.as_u64()).unwrap_or(0);
            let op = str_field(data, "operator_id");
            (
                "🔴",
                format!("Revocation — kill-switch by {op}"),
                vec![
                    ("Operator", Borrowed(op)),
                    ("Epoch", Owned(format!("{old} → {new}"))),
                ],
            )
        }
        "budget.exhausted" => {
            let action = str_field(data, "action_id");
            (
                "💰",
                format!("Budget Exhausted — {action}"),
                vec![
                    ("Action", Borrowed(action)),
                    ("Principal", Borrowed(str_field(data, "principal"))),
                    ("Session", Borrowed(str_field(data, "session_id"))),
                ],
            )
        }
        "test" => (
            "🔔",
            "Webhook Test".to_string(),
            vec![
                ("Endpoint", Borrowed(str_field(data, "endpoint_name"))),
                ("Message", Borrowed(str_field(data, "message"))),
            ],
        ),
        other => ("📌", format!("Event: {other}"), vec![]),
    }
}

/// Zero-copy string field extraction from a JSON value.
fn str_field<'a>(data: &'a serde_json::Value, key: &str) -> &'a str {
    data.get(key).and_then(|v| v.as_str()).unwrap_or("")
}

/// Severity-to-color mapping for Discord embeds (decimal RGB).
const DISCORD_RED: u32 = 0xE74C3C;
const DISCORD_YELLOW: u32 = 0xF39C12;
const DISCORD_GREEN: u32 = 0x2ECC71;
const DISCORD_BLUE: u32 = 0x3498DB;

/// Produce a Discord embed message from a webhook payload.
fn format_discord(payload: &WebhookPayload) -> serde_json::Value {
    let (emoji, title, fields) = event_display_parts(&payload.event_type, &payload.data);
    let color = discord_color(&payload.event_type);
    let headline = format!("{emoji} {title}");

    let embed_fields: Vec<serde_json::Value> = fields
        .iter()
        .map(|(k, v)| json!({ "name": k, "value": v.as_ref(), "inline": true }))
        .collect();

    let embed = json!({
        "title": &headline,
        "color": color,
        "fields": embed_fields,
        "footer": { "text": format!("{} · LatchGate {}", payload.id, payload.gate_version) },
        "timestamp": &payload.timestamp,
    });

    json!({ "content": headline, "embeds": [embed] })
}

fn discord_color(event_type: &str) -> u32 {
    match event_type {
        "revocation" | "action.failed" => DISCORD_RED,
        "approval.pending" | "approval.expired" | "budget.exhausted" => DISCORD_YELLOW,
        "action.executed" | "approval.granted" => DISCORD_GREEN,
        _ => DISCORD_BLUE,
    }
}

/// Produce a PagerDuty Events API v2 trigger payload.
///
/// The routing key is read from the endpoint's `X-Routing-Key` header.
/// If absent, the field is set to an empty string — PagerDuty will reject
/// the event with a 400, surfacing the misconfiguration at delivery time
/// rather than silently dropping it.
fn format_pagerduty(
    payload: &WebhookPayload,
    endpoint: &WebhookEndpointConfig,
) -> serde_json::Value {
    let routing_key = endpoint
        .headers
        .get("X-Routing-Key")
        .map(String::as_str)
        .unwrap_or("");

    let (severity, summary) = pagerduty_severity_summary(&payload.event_type, &payload.data);

    let component = payload
        .data
        .get("action_id")
        .and_then(|v| v.as_str())
        .unwrap_or("latchgate");

    let group = payload.event_type.split('.').next().unwrap_or("event");

    json!({
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": &payload.id,
        "payload": {
            "summary": summary,
            "severity": severity,
            "source": "latchgate",
            "component": component,
            "group": group,
            "timestamp": &payload.timestamp,
            "custom_details": &payload.data,
        },
        "links": [],
        "images": [],
    })
}

/// Map event types to PagerDuty severity and a human-readable summary.
fn pagerduty_severity_summary(
    event_type: &str,
    data: &serde_json::Value,
) -> (&'static str, String) {
    match event_type {
        "revocation" => {
            let op = str_field(data, "operator_id");
            (
                "critical",
                format!("LatchGate: Revocation — kill-switch activated by {op}"),
            )
        }
        "action.failed" => {
            let action = str_field(data, "action_id");
            let error = str_field(data, "error_class");
            (
                "error",
                format!("LatchGate: Action failed — {action} ({error})"),
            )
        }
        "budget.exhausted" => {
            let action = str_field(data, "action_id");
            ("error", format!("LatchGate: Budget exhausted — {action}"))
        }
        "approval.pending" => {
            let action = str_field(data, "action_id");
            let risk = str_field(data, "risk_level");
            (
                "warning",
                format!("LatchGate: Approval required — {action} ({risk} risk)"),
            )
        }
        "approval.expired" => {
            let action = str_field(data, "action_id");
            ("warning", format!("LatchGate: Approval expired — {action}"))
        }
        "action.denied" => {
            let action = str_field(data, "action_id");
            ("warning", format!("LatchGate: Action denied — {action}"))
        }
        "action.executed" => {
            let action = str_field(data, "action_id");
            ("info", format!("LatchGate: Action executed — {action}"))
        }
        "approval.granted" => {
            let action = str_field(data, "action_id");
            ("info", format!("LatchGate: Approval granted — {action}"))
        }
        "approval.denied" => {
            let action = str_field(data, "action_id");
            ("info", format!("LatchGate: Approval denied — {action}"))
        }
        "test" => ("info", "LatchGate: Webhook test event".to_string()),
        other => ("info", format!("LatchGate: {other}")),
    }
}

/// Sentinel value for redacted fields.
const REDACTED: &str = "***REDACTED***";

/// Maximum JSON nesting depth before truncation.
const MAX_SUMMARY_DEPTH: usize = 5;

/// String values longer than this (bytes) are truncated in the preview.
const MAX_STRING_PREVIEW_BYTES: usize = 256;

/// Maximum characters to include in a truncated string preview.
const MAX_STRING_PREVIEW_CHARS: usize = 200;

/// Maximum array items to include in the summary.
const MAX_SUMMARY_ARRAY_ITEMS: usize = 10;

/// Lowercase substrings that indicate a JSON key likely holds sensitive data.
///
/// Best-effort heuristic. The evidence ledger — not webhooks — is the
/// authoritative record. Erring on the side of over-redaction is correct:
/// a redacted webhook is an inconvenience; a leaked credential is an incident.
const SENSITIVE_KEY_PATTERNS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "key",
    "credential",
    "auth",
    "api_key",
    "apikey",
    "private",
    "bearer",
    "cookie",
    "session",
    "pin",
    "cvv",
    "ssn",
];

/// Redact sensitive values from a request body before webhook transmission.
///
/// SECURITY: the raw request body may contain credentials, tokens, or other
/// sensitive parameters submitted by the calling agent. This function
/// defensively redacts values at JSON keys that match declared secret names
/// or common sensitive patterns, truncates long string values, and caps
/// nesting depth.
///
/// `secret_names` are the environment variable names declared in the action
/// manifest's `[[secrets]]` section (e.g., `GITHUB_TOKEN`, `DB_PASSWORD`).
/// These are matched case-insensitively against JSON keys.
///
/// # Redaction rules
///
/// 1. Keys matching a declared secret name (case-insensitive) => value
///    replaced with `***REDACTED***`.
/// 2. Keys containing a common sensitive substring (`password`, `token`,
///    `secret`, `key`, `credential`, `auth`, `bearer`, etc.) => value
///    replaced.
/// 3. String values exceeding 256 bytes => truncated with byte count.
/// 4. Arrays exceeding 10 items => truncated with item count.
/// 5. Nesting deeper than 5 levels => replaced with truncation marker.
/// 6. Numbers, booleans, null => passed through unchanged.
pub fn redact_summary<S: AsRef<str>>(
    value: &serde_json::Value,
    secret_names: &[S],
) -> serde_json::Value {
    redact_inner(value, secret_names, 0)
}

/// Check if a JSON key name looks sensitive.
fn is_sensitive_key<S: AsRef<str>>(key: &str, secret_names: &[S]) -> bool {
    let lower = key.to_ascii_lowercase();

    // Exact match against declared secret names (case-insensitive).
    for name in secret_names {
        if lower == name.as_ref().to_ascii_lowercase() {
            return true;
        }
    }

    // Heuristic: key contains a common sensitive substring.
    SENSITIVE_KEY_PATTERNS.iter().any(|p| lower.contains(p))
}

fn redact_inner<S: AsRef<str>>(
    value: &serde_json::Value,
    secret_names: &[S],
    depth: usize,
) -> serde_json::Value {
    if depth > MAX_SUMMARY_DEPTH {
        return json!("***TRUNCATED (max depth)***");
    }

    match value {
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                if is_sensitive_key(k, secret_names) {
                    out.insert(k.clone(), json!(REDACTED));
                } else {
                    out.insert(k.clone(), redact_inner(v, secret_names, depth + 1));
                }
            }
            serde_json::Value::Object(out)
        }

        serde_json::Value::Array(arr) => {
            let mut items: Vec<serde_json::Value> = arr
                .iter()
                .take(MAX_SUMMARY_ARRAY_ITEMS)
                .map(|v| redact_inner(v, secret_names, depth + 1))
                .collect();
            if arr.len() > MAX_SUMMARY_ARRAY_ITEMS {
                items.push(json!(format!(
                    "…[{} more items]",
                    arr.len() - MAX_SUMMARY_ARRAY_ITEMS
                )));
            }
            serde_json::Value::Array(items)
        }

        serde_json::Value::String(s) => {
            if s.len() > MAX_STRING_PREVIEW_BYTES {
                let preview: String = s.chars().take(MAX_STRING_PREVIEW_CHARS).collect();
                json!(format!("{}…[{} bytes total]", preview, s.len()))
            } else {
                value.clone()
            }
        }

        // Numbers, booleans, null — no sensitive data, pass through.
        _ => value.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use latchgate_core::ApprovalPendingEvent;

    #[test]
    fn approval_pending_envelope_has_correct_type() {
        let event = DomainEvent::ApprovalPending(ApprovalPendingEvent {
            approval_id: "apr_001".into(),
            action_id: "github_create_issue".into(),
            principal: "agent-ops".into(),
            owner: Some("alice@company.com".into()),
            risk_level: "high".into(),
            request_hash: "sha256:abc123".into(),
            expires_at: "2025-03-28T14:35:00Z".into(),
            request_body: json!({"owner": "acme", "repo": "app"}),
            secret_names: vec![],
            unresolved_domains: vec![],
            unresolved_paths: vec![],
            trace_id: "trace_001".into(),
        });
        let payload = format_event(&event, "0.1.0");

        assert_eq!(payload.event_type, "approval.pending");
        assert_eq!(payload.gate_version, "0.1.0");
        assert!(payload.id.starts_with("evt_"));
        assert_eq!(payload.data["approval_id"], "apr_001");
        assert_eq!(payload.data["risk_level"], "high");
        assert_eq!(payload.data["request_summary"]["owner"], "acme");
        assert_eq!(payload.data["owner"], "alice@company.com");
    }

    #[test]
    fn approval_pending_redacts_secrets_at_format_time() {
        let event = DomainEvent::ApprovalPending(ApprovalPendingEvent {
            approval_id: "apr_001".into(),
            action_id: "github_create_issue".into(),
            principal: "agent-ops".into(),
            owner: None,
            risk_level: "high".into(),
            request_hash: "sha256:abc123".into(),
            expires_at: "2025-03-28T14:35:00Z".into(),
            request_body: json!({"API_KEY": "secret-value", "url": "https://example.com"}),
            secret_names: vec!["API_KEY".into()],
            unresolved_domains: vec![],
            unresolved_paths: vec![],
            trace_id: "trace_001".into(),
        });
        let payload = format_event(&event, "0.1.0");

        let summary = &payload.data["request_summary"];
        assert_eq!(
            summary["API_KEY"], "***REDACTED***",
            "declared secret must be redacted in webhook payload"
        );
        assert_eq!(
            summary["url"], "https://example.com",
            "non-secret fields must survive redaction"
        );
    }

    #[test]
    fn approval_granted_contains_receipt_id() {
        let event = DomainEvent::ApprovalGranted {
            approval_id: "apr_001".into(),
            action_id: "github_create_issue".into(),
            approved_by: "alice".into(),
            receipt_id: "rct_001".into(),
            trace_id: "trace_002".into(),
        };
        let payload = format_event(&event, "0.1.0");

        assert_eq!(payload.event_type, "approval.granted");
        assert_eq!(payload.data["approved_by"], "alice");
        assert_eq!(payload.data["receipt_id"], "rct_001");
    }

    #[test]
    fn approval_denied_contains_reason() {
        let event = DomainEvent::ApprovalDenied {
            approval_id: "apr_001".into(),
            action_id: "github_create_issue".into(),
            denied_by: "bob".into(),
            reason: "too risky".into(),
            trace_id: "trace_003".into(),
        };
        let payload = format_event(&event, "0.1.0");

        assert_eq!(payload.event_type, "approval.denied");
        assert_eq!(payload.data["reason"], "too risky");
    }

    #[test]
    fn revocation_contains_epochs() {
        let event = DomainEvent::Revocation {
            old_epoch: 4,
            new_epoch: 5,
            operator_id: "alice".into(),
        };
        let payload = format_event(&event, "0.1.0");

        assert_eq!(payload.event_type, "revocation");
        assert_eq!(payload.data["old_epoch"], 4);
        assert_eq!(payload.data["new_epoch"], 5);
    }

    #[test]
    fn budget_exhausted_serializes_fields() {
        let event = DomainEvent::BudgetExhausted {
            action_id: "db_query".into(),
            principal: "agent-data".into(),
            owner: None,
            session_id: "sess_001".into(),
        };
        let payload = format_event(&event, "0.1.0");

        assert_eq!(payload.event_type, "budget.exhausted");
        assert_eq!(payload.data["action_id"], "db_query");
    }

    #[test]
    fn all_event_types_produce_valid_json() {
        let events = all_domain_event_variants();

        for event in &events {
            let payload = format_event(event, "0.1.0");
            // Must round-trip through serde_json without error.
            let json = serde_json::to_string(&payload).expect("payload must serialize");
            let parsed: serde_json::Value =
                serde_json::from_str(&json).expect("payload must be valid JSON");
            assert!(parsed["id"].is_string());
            assert!(parsed["type"].is_string());
            assert!(parsed["timestamp"].is_string());
            assert!(parsed["gate_version"].is_string());
            assert!(parsed["data"].is_object());
        }
    }

    #[test]
    fn envelope_timestamp_is_rfc3339() {
        let event = DomainEvent::Revocation {
            old_epoch: 0,
            new_epoch: 1,
            operator_id: "op".into(),
        };
        let payload = format_event(&event, "0.1.0");
        // RFC 3339 timestamps end with Z for UTC.
        assert!(
            payload.timestamp.ends_with('Z'),
            "timestamp: {}",
            payload.timestamp
        );
        // Must parse back.
        chrono::DateTime::parse_from_rfc3339(&payload.timestamp)
            .expect("timestamp must be valid RFC 3339");
    }

    // -- redact_summary --

    #[test]
    fn redact_passes_through_safe_object() {
        let input = json!({"owner": "acme", "repo": "app", "title": "Deploy hotfix"});
        let result = redact_summary(&input, &[] as &[String]);
        assert_eq!(result, input);
    }

    #[test]
    fn redact_hides_sensitive_keys_by_pattern() {
        let input = json!({
            "username": "alice",
            "password": "hunter2",
            "api_token": "sk-xxx"
        });
        let result = redact_summary(&input, &[] as &[String]);
        assert_eq!(result["username"], "alice");
        assert_eq!(result["password"], "***REDACTED***");
        assert_eq!(result["api_token"], "***REDACTED***");
    }

    #[test]
    fn redact_hides_declared_secret_names() {
        let input = json!({"GITHUB_TOKEN": "ghp_xxx", "repo": "app"});
        let secrets = vec!["GITHUB_TOKEN".to_string()];
        let result = redact_summary(&input, &secrets);
        assert_eq!(result["GITHUB_TOKEN"], "***REDACTED***");
        assert_eq!(result["repo"], "app");
    }

    #[test]
    fn redact_secret_name_matching_is_case_insensitive() {
        let input = json!({"github_token": "ghp_xxx"});
        let secrets = vec!["GITHUB_TOKEN".to_string()];
        let result = redact_summary(&input, &secrets);
        assert_eq!(result["github_token"], "***REDACTED***");
    }

    #[test]
    fn redact_recurses_into_nested_objects() {
        let input = json!({
            "config": {"database_password": "secret123", "host": "db.local"}
        });
        let result = redact_summary(&input, &[] as &[String]);
        assert_eq!(result["config"]["database_password"], "***REDACTED***");
        assert_eq!(result["config"]["host"], "db.local");
    }

    #[test]
    fn redact_truncates_deep_nesting() {
        // Build 7 levels deep — exceeds MAX_SUMMARY_DEPTH (5).
        let mut value = json!("leaf");
        for _ in 0..7 {
            value = json!({"nested": value});
        }
        let result = redact_summary(&value, &[] as &[String]);

        // Walk down — should hit truncation before reaching "leaf".
        let mut cursor = &result;
        let mut found_truncation = false;
        for _ in 0..8 {
            if let Some(s) = cursor.as_str() {
                if s.contains("TRUNCATED") {
                    found_truncation = true;
                    break;
                }
            }
            match cursor.get("nested") {
                Some(next) => cursor = next,
                None => break,
            }
        }
        assert!(found_truncation, "deep nesting must be truncated");
    }

    #[test]
    fn redact_truncates_long_strings() {
        let long_value = "x".repeat(500);
        let input = json!({"query": long_value});
        let result = redact_summary(&input, &[] as &[String]);
        let query_str = result["query"].as_str().unwrap();
        assert!(
            query_str.contains("500 bytes total"),
            "truncated string must include byte count, got: {query_str}"
        );
        assert!(
            query_str.len() < 300,
            "truncated output must be shorter than original"
        );
    }

    #[test]
    fn redact_preserves_short_strings() {
        let input = json!({"name": "alice"});
        let result = redact_summary(&input, &[] as &[String]);
        assert_eq!(result["name"], "alice");
    }

    #[test]
    fn redact_truncates_large_arrays() {
        let arr: Vec<serde_json::Value> = (0..20).map(|i| json!(i)).collect();
        let input = json!({"items": arr});
        let result = redact_summary(&input, &[] as &[String]);
        let items = result["items"].as_array().unwrap();
        // 10 kept items + 1 truncation marker.
        assert_eq!(items.len(), 11);
        let marker = items[10].as_str().unwrap();
        assert!(
            marker.contains("10 more items"),
            "truncation marker: {marker}"
        );
    }

    #[test]
    fn redact_preserves_small_arrays() {
        let input = json!({"tags": ["a", "b", "c"]});
        let result = redact_summary(&input, &[] as &[String]);
        assert_eq!(result["tags"], json!(["a", "b", "c"]));
    }

    #[test]
    fn redact_preserves_numbers_bools_null() {
        let input = json!({"count": 42, "active": true, "metadata": null});
        let result = redact_summary(&input, &[] as &[String]);
        assert_eq!(result, input);
    }

    #[test]
    fn redact_handles_empty_object() {
        assert_eq!(redact_summary(&json!({}), &[] as &[String]), json!({}));
    }

    #[test]
    fn redact_handles_null_input() {
        assert_eq!(redact_summary(&json!(null), &[] as &[String]), json!(null));
    }

    #[test]
    fn redact_catches_multiple_sensitive_patterns() {
        let input = json!({
            "db_password": "pass1",
            "auth_header": "Bearer xxx",
            "session_id": "sess-123",
            "user_credential": "cred",
            "safe_field": "visible"
        });
        let result = redact_summary(&input, &[] as &[String]);
        assert_eq!(result["db_password"], "***REDACTED***");
        assert_eq!(result["auth_header"], "***REDACTED***");
        assert_eq!(result["session_id"], "***REDACTED***");
        assert_eq!(result["user_credential"], "***REDACTED***");
        assert_eq!(result["safe_field"], "visible");
    }

    #[test]
    fn redact_combines_declared_and_pattern_matching() {
        let input = json!({
            "CUSTOM_SECRET": "val1",
            "password": "val2",
            "name": "visible"
        });
        let secrets = vec!["CUSTOM_SECRET".to_string()];
        let result = redact_summary(&input, &secrets);
        assert_eq!(result["CUSTOM_SECRET"], "***REDACTED***");
        assert_eq!(result["password"], "***REDACTED***");
        assert_eq!(result["name"], "visible");
    }

    #[test]
    fn redact_redacts_inside_arrays_of_objects() {
        let input = json!([
            {"host": "db.local", "password": "secret"},
            {"host": "cache.local", "token": "tok"}
        ]);
        let result = redact_summary(&input, &[] as &[String]);
        let arr = result.as_array().unwrap();
        assert_eq!(arr[0]["host"], "db.local");
        assert_eq!(arr[0]["password"], "***REDACTED***");
        assert_eq!(arr[1]["token"], "***REDACTED***");
    }

    // -- Test fixture --

    /// All 9 `DomainEvent` variants for exhaustive tests.
    fn all_domain_event_variants() -> Vec<DomainEvent> {
        vec![
            DomainEvent::ApprovalPending(ApprovalPendingEvent {
                approval_id: "a".into(),
                action_id: "b".into(),
                principal: "c".into(),
                owner: None,
                risk_level: "low".into(),
                request_hash: "sha256:x".into(),
                expires_at: "t".into(),
                request_body: json!(null),
                secret_names: vec![],
                unresolved_domains: vec![],
                unresolved_paths: vec![],
                trace_id: "t".into(),
            }),
            DomainEvent::ApprovalGranted {
                approval_id: "a".into(),
                action_id: "b".into(),
                approved_by: "c".into(),
                receipt_id: "r".into(),
                trace_id: "t".into(),
            },
            DomainEvent::ApprovalDenied {
                approval_id: "a".into(),
                action_id: "b".into(),
                denied_by: "c".into(),
                reason: "r".into(),
                trace_id: "t".into(),
            },
            DomainEvent::ApprovalExpired {
                approval_id: "a".into(),
                action_id: "b".into(),
                principal: "c".into(),
                owner: None,
                created_at: "t1".into(),
                expired_at: "t2".into(),
            },
            DomainEvent::ActionDenied {
                action_id: "b".into(),
                principal: "c".into(),
                owner: None,
                deny_reason: "r".into(),
                trace_id: "t".into(),
            },
            DomainEvent::ActionExecuted {
                action_id: "b".into(),
                principal: "c".into(),
                owner: None,
                receipt_id: "r".into(),
                verification_outcome: "pass".into(),
                trace_id: "t".into(),
            },
            DomainEvent::ActionFailed {
                action_id: "b".into(),
                principal: "c".into(),
                owner: None,
                error_class: "timeout".into(),
                trace_id: "t".into(),
            },
            DomainEvent::Revocation {
                old_epoch: 0,
                new_epoch: 1,
                operator_id: "op".into(),
            },
            DomainEvent::BudgetExhausted {
                action_id: "b".into(),
                principal: "c".into(),
                owner: None,
                session_id: "s".into(),
            },
        ]
    }

    // -- Platform formatter tests --

    fn test_payload(event_type: &str, data: serde_json::Value) -> WebhookPayload {
        WebhookPayload {
            id: "evt_test_001".into(),
            event_type: event_type.into(),
            timestamp: "2025-06-01T12:00:00Z".into(),
            gate_version: "0.1.0".into(),
            data,
        }
    }

    fn generic_endpoint() -> crate::config::WebhookEndpointConfig {
        crate::config::WebhookEndpointConfig {
            name: "test".into(),
            url: "https://example.com/hook".into(),
            secret: "whsec_test".into(),
            events: vec![],
            headers: std::collections::HashMap::new(),
            timeout_seconds: 5,
            max_retries: 0,
            retry_backoff_seconds: vec![],
            disable: false,
            format: crate::config::WebhookFormat::Generic,
        }
    }

    #[test]
    fn slack_revocation_has_valid_block_kit() {
        let payload = test_payload(
            "revocation",
            json!({
                "old_epoch": 2,
                "new_epoch": 3,
                "operator_id": "alice",
            }),
        );
        let out = format_slack(&payload);

        // Required fallback text.
        let text = out["text"].as_str().unwrap();
        assert!(text.contains("Revocation"), "text: {text}");
        assert!(text.contains("alice"), "text: {text}");

        // Blocks structure.
        let blocks = out["blocks"].as_array().unwrap();
        assert_eq!(blocks[0]["type"], "header");
        assert_eq!(blocks[1]["type"], "section");
        assert_eq!(blocks[2]["type"], "context");

        // Fields contain operator and epoch.
        let fields = blocks[1]["fields"].as_array().unwrap();
        let field_text: Vec<&str> = fields.iter().map(|f| f["text"].as_str().unwrap()).collect();
        assert!(field_text.iter().any(|t| t.contains("alice")));
        assert!(field_text.iter().any(|t| t.contains("2 → 3")));
    }

    #[test]
    fn slack_approval_pending_includes_optional_owner() {
        let payload = test_payload(
            "approval.pending",
            json!({
                "action_id": "deploy",
                "principal": "agent-x",
                "risk_level": "high",
                "expires_at": "2025-06-01T13:00:00Z",
                "owner": "bob@corp.com",
            }),
        );
        let out = format_slack(&payload);
        let fields = out["blocks"][1]["fields"].as_array().unwrap();
        let field_text: Vec<&str> = fields.iter().map(|f| f["text"].as_str().unwrap()).collect();
        assert!(field_text.iter().any(|t| t.contains("bob@corp.com")));
        assert_eq!(fields.len(), 5); // Action, Principal, Risk, Expires, Owner
    }

    #[test]
    fn discord_revocation_is_red() {
        let payload = test_payload(
            "revocation",
            json!({
                "old_epoch": 0, "new_epoch": 1, "operator_id": "op1",
            }),
        );
        let out = format_discord(&payload);

        assert_eq!(out["embeds"][0]["color"], DISCORD_RED);
        assert!(out["content"].as_str().unwrap().contains("Revocation"));
        // Title and content are the same string.
        assert_eq!(out["content"], out["embeds"][0]["title"]);
    }

    #[test]
    fn discord_color_mapping() {
        assert_eq!(discord_color("revocation"), DISCORD_RED);
        assert_eq!(discord_color("action.failed"), DISCORD_RED);
        assert_eq!(discord_color("approval.pending"), DISCORD_YELLOW);
        assert_eq!(discord_color("budget.exhausted"), DISCORD_YELLOW);
        assert_eq!(discord_color("action.executed"), DISCORD_GREEN);
        assert_eq!(discord_color("approval.granted"), DISCORD_GREEN);
        assert_eq!(discord_color("test"), DISCORD_BLUE);
        assert_eq!(discord_color("unknown.event"), DISCORD_BLUE);
    }

    #[test]
    fn pagerduty_revocation_is_critical() {
        let mut ep = generic_endpoint();
        ep.format = crate::config::WebhookFormat::PagerDuty;
        ep.headers
            .insert("X-Routing-Key".into(), "test-key-123".into());

        let payload = test_payload(
            "revocation",
            json!({
                "old_epoch": 5, "new_epoch": 6, "operator_id": "eve",
            }),
        );
        let out = format_pagerduty(&payload, &ep);

        assert_eq!(out["routing_key"], "test-key-123");
        assert_eq!(out["event_action"], "trigger");
        assert_eq!(out["dedup_key"], "evt_test_001");
        assert_eq!(out["payload"]["severity"], "critical");
        assert!(out["payload"]["summary"].as_str().unwrap().contains("eve"));
        assert_eq!(out["payload"]["source"], "latchgate");
        assert_eq!(out["payload"]["group"], "revocation");
    }

    #[test]
    fn pagerduty_missing_routing_key_sends_empty() {
        let mut ep = generic_endpoint();
        ep.format = crate::config::WebhookFormat::PagerDuty;
        // No X-Routing-Key header.

        let payload = test_payload("test", json!({"message": "ping"}));
        let out = format_pagerduty(&payload, &ep);
        assert_eq!(out["routing_key"], "");
    }

    #[test]
    fn pagerduty_severity_mapping() {
        let cases = [
            ("revocation", "critical"),
            ("action.failed", "error"),
            ("budget.exhausted", "error"),
            ("approval.pending", "warning"),
            ("approval.expired", "warning"),
            ("action.denied", "warning"),
            ("action.executed", "info"),
            ("approval.granted", "info"),
            ("test", "info"),
        ];
        for (event_type, expected) in cases {
            let (severity, _) = pagerduty_severity_summary(event_type, &json!({}));
            assert_eq!(severity, expected, "event: {event_type}");
        }
    }

    #[test]
    fn format_for_endpoint_dispatches_by_format() {
        let payload = test_payload("test", json!({"message": "ping", "endpoint_name": "e"}));

        let mut ep = generic_endpoint();
        let generic = format_for_endpoint(&payload, &ep);
        assert_eq!(generic["type"], "test"); // generic envelope

        ep.format = crate::config::WebhookFormat::Slack;
        let slack = format_for_endpoint(&payload, &ep);
        assert!(slack.get("blocks").is_some()); // Block Kit

        ep.format = crate::config::WebhookFormat::Discord;
        let discord = format_for_endpoint(&payload, &ep);
        assert!(discord.get("embeds").is_some()); // Embed

        ep.format = crate::config::WebhookFormat::PagerDuty;
        let pd = format_for_endpoint(&payload, &ep);
        assert_eq!(pd["event_action"], "trigger"); // Events API v2
    }
}
