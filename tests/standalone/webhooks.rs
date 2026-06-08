//! Webhook integration tests.
//!
//! Verifies the full webhook pipeline: config parsing through the top-level
//! `Config` struct, dispatcher lifecycle, and event formatting. No Docker
//! required.
//!
//! Signing round-trip, SSRF protection, and event-type exhaustiveness are
//! covered by unit tests in `latchgate-webhooks::delivery`,
//! `latchgate-core::net`, and `latchgate-webhooks::dispatcher`.

use std::collections::HashMap;

use latchgate_config::Config;
use latchgate_core::DomainEvent;
use latchgate_webhooks::{EventKind, WebhookDispatcher, WebhookEndpointConfig};

// ---------------------------------------------------------------------------
// Config integration — [[webhooks]] TOML sections through Config::from_file
// ---------------------------------------------------------------------------

/// [[webhooks]] TOML sections survive Config deserialization and parse
/// into typed WebhookEndpointConfig with correct defaults applied.
#[test]
fn webhooks_config_round_trips_through_config_struct() {
    let toml_str = r#"
log_level = "info"

[[webhooks]]
name = "slack"
url = "https://hooks.slack.com/services/T/B/x"
secret = "whsec_test"
events = ["approval.pending", "approval.expired"]

[[webhooks]]
name = "siem"
url = "https://siem.corp.internal/v1/events"
secret = "whsec_siem"
events = ["action.denied", "revocation"]
headers = { "Authorization" = "Bearer token123" }
timeout_seconds = 10
"#;

    let config: Config = toml::from_str(toml_str).unwrap();
    assert_eq!(config.webhooks.len(), 2);

    let typed: Vec<WebhookEndpointConfig> = config
        .webhooks
        .iter()
        .map(|v| v.clone().try_into().unwrap())
        .collect();

    assert_eq!(typed[0].name, "slack");
    assert_eq!(typed[0].events.len(), 2);
    assert_eq!(typed[0].events[0], EventKind::ApprovalPending);
    assert_eq!(typed[0].events[1], EventKind::ApprovalExpired);
    assert_eq!(typed[0].timeout_seconds, 5);
    assert_eq!(typed[0].max_retries, 3);

    assert_eq!(typed[1].name, "siem");
    assert_eq!(typed[1].timeout_seconds, 10);
    assert_eq!(typed[1].headers["Authorization"], "Bearer token123");
}

/// Config with no [[webhooks]] section defaults to empty vec.
#[test]
fn config_without_webhooks_has_empty_vec() {
    let config = Config::default();
    assert!(config.webhooks.is_empty());
}

/// Config with an unknown webhook event type fails deserialization.
#[test]
fn config_with_unknown_webhook_event_fails() {
    let toml_str = r#"
[[webhooks]]
name = "bad"
url = "https://example.com/hook"
secret = "s"
events = ["nonexistent.type"]
"#;

    let config: Config = toml::from_str(toml_str).unwrap();
    let result: Result<WebhookEndpointConfig, _> = config.webhooks[0].clone().try_into();
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Dispatcher lifecycle
// ---------------------------------------------------------------------------

/// Dispatcher starts and accepts events without endpoints configured.
#[tokio::test]
async fn dispatcher_starts_with_empty_config() {
    let dispatcher = WebhookDispatcher::start(vec![], "0.1.0", false).unwrap();
    assert!(dispatcher.is_active());
    assert_eq!(dispatcher.gate_version(), "0.1.0");
}

/// Dispatcher rejects config with HTTP URL in production mode.
#[tokio::test]
async fn dispatcher_rejects_http_in_production() {
    let configs = vec![WebhookEndpointConfig {
        name: "bad".into(),
        url: "http://example.com/hook".into(),
        secret: "whsec_test".into(),
        events: vec![EventKind::Revocation],
        headers: HashMap::new(),
        timeout_seconds: 5,
        max_retries: 0,
        retry_backoff_seconds: vec![],
        disable: false,
        format: latchgate_webhooks::WebhookFormat::Generic,
    }];
    let result = WebhookDispatcher::start(configs, "0.1.0", false);
    assert!(result.is_err());
}

/// Events sent to the dispatcher are accepted without panic or blocking.
#[tokio::test]
async fn dispatcher_accepts_all_event_types() {
    let configs = vec![WebhookEndpointConfig {
        name: "test".into(),
        url: "https://example.com/hook".into(),
        secret: "whsec_test".into(),
        events: vec![
            EventKind::ApprovalPending,
            EventKind::ApprovalGranted,
            EventKind::ApprovalDenied,
            EventKind::ApprovalExpired,
            EventKind::ActionDenied,
            EventKind::ActionExecuted,
            EventKind::ActionFailed,
            EventKind::Revocation,
            EventKind::BudgetExhausted,
        ],
        headers: HashMap::new(),
        timeout_seconds: 1,
        max_retries: 0,
        retry_backoff_seconds: vec![],
        disable: false,
        format: latchgate_webhooks::WebhookFormat::Generic,
    }];
    let dispatcher = WebhookDispatcher::start(configs, "0.1.0", false).unwrap();

    let events: Vec<DomainEvent> = vec![
        DomainEvent::ApprovalPending(latchgate_core::ApprovalPendingEvent {
            approval_id: "a".into(),
            action_id: "b".into(),
            principal: "c".into(),
            owner: None,
            risk_level: "high".into(),
            request_hash: "h".into(),
            expires_at: "t".into(),
            request_body: serde_json::json!(null),
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
    ];

    for event in events {
        assert!(dispatcher.send(event).is_ok());
    }
}

// ---------------------------------------------------------------------------
// Formatter envelope
// ---------------------------------------------------------------------------

/// format_event produces valid JSON with all required envelope fields.
#[test]
fn format_event_produces_valid_envelope() {
    let event = DomainEvent::Revocation {
        old_epoch: 3,
        new_epoch: 4,
        operator_id: "alice".into(),
    };
    let payload = latchgate_webhooks::format_event(&event, "0.1.0");

    let json = serde_json::to_string(&payload).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert!(parsed["id"].as_str().unwrap().starts_with("evt_"));
    assert_eq!(parsed["type"], "revocation");
    assert!(parsed["timestamp"].as_str().unwrap().ends_with('Z'));
    assert_eq!(parsed["gate_version"], "0.1.0");
    assert_eq!(parsed["data"]["old_epoch"], 3);
    assert_eq!(parsed["data"]["new_epoch"], 4);
    assert_eq!(parsed["data"]["operator_id"], "alice");
}
