//! Non-blocking webhook event dispatcher with graceful shutdown.
//!
//! Receives [`DomainEvent`]s through a bounded async channel, matches them
//! to subscribed endpoints, and spawns a delivery task per endpoint.
//! Delivery never blocks the enforcement pipeline.

use std::sync::Arc;

use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use latchgate_core::{DomainEvent, EventSink};

use crate::config::WebhookEndpointConfig;
use crate::{config, delivery, formatter, WebhookError};

const CHANNEL_CAPACITY: usize = 1024;

/// 10 seconds — enough for most first-retry deliveries
/// but won't block process shutdown for a full retry cycle (1+5+30=36s).
const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

const SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(12);

/// Non-blocking webhook event dispatcher with graceful shutdown.
///
/// Cloneable — all clones share the same channel and shutdown handle.
/// `shutdown()` is safe to call from any clone; subsequent calls are no-ops.
///
/// # Lifecycle
///
/// 1. `WebhookDispatcher::start()` — validates config, spawns background loop.
/// 2. `dispatcher.send(event)` — non-blocking channel send (returns immediately).
/// 3. `dispatcher.shutdown()` — signals the loop to stop, drains queued events,
///    waits up to 10 seconds for in-flight deliveries, then aborts stragglers.
///
/// The background loop matches each event to subscribed endpoints and spawns
/// a delivery task per endpoint via `JoinSet`. On shutdown, the `JoinSet` is
/// drained with a timeout — deliveries that complete in time succeed; those
/// still in-flight are aborted.
#[derive(Clone)]
pub struct WebhookDispatcher {
    tx: mpsc::Sender<DomainEvent>,
    /// Gate version stamped into every payload envelope.
    gate_version: String,
    /// Shared shutdown state. Signal to initiate graceful drain.
    shutdown_tx: Arc<watch::Sender<bool>>,
    /// Handle to the background dispatch loop task. Taken by the first
    /// `shutdown()` call; subsequent calls on any clone are no-ops.
    loop_handle: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl WebhookDispatcher {
    /// Validate config and start the background dispatch loop.
    ///
    /// Returns an error if any webhook endpoint config is invalid.
    /// On success, the dispatcher is ready to accept events.
    pub fn start(
        configs: Vec<WebhookEndpointConfig>,
        gate_version: &str,
        dev_mode: bool,
    ) -> Result<Self, WebhookError> {
        let validated = config::validate_webhook_configs(configs, dev_mode)?;

        // Filter out disabled endpoints. Wrap in Arc so dispatch_event
        // can share endpoint configs across spawned delivery tasks without
        // cloning the full struct (including the HMAC secret) per event.
        let active: Vec<Arc<WebhookEndpointConfig>> = validated
            .into_iter()
            .filter(|c| !c.disable)
            .map(Arc::new)
            .collect();

        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let gv = gate_version.to_string();

        if active.is_empty() {
            info!("no active webhook endpoints configured — dispatcher idle");
        } else {
            info!(endpoints = active.len(), "webhook dispatcher started");
        }

        let gv_clone = gv.clone();
        let handle = tokio::spawn(async move {
            dispatch_loop(rx, active, &gv_clone, dev_mode, shutdown_rx).await;
        });

        Ok(Self {
            tx,
            gate_version: gv,
            shutdown_tx: Arc::new(shutdown_tx),
            loop_handle: Arc::new(tokio::sync::Mutex::new(Some(handle))),
        })
    }

    /// Send a domain event to the dispatcher. Non-blocking.
    ///
    /// Returns `Ok(())` on success, `Err(WebhookError::ChannelFull)` if
    /// the channel is at capacity (event is dropped — this is by design).
    pub fn send(&self, event: DomainEvent) -> Result<(), WebhookError> {
        match self.tx.try_send(event) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(dropped)) => {
                warn!(
                    event_type = %dropped.kind(),
                    "webhook channel full — event dropped"
                );
                Err(WebhookError::ChannelFull)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(WebhookError::ChannelClosed),
        }
    }

    /// Graceful shutdown: drain queued events, wait for in-flight deliveries.
    ///
    /// Signals the background dispatch loop to stop accepting new events,
    /// drain remaining channel items, and wait for in-flight delivery tasks
    /// to complete (bounded by `DRAIN_TIMEOUT`). Deliveries still in-flight
    /// after the timeout are aborted.
    ///
    /// Safe to call from any clone. The first call drives shutdown; subsequent
    /// calls on any clone return immediately. Total wait is bounded by
    /// `SHUTDOWN_TIMEOUT` (12 seconds).
    pub async fn shutdown(&self) {
        // Signal the dispatch loop to stop.
        let _ = self.shutdown_tx.send(true);

        // Take the loop handle — first caller wins.
        let handle = self.loop_handle.lock().await.take();
        if let Some(h) = handle {
            match tokio::time::timeout(SHUTDOWN_TIMEOUT, h).await {
                Ok(Ok(())) => {
                    debug!("webhook dispatcher shut down gracefully");
                }
                Ok(Err(e)) => {
                    warn!(error = %e, "webhook dispatch loop panicked during shutdown");
                }
                Err(_) => {
                    warn!(
                        "webhook shutdown timed out after {}s",
                        SHUTDOWN_TIMEOUT.as_secs()
                    );
                }
            }
        }
    }

    /// Return the number of events pending in the channel (diagnostic).
    pub fn pending_count(&self) -> usize {
        CHANNEL_CAPACITY - self.tx.capacity()
    }

    /// Whether the dispatcher has active endpoint subscriptions.
    pub fn is_active(&self) -> bool {
        !self.tx.is_closed()
    }

    /// Return the gate version stamped into payloads.
    pub fn gate_version(&self) -> &str {
        &self.gate_version
    }
}

/// Receives events from the channel, matches them to subscribed endpoints,
/// and spawns a delivery task per matching endpoint in a `JoinSet`.
///
/// On shutdown (signal or channel close), drains remaining queued events
/// and waits for all in-flight delivery tasks with `DRAIN_TIMEOUT`.
async fn dispatch_loop(
    mut rx: mpsc::Receiver<DomainEvent>,
    endpoints: Vec<Arc<WebhookEndpointConfig>>,
    gate_version: &str,
    dev_mode: bool,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut deliveries = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            biased;

            // Shutdown signal takes priority — stop accepting new events.
            _ = shutdown_rx.changed() => {
                debug!("webhook dispatch loop: shutdown signal received");
                break;
            }

            event = rx.recv() => {
                match event {
                    Some(e) => {
                        dispatch_event(
                            &e, &endpoints, gate_version, dev_mode, &mut deliveries,
                        );
                    }
                    None => break, // all senders dropped
                }
            }
        }
    }

    // Drain remaining queued events. These were already in the channel buffer
    // when shutdown was signaled — dispatch them so the webhook is attempted.
    let mut drained = 0u32;
    while let Ok(event) = rx.try_recv() {
        dispatch_event(&event, &endpoints, gate_version, dev_mode, &mut deliveries);
        drained += 1;
    }
    if drained > 0 {
        debug!(drained, "webhook dispatch loop: drained queued events");
    }

    // Wait for in-flight delivery tasks, bounded by DRAIN_TIMEOUT.
    let pending = deliveries.len();
    if pending > 0 {
        debug!(
            pending,
            "waiting for in-flight webhook deliveries to complete"
        );
        let deadline = tokio::time::sleep(DRAIN_TIMEOUT);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                biased;

                _ = &mut deadline => {
                    let remaining = deliveries.len();
                    if remaining > 0 {
                        warn!(
                            remaining,
                            timeout_seconds = DRAIN_TIMEOUT.as_secs(),
                            "webhook drain timeout — aborting remaining deliveries"
                        );
                        deliveries.abort_all();
                    }
                    break;
                }

                result = deliveries.join_next() => {
                    match result {
                        Some(Ok(())) => {} // delivery task completed
                        Some(Err(e)) if e.is_cancelled() => {
                            debug!("webhook delivery task cancelled during shutdown");
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "webhook delivery task panicked");
                        }
                        None => break, // all tasks completed
                    }
                }
            }
        }
    }

    debug!("webhook dispatch loop terminated");
}

/// Format one event and spawn a delivery task per matching endpoint.
///
/// Endpoint configs and the formatted payload are shared via `Arc` — each
/// spawned task bumps a reference count instead of deep-cloning the config
/// (which includes the HMAC signing secret) and the JSON Value tree.
fn dispatch_event(
    event: &DomainEvent,
    endpoints: &[Arc<WebhookEndpointConfig>],
    gate_version: &str,
    dev_mode: bool,
    deliveries: &mut tokio::task::JoinSet<()>,
) {
    let wh_event_type = event.kind();
    let payload = Arc::new(formatter::format_event(event, gate_version));

    for ep in endpoints {
        if ep.events.contains(&wh_event_type) {
            let ep = Arc::clone(ep);
            let payload = Arc::clone(&payload);
            deliveries.spawn(async move {
                // Fire-and-forget in async channel mode. deliver() logs
                // success/failure internally; Result is intentionally dropped.
                let _ = delivery::deliver(&ep, &payload, dev_mode).await;
            });
        }
    }
}

impl EventSink for WebhookDispatcher {
    fn emit(&self, event: &DomainEvent) {
        if let Err(e) = self.send(event.clone()) {
            match e {
                WebhookError::ChannelFull => {
                    // Already logged inside send().
                }
                WebhookError::ChannelClosed => {
                    warn!("webhook dispatcher channel closed — event dropped");
                }
                _ => {
                    warn!(error = %e, "webhook event dropped — unexpected dispatcher error");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EventKind;
    use serde::Deserialize;
    use std::collections::HashMap;

    fn test_endpoint(name: &str, events: Vec<EventKind>) -> WebhookEndpointConfig {
        WebhookEndpointConfig {
            name: name.into(),
            url: "https://example.com/hook".into(),
            secret: "whsec_test".into(),
            events,
            headers: HashMap::new(),
            timeout_seconds: 5,
            max_retries: 0,
            retry_backoff_seconds: vec![],
            disable: false,
            format: crate::config::WebhookFormat::Generic,
        }
    }

    // -- EventKind serde --

    #[test]
    fn event_type_serializes_to_dotted_string() {
        assert_eq!(
            serde_json::to_string(&EventKind::ApprovalPending).unwrap(),
            "\"approval.pending\""
        );
        assert_eq!(
            serde_json::to_string(&EventKind::ActionDenied).unwrap(),
            "\"action.denied\""
        );
        assert_eq!(
            serde_json::to_string(&EventKind::Revocation).unwrap(),
            "\"revocation\""
        );
        assert_eq!(
            serde_json::to_string(&EventKind::BudgetExhausted).unwrap(),
            "\"budget.exhausted\""
        );
    }

    #[test]
    fn event_type_deserializes_from_dotted_string() {
        let ty: EventKind = serde_json::from_str("\"approval.granted\"").unwrap();
        assert_eq!(ty, EventKind::ApprovalGranted);
    }

    #[test]
    fn unknown_event_type_fails_deserialization() {
        let result: Result<EventKind, _> = serde_json::from_str("\"unknown.type\"");
        assert!(result.is_err());
    }

    // -- event_type mapping --

    #[test]
    fn domain_event_maps_to_correct_webhook_type() {
        let event = DomainEvent::Revocation {
            old_epoch: 0,
            new_epoch: 1,
            operator_id: "op".into(),
        };
        assert_eq!(event.kind(), EventKind::Revocation);
    }

    #[test]
    fn all_domain_variants_map_to_distinct_types() {
        use std::collections::HashSet;

        let events = vec![
            DomainEvent::ApprovalPending(latchgate_core::ApprovalPendingEvent {
                approval_id: "a".into(),
                action_id: "b".into(),
                principal: "c".into(),
                owner: None,
                risk_level: "low".into(),
                request_hash: "h".into(),
                expires_at: "t".into(),
                request_body: serde_json::Value::Null,
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
            DomainEvent::BudgetRollbackFailed {
                session_id: "s".into(),
                error: "connection refused".into(),
                trace_id: "t".into(),
                label: "dispatch_error".into(),
            },
        ];

        let types: HashSet<EventKind> = events.iter().map(|e| e.kind()).collect();
        assert_eq!(types.len(), 10, "all 10 event types must be distinct");
    }

    // -- Dispatcher --

    #[tokio::test]
    async fn dispatcher_starts_with_no_endpoints() {
        let dispatcher = WebhookDispatcher::start(vec![], "0.1.0", false).unwrap();
        assert!(dispatcher.is_active());
    }

    #[tokio::test]
    async fn dispatcher_starts_with_valid_endpoints() {
        let eps = vec![test_endpoint("slack", vec![EventKind::ApprovalPending])];
        let dispatcher = WebhookDispatcher::start(eps, "0.1.0", false).unwrap();
        assert!(dispatcher.is_active());
    }

    #[tokio::test]
    async fn dispatcher_rejects_invalid_config() {
        let eps = vec![WebhookEndpointConfig {
            name: "bad".into(),
            url: "not-a-url".into(),
            secret: "s".into(),
            events: vec![EventKind::Revocation],
            headers: HashMap::new(),
            timeout_seconds: 5,
            max_retries: 0,
            retry_backoff_seconds: vec![],
            disable: false,
            format: crate::config::WebhookFormat::Generic,
        }];
        let result = WebhookDispatcher::start(eps, "0.1.0", false);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn send_returns_ok_when_channel_has_capacity() {
        let eps = vec![test_endpoint("test", vec![EventKind::Revocation])];
        let dispatcher = WebhookDispatcher::start(eps, "0.1.0", false).unwrap();

        let event = DomainEvent::Revocation {
            old_epoch: 0,
            new_epoch: 1,
            operator_id: "alice".into(),
        };
        assert!(dispatcher.send(event).is_ok());
    }

    #[tokio::test]
    async fn disabled_endpoints_are_filtered_out() {
        let mut ep = test_endpoint("disabled", vec![EventKind::Revocation]);
        ep.disable = true;
        // Should start fine — disabled endpoints are validated but not delivered to.
        let dispatcher = WebhookDispatcher::start(vec![ep], "0.1.0", false).unwrap();
        assert!(dispatcher.is_active());
    }

    #[tokio::test]
    async fn gate_version_is_preserved() {
        let dispatcher = WebhookDispatcher::start(vec![], "1.2.3", false).unwrap();
        assert_eq!(dispatcher.gate_version(), "1.2.3");
    }

    // -- Config TOML deserialization --

    #[test]
    fn webhook_config_deserializes_from_toml() {
        let toml_str = r#"
name = "slack-approvals"
url = "https://hooks.slack.com/services/T/B/x"
secret = "whsec_test"
events = ["approval.pending", "approval.expired"]
"#;
        let cfg: WebhookEndpointConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.name, "slack-approvals");
        assert_eq!(cfg.events.len(), 2);
        assert_eq!(cfg.events[0], EventKind::ApprovalPending);
        assert_eq!(cfg.events[1], EventKind::ApprovalExpired);
        // Defaults applied:
        assert_eq!(cfg.timeout_seconds, 5);
        assert_eq!(cfg.max_retries, 3);
        assert_eq!(cfg.retry_backoff_seconds, vec![1, 5, 30]);
        assert!(!cfg.disable);
    }

    #[test]
    fn webhook_config_with_all_fields() {
        let toml_str = r#"
name = "siem"
url = "https://siem.corp/v1/events"
secret = "whsec_siem"
events = ["action.denied", "revocation"]
timeout_seconds = 10
max_retries = 5
retry_backoff_seconds = [2, 10, 60]
disable = false

[headers]
Authorization = "Bearer token123"
X-Custom = "value"
"#;
        let cfg: WebhookEndpointConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.timeout_seconds, 10);
        assert_eq!(cfg.max_retries, 5);
        assert_eq!(cfg.headers.len(), 2);
        assert_eq!(cfg.headers["Authorization"], "Bearer token123");
    }

    #[test]
    fn unknown_event_type_in_toml_fails() {
        let toml_str = r#"
name = "bad"
url = "https://example.com/hook"
secret = "s"
events = ["nonexistent.event"]
"#;
        let result: Result<WebhookEndpointConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    // -- TOML array table (simulates latchgate.toml [[webhooks]] sections) --

    #[test]
    fn multiple_webhooks_from_toml_array_table() {
        #[derive(Deserialize)]
        struct Outer {
            webhooks: Vec<WebhookEndpointConfig>,
        }

        let toml_str = r#"
[[webhooks]]
name = "slack"
url = "https://hooks.slack.com/x"
secret = "whsec_a"
events = ["approval.pending"]

[[webhooks]]
name = "siem"
url = "https://siem.corp/v1"
secret = "whsec_b"
events = ["action.denied", "revocation"]
"#;
        let outer: Outer = toml::from_str(toml_str).unwrap();
        assert_eq!(outer.webhooks.len(), 2);
        assert_eq!(outer.webhooks[0].name, "slack");
        assert_eq!(outer.webhooks[1].events.len(), 2);
    }

    // -- Shutdown --

    #[tokio::test]
    async fn shutdown_completes_without_panic() {
        let dispatcher = WebhookDispatcher::start(vec![], "0.1.0", false).unwrap();
        dispatcher.shutdown().await;
        // After shutdown, channel is closed — send should fail.
        let event = DomainEvent::Revocation {
            old_epoch: 0,
            new_epoch: 1,
            operator_id: "op".into(),
        };
        assert!(dispatcher.send(event).is_err());
    }

    #[tokio::test]
    async fn shutdown_is_idempotent() {
        let dispatcher = WebhookDispatcher::start(vec![], "0.1.0", false).unwrap();
        // Both calls should complete without panic or deadlock.
        dispatcher.shutdown().await;
        dispatcher.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_from_clone_works() {
        let dispatcher = WebhookDispatcher::start(vec![], "0.1.0", false).unwrap();
        let clone = dispatcher.clone();
        // Shutdown from the clone — original should also see closed channel.
        clone.shutdown().await;
        assert!(!dispatcher.is_active());
    }

    #[tokio::test]
    async fn shutdown_with_pending_events_drains_channel() {
        // Pause tokio time so DRAIN_TIMEOUT / SHUTDOWN_TIMEOUT fire instantly.
        // Delivery tasks to the unreachable URL get aborted by the drain
        // deadline without waiting for real network I/O.
        tokio::time::pause();

        let eps = vec![test_endpoint("test", vec![EventKind::Revocation])];
        let dispatcher = WebhookDispatcher::start(eps, "0.1.0", false).unwrap();

        // Send a few events before shutdown.
        for i in 0..5 {
            let _ = dispatcher.send(DomainEvent::Revocation {
                old_epoch: i,
                new_epoch: i + 1,
                operator_id: "alice".into(),
            });
        }

        // Shutdown should complete — drain aborts unreachable deliveries via
        // DRAIN_TIMEOUT which fires immediately under paused time.
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(30), dispatcher.shutdown()).await;
        assert!(result.is_ok(), "shutdown must not hang");
    }

    #[tokio::test]
    async fn is_active_returns_false_after_shutdown() {
        let dispatcher = WebhookDispatcher::start(vec![], "0.1.0", false).unwrap();
        assert!(dispatcher.is_active());
        dispatcher.shutdown().await;
        // The dispatch loop has exited — channel receiver is dropped,
        // which closes the channel.
        assert!(!dispatcher.is_active());
    }
}
