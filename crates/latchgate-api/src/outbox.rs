//! Background webhook outbox poller.
//!
//! Periodically reads pending entries from the webhook outbox's own SQLite
//! database and delivers them via the webhook delivery module. This is the
//! "read" half of the transactional outbox pattern — events are persisted
//! before any delivery attempt, ensuring zero event loss under crashes.
//!
//! # Lifecycle
//!
//! The poller runs as a background tokio task started from `server.rs`.
//! It polls every `poll_interval` and processes up to `batch_size` entries
//! per cycle. On shutdown signal, it completes the current batch and exits.
//!
//! # Poller identity
//!
//! Each poller instance generates a random `poller_id` at startup. This ID
//! is passed to [`WebhookOutbox::poll_pending`] which uses it for atomic
//! row claiming — multiple OS processes polling the same SQLite file will
//! never dispatch the same row twice.

use std::sync::Arc;
use std::time::Duration;

use latchgate_webhooks::{deliver, WebhookEndpointConfig, WebhookOutbox, WebhookPayload};
use rand::Rng;
use tokio::sync::watch;
use tracing::{debug, info, warn};

/// Configuration for the outbox poller.
pub struct OutboxPollerConfig {
    /// How often to poll for pending deliveries.
    pub poll_interval: Duration,
    /// Maximum entries to process per poll cycle.
    pub batch_size: u32,
    /// Whether to allow HTTP (non-TLS) endpoints (dev mode).
    pub dev_mode: bool,
}

impl Default for OutboxPollerConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(2),
            batch_size: 50,
            dev_mode: false,
        }
    }
}

/// Generate a cryptographically random poller identifier.
///
/// 8 random bytes => 16 hex chars. Used as the `claimed_by` value in the
/// outbox table to distinguish concurrent pollers.
fn generate_poller_id() -> String {
    let bytes: [u8; 8] = rand::thread_rng().gen();
    hex::encode(bytes)
}

/// Start the background outbox poller. Returns a handle to the spawned task.
///
/// The poller will run until `shutdown_rx` receives `true` or the sender
/// is dropped.
pub fn start(
    outbox: Arc<WebhookOutbox>,
    endpoints: Vec<WebhookEndpointConfig>,
    config: OutboxPollerConfig,
    mut shutdown_rx: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    let poller_id = generate_poller_id();

    info!(
        poll_interval_ms = config.poll_interval.as_millis() as u64,
        batch_size = config.batch_size,
        endpoints = endpoints.len(),
        %poller_id,
        "webhook outbox poller started"
    );

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(config.poll_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                biased;
                _ = shutdown_rx.changed() => {
                    debug!("outbox poller: shutdown signal received");
                    break;
                }
                _ = interval.tick() => {
                    if let Err(e) = poll_and_deliver(&outbox, &endpoints, &config, &poller_id).await {
                        warn!(error = %e, "outbox poller cycle failed");
                    }
                }
            }
        }

        info!(%poller_id, "webhook outbox poller stopped");
    })
}

/// One poll cycle: atomically claim pending entries, attempt delivery, update status.
async fn poll_and_deliver(
    outbox: &Arc<WebhookOutbox>,
    endpoints: &[WebhookEndpointConfig],
    config: &OutboxPollerConfig,
    poller_id: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let entries = {
        let outbox = Arc::clone(outbox);
        let batch_size = config.batch_size;
        let poller_id = poller_id.to_owned();
        tokio::task::spawn_blocking(move || outbox.poll_pending(batch_size, &poller_id)).await??
    };

    if entries.is_empty() {
        return Ok(());
    }

    debug!(count = entries.len(), "outbox poller: processing batch");

    for entry in entries {
        let endpoint = match endpoints.iter().find(|ep| ep.name == entry.endpoint_name) {
            Some(ep) => ep,
            None => {
                warn!(
                    endpoint = %entry.endpoint_name,
                    event_id = %entry.event_id,
                    "outbox: endpoint not found in config, dead-lettering"
                );
                let outbox = Arc::clone(outbox);
                let id = entry.id;
                let _ = tokio::task::spawn_blocking(move || {
                    outbox.record_failure(id, "endpoint removed from config", 0, &[])
                })
                .await;
                continue;
            }
        };

        let payload: WebhookPayload = match serde_json::from_str(&entry.payload_json) {
            Ok(p) => p,
            Err(e) => {
                warn!(
                    event_id = %entry.event_id,
                    error = %e,
                    "outbox: corrupt payload, dead-lettering"
                );
                let outbox = Arc::clone(outbox);
                let id = entry.id;
                let err_msg = format!("payload deserialization failed: {e}");
                let _ = tokio::task::spawn_blocking(move || {
                    outbox.record_failure(id, &err_msg, 0, &[])
                })
                .await;
                continue;
            }
        };

        let ep_clone = endpoint.clone();
        let dev_mode = config.dev_mode;
        let delivery_result = tokio::time::timeout(
            Duration::from_secs(ep_clone.timeout_seconds + 5),
            deliver(&ep_clone, &payload, dev_mode),
        )
        .await;

        let outbox = Arc::clone(outbox);
        let id = entry.id;
        let max_retries = endpoint.max_retries;
        let backoff = endpoint.retry_backoff_seconds.to_vec();

        match delivery_result {
            Ok(Ok(())) => {
                let _ = tokio::task::spawn_blocking(move || outbox.mark_delivered(id)).await;
            }
            Ok(Err(e)) => {
                let err_msg = e.to_string();
                let _ = tokio::task::spawn_blocking(move || {
                    outbox.record_failure(id, &err_msg, max_retries, &backoff)
                })
                .await;
            }
            Err(_timeout) => {
                let _ = tokio::task::spawn_blocking(move || {
                    outbox.record_failure(id, "delivery timed out", max_retries, &backoff)
                })
                .await;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let cfg = OutboxPollerConfig::default();
        assert_eq!(cfg.poll_interval, Duration::from_secs(2));
        assert_eq!(cfg.batch_size, 50);
        assert!(!cfg.dev_mode);
    }

    #[test]
    fn poller_id_is_16_hex_chars() {
        let id = generate_poller_id();
        assert_eq!(id.len(), 16);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn poller_ids_are_unique() {
        let a = generate_poller_id();
        let b = generate_poller_id();
        assert_ne!(a, b);
    }
}
