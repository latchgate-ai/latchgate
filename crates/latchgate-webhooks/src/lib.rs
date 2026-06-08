//! Outbound webhook notifications for LatchGate security events.
//!
//! Fire-and-forget delivery with HMAC-SHA256 signing, retry with exponential
//! backoff, and dead-letter audit logging. Webhook delivery never blocks the
//! enforcement pipeline — events are dispatched through a bounded async channel.
//!

pub(crate) mod config;
pub(crate) mod delivery;
pub(crate) mod dispatcher;
pub(crate) mod formatter;
pub(crate) mod outbox;

pub use config::{
    validate_webhook_configs, WebhookConfigError, WebhookEndpointConfig, WebhookFormat,
};
pub use delivery::{
    deliver, sign_payload, test_deliver, verify_signature, DeliveryError, TestDeliveryResult,
};
pub use dispatcher::WebhookDispatcher;
pub use formatter::{format_event, format_for_endpoint, redact_summary, WebhookPayload};
pub use outbox::{DeadLetterEntry, OutboxEntry, OutboxError, WebhookOutbox};

// Re-export EventKind from core — webhook config and dispatcher use this
// for subscription matching. No separate WebhookEventType needed.
pub use latchgate_core::EventKind;

/// Errors from the public dispatcher API.
#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    #[error("webhook config validation failed: {0}")]
    Config(#[from] WebhookConfigError),

    #[error("webhook channel full — event dropped")]
    ChannelFull,

    #[error("webhook dispatcher shut down")]
    ChannelClosed,
}
