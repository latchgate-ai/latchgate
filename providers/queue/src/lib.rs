//! LatchGate Queue provider.
//!
//! Publishes messages to queues via the host-mediated queue import.
//! The host manages broker connections, TLS, and credential injection.
//!
//! # Request format
//!
//! ```json
//! {
//!   "queue_name": "order-events",
//!   "payload": { "event": "shipped", "order_id": "123" },
//!   "routing_key": "orders.shipped"
//! }
//! ```

wit_bindgen::generate!({
    world: "provider",
    path: "../wit",
});

use serde::{Deserialize, Serialize};

use crate::latchgate::provider::io_log;
use crate::latchgate::provider::io_queue;

#[derive(Deserialize)]
struct QueueRequest {
    queue_name: String,
    payload: serde_json::Value,
    #[serde(default)]
    routing_key: Option<String>,
    #[serde(default)]
    headers: std::collections::HashMap<String, String>,
}

#[derive(Serialize)]
struct QueueResponse {
    delivery_tag: String,
    queue_name: String,
}

struct QueueProvider;

impl Guest for QueueProvider {
    fn execute(task_json: String) -> Result<String, String> {
        io_log::log_info("queue provider: parsing request");

        let req: QueueRequest = serde_json::from_str(&task_json)
            .map_err(|e| format!("invalid request JSON: {e}"))?;

        let payload = serde_json::to_vec(&req.payload)
            .map_err(|e| format!("serialise payload: {e}"))?;

        let headers: Vec<(String, String)> = req.headers.into_iter().collect();

        let pub_req = io_queue::PublishRequest {
            queue_name: req.queue_name,
            payload,
            routing_key: req.routing_key,
            headers,
        };

        let ack = io_queue::publish(&pub_req)?;

        let response = QueueResponse {
            delivery_tag: ack.delivery_tag,
            queue_name: ack.queue_name,
        };

        serde_json::to_string(&response)
            .map_err(|e| format!("failed to serialise response: {e}"))
    }
}

export!(QueueProvider);
