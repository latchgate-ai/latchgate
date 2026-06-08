//! LatchGate Email provider.
//!
//! Sends email via the host-mediated SMTP import. The host handles
//! TLS, authentication, and connection management.
//!
//! # Request format
//!
//! ```json
//! {
//!   "to": ["user@example.com"],
//!   "cc": [],
//!   "subject": "Order confirmation",
//!   "body": "<html>...</html>",
//!   "content_type": "text/html"
//! }
//! ```

wit_bindgen::generate!({
    world: "provider",
    path: "../wit",
});

use serde::{Deserialize, Serialize};

use crate::latchgate::provider::io_log;
use crate::latchgate::provider::io_smtp;

#[derive(Deserialize)]
struct EmailRequest {
    to: Vec<String>,
    #[serde(default)]
    cc: Vec<String>,
    #[serde(default)]
    bcc: Vec<String>,
    subject: String,
    body: String,
    #[serde(default = "default_content_type")]
    content_type: String,
}

fn default_content_type() -> String {
    "text/plain".into()
}

#[derive(Serialize)]
struct EmailResponse {
    message_id: String,
    recipients: u32,
}

struct EmailProvider;

impl Guest for EmailProvider {
    fn execute(task_json: String) -> Result<String, String> {
        io_log::log_info("email provider: parsing request");

        let req: EmailRequest = serde_json::from_str(&task_json)
            .map_err(|e| format!("invalid request JSON: {e}"))?;

        io_log::log_info(&format!(
            "email provider: sending to {} recipients",
            req.to.len()
        ));

        let msg = io_smtp::EmailMessage {
            to: req.to,
            cc: req.cc,
            bcc: req.bcc,
            subject: req.subject,
            body: req.body,
            content_type: req.content_type,
        };

        let receipt = io_smtp::send(&msg)?;

        let response = EmailResponse {
            message_id: receipt.message_id,
            recipients: receipt.recipients,
        };

        serde_json::to_string(&response)
            .map_err(|e| format!("failed to serialise response: {e}"))
    }
}

export!(EmailProvider);
