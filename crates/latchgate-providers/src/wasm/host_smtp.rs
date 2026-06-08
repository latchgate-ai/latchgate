//! Host implementation for `latchgate:io/smtp` — outbound email.
//!
//! SECURITY: ALL recipient fields (To, Cc, Bcc) are validated against
//! allowed_sinks. A malicious provider could exfiltrate data via CC/BCC
//! if only the To field were checked.

use lettre::{AsyncTransport, Message};
use tracing::debug;

use super::latchgate;
use super::{strip_html_tags, WasmHostState};

impl latchgate::provider::io_smtp::Host for WasmHostState {
    async fn send(
        &mut self,
        msg: latchgate::provider::io_smtp::EmailMessage,
    ) -> Result<latchgate::provider::io_smtp::SendReceipt, String> {
        debug!(
            trace_id = %self.host_io.trace_id,
            to_count = msg.to.len(),
            cc_count = msg.cc.len(),
            bcc_count = msg.bcc.len(),
            "host_io.smtp: send"
        );

        if let Err(e) = self.host_io.check_import_allowed("latchgate:io/smtp") {
            return Err(format!("{e}"));
        }
        if let Err(e) = self.host_io.consume_io_call() {
            return Err(format!("{e}"));
        }
        // SECURITY: validate ALL recipient fields against allowed_sinks.
        // A malicious provider could exfiltrate data via CC/BCC if only
        // the To field were checked.
        for addr in msg.to.iter().chain(msg.cc.iter()).chain(msg.bcc.iter()) {
            if let Err(e) = self.host_io.validate_sink(addr) {
                return Err(format!("{e}"));
            }
        }

        let transport = self.resources.smtp_transport.as_ref().ok_or_else(|| {
            "SMTP host import unavailable: smtp_url is not configured in latchgate.toml".to_string()
        })?;

        // SMTP_FROM: per-action sender override. Falls back to the address
        // embedded in smtp_url (set at startup). Letting providers specify an
        // arbitrary sender is intentional — the relay is fixed, only the
        // envelope from varies.
        let from_addr = self
            .host_io
            .get_secret("SMTP_FROM")
            .map(|s| s.to_string())
            .ok_or_else(|| {
                "SMTP_FROM secret required (sender address for this action)".to_string()
            })?;

        let from_mailbox: lettre::message::Mailbox = from_addr
            .parse()
            .map_err(|e| format!("SMTP_FROM is not a valid address '{from_addr}': {e}"))?;

        let mut builder = Message::builder()
            .from(from_mailbox)
            .subject(msg.subject.clone());

        for to in &msg.to {
            let mbox: lettre::message::Mailbox =
                to.parse().map_err(|e| format!("invalid To '{to}': {e}"))?;
            builder = builder.to(mbox);
        }
        for cc in &msg.cc {
            let mbox: lettre::message::Mailbox =
                cc.parse().map_err(|e| format!("invalid Cc '{cc}': {e}"))?;
            builder = builder.cc(mbox);
        }
        for bcc in &msg.bcc {
            let mbox: lettre::message::Mailbox = bcc
                .parse()
                .map_err(|e| format!("invalid Bcc '{bcc}': {e}"))?;
            builder = builder.bcc(mbox);
        }

        let email = if msg.content_type.to_ascii_lowercase().contains("text/html") {
            // Strip HTML tags to produce a basic plain-text fallback.
            // Email clients that cannot render HTML will show this instead
            // of an empty body.
            let plain_fallback = strip_html_tags(&msg.body);
            builder
                .multipart(lettre::message::MultiPart::alternative_plain_html(
                    plain_fallback,
                    msg.body.clone(),
                ))
                .map_err(|e| format!("build html email: {e}"))?
        } else {
            builder
                .body(msg.body.clone())
                .map_err(|e| format!("build plain email: {e}"))?
        };

        transport
            .send(email)
            .await
            .map_err(|e| format!("SMTP send failed: {e}"))?;

        let total_recipients = (msg.to.len() + msg.cc.len() + msg.bcc.len()) as u32;
        // Generate a message-id for the receipt. SMTP servers typically assign
        // their own; ours serves as a correlation handle when the server
        // response doesn't include one.
        let message_id = format!("<{}@latchgate>", uuid::Uuid::now_v7());

        debug!(
            trace_id = %self.host_io.trace_id,
            recipients = total_recipients,
            "host_io.smtp: sent"
        );

        Ok(latchgate::provider::io_smtp::SendReceipt {
            message_id,
            recipients: total_recipients,
        })
    }
}
