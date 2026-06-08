//! Host implementation for `latchgate:io/queue` — AMQP message publishing.
//!
//! SECURITY: queue names are validated against allowed_sinks. Publisher
//! confirms are enabled so delivery is broker-acknowledged before returning.

use tracing::debug;

use super::latchgate;
use super::WasmHostState;

impl latchgate::provider::io_queue::Host for WasmHostState {
    async fn publish(
        &mut self,
        req: latchgate::provider::io_queue::PublishRequest,
    ) -> Result<latchgate::provider::io_queue::PublishAck, String> {
        debug!(
            trace_id = %self.host_io.trace_id,
            queue = %req.queue_name,
            payload_bytes = req.payload.len(),
            "host_io.queue: publish"
        );

        if let Err(e) = self.host_io.check_import_allowed("latchgate:io/queue") {
            return Err(format!("{e}"));
        }
        if let Err(e) = self.host_io.consume_io_call() {
            return Err(format!("{e}"));
        }
        if let Err(e) = self.host_io.validate_sink(&req.queue_name) {
            return Err(format!("{e}"));
        }

        let pool = self.resources.amqp_pool.as_ref().ok_or_else(|| {
            "queue host import unavailable: amqp_url is not configured in latchgate.toml"
                .to_string()
        })?;

        // Acquire a connection from the pool and create a channel.
        // Channels are cheap to open on an existing connection — we create a
        // fresh one per call so each execution gets its own confirm scope and
        // there is no state bleed between concurrent executions.
        let conn = pool
            .get()
            .await
            .map_err(|e| format!("AMQP pool acquire failed: {e}"))?;

        let channel = conn
            .create_channel()
            .await
            .map_err(|e| format!("AMQP channel create failed: {e}"))?;

        // Enable publisher confirms so we get a broker-level delivery
        // acknowledgement before returning. Without this, publish is
        // fire-and-forget and we cannot confirm delivery in the receipt.
        channel
            .confirm_select(lapin::options::ConfirmSelectOptions::default())
            .await
            .map_err(|e| format!("AMQP confirm select failed: {e}"))?;

        // Routing key: explicit if provided, falls back to queue_name for
        // the default direct exchange.
        let routing_key = req
            .routing_key
            .as_deref()
            .unwrap_or(&req.queue_name)
            .to_string();

        // Build AMQP basic properties from WIT headers.
        let mut amqp_props = lapin::BasicProperties::default();
        for (key, value) in &req.headers {
            if key.eq_ignore_ascii_case("content-type") {
                amqp_props =
                    amqp_props.with_content_type(lapin::types::ShortString::from(value.as_str()));
            }
            if key.eq_ignore_ascii_case("message-id") {
                amqp_props =
                    amqp_props.with_message_id(lapin::types::ShortString::from(value.as_str()));
            }
        }

        let confirm = channel
            .basic_publish(
                "".into(), // default exchange — routes by queue name
                lapin::types::ShortString::from(routing_key.as_str()),
                lapin::options::BasicPublishOptions::default(),
                &req.payload,
                amqp_props,
            )
            .await
            .map_err(|e| format!("AMQP publish failed: {e}"))?;

        // Await the publisher confirm from the broker.
        // Confirmation is an enum (Ack/Nack/NotRequested) — delivery_tag
        // lives on the underlying BasicAck/BasicNack, not on Confirmation.
        let delivery_tag = match confirm
            .await
            .map_err(|e| format!("AMQP confirm failed: {e}"))?
        {
            lapin::Confirmation::Ack(Some(ack)) => ack.delivery_tag.to_string(),
            lapin::Confirmation::Ack(None) => String::new(),
            lapin::Confirmation::Nack(nack) => {
                return Err(format!(
                    "AMQP broker NACKed message (delivery_tag={})",
                    nack.map_or(0, |n| n.delivery_tag)
                ));
            }
            lapin::Confirmation::NotRequested => String::new(),
        };

        debug!(
            trace_id = %self.host_io.trace_id,
            queue = %req.queue_name,
            routing_key = %routing_key,
            delivery_tag = %delivery_tag,
            "host_io.queue: published and confirmed"
        );

        Ok(latchgate::provider::io_queue::PublishAck {
            delivery_tag,
            queue_name: req.queue_name.clone(),
        })
    }
}
