//! Host implementation for `latchgate:io/log` — structured provider logging.
//!
//! Log calls are rate-limited and sanitized by `HostState::consume_log_call`.

use super::latchgate;
use super::WasmHostState;

// io-log host import

impl latchgate::provider::io_log::Host for WasmHostState {
    async fn log_debug(&mut self, message: String) {
        if let Some(safe) = self.host_io.consume_log_call(&message) {
            tracing::debug!(
                trace_id = %self.host_io.trace_id,
                "[wasm-provider] {safe}"
            );
        }
    }

    async fn log_info(&mut self, message: String) {
        if let Some(safe) = self.host_io.consume_log_call(&message) {
            tracing::info!(
                trace_id = %self.host_io.trace_id,
                "[wasm-provider] {safe}"
            );
        }
    }

    async fn log_warn(&mut self, message: String) {
        if let Some(safe) = self.host_io.consume_log_call(&message) {
            tracing::warn!(
                trace_id = %self.host_io.trace_id,
                "[wasm-provider] {safe}"
            );
        }
    }
}
