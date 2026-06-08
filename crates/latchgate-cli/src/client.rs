//! Re-export the standalone `latchgate-client` crate.
//!
//! The HTTP client was extracted into its own crate so that the Rust SDK,
//! CLI, and third-party integrations share a single implementation.

pub use latchgate_client::*;
