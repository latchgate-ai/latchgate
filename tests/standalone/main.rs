//! Standalone tests — no external infrastructure required.
//!
//! Run via: `cargo test --test standalone`
//!
//! These tests exercise cross-crate security invariants that don't fit
//! in a single crate's unit test module but require no Redis, OPA, or
//! Docker.

mod compose_ports;
mod execution_path;
mod isolation;
mod ledger_integrity;
mod manifest_coverage;
mod receipt_rotation;
mod wasm_conformance;
mod webhooks;
