//! High-level operations exposed to the API layer.
//!
//! Each sub-module provides facade methods that hide subsystem internals
//! (`latchgate-ledger`, `latchgate-state`, `latchgate-auth`, `latchgate-providers`).
//! The API crate imports only from `latchgate-kernel` and `latchgate-core`.

pub mod actions;
pub mod approvals;
pub mod audit;
pub mod domains;
pub mod operator_auth;
pub mod paths;
pub mod receipts;
