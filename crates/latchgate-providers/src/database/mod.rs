//! Database provider domain types, SQL classification, policy context,
//! and host-side request validation.
//!
//! This module owns all database-specific logic. Core, kernel, policy,
//! and registry treat provider configuration as opaque `serde_json::Value`.

pub mod classify;
pub mod context;
pub mod types;
pub mod validate;

// Re-export primary types for ergonomic imports.
pub use classify::{classify_sql, count_sql_params, extract_tables};
pub use types::{DatabaseConfig, DatabaseMode, OperationClass};

// Internal-only re-exports — used within the crate but not by downstream consumers.
pub(crate) use context::build_database_policy_context;
pub(crate) use validate::validate_database_request;
