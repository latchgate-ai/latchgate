//! Action discovery helpers — kernel facade.
//!
//! Re-exports provider-specific types (database mode, SQL classification)
//! so the API layer never imports `latchgate-providers` directly.

// Re-export database types used by action listing and approval review.
pub use latchgate_providers::{
    classify_sql, count_sql_params, extract_tables, DatabaseConfig, DatabaseMode, OperationClass,
};
