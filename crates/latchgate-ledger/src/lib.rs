//! Append-only audit ledger, Prometheus metrics, and event types.
//!
//! Every action call (allow, deny, error, timeout) produces an `AuditEvent`
//! that is written to the SQLite WAL ledger and can be exported as JSONL.
//! The ledger is hash-chained for tamper detection.

pub(crate) mod events;
pub(crate) mod learned_allowlist;
pub(crate) mod learned_domains;
pub(crate) mod learned_paths;
pub(crate) mod metrics;
pub(crate) mod schema;
pub(crate) mod store;
mod store_approvals;
mod store_events;
mod store_intents;
mod store_receipts;

pub use events::{
    AuditAction, AuditApproval, AuditEvent, AuditEventBuilder, AuditExecution, AuditPolicy,
    AuditRequest, AuditSubject, Decision, EventType, RuntimeAudit,
};
pub use latchgate_core::ExecutionReceipt;
pub use learned_allowlist::EntrySource;
pub use learned_domains::LearnedDomain;
pub use learned_paths::{validate_path_glob, LearnedPath};
pub use metrics::Metrics;
pub use schema::REQUIRED_TABLES;
pub use store::{ChainVerification, EventFilter, ExecutionIntent, LedgerError, LedgerStore};
