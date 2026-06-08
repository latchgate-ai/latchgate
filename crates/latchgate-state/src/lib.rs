//! Persistent state stores for LatchGate.
//!
//! This crate owns stateful enforcement data that persists across requests
//! and (for durable backends) across process restarts:
//!
//!
//! # Backends
//!
//! | Backend  | Persistence | Use case                           |
//! |----------|-------------|------------------------------------|
//! | Redis    | Yes         | Multi-instance / HA deployments    |
//! | SQLite   | Yes         | Single-binary production mode      |
//! | InMemory | No          | Tests only                         |
//!
//! Backend selection is driven by config: `redis_url` present => Redis,
//! absent => SQLite. The in-memory backend is never used in production.

pub(crate) mod approval_inmemory;
pub(crate) mod approval_redis;
pub(crate) mod approval_sqlite;
pub(crate) mod approval_types;
pub mod approvals;
pub(crate) mod budgets;
pub(crate) mod sqlite;

#[cfg(test)]
pub(crate) mod approval_contract_tests;

// ── Primary re-exports ──────────────────────────────────────────────────────

pub use approval_types::{
    ApprovalError, ApprovalRecord, ApprovalState, ApprovalStatus, ApprovalSummary, ClaimInfo,
    ClaimedApproval, CompletionInfo, OutcomeMarker, PendingApproval,
};
pub use approvals::ApprovalStore;
pub use budgets::{BudgetError, BudgetManager};
pub use latchgate_core::SqliteInit;
pub use sqlite::{SqliteStateDb, SqliteStateError};
