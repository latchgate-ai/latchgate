//! Budget domain types shared across enforcement crates.
//!
//! [`BudgetSnapshot`] represents the remaining budget for a session at a
//! point in time. It is produced by the budget manager (in `latchgate-state`)
//! and consumed by the policy evaluator (in `latchgate-policy`) and the
//! enforcement pipeline (in `latchgate-kernel`).

use serde::{Deserialize, Serialize};

/// Point-in-time budget counters for a session.
///
/// Sent to OPA in `budgets_before`; returned (decremented) in
/// `budgets_after` on allow decisions. Uses `i64` to allow OPA policies
/// to detect underflow without unsigned arithmetic surprises.
#[must_use = "budget snapshots inform enforcement decisions — dropping one may skip budget checks"]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct BudgetSnapshot {
    /// Remaining action invocations in this session.
    pub calls_remaining: i64,
}
