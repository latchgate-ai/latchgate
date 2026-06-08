//! Execution pipeline types: plans, grants, receipts, and their integrity
//! primitives.
//!
//! This module groups the artifacts that flow through the enforcement
//! pipeline — from operator approval through grant issuance to receipt
//! finalization. [`plan_hash`] provides the shared hashing contract;
//! [`plan_core`] holds the security-binding fields shared between plans
//! and grants.

mod approval;
mod budget;
mod grant;
mod plan_core;
mod plan_hash;
mod receipt;
mod trust;

pub use approval::ApprovedExecutionPlan;
pub use budget::BudgetSnapshot;
pub use grant::{BudgetReservation, ExecutionGrant, ExecutionGrantBuilder, GrantIdentity};
pub use plan_core::ExecutionPlanCore;
pub use receipt::{
    ExecutionReceipt, FailureClass, NormalizedResult, ReceiptSignatureStatus, VerificationOutcome,
};
pub use trust::TrustError;
