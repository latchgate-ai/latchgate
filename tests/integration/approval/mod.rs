//! Approval lifecycle integration tests.
//!
//! Each submodule exercises a distinct security property of the approval
//! system through the full HTTP stack with real Redis + OPA.

mod api_contract;
mod atomic;
mod fault_recovery;
mod plan;
mod rollback;
